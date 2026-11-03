from __future__ import annotations

import argparse
import json
import re
import shutil
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SIGNATURE_FILENAME = 'map_cat_health_icons_signatures.json'

@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int

@dataclass(frozen=True)
class MatchResult:
    symbol_name: str
    value: int
    section_name: str
    file_offset: int

class PeImage:
    def __init__(self, image_path: Path) -> None:
        self.image_path = image_path
        self.data = image_path.read_bytes()
        self.pe_offset = self._read_pe_offset()
        self.optional_header_offset = self.pe_offset + 24
        self.magic = struct.unpack_from("<H", self.data, self.optional_header_offset)[0]
        if self.magic not in (0x10B, 0x20B):
            raise ValueError(f"Unsupported PE optional-header magic 0x{self.magic:X}.")
        self.pointer_size = 8 if self.magic == 0x20B else 4
        self.image_base = struct.unpack_from("<Q" if self.pointer_size == 8 else "<I", self.data, self.optional_header_offset + (24 if self.pointer_size == 8 else 28))[0]
        self.sections = self._read_sections()

    def _read_pe_offset(self) -> int:
        if len(self.data) < 0x40 or self.data[:2] != b"MZ":
            raise ValueError("Input is not a valid PE file: missing MZ header.")
        pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe_offset:pe_offset + 4] != b"PE\0\0":
            raise ValueError("Input is not a valid PE file: missing PE signature.")
        return pe_offset

    def _read_sections(self) -> list[Section]:
        count = struct.unpack_from("<H", self.data, self.pe_offset + 6)[0]
        optional_size = struct.unpack_from("<H", self.data, self.pe_offset + 20)[0]
        table = self.pe_offset + 24 + optional_size
        out: list[Section] = []
        for index in range(count):
            offset = table + index * 40
            name = self.data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", self.data, offset + 8)
            out.append(Section(name, virtual_address, virtual_size, raw_pointer, raw_size))
        return out

    def section_for_rva(self, rva: int) -> Section | None:
        for section in self.sections:
            mapped_size = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + mapped_size:
                return section
        return None

    def rva_to_file_offset(self, rva: int) -> tuple[int, Section]:
        section = self.section_for_rva(rva)
        if section is None:
            raise ValueError(f"RVA 0x{rva:X} is not inside a PE section.")
        delta = rva - section.virtual_address
        if delta >= section.raw_size:
            raise ValueError(f"RVA 0x{rva:X} is in the virtual-only tail of section {section.name}.")
        return section.raw_pointer + delta, section

    def file_offset_to_rva(self, file_offset: int) -> int:
        for section in self.sections:
            if section.raw_pointer <= file_offset < section.raw_pointer + section.raw_size:
                return section.virtual_address + (file_offset - section.raw_pointer)
        raise ValueError(f"File offset 0x{file_offset:X} is not inside a PE section.")

    def get_section_bytes(self, section: Section) -> bytes:
        return self.data[section.raw_pointer:section.raw_pointer + section.raw_size]

    def data_directory(self, index: int) -> tuple[int, int]:
        directory_base = self.optional_header_offset + (112 if self.pointer_size == 8 else 96)
        return struct.unpack_from("<II", self.data, directory_base + index * 8)

    def import_iat_rva(self, dll_name: str, function_name: str) -> int:
        import_rva, import_size = self.data_directory(1)
        if import_rva == 0 or import_size == 0:
            raise RuntimeError("PE has no import directory.")
        descriptor_offset, _ = self.rva_to_file_offset(import_rva)
        stride = self.pointer_size
        ordinal_flag = 0x8000000000000000 if stride == 8 else 0x80000000
        index = 0
        while True:
            off = descriptor_offset + index * 20
            original_first_thunk, _timestamp, _forwarder, name_rva, first_thunk = struct.unpack_from("<IIIII", self.data, off)
            if not any((original_first_thunk, name_rva, first_thunk)):
                break
            name_off, _ = self.rva_to_file_offset(name_rva)
            dll = self.data[name_off:self.data.find(b"\0", name_off)].decode("ascii", errors="replace")
            if dll.casefold() == dll_name.casefold():
                lookup_rva = original_first_thunk or first_thunk
                thunk_index = 0
                while True:
                    thunk_off, _ = self.rva_to_file_offset(lookup_rva + thunk_index * stride)
                    thunk_value = struct.unpack_from("<Q" if stride == 8 else "<I", self.data, thunk_off)[0]
                    if thunk_value == 0:
                        break
                    if not (thunk_value & ordinal_flag):
                        hint_name_rva = thunk_value & (ordinal_flag - 1)
                        hint_name_off, _ = self.rva_to_file_offset(hint_name_rva)
                        end = self.data.find(b"\0", hint_name_off + 2)
                        imported = self.data[hint_name_off + 2:end].decode("ascii", errors="replace")
                        if imported == function_name:
                            return first_thunk + thunk_index * stride
                    thunk_index += 1
            index += 1
        raise RuntimeError(f"Import {dll_name}!{function_name} was not found.")

def parse_pattern(pattern_text: str) -> tuple[bytes, list[bool]]:
    values: list[int] = []
    mask: list[bool] = []
    for token in pattern_text.split():
        if token in ("?", "??"):
            values.append(0)
            mask.append(False)
        else:
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", token):
                raise ValueError(f"Invalid pattern token: {token}")
            values.append(int(token, 16))
            mask.append(True)
    return bytes(values), mask

def find_pattern(buffer: bytes, pattern: bytes, mask: list[bool]) -> list[int]:
    if not pattern:
        return []
    best_start = 0
    best_length = 0
    run_start: int | None = None
    for index, fixed in enumerate(mask + [False]):
        if fixed and run_start is None:
            run_start = index
        elif not fixed and run_start is not None:
            if index - run_start > best_length:
                best_start = run_start
                best_length = index - run_start
            run_start = None
    if best_length == 0:
        return []
    anchor = pattern[best_start:best_start + best_length]
    out: list[int] = []
    search_from = 0
    while True:
        anchor_pos = buffer.find(anchor, search_from)
        if anchor_pos < 0:
            break
        start = anchor_pos - best_start
        if 0 <= start and start + len(pattern) <= len(buffer):
            chunk = buffer[start:start + len(pattern)]
            if all((not mask[i]) or chunk[i] == pattern[i] for i in range(len(pattern))):
                out.append(start)
        search_from = anchor_pos + 1
    return out

def find_unique_pattern(pe_image: PeImage, symbol_name: str, config: dict[str, Any]) -> tuple[Section, int]:
    pattern, mask = parse_pattern(str(config["pattern"]))
    search_names = {str(x) for x in config.get("search_sections", [])}
    found: list[tuple[Section, int]] = []
    for section in pe_image.sections:
        if search_names and section.name not in search_names:
            continue
        for relative_offset in find_pattern(pe_image.get_section_bytes(section), pattern, mask):
            found.append((section, relative_offset))
    if not found:
        raise RuntimeError(f"{symbol_name}: signature did not match anything.")
    if len(found) != 1:
        where = ", ".join(f"{s.name}+0x{o:X}" for s, o in found[:8])
        raise RuntimeError(f"{symbol_name}: signature matched {len(found)} locations: {where}")
    return found[0]

def resolve_symbol(pe_image: PeImage, symbol_name: str, config: dict[str, Any]) -> MatchResult:
    resolver = str(config.get("resolver", "pattern_start_rva"))
    if resolver == "constant":
        return MatchResult(symbol_name, int(config["value"]), "constant", 0)
    if resolver == "import_iat_rva":
        value = pe_image.import_iat_rva(str(config["dll"]), str(config["name"]))
        section = pe_image.section_for_rva(value)
        return MatchResult(symbol_name, value, section.name if section else "IAT", 0)

    section, relative_offset = find_unique_pattern(pe_image, symbol_name, config)
    pattern_file_offset = section.raw_pointer + relative_offset
    pattern_rva = section.virtual_address + relative_offset

    if resolver == "pattern_start_rva":
        match_offset = int(config.get("match_offset", 0))
        value = pattern_rva + match_offset
        return MatchResult(symbol_name, value, section.name, pattern_file_offset + match_offset)
    if resolver == "rip_relative_rva":
        displacement_offset = int(config["displacement_offset"])
        instruction_end_offset = int(config["instruction_end_offset"])
        disp_file_offset = pattern_file_offset + displacement_offset
        displacement = struct.unpack_from("<i", pe_image.data, disp_file_offset)[0]
        value = pattern_rva + instruction_end_offset + displacement
        resolved_section = pe_image.section_for_rva(value)
        return MatchResult(symbol_name, value, resolved_section.name if resolved_section else "unknown", disp_file_offset)
    if resolver in ("u8_at_pattern_offset", "u16_at_pattern_offset", "u32_at_pattern_offset"):
        value_offset = int(config["value_offset"])
        file_offset = pattern_file_offset + value_offset
        fmt = {"u8_at_pattern_offset": "<B", "u16_at_pattern_offset": "<H", "u32_at_pattern_offset": "<I"}[resolver]
        value = struct.unpack_from(fmt, pe_image.data, file_offset)[0]
        return MatchResult(symbol_name, value, section.name, file_offset)
    raise ValueError(f"{symbol_name}: unknown resolver '{resolver}'.")

def format_define_value(original_numeric_text: str, value: int) -> str:
    if original_numeric_text.lower().startswith("0x"):
        width = max(len(original_numeric_text) - 2, 2)
        return f"0x{value:0{width}X}"
    return str(value)

def update_define_in_text(text: str, symbol_name: str, value: int) -> tuple[str, int]:
    pattern = re.compile(rf"(^\s*#define\s+{re.escape(symbol_name)}\s+)(0x[0-9A-Fa-f]+|\d+)([uUlL]*)(.*$)", re.MULTILINE)
    def replace(match: re.Match[str]) -> str:
        return f"{match.group(1)}{format_define_value(match.group(2), value)}{match.group(3)}{match.group(4)}"
    return pattern.subn(replace, text)

def load_signatures(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        config: dict[str, Any] = json.load(handle)
    if not isinstance(config.get("symbols"), dict):
        raise ValueError("Signature file must contain a 'symbols' object.")
    if not isinstance(config.get("source_files"), list):
        raise ValueError("Signature file must contain a 'source_files' array.")
    return config

def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve game RVAs/offsets from signatures and update this mod's source defines.")
    parser.add_argument("exe_path", type=Path, help="Path to the Mewgenics executable to resolve against.")
    parser.add_argument("--mod-root", type=Path, default=Path(__file__).resolve().parent.parent, help="Mod root containing src/ (defaults to parent of re_tools).")
    parser.add_argument("--signatures", type=Path, default=Path(__file__).resolve().parent / SIGNATURE_FILENAME, help="Path to the signature JSON.")
    parser.add_argument("--dry-run", action="store_true", help="Resolve and print values without rewriting source files.")
    parser.add_argument("--no-backup", action="store_true", help="Do not create .bak copies before rewriting source files.")
    args = parser.parse_args()

    pe_image = PeImage(args.exe_path)
    signature_config = load_signatures(args.signatures)
    resolved: dict[str, int] = {}
    for symbol_name, config_any in signature_config["symbols"].items():
        result = resolve_symbol(pe_image, symbol_name, dict(config_any))
        
        if config_any.get("function_entry"):
            table_rva, table_size = pe_image.data_directory(3)
            table_offset, _ = pe_image.rva_to_file_offset(table_rva)

            entries = {
                struct.unpack_from("<I", pe_image.data, offset)[0]
                for offset in range(table_offset, table_offset + table_size, 12)
            }

            if result.value not in entries:
                raise RuntimeError(f"{symbol_name}: resolved address is not a function entry!")
        resolved[symbol_name] = result.value
        print(f"{symbol_name} = 0x{result.value:X} ({result.section_name}, file+0x{result.file_offset:X})")

    call_offset, _ = pe_image.rva_to_file_offset(resolved["RVA_VANILLA_FALLBACK_SETFRAME_CALL"])
    displacement = struct.unpack_from("<i", pe_image.data, call_offset + 1)[0]
    target = resolved["RVA_VANILLA_FALLBACK_SETFRAME_CALL"] + 5 + displacement

    if pe_image.data[call_offset] != 0xE8 or target != resolved["RVA_SET_TIMELINE_FRAME"]:
        raise RuntimeError("Map fallback is not a call to the resolved timeline frame setter!")

    if args.dry_run:
        print("Dry run complete. Source files were not modified.")
        return 0

    file_texts: dict[Path, str] = {}
    original_texts: dict[Path, str] = {}
    for relative in signature_config["source_files"]:
        path = args.mod_root / str(relative)
        original = path.read_text(encoding="utf-8")
        original_texts[path] = original
        file_texts[path] = original

    missing: list[str] = []
    updated_counts: dict[Path, int] = {path: 0 for path in file_texts}
    for symbol_name, value in resolved.items():
        replacements = 0
        for path, text in list(file_texts.items()):
            new_text, count = update_define_in_text(text, symbol_name, value)
            if count:
                file_texts[path] = new_text
                updated_counts[path] += count
                replacements += count
        if replacements == 0:
            missing.append(symbol_name)
    if missing:
        raise RuntimeError("Could not find matching #define(s) for: " + ", ".join(missing))

    changed = [path for path in file_texts if file_texts[path] != original_texts[path]]
    if not changed:
        print("No source changes needed.")
        return 0
    for path in changed:
        if not args.no_backup:
            backup = path.with_suffix(path.suffix + ".bak")
            shutil.copy2(path, backup)
            print(f"Backup written: {backup}")
        path.write_text(file_texts[path], encoding="utf-8", newline="")
        print(f"Updated {updated_counts[path]} define(s) in {path}")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exception:
        print(f"error: {exception}", file=sys.stderr)
        raise SystemExit(1)
