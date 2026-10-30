#include <stdint.h>
#include <string.h>
#include <windows.h>

#include "mewjector.h"

typedef uint8_t u8;
typedef uint32_t u32;
typedef int32_t i32;
typedef int64_t i64;
typedef uintptr_t uptr;

#define MOD_NAME "Map Cat Health Icons"

#define RVA_MAP_PLAYER_ICON_REFRESH 0x00223C00ULL // Refreshes map cat icons...
#define MAP_REFRESH_STOLEN_BYTES 15
#define RVA_GET_MAP_CONTEXT 0x00091CD0ULL // Grabs map context and its cat database...
#define RVA_LOOKUP_CAT 0x000D85A0ULL // Finds cat by ID...
#define RVA_CAT_MAX_HP 0x000C3A00ULL // Works out max HP, stat overrides and all...
#define RVA_SET_TIMELINE_FRAME 0x009B47F0ULL // Sets the timeline frame...
#define RVA_SET_TIMELINE_LABEL_STOP 0x009B4B50ULL // Jumps to a label and stops the thing...
#define LABEL_STOP_HOOK_STOLEN_BYTES 15
#define RVA_VANILLA_FALLBACK_SETFRAME_CALL 0x002247D6ULL // Frame zero reset that kills the animation...
#define VANILLA_FALLBACK_CALL_SIZE 5U

// Map icon guts...
#define MAP_ICON_COUNT_OFFSET 0x4CULL
#define MAP_ICON_ENTRIES_OFFSET 0x50ULL
#define MAP_ENTRY_SIZE 0x20ULL
#define MAP_ENTRY_ICON_OFFSET 0x00ULL
#define MAP_ENTRY_CAT_ID_OFFSET 0x10ULL
#define MAP_ENTRY_ACTIVE_OFFSET 0x18ULL
#define MAP_CONTEXT_CATDB_OFFSET 0x598ULL

// Cat health bits...
#define CAT_CURRENT_HP_OFFSET 0x7A8ULL
#define CAT_DEAD_FLAG_OFFSET 0x7ACULL
#define CAT_STATUS_FLAGS_OFFSET 0xBF8ULL
#define CAT_STATUS_DEAD_BIT 0x20U
#define CAT_HP_FULL_SENTINEL 0x3FFFFFFF

// Flash timeline crap...
#define DISPLAY_TIMELINE_OFFSET 0x80ULL
#define TIMELINE_PLAY_FLAGS_OFFSET 0x09ULL
#define TIMELINE_MOVIE_DEF_OFFSET 0xD0ULL
#define TIMELINE_CURRENT_FRAME_OFFSET 0xD8ULL
#define TIMELINE_PLAYING_BIT 0x02U
#define MAP_PLAYER_ICON_FRAME_COUNT 20

// A party should never have this many damn icons...
#define MAX_REASONABLE_MAP_ICONS 32U

// Game functions we poke...
typedef void  (__fastcall *fn_map_refresh)(void* map);
typedef void* (__fastcall *fn_get_map_context)(void* map);
typedef void* (__fastcall *fn_lookup_cat)(void* catDb, i64 catID);
typedef int   (__fastcall *fn_cat_max_hp)(void* catData, const i32* statOverrides);
typedef void  (__fastcall *fn_set_timeline_frame)(void* timeline, int frame);
typedef void  (__fastcall *fn_set_timeline_label_stop)(void* timeline, void* labelString);
typedef int   (__fastcall *fn_timeline_type)(void* timeline);

static MewjectorAPI g_mj;
static fn_map_refresh g_origMapRefresh;
static fn_set_timeline_label_stop g_origSetTimelineLabelStop;
static uptr g_gameBase;

// -1 means use the real stat, no override bullshit...
// (Helper reads seven ints, eight keeps this aligned to 16 bytes...)
__declspec(align(16)) static const i32 g_defaultStatOverrides[8] = {
    -1, -1, -1, -1, -1, -1, -1, -1
};

static int current_build_matches(void)
{
    static const u8 expectedMapRefreshPrologue[MAP_REFRESH_STOLEN_BYTES] = {
        0x48, 0x8B, 0xC4, 0x55, 0x53, 0x56, 0x57, 0x41,
        0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57
    };

    static const u8 expectedFallbackSetFrameCall[VANILLA_FALLBACK_CALL_SIZE] = {
        0xE8, 0x55, 0xC3, 0x77, 0x00
    };

    static const u8 expectedLabelStopPrologue[LABEL_STOP_HOOK_STOLEN_BYTES] = {
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x18,
        0x48, 0x89, 0x74, 0x24, 0x20
    };

    if (!g_gameBase) {
        return 0;
    }

    if (memcmp((const u8*)(g_gameBase + RVA_MAP_PLAYER_ICON_REFRESH), expectedMapRefreshPrologue, MAP_REFRESH_STOLEN_BYTES) != 0) {
        return 0;
    }

    if (memcmp((const u8*)(g_gameBase + RVA_SET_TIMELINE_LABEL_STOP), expectedLabelStopPrologue, LABEL_STOP_HOOK_STOLEN_BYTES) != 0) {
        return 0;
    }

    return memcmp((const u8*)(g_gameBase + RVA_VANILLA_FALLBACK_SETFRAME_CALL), expectedFallbackSetFrameCall, VANILLA_FALLBACK_CALL_SIZE) == 0;
}

// Vanilla keeps resetting frame 0 and restarting the damn cat animation...
// NOP just that call, vanilla still stops the parent timeline afterward...
// Pyrophina, Zaratana, and dead labels use separate path...
static int suppress_vanilla_fallback_frame_reset(void)
{
    u8* target;
    DWORD oldProtect = 0U;
    DWORD ignoredProtect = 0U;

    target = (u8*)(g_gameBase + RVA_VANILLA_FALLBACK_SETFRAME_CALL);

    if (!VirtualProtect(target, VANILLA_FALLBACK_CALL_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return 0;
    }

    memset(target, 0x90, VANILLA_FALLBACK_CALL_SIZE);

    FlushInstructionCache(GetCurrentProcess(), target, VANILLA_FALLBACK_CALL_SIZE);

    VirtualProtect(target, VANILLA_FALLBACK_CALL_SIZE, oldProtect, &ignoredProtect);
    return 1;
}

static int game_string_equals_ascii(const void* gameString, const char* wanted)
{
    const u8* s = (const u8*)gameString;
    const char* data;
    uptr len;
    uptr cap;
    uptr i;

    if (!s || !wanted) {
        return 0;
    }

    len = *(const uptr*)(s + 0x10);
    cap = *(const uptr*)(s + 0x18);
    data = (cap > 15U) ? *(const char* const*)s : (const char*)s;

    if (!data) {
        return 0;
    }

    for (i = 0; i < len; ++i) {
        if (wanted[i] == 0 || data[i] != wanted[i]) {
            return 0;
        }
    }

    return wanted[len] == 0;
}

static int is_map_player_damage_timeline(void* timeline)
{
    u8* t = (u8*)timeline;
    void* movieDef;
    i32 frameCount;
    i32 currentFrame;

    if (!t) {
        return 0;
    }

    movieDef = *(void**)(t + TIMELINE_MOVIE_DEF_OFFSET);

    if (!movieDef) {
        return 0;
    }

    frameCount = *(i32*)movieDef;
    currentFrame = *(i32*)(t + TIMELINE_CURRENT_FRAME_OFFSET);
    return frameCount == MAP_PLAYER_ICON_FRAME_COUNT && (currentFrame == 1 || currentFrame == 2);
}

// The colorless label pulls frame 0 bullshit...
// Block it only on a 20-frame icon already showing damage...
// Leave the other labels alone...
static void __fastcall HookTimelineLabelStop(void* timeline, void* labelString)
{
    if (is_map_player_damage_timeline(timeline) && game_string_equals_ascii(labelString, "colorless")) {
        *(u8*)((u8*)timeline + TIMELINE_PLAY_FLAGS_OFFSET) &= (u8)~TIMELINE_PLAYING_BIT;
        return;
    }

    if (g_origSetTimelineLabelStop) {
        g_origSetTimelineLabelStop(timeline, labelString);
    }
}

static int choose_health_frame(i32 hp, i32 maxHp)
{
    float ratio;

    if (maxHp <= 0) {
        return 0;
    }
    if (hp == CAT_HP_FULL_SENTINEL) {
        return 0;
    }

    // Match Cathead's float rounding, weird low-HP cutoffs and all...
    // Check superweak first, integer math would screw up the boundaries...
    // RVA_CAT_MAX_HP supplies the same effective max HP...
    ratio = (float)hp / (float)maxHp;

    if (hp <= 1 || (double)ratio < 0.1) {
        return 2; // Superweak, cat is fucked...
    }

    if (hp <= 5 || ratio < 0.5f) {
        return 1; // Weak, cat is having a bad time...
    }
    
    return 0; // Normal, cat is fine...
}

static void apply_health_frames(void* map)
{
    fn_get_map_context getMapContext;
    fn_lookup_cat lookupCat;
    fn_cat_max_hp catMaxHp;
    fn_set_timeline_frame setFrame;
    u8* mapBytes = (u8*)map;
    void* context;
    void* catDb;
    u8* entries;
    u32 count;
    u32 i;

    if (!map || !g_gameBase) {
        return;
    }

    getMapContext = (fn_get_map_context)(g_gameBase + RVA_GET_MAP_CONTEXT);
    lookupCat = (fn_lookup_cat)(g_gameBase + RVA_LOOKUP_CAT);
    catMaxHp = (fn_cat_max_hp)(g_gameBase + RVA_CAT_MAX_HP);
    setFrame = (fn_set_timeline_frame)(g_gameBase + RVA_SET_TIMELINE_FRAME);

    context = getMapContext(map);

    if (!context) {
        return;
    }

    catDb = *(void**)((u8*)context + MAP_CONTEXT_CATDB_OFFSET);

    if (!catDb) {
        return;
    }

    count = *(u32*)(mapBytes + MAP_ICON_COUNT_OFFSET);
    entries = *(u8**)(mapBytes + MAP_ICON_ENTRIES_OFFSET);

    if (!entries || count == 0U || count > MAX_REASONABLE_MAP_ICONS) {
        return;
    }

    for (i = 0; i < count; ++i) {
        u8* entry = entries + ((uptr)i * MAP_ENTRY_SIZE);
        i64 catID;
        void* cat;
        void* icon;
        void* timeline;
        void** vtable;
        fn_timeline_type timelineType;
        i32 hp;
        i32 maxHp;
        int frame;

        if (*(u8*)(entry + MAP_ENTRY_ACTIVE_OFFSET) == 0U) {
            continue;
        }

        // Negative IDs are special follower/sentinel stuff...
        catID = *(i64*)(entry + MAP_ENTRY_CAT_ID_OFFSET);

        if (catID < 0) {
            continue;
        }

        cat = lookupCat(catDb, catID);
        
        if (!cat) {
            continue;
        }

        // Let the game normally handle the dead cats...
        if (*(u8*)((u8*)cat + CAT_DEAD_FLAG_OFFSET) != 0U) {
            continue;
        }

        if ((*(u8*)((u8*)cat + CAT_STATUS_FLAGS_OFFSET) & CAT_STATUS_DEAD_BIT) != 0U) {
            continue;
        }

        icon = *(void**)(entry + MAP_ENTRY_ICON_OFFSET);

        if (!icon) {
            continue;
        }

        timeline = *(void**)((u8*)icon + DISPLAY_TIMELINE_OFFSET);

        if (!timeline) {
            continue;
        }

        // The game normally checks this type too, numeric setter needs type 2...
        vtable = *(void***)timeline;

        if (!vtable || !vtable[0]) {
            continue;
        }

        timelineType = (fn_timeline_type)vtable[0];

        if (timelineType(timeline) != 2) {
            continue;
        }

        hp = *(i32*)((u8*)cat + CAT_CURRENT_HP_OFFSET);
        maxHp = catMaxHp(cat, g_defaultStatOverrides);
        frame = choose_health_frame(hp, maxHp);

        // Stop the parent, let the nested cat animation do its thing...
        // (Same frame means no rebuild, so no animation restart...)
        setFrame(timeline, frame);
        *(u8*)((u8*)timeline + TIMELINE_PLAY_FLAGS_OFFSET) &= (u8)~TIMELINE_PLAYING_BIT;
    }
}

static void __fastcall HookMapRefresh(void* map)
{
    if (g_origMapRefresh) {
        g_origMapRefresh(map);
    }
    
    apply_health_frames(map);
}

BOOL __stdcall DllMain(HINSTANCE hinst, DWORD reason, void* reserved)
{
    void* trampoline = (void*)0;
    void* labelTrampoline = (void*)0;
    int isOkay;
    (void)reserved;

    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    DisableThreadLibraryCalls(hinst);

    if (!MJ_Resolve(&g_mj)) {
        return TRUE;
    }

    g_gameBase = g_mj.GetGameBase();

    if (!g_gameBase) {
        return TRUE;
    }

    if (!current_build_matches()) {
        g_mj.Log(MOD_NAME, "Unsupported game build!");
        return TRUE;
    }

    isOkay = g_mj.InstallHook((uptr)RVA_SET_TIMELINE_LABEL_STOP, LABEL_STOP_HOOK_STOLEN_BYTES, (void*)&HookTimelineLabelStop, &labelTrampoline, 10, MOD_NAME);

    if (!isOkay || !labelTrampoline) {
        g_mj.Log(MOD_NAME, "Failed to install timeline label-stop hook.");
        return TRUE;
    }

    g_origSetTimelineLabelStop = (fn_set_timeline_label_stop)labelTrampoline;

    isOkay = g_mj.InstallHook((uptr)RVA_MAP_PLAYER_ICON_REFRESH, MAP_REFRESH_STOLEN_BYTES, (void*)&HookMapRefresh, &trampoline, 10, MOD_NAME);
    
    if (!isOkay || !trampoline) {
        g_mj.Log(MOD_NAME, "Failed to install map icon refresh hook.");
        return TRUE;
    }

    g_origMapRefresh = (fn_map_refresh)trampoline;

    if (!suppress_vanilla_fallback_frame_reset()) {
        g_mj.Log(MOD_NAME, "Installed, but failed to suppress vanilla frame 0 reset!");
        return TRUE;
    }

    g_mj.Log(MOD_NAME, "Loaded!");

    return TRUE;
}
