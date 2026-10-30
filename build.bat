@echo off
REM Build MapCatHealthIcons.dll!

set "DESTINATION_DIR=C:\Users\Pseudonym_Tim\Desktop\Tools\Mewtator\mods\MapCatHealthIcons"
REM set "DESTINATION_DIR=D:\SteamLibrary\steamapps\common\Mewgenics"

REM Toggle deployment mode:
REM true = Mewtator deploy (Mewtator deploy, set to existing Mewtator mod folder)
REM false = Normal deploy (Normal deploy, set to game root directory)
set "MEWTATOR_DEPLOY=true"

setlocal
cd /d "%~dp0"

REM Locate Visual Studio via vswhere...
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found. Is Visual Studio installed?
    pause
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do (
    set "VSDIR=%%i"
)

if not defined VSDIR (
    echo ERROR: Could not find a Visual Studio installation.
    pause
    exit /b 1
)

if not exist "%VSDIR%\VC\Auxiliary\Build\vcvarsall.bat" (
    echo ERROR: vcvarsall.bat not found at "%VSDIR%\VC\Auxiliary\Build\"
    pause
    exit /b 1
)

echo Setting up x64 MSVC environment...
call "%VSDIR%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

REM Build...
echo.
echo Building MapCatHealthIcons.dll...

cl /LD /O2 /GS- /W3 /D_CRT_SECURE_NO_WARNINGS /TC src\MapCatHealthIcons.c /Fe:MapCatHealthIcons.dll

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Build FAILED.
    pause
    exit /b 1
)

echo.
echo Build succeeded!

REM Clean intermediate files...
del /Q MapCatHealthIcons.obj MapCatHealthIcons.lib MapCatHealthIcons.exp 2>nul

if /I "%~1"=="--build-only" exit /b 0

REM Determine deploy path...
if /I "%MEWTATOR_DEPLOY%"=="true" (
    set "DEPLOY_DIR=%DESTINATION_DIR%"
) else (
    set "DEPLOY_DIR=%DESTINATION_DIR%\mods"
)

REM Create deploy directory if needed...
if not exist "%DEPLOY_DIR%" (
    mkdir "%DEPLOY_DIR%"
)

REM Deploy main files...
copy /Y MapCatHealthIcons.dll "%DEPLOY_DIR%\MapCatHealthIcons.dll"
copy /Y description.json "%DEPLOY_DIR%\description.json"


echo Deployed to %DEPLOY_DIR%