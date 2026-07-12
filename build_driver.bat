@echo off
REM =============================================================================
REM build_driver.bat — Build dmmdzz_injector.sys with raw cl.exe + WDK headers
REM
REM This script uses the MSVC compiler directly with WDK include paths,
REM bypassing the need for the WindowsKernelModeDriver10.0 VS integration
REM (which is not available for VS 18 preview).
REM
REM Usage:
REM     build_driver.bat              [Release]
REM     build_driver.bat Debug
REM =============================================================================
setlocal enabledelayedexpansion

set "CONFIG=%~1"
if "%CONFIG%"=="" set "CONFIG=Release"
set "ARCH=x64"
set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"
set "DRIVER_SRC=%PROJECT_ROOT%\driver"
set "OUT_DIR=%PROJECT_ROOT%\build_driver"
set "OBJ_DIR=%OUT_DIR%\obj"

echo [*] Configuration: %CONFIG%
echo [*] Project root:  %PROJECT_ROOT%
echo.

REM --- 1. Find Visual Studio ---
echo [*] Locating Visual Studio...
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL=%%i"
echo [+] VS: !VS_INSTALL!
set "VCVARS=!VS_INSTALL!\VC\Auxiliary\Build\vcvars64.bat"

REM --- 2. Find WDK ---
echo [*] Locating WDK...
set "WDK_ROOT=D:\Windows Kits\10"
if not exist "%WDK_ROOT%" set "WDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "WDK_VERSION="
for /f "usebackq delims=" %%d in (`dir /b /ad "%WDK_ROOT%\Include" 2^>nul ^| findstr /r "^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$"`) do (
    if exist "%WDK_ROOT%\Include\%%d\km\ntddk.h" set "WDK_VERSION=%%d"
)
if not defined WDK_VERSION (
    echo [!] WDK not found!
    exit /b 1
)
set "KM_INC=%WDK_ROOT%\Include\%WDK_VERSION%\km"
set "KM_CRT_INC=%WDK_ROOT%\Include\%WDK_VERSION%\km\crt"
set "SHARED_INC=%WDK_ROOT%\Include\%WDK_VERSION%\shared"
set "UCRT_INC=%WDK_ROOT%\Include\%WDK_VERSION%\ucrt"
set "KM_LIB=%WDK_ROOT%\Lib\%WDK_VERSION%\km\%ARCH%"
echo [+] WDK: %WDK_VERSION%
echo.

REM --- 3. Load MSVC environment ---
echo [*] Loading MSVC environment...
call "%VCVARS%" >nul 2>&1
REM Clear INCLUDE/LIB so only our explicit paths are used (avoid um\ conflicts)
set "INCLUDE="
set "LIB="
set "LIBPATH="
echo [+] cl.exe ready.
echo.

REM --- 4. Prepare output ---
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

REM --- 5. Compile ---
REM _KERNEL_MODE is defined by the /kernel flag. This makes driver.h include
REM ntddk.h (which defines NT_INCLUDED), preventing minwindef.h from
REM including winnt.h — so we don't need um\ in the include path.
set "INCLUDE_ARGS=/I"%KM_INC%" /I"%KM_CRT_INC%" /I"%SHARED_INC%" /I"%UCRT_INC%" /I"%DRIVER_SRC%""
set "COMPILE_FLAGS=/c /kernel /GS- /Zl /Zi /W3 /WX- /O2 /DNT=1 /D_AMD64_=1 /D_WIN32_WINNT=0x0A00 /utf-8"

echo [*] Compiling (config: %CONFIG%)...
for %%S in (main.c ioctl.c memory.c process.c) do (
    echo   -^> %%S
    cl.exe %COMPILE_FLAGS% %INCLUDE_ARGS% /Fo"%OBJ_DIR%\%%~nS.obj" "%DRIVER_SRC%\%%S"
    if errorlevel 1 (
        echo [!] Compile of %%S failed.
        exit /b 1
    )
)
echo [+] All sources compiled.
echo.

REM --- 6. Link ---
echo [*] Linking dmmdzz_injector.sys ...
set "OBJ_FILES=%OBJ_DIR%\main.obj %OBJ_DIR%\ioctl.obj %OBJ_DIR%\memory.obj %OBJ_DIR%\process.obj"
set "LINK_FLAGS=/SUBSYSTEM:NATIVE,10.0 /DRIVER /ENTRY:DriverEntry /NODEFAULTLIB /MACHINE:X64"
set "LINK_LIBS=/LIBPATH:"%KM_LIB%" ntoskrnl.lib hal.lib BufferOverflowFastFailK.lib"
set "LINK_OUT=/OUT:"%OUT_DIR%\dmmdzz_injector.sys" /DEBUG /PDB:"%OUT_DIR%\dmmdzz_injector.pdb""

link.exe %LINK_FLAGS% %LINK_LIBS% %LINK_OUT% %OBJ_FILES%
if errorlevel 1 (
    echo [!] Link failed.
    exit /b 1
)
echo [+] Linked successfully.
echo.

REM --- 7. Copy INF ---
copy /Y "%DRIVER_SRC%\dmmdzz_injector.inf" "%OUT_DIR%\dmmdzz_injector.inf" >nul

REM --- 8. Done ---
echo ============================================================
echo  Build complete!
echo ============================================================
echo.
echo  Artifacts:
dir /b "%OUT_DIR%\dmmdzz_injector.*" 2>nul
echo.
echo  Next steps:
echo    1. Enable test signing (admin CMD):
echo         bcdedit /set testsigning on
echo         shutdown /r /t 0
echo    2. After reboot, install the driver (admin CMD):
echo         sc create dmmdzz_injector type= kernel binPath= "%OUT_DIR%\dmmdzz_injector.sys"
echo         sc start  dmmdzz_injector
echo    3. Run the user-mode controller:
echo         dmmdzz_ctl.exe target.exe
echo.

endlocal
