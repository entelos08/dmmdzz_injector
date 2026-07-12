$ErrorActionPreference = 'Continue'
Set-Location 'd:\Project\dmmdzz_injector'

# Find VS
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { $vswhere = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe" }
$vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
$vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
Write-Host "[+] VS: $vsInstall"

# Find WDK
$wdkRoot = "D:\Windows Kits\10"
$wdkVer = (Get-ChildItem "$wdkRoot\Include" -Directory | Where-Object { Test-Path "$wdkRoot\Include\$($_.Name)\km\ntddk.h" } | Select-Object -Last 1).Name
$kmInc = "$wdkRoot\Include\$wdkVer\km"
$kmCrtInc = "$wdkRoot\Include\$wdkVer\km\crt"
$sharedInc = "$wdkRoot\Include\$wdkVer\shared"
$ucrtInc = "$wdkRoot\Include\$wdkVer\ucrt"
$kmLib = "$wdkRoot\Lib\$wdkVer\km\x64"
Write-Host "[+] WDK: $wdkVer"

# Prepare output
$outDir = "d:\Project\dmmdzz_injector\build_driver"
$objDir = "$outDir\obj"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

# Create a temp batch file that loads vcvars then runs cl.exe
$tempBat = [System.IO.Path]::GetTempFileName() + ".bat"
$srcDir = "d:\Project\dmmdzz_injector\driver"
$batContent = @"
@echo off
call "$vcvars" >nul 2>&1
set INCLUDE=
set LIB=
set LIBPATH=

set INCLUDE_ARGS=/I"$kmInc" /I"$kmCrtInc" /I"$sharedInc" /I"$ucrtInc" /I"$srcDir"
set COMPILE_FLAGS=/c /kernel /GS- /Zl /Zi /W3 /WX- /O2 /DNT=1 /D_AMD64_=1 /D_WIN32_WINNT=0x0A00 /utf-8

echo [*] Compiling main.c ...
cl.exe %COMPILE_FLAGS% %INCLUDE_ARGS% /Fo"$objDir\main.obj" "$srcDir\main.c"
if errorlevel 1 (echo [!] main.c failed & exit /b 1)

echo [*] Compiling ioctl.c ...
cl.exe %COMPILE_FLAGS% %INCLUDE_ARGS% /Fo"$objDir\ioctl.obj" "$srcDir\ioctl.c"
if errorlevel 1 (echo [!] ioctl.c failed & exit /b 1)

echo [*] Compiling memory.c ...
cl.exe %COMPILE_FLAGS% %INCLUDE_ARGS% /Fo"$objDir\memory.obj" "$srcDir\memory.c"
if errorlevel 1 (echo [!] memory.c failed & exit /b 1)

echo [*] Compiling process.c ...
cl.exe %COMPILE_FLAGS% %INCLUDE_ARGS% /Fo"$objDir\process.obj" "$srcDir\process.c"
if errorlevel 1 (echo [!] process.c failed & exit /b 1)

echo [*] Linking ...
link.exe /SUBSYSTEM:NATIVE,10.0 /DRIVER /ENTRY:DriverEntry /NODEFAULTLIB /MACHINE:X64 /LIBPATH:"$kmLib" ntoskrnl.lib hal.lib BufferOverflowFastFailK.lib /OUT:"$outDir\dmmdzz_injector.sys" /DEBUG /PDB:"$outDir\dmmdzz_injector.pdb" $objDir\main.obj $objDir\ioctl.obj $objDir\memory.obj $objDir\process.obj
if errorlevel 1 (echo [!] link failed & exit /b 1)

echo [+] Build complete!
exit /b 0
"@
[System.IO.File]::WriteAllText($tempBat, $batContent, [System.Text.Encoding]::ASCII)

# Run the batch file
$proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$tempBat`"" -Wait -PassThru -NoNewWindow
Remove-Item $tempBat -ErrorAction SilentlyContinue

if ($proc.ExitCode -ne 0) {
    Write-Host "[!] Build failed with exit code $($proc.ExitCode)"
    exit 1
}

# Copy INF
Copy-Item "$srcDir\dmmdzz_injector.inf" "$outDir\dmmdzz_injector.inf" -Force

# Show artifacts
Write-Host ""
Write-Host "=== Artifacts ==="
Get-ChildItem "$outDir\dmmdzz_injector.*" | Select-Object Name, Length
