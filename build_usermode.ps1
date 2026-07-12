# =============================================================================
# build_usermode.ps1 - Build dmmdzz_ctl.exe and dmmdzz_ce.exe on Windows with MSVC
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File build_usermode.ps1
#   powershell -ExecutionPolicy Bypass -File build_usermode.ps1 -Config Debug
#   powershell -ExecutionPolicy Bypass -File build_usermode.ps1 -Target ce
#   powershell -ExecutionPolicy Bypass -File build_usermode.ps1 -Target all
# =============================================================================
param(
    [ValidateSet("Release", "Debug")]
    [string]$Config = "Release",
    [ValidateSet("ctl", "ce", "all")]
    [string]$Target = "all"
)

# --- Admin not required, but we need MSVC dev environment ---

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSCommandPath

Write-Host ""
Write-Host "=== dmmdzz_injector - Usermode Build (MSVC) ===" -ForegroundColor Cyan
Write-Host "  Config:      $Config"
Write-Host "  Target:      $Target"
Write-Host "  ProjectRoot: $ProjectRoot"
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Find Visual Studio
# ---------------------------------------------------------------------------
Write-Host "[*] Locating Visual Studio..." -ForegroundColor Yellow

$vsPaths = @(
    "${env:ProgramFiles}\Microsoft Visual Studio",
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio",
    "D:\Program Files\Microsoft Visual Studio",
    "C:\Program Files\Microsoft Visual Studio"
)

$vsInstance = $null
foreach ($base in $vspaths) {
    if (-not (Test-Path $base)) { continue }
    # Search for any VS edition (2022 = 17, 18, etc.)
    $editions = Get-ChildItem $base -Directory -ErrorAction SilentlyContinue
    foreach ($ed in $editions) {
        $verDir = Join-Path $base $ed.Name
        if (Test-Path $verDir) {
            $vers = Get-ChildItem $verDir -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
            foreach ($v in $vers) {
                $vcTools = Join-Path $v.FullName "VC\Tools\MSVC"
                if (Test-Path $vcTools) {
                    $vsInstance = $v.FullName
                    break
                }
            }
        }
        if ($vsInstance) { break }
    }
    if ($vsInstance) { break }
}

if (-not $vsInstance) {
    Write-Host "[!] Visual Studio not found." -ForegroundColor Red
    Write-Host "    Install Visual Studio with 'Desktop development with C++' workload." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[+] Visual Studio: $vsInstance" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Find MSVC toolchain (cl.exe) — prefer a version that has x64 libs
# ---------------------------------------------------------------------------
$vcToolsDir = Join-Path $vsInstance "VC\Tools\MSVC"
$msvcVersions = Get-ChildItem $vcToolsDir -Directory | Sort-Object Name -Descending
$msvcVer = $null
foreach ($v in $msvcVersions) {
    $x64LibPath = Join-Path $v.FullName "lib\x64"
    if (Test-Path $x64LibPath) {
        $msvcVer = $v.Name
        break
    }
}
if (-not $msvcVer) {
    # Fallback: use latest even without x64 libs (will fail later but with a clear error)
    $msvcVer = $msvcVersions[0].Name
    Write-Host "[!] Warning: No MSVC version has x64 libraries installed." -ForegroundColor Red
    Write-Host "    Install 'MSVC v143 - VS 2022 C++ x64/x86 build tools' via Visual Studio Installer." -ForegroundColor Red
}

$msvcBin = Join-Path $vcToolsDir "$msvcVer\bin\Hostx64\x64"
$clExe = Join-Path $msvcBin "cl.exe"

if (-not (Test-Path $clExe)) {
    Write-Host "[!] cl.exe not found at $clExe" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[+] MSVC version: $msvcVer" -ForegroundColor Green
Write-Host "[+] cl.exe: $clExe" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Find Windows SDK
# ---------------------------------------------------------------------------
Write-Host "[*] Locating Windows SDK..." -ForegroundColor Yellow

$sdkRoot = $null
foreach ($candidate in @("D:\Windows Kits\10", "${env:ProgramFiles(x86)}\Windows Kits\10", "C:\Program Files (x86)\Windows Kits\10")) {
    if (Test-Path $candidate) {
        $sdkRoot = $candidate
        break
    }
}

if (-not $sdkRoot) {
    Write-Host "[!] Windows SDK not found." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$sdkVer = (Get-ChildItem (Join-Path $sdkRoot "Include") -Directory | Where-Object { $_.Name -like "10.*" } | Sort-Object Name -Descending | Select-Object -First 1).Name
$sdkInclude = Join-Path $sdkRoot "Include\$sdkVer"
$sdkLib = Join-Path $sdkRoot "Lib\$sdkVer"

Write-Host "[+] SDK version: $sdkVer" -ForegroundColor Green
Write-Host "[+] SDK root: $sdkRoot" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. Build include/lib paths
# ---------------------------------------------------------------------------
$msvcInclude = Join-Path $vcToolsDir "$msvcVer\include"
$msvcLib     = Join-Path $vcToolsDir "$msvcVer\lib\x64"

$includes = @(
    $msvcInclude,
    (Join-Path $sdkInclude "ucrt"),
    (Join-Path $sdkInclude "um"),
    (Join-Path $sdkInclude "shared"),
    (Join-Path $ProjectRoot "driver")    # for driver.h (shared IOCTL definitions)
)

$libs = @(
    $msvcLib,
    (Join-Path $sdkLib "ucrt\x64"),
    (Join-Path $sdkLib "um\x64")
)

$includeFlags = ($includes | ForEach-Object { "/I`"$_`"" }) -join " "
$libFlags     = ($libs | ForEach-Object { "/LIBPATH:`"$_`"" }) -join " "

# ---------------------------------------------------------------------------
# 5. Prepare output
# ---------------------------------------------------------------------------
$OutDir = Join-Path $ProjectRoot "build_usermode"
if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# Common sources shared by both targets
$commonSources = @(
    "usermode\driver_ctl.cpp",
    "usermode\driver_loader.cpp",
    "usermode\process.cpp"
)

# Target-specific source lists
$targets = @()
if ($Target -eq "ctl" -or $Target -eq "all") {
    $targets += @{
        Name      = "dmmdzz_ctl"
        MainSrc   = "usermode\main.cpp"
        Sources   = $commonSources
    }
}
if ($Target -eq "ce" -or $Target -eq "all") {
    $targets += @{
        Name      = "dmmdzz_ce"
        MainSrc   = "usermode\ce_cli.cpp"
        Sources   = @("usermode\scanner.cpp") + $commonSources
    }
}

# Check all source files exist
$allSrcFiles = @()
foreach ($t in $targets) {
    $allSrcFiles += $t.MainSrc
    $allSrcFiles += $t.Sources
}
$allSrcFiles = $allSrcFiles | Select-Object -Unique
foreach ($f in $allSrcFiles) {
    $fullPath = Join-Path $ProjectRoot $f
    if (-not (Test-Path $fullPath)) {
        Write-Host "[!] Source file not found: $fullPath" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# ---------------------------------------------------------------------------
# 6. Compiler flags
# ---------------------------------------------------------------------------
$cxxFlags = @(
    "/std:c++17",
    "/EHsc",
    "/W3",
    "/nologo",
    "/Zi",                    # debug info
    "/utf-8",                 # UTF-8 source encoding
    "/D_CRT_SECURE_NO_WARNINGS",
    "/DUNICODE",
    "/D_UNICODE",
    "/DWIN32_LEAN_AND_MEAN",
    "/DNOMINMAX"
)

if ($Config -eq "Release") {
    $cxxFlags += @("/O2", "/DNDEBUG", "/MD")
} else {
    $cxxFlags += @("/Od", "/DDEBUG", "/MDd")
}

$linkFlags = @(
    "/NOLOGO",
    "/SUBSYSTEM:CONSOLE",
    "/MACHINE:X64",
    "/DEBUG",
    $libFlags
)

$libNames = "advapi32.lib user32.lib psapi.lib"

# ---------------------------------------------------------------------------
# 7. Compile each target
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] Compiling $($targets.Count) target(s)..." -ForegroundColor Yellow

$builtArtifacts = @()

foreach ($t in $targets) {
    Write-Host ""
    Write-Host "[*] Building $($t.Name)..." -ForegroundColor Cyan

    $srcPaths = @($t.MainSrc) + $t.Sources
    $srcPaths = $srcPaths | ForEach-Object { Join-Path $ProjectRoot $_ }

    $srcArg = ($srcPaths | ForEach-Object { "`"$_`"" }) -join " "
    $cxxArg = ($cxxFlags -join " ")
    $linkArg = ($linkFlags -join " ")

    $exePath = Join-Path $OutDir "$($t.Name).exe"
    $pdbPath = Join-Path $OutDir "$($t.Name).pdb"

    # Use cmd.exe to run cl.exe (handles env vars and quoting better)
    $tempBat = Join-Path $env:TEMP "dmmdzz_build_$($t.Name).bat"
    @"
@echo off
"$clExe" $cxxArg $includeFlags $srcArg /link $linkArg $libNames /OUT:"$exePath" /PDB:"$pdbPath"
exit /b %ERRORLEVEL%
"@ | Set-Content $tempBat -Encoding ASCII

    Push-Location $OutDir
    & cmd.exe /c $tempBat
    $exitCode = $LASTEXITCODE
    Pop-Location

    Remove-Item $tempBat -ErrorAction SilentlyContinue

    if ($exitCode -ne 0) {
        Write-Host ""
        Write-Host "[!] Build of $($t.Name) failed (exit code $exitCode)" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }

    $builtArtifacts += @{ Name = "$($t.Name).exe"; Path = $exePath }
    $builtArtifacts += @{ Name = "$($t.Name).pdb"; Path = $pdbPath }
    Write-Host "[+] $($t.Name) built." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Build Succeeded ===" -ForegroundColor Green
Write-Host ""
Write-Host "Artifacts:" -ForegroundColor Yellow

foreach ($a in $builtArtifacts) {
    if (Test-Path $a.Path) {
        $f = Get-Item $a.Path
        $sizeKB = [math]::Round($f.Length / 1024, 1)
        Write-Host ("  {0,-25} {1,10} KB" -f $a.Name, $sizeKB) -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Output directory: $OutDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  Copy dmmdzz_ctl.exe / dmmdzz_ce.exe + dmmdzz_injector.sys to the same directory"
Write-Host "  Run as Administrator:"
Write-Host "    dmmdzz_ctl.exe <target.exe>    (original demo)"
Write-Host "    dmmdzz_ce.exe   <target.exe>   (CE-style scanner)"
Write-Host ""
