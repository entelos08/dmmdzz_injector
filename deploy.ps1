# =============================================================================
# deploy.ps1 - Collect all KDU + driver + controller files into one folder.
#
# Usage (right-click -> Run with PowerShell, or):
#   powershell -ExecutionPolicy Bypass -File deploy.ps1
#
# Optional: specify output folder
#   powershell -ExecutionPolicy Bypass -File deploy.ps1 -OutDir C:\kdu_test
# =============================================================================

param(
    [string]$OutDir = ""
)

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$KDURoot     = Join-Path $ProjectRoot "KDU-1.4.9\Source"

# Default output folder
if ($OutDir -eq "") {
    $OutDir = Join-Path $ProjectRoot "deploy"
}

Write-Host ""
Write-Host "=== dmmdzz_injector - Deploy Script ===" -ForegroundColor Cyan
Write-Host ""

# --- 1. Define source -> dest file mapping ---
$files = @(
    @{
        Name   = "kdu.exe"
        Source = Join-Path $KDURoot "Hamakaze\output\x64\Release\kdu.exe"
        Desc   = "KDU main executable"
    },
    @{
        Name   = "drv64.dll"
        Source = Join-Path $KDURoot "Tanikaze\output\x64\Release\drv64.dll"
        Desc   = "KDU provider DLL (Tanikaze)"
    },
    @{
        Name   = "Taigei64.dll"
        Source = Join-Path $KDURoot "Taigei\output\x64\Release\Taigei64.dll"
        Desc   = "KDU provider DLL (Taigei)"
    },
    @{
        Name   = "kdu.db"
        Source = Join-Path $KDURoot "Tanikaze\data\kdu.db"
        Desc   = "KDU driver database"
    },
    @{
        Name   = "dmmdzz_injector.sys"
        Source = Join-Path $ProjectRoot "build_driver\dmmdzz_injector.sys"
        Desc   = "Kernel driver"
    },
    @{
        Name   = "dmmdzz_ctl.exe"
        Source = Join-Path $ProjectRoot "build\bin\dmmdzz_ctl.exe"
        Desc   = "User-mode controller (cross-compiled)"
    },
    @{
        Name   = "dmmdzz_injector.inf"
        Source = Join-Path $ProjectRoot "driver\dmmdzz_injector.inf"
        Desc   = "Driver INF (optional, for manual install)"
    }
)

# --- 2. Create output directory ---
if (Test-Path $OutDir) {
    Write-Host "[*] Output directory exists: $OutDir" -ForegroundColor Yellow
} else {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    Write-Host "[+] Created output directory: $OutDir" -ForegroundColor Green
}

# --- 3. Copy files ---
$found    = 0
$missing  = 0

Write-Host ""
Write-Host "Collecting files..." -ForegroundColor Cyan
Write-Host ""

foreach ($f in $files) {
    $destPath = Join-Path $OutDir $f.Name
    if (Test-Path $f.Source) {
        Copy-Item -Path $f.Source -Destination $destPath -Force
        $size = (Get-Item $f.Source).Length
        $sizeKB = [math]::Round($size / 1024, 1)
        Write-Host ("  [+] {0,-25} {1,8} KB  {2}" -f $f.Name, $sizeKB, $f.Desc) -ForegroundColor Green
        $found++
    } else {
        Write-Host ("  [!] {0,-25} MISSING   {1}" -f $f.Name, $f.Desc) -ForegroundColor Red
        Write-Host "      Expected at: $($f.Source)" -ForegroundColor DarkGray
        $missing++
    }
}

# --- 4. Summary ---
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Deploy Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Output folder: $OutDir"
Write-Host "  Found: $found   Missing: $missing"
Write-Host ""

if ($missing -gt 0) {
    Write-Host "  Some files are missing!" -ForegroundColor Yellow
    Write-Host "  Make sure you have:"
    Write-Host "    1. Built KDU:      run MSBuild on KDU.sln (Windows)"
    Write-Host "    2. Built driver:   .\build_driver.ps1 (Windows)"
    Write-Host "    3. Built ctl.exe:  ./build.sh (Linux, then copy here)"
    Write-Host ""
}

if ($missing -eq 0) {
    Write-Host "  All files collected! Next steps:" -ForegroundColor Green
    Write-Host ""
    Write-Host "  1. Open this folder as Administrator CMD:"
    Write-Host "     cd `"$OutDir`""
    Write-Host ""
    Write-Host "  2. Load driver via KDU (no test signing, no reboot):"
    Write-Host "     kdu.exe -map dmmdzz_injector.sys"
    Write-Host ""
    Write-Host "  3. Start target process:"
    Write-Host "     start target.exe"
    Write-Host ""
    Write-Host "  4. Run controller:"
    Write-Host "     dmmdzz_ctl.exe target.exe"
    Write-Host ""
}

# --- 5. List final directory ---
Write-Host "  Final directory contents:" -ForegroundColor Cyan
Write-Host "  -------------------------------------------"
Get-ChildItem $OutDir -File | ForEach-Object {
    $sizeKB = [math]::Round($_.Length / 1024, 1)
    Write-Host ("  {0,-30} {1,8} KB" -f $_.Name, $sizeKB)
}
Write-Host ""

Read-Host "Press Enter to exit"
