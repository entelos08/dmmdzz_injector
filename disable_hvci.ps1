# =============================================================================
# disable_hvci.ps1 - Disable HVCI + Vulnerable Driver Blocklist for KDU
#
# This is REQUIRED for KDU to work. KDU uses a vulnerable signed driver to
# load unsigned drivers into the kernel. HVCI and the blocklist prevent this.
#
# Usage (Administrator):
#   powershell -ExecutionPolicy Bypass -File disable_hvci.ps1
# =============================================================================

# --- Auto-elevate ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[*] Re-launching as Administrator..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "=== Disable HVCI + Blocklist for KDU ===" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Check Secure Boot (must be OFF)
# ---------------------------------------------------------------------------
$secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
if ($secureBoot) {
    Write-Host "[!] Secure Boot is ON. You MUST disable it in BIOS first." -ForegroundColor Red
    Write-Host "    KDU will not work with Secure Boot enabled." -ForegroundColor Red
    Write-Host ""
    Write-Host "    To disable:" -ForegroundColor Yellow
    Write-Host "      shutdown /r /fw /t 0"
    Write-Host "    Then find Secure Boot in BIOS -> set to Disabled -> Save -> Exit"
    Read-Host "Press Enter to exit"
    exit 1
} else {
    Write-Host "[+] Secure Boot is OFF" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 2. Disable HVCI / VBS via registry
# ---------------------------------------------------------------------------
Write-Host "[*] Disabling HVCI / VBS..." -ForegroundColor Yellow

$ciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if (Test-Path $ciPath) {
    Set-ItemProperty -Path $ciPath -Name "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $ciPath -Name "WasEnabledBy" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "[+] HVCI disabled in registry" -ForegroundColor Green
} else {
    New-Item -Path $ciPath -Force | Out-Null
    New-ItemProperty -Path $ciPath -Name "Enabled" -Value 0 -PropertyType DWord | Out-Null
    Write-Host "[+] HVCI disabled in registry (key created)" -ForegroundColor Green
}

$dgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
Set-ItemProperty -Path $dgPath -Name "EnableVirtualizationBasedSecurity" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path $dgPath -Name "RequirePlatformSecurityFeatures" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Write-Host "[+] VBS disabled in registry" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Disable hypervisor launch
# ---------------------------------------------------------------------------
Write-Host "[*] Disabling hypervisor launch..." -ForegroundColor Yellow
& bcdedit /set hypervisorlaunchtype off 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] hypervisorlaunchtype set to off" -ForegroundColor Green
} else {
    Write-Host "[!] bcdedit failed for hypervisorlaunchtype" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 4. Disable Vulnerable Driver Blocklist
# ---------------------------------------------------------------------------
Write-Host "[*] Disabling Vulnerable Driver Blocklist..." -ForegroundColor Yellow

$blPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
if (Test-Path $blPath) {
    Set-ItemProperty -Path $blPath -Name "VulnerableDriverBlocklistEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
} else {
    New-Item -Path $blPath -Force | Out-Null
    New-ItemProperty -Path $blPath -Name "VulnerableDriverBlocklistEnable" -Value 0 -PropertyType DWord | Out-Null
}
Write-Host "[+] VulnerableDriverBlocklistEnable = 0" -ForegroundColor Green

# Rename the policy file if it exists
$policyFile = "C:\Windows\System32\CodeIntegrity\driversipolicy.p7b"
if (Test-Path $policyFile) {
    Rename-Item $policyFile "driversipolicy.p7b.bak" -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Renamed driversipolicy.p7b -> .bak" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 5. Turn OFF test signing (we don't need it with KDU)
# ---------------------------------------------------------------------------
Write-Host "[*] Turning OFF test signing (not needed for KDU)..." -ForegroundColor Yellow
& bcdedit /set testsigning off 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] testsigning set to off" -ForegroundColor Green
} else {
    Write-Host "[!] bcdedit failed for testsigning (may already be off)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host ""
Write-Host "Changes made:" -ForegroundColor Yellow
Write-Host "  [x] HVCI disabled"
Write-Host "  [x] VBS disabled"
Write-Host "  [x] Hypervisor launch type = off"
Write-Host "  [x] Vulnerable driver blocklist disabled"
Write-Host "  [x] Test signing turned OFF (no watermark)"
Write-Host ""
Write-Host "*** REBOOT REQUIRED ***" -ForegroundColor Red
Write-Host ""

$reboot = Read-Host "Reboot now? (y/n)"
if ($reboot -eq "y" -or $reboot -eq "Y") {
    shutdown /r /t 3
    Write-Host "Rebooting in 3 seconds..." -ForegroundColor Yellow
} else {
    Write-Host "Please reboot manually before using KDU." -ForegroundColor Yellow
}

Write-Host ""
Read-Host "Press Enter to exit"
