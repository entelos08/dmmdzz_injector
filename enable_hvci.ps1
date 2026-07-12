# =============================================================================
# enable_hvci.ps1 - Re-enable HVCI / VBS / Hypervisor for Docker/WSL2
#
# This reverses the changes made by disable_hvci.ps1 so that Docker Desktop
# and WSL2 can use hardware virtualization again.
#
# Usage (Administrator):
#   powershell -ExecutionPolicy Bypass -File enable_hvci.ps1
# =============================================================================

# --- Auto-elevate ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[*] Re-launching as Administrator..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "=== Re-enable HVCI / VBS / Hypervisor ===" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Re-enable HVCI
# ---------------------------------------------------------------------------
Write-Host "[*] Re-enabling HVCI..." -ForegroundColor Yellow

$ciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if (Test-Path $ciPath) {
    Set-ItemProperty -Path $ciPath -Name "Enabled" -Value 1 -Type DWord
    Write-Host "[+] HVCI Enabled = 1" -ForegroundColor Green
} else {
    New-Item -Path $ciPath -Force | Out-Null
    New-ItemProperty -Path $ciPath -Name "Enabled" -Value 1 -PropertyType DWord | Out-Null
    Write-Host "[+] HVCI Enabled = 1 (key created)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 2. Re-enable VBS
# ---------------------------------------------------------------------------
Write-Host "[*] Re-enabling VBS..." -ForegroundColor Yellow

$dgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
Set-ItemProperty -Path $dgPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
Set-ItemProperty -Path $dgPath -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord
Write-Host "[+] VBS Enabled = 1" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Re-enable hypervisor launch (REQUIRED for Docker/WSL2)
# ---------------------------------------------------------------------------
Write-Host "[*] Re-enabling hypervisor launch..." -ForegroundColor Yellow
& bcdedit /set hypervisorlaunchtype auto 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] hypervisorlaunchtype set to auto" -ForegroundColor Green
} else {
    Write-Host "[!] bcdedit failed for hypervisorlaunchtype" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 4. Re-enable Vulnerable Driver Blocklist
# ---------------------------------------------------------------------------
Write-Host "[*] Re-enabling Vulnerable Driver Blocklist..." -ForegroundColor Yellow

$blPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
if (Test-Path $blPath) {
    Set-ItemProperty -Path $blPath -Name "VulnerableDriverBlocklistEnable" -Value 1 -Type DWord
} else {
    New-Item -Path $blPath -Force | Out-Null
    New-ItemProperty -Path $blPath -Name "VulnerableDriverBlocklistEnable" -Value 1 -PropertyType DWord | Out-Null
}
Write-Host "[+] VulnerableDriverBlocklistEnable = 1" -ForegroundColor Green

# Restore the policy file if it was backed up
$policyBak = "C:\Windows\System32\CodeIntegrity\driversipolicy.p7b.bak"
$policyFile = "C:\Windows\System32\CodeIntegrity\driversipolicy.p7b"
if ((Test-Path $policyBak) -and (-not (Test-Path $policyFile))) {
    Rename-Item $policyBak "driversipolicy.p7b" -Force
    Write-Host "[+] Restored driversipolicy.p7b" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 5. Turn OFF test signing (should already be off, but just in case)
# ---------------------------------------------------------------------------
Write-Host "[*] Ensuring test signing is OFF..." -ForegroundColor Yellow
& bcdedit /set testsigning off 2>$null
Write-Host "[+] testsigning set to off" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host ""
Write-Host "Restored settings:" -ForegroundColor Yellow
Write-Host "  [x] HVCI enabled"
Write-Host "  [x] VBS enabled"
Write-Host "  [x] Hypervisor launch type = auto  (Docker/WSL2 ready)"
Write-Host "  [x] Vulnerable driver blocklist enabled"
Write-Host "  [x] Test signing OFF"
Write-Host ""
Write-Host "*** REBOOT REQUIRED ***" -ForegroundColor Red
Write-Host "    Docker/WSL2 will work after reboot." -ForegroundColor Yellow
Write-Host ""

$reboot = Read-Host "Reboot now? (y/n)"
if ($reboot -eq "y" -or $reboot -eq "Y") {
    shutdown /r /t 3
    Write-Host "Rebooting in 3 seconds..." -ForegroundColor Yellow
} else {
    Write-Host "Please reboot manually for changes to take effect." -ForegroundColor Yellow
}

Write-Host ""
Read-Host "Press Enter to exit"
