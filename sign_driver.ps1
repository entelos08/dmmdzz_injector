# =============================================================================
# sign_driver.ps1 — Self-sign the kernel driver with a test certificate.
#
# This avoids the need for 'bcdedit /set testsigning on' + reboot.
# Run this once after building the .sys, on the Windows target machine.
#
# Usage (right-click → Run with PowerShell, or):
#   powershell -ExecutionPolicy Bypass -File sign_driver.ps1
# =============================================================================

# --- 0. Self-elevate to Administrator ---
if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[*] Re-launching as Administrator..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" `
                  -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" `
                  -Verb RunAs
    exit
}

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SysFiles   = @(
    Join-Path $ProjectRoot "build_driver\dmmdzz_injector.sys",
    Join-Path $ProjectRoot "build_driver\dmmdzz_injector_kdu.sys"
)
$CertName    = "dmmdzz_test_cert"
$CertFile    = Join-Path $ProjectRoot "build_driver\$CertName.cer"
$PfxFile     = Join-Path $ProjectRoot "build_driver\$CertName.pfx"
$CertPass    = "dmmdzz123"

Write-Host ""
Write-Host "=== dmmdzz_injector - Driver Self-Signing Tool ===" -ForegroundColor Cyan
Write-Host ""

# --- 1. Check .sys exists ---
foreach ($f in $SysFiles) {
    if (-not (Test-Path $f)) {
        Write-Host "[!] $f not found. Build the driver first (build_driver.ps1)." -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "[+] Driver: $f" -ForegroundColor Green
}

# --- 2. Find signtool.exe ---
Write-Host "[*] Locating signtool.exe..."

$KitRoots = @(
    "D:\Windows Kits\10",
    "C:\Program Files (x86)\Windows Kits\10",
    "C:\Program Files\Windows Kits\10"
)

$SignTool = $null
foreach ($kit in $KitRoots) {
    if (Test-Path $kit) {
        $found = Get-ChildItem -Path "$kit\bin" -Recurse -Filter "signtool.exe" `
                  -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\x64\\' } |
                Sort-Object FullName -Descending |
                Select-Object -First 1
        if ($found) {
            $SignTool = $found.FullName
            break
        }
    }
}

if (-not $SignTool) {
    # Try Visual Studio
    $vsSign = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio" -Recurse -Filter "signtool.exe" `
               -ErrorAction SilentlyContinue |
             Where-Object { $_.FullName -match '\\x64\\' } |
             Select-Object -First 1
    if ($vsSign) { $SignTool = $vsSign.FullName }
}

if (-not $SignTool) {
    Write-Host "[!] signtool.exe not found. Install Windows SDK." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[+] signtool: $SignTool" -ForegroundColor Green

# --- 3. Create self-signed certificate ---
Write-Host "[*] Creating self-signed code signing certificate..."

# Remove old cert if it exists
Get-ChildItem "Cert:\CurrentUser\My" |
    Where-Object { $_.Subject -eq "CN=$CertName" } |
    Remove-Item -ErrorAction SilentlyContinue

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=$CertName" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyUsage DigitalSignature `
    -KeyAlgorithm RSA -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(5)

if (-not $cert) {
    Write-Host "[!] Failed to create certificate." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[+] Certificate created: CN=$CertName (thumbprint: $($cert.Thumbprint))" -ForegroundColor Green

# --- 4. Export PFX and CER ---
$pwd = ConvertTo-SecureString -String $CertPass -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $PfxFile -Password $pwd | Out-Null
Export-Certificate    -Cert $cert -FilePath $CertFile | Out-Null
Write-Host "[+] Exported: $PfxFile" -ForegroundColor Green
Write-Host "[+] Exported: $CertFile" -ForegroundColor Green

# --- 5. Install certificate to Trusted Root + Trusted Publisher ---
Write-Host "[*] Installing certificate to Trusted Root Certification Authorities..."

# Import to LocalMachine\Root (requires admin - we already elevated)
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
$rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$rootStore.Add($cert)
$rootStore.Close()
Write-Host "[+] Installed to Trusted Root." -ForegroundColor Green

Write-Host "[*] Installing certificate to Trusted Publishers..."
$pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
$pubStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$pubStore.Add($cert)
$pubStore.Close()
Write-Host "[+] Installed to Trusted Publisher." -ForegroundColor Green

# --- 6. Sign the drivers ---
foreach ($f in $SysFiles) {
    Write-Host "[*] Signing $f ..."
    $signArgs = @(
        "sign",
        "/f", $PfxFile,
        "/p", $CertPass,
        "/fd", "SHA256",
        "/tr", "http://timestamp.digicert.com",
        "/td", "SHA256",
        "/v",
        $f
    )
    & $SignTool $signArgs

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] signtool failed for $f with exit code $LASTEXITCODE" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Driver signed successfully!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  The certificate has been installed to:"
Write-Host "    - Trusted Root Certification Authorities"
Write-Host "    - Trusted Publishers"
Write-Host ""
Write-Host "  You can now load the driver WITHOUT test signing mode."
Write-Host "  No reboot needed. Just run:"
Write-Host "    dmmdzz_ctl.exe target.exe"
Write-Host ""
Read-Host "Press Enter to exit"
