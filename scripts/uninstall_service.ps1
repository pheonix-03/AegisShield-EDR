# AegisShield EDR - Clean Service Uninstallation Script
param(
    [string]$ServiceName = "AegisShieldEDR"
)

Write-Host "==========================================================" -ForegroundColor Yellow
Write-Host " AegisShield EDR - Safe Uninstaller" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Yellow

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[*] Halting active service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    Write-Host "[*] Deregistering service from SCM..."
    sc.exe delete $ServiceName
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Service successfully removed from Windows." -ForegroundColor Green
    } else {
        Write-Error "[-] Failed to delete service. Error code: $LASTEXITCODE"
    }
} else {
    Write-Host "[*] Service '$ServiceName' was not registered."
}

Write-Host "[+] Clean uninstallation complete. Windows system files preserved intact." -ForegroundColor Green
