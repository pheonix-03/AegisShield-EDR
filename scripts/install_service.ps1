# AegisShield EDR - Windows Service Installation Script
# Requires Administrator privileges

param(
    [string]$ServiceName = "AegisShieldEDR",
    [string]$DisplayName = "AegisShield Endpoint Detection & Response Service",
    [string]$Description = "Production-grade Windows antivirus, ransomware tripwire, and endpoint management service.",
    [string]$PythonPath = (Get-Command python.exe).Source,
    [string]$ServiceScript = "$PSScriptRoot\..\aegis\agent\service.py"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AegisShield EDR - Windows Service Provisioner" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Verify Administrator elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script requires Administrator privileges. Please re-run from an elevated PowerShell prompt."
}

$ResolvedScript = (Resolve-Path $ServiceScript).Path
$BinaryPath = "`"$PythonPath`" `"$ResolvedScript`" run"

Write-Host "[*] Service Name: $ServiceName"
Write-Host "[*] Binary Command: $BinaryPath"

# Check if service already exists
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[*] Stopping existing service instance..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName
    Start-Sleep -Seconds 2
}

# Create Windows Service via sc.exe
Write-Host "[*] Registering service with Windows Service Control Manager (SCM)..."
$createResult = sc.exe create $ServiceName binPath= "$BinaryPath" start= auto DisplayName= "$DisplayName"
if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Service created successfully." -ForegroundColor Green
    sc.exe description $ServiceName "$Description"
    
    # Configure auto-recovery on failure
    sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000
    Write-Host "[+] Auto-recovery failure policies configured." -ForegroundColor Green
} else {
    Write-Error "[-] Failed to register Windows Service. Error code: $LASTEXITCODE"
}

Write-Host "`n[+] Installation completed." -ForegroundColor Cyan
Write-Host "To start the service now, execute: Start-Service -Name $ServiceName"
