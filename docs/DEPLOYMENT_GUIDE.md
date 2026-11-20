# AegisShield EDR - Enterprise Deployment Guide (50–100 Windows Workstations)

## 1. Prerequisites
- **Supported Operating Systems:** Windows 10 & Windows 11 (Pro, Enterprise, Education, Home) 64-bit.
- **Runtimes:** Python 3.10+ (or bundled standalone binary compiled with PyInstaller/Nuitka).
- **Network Ports:** Port 8443 (HTTPS/REST telemetry between endpoint agents and central server).
- **Administrative Rights:** Administrator elevation required for Windows Service installation and Windows Advanced Firewall rule enforcement.

---

## 2. Server Deployment (Central Management Hub)
The central management server aggregates fleet telemetry, serves the web dashboard, manages threat policies, and issues cryptographically signed scan orders.

### Step 1: Start Central Management Server
```powershell
python scripts/run_server.py
```
*By default, the server listens on `http://0.0.0.0:8443` and creates an embedded SQLite database in `data/server/aegis_central.db`.*

### Step 2: Access Administrator Console
Open your browser to:
```
http://127.0.0.1:8443
```
You will be greeted with the Fleet Security Overview dashboard displaying enrolled workstations, threat alerts, quarantine vault, and policy controls.

---

## 3. Endpoint Agent Deployment (Office Workstations)

### Step 1: Automated Agent Installation via PowerShell
Run from an elevated PowerShell console on each target workstation:
```powershell
# Set management server address
$env:AEGIS_SERVER_URL = "http://10.0.0.5:8443"

# Register and start Windows Service
.\scripts\install_service.ps1
```
The script registers `AegisShieldEDR` with the Windows Service Control Manager (SCM), sets the startup type to `Automatic`, and configures restart recovery on failure.

### Step 2: Interactive Standalone / Testing Mode
For developer testing or non-service execution:
```powershell
python -m aegis.agent.service run
```

---

## 4. Multi-Office Fleet Seeding & Verification
To verify dashboard capacity and test multi-office workflows for 50–100 PCs:
```powershell
python -m cli.aegis_admin seed-fleet --count 60
```
This registers workstations distributed across:
- `Headquarters - Floor 3`
- `Branch Office Alpha (Chicago)`
- `Branch Office Beta (Austin)`

---

## 5. Local Command Line Interface (CLI) Usage
Each workstation has full local visibility and scanning tools:

```powershell
# Scan a specific file or directory
python -m cli.aegis_cli scan --path C:\Users\User\Downloads --quarantine

# Run rapid Quick Scan on high-risk locations
python -m cli.aegis_cli quick-scan

# Test EICAR standard antivirus verification
python -m cli.aegis_cli test-eicar --quarantine

# Inspect Quarantine Vault
python -m cli.aegis_cli quarantine list

# Restore a quarantined file
python -m cli.aegis_cli quarantine restore --id <UUID>

# Audit active processes with security heuristics
python -m cli.aegis_cli processes

# Audit persistence mechanisms (Registry Run keys, Startup folders, Scheduled tasks)
python -m cli.aegis_cli persistence

# Inspect connected removable USB storage
python -m cli.aegis_cli usb
```

---

## 6. Uninstallation & Clean Rollback
To cleanly remove AegisShield without damaging Windows or existing security tools:
```powershell
.\scripts\uninstall_service.ps1
```
This safely stops the agent, deregisters the service from SCM, removes Aegis firewall containment rules, and restores system files intact.
