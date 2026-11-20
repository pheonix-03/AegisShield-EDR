# AegisShield EDR - Production-Grade Windows Antivirus & Endpoint Security Platform

[![Windows 10 / 11 Tested](https://img.shields.io/badge/Windows-10%20%7C%2011%20Pro%20%26%20Home-blue.svg)](https://microsoft.com)
[![Tests Passing](https://img.shields.io/badge/Tests-23%20Passed-brightgreen.svg)]()
[![EDR Architecture](https://img.shields.io/badge/Architecture-Modular%20Layered%20EDR-orange.svg)]()

A genuine, production-grade defensive endpoint security and antivirus application built for Windows 10 and Windows 11. Designed to protect individual PCs and centrally manage 50–100 Windows computers across multiple office locations.

---

## 🌟 Key Capabilities

1. **Multi-Layered Antivirus Scanning Engine**
   - **Signature Detection:** Streaming SHA-256 file hashing with timestamp-based caching; pre-compiled databases for WannaCry, Locky, Mimikatz, RedLine.
   - **Byte-Stream & EICAR Detection:** Direct pattern matching for the standard EICAR antivirus verification string.
   - **YARA Rule Engine:** Pure-Python engine supporting hex patterns, regular expressions, ASCII/wide strings, and condition logic (`all of them`, `any of them`, `uint16(0) == 0x5A4D`).
   - **PE Executable Static Analysis:** Shannon section entropy calculations to detect packers/crypters (> 7.2) and correlation of suspicious imports (process injection, evasion, credential dumping, ransomware encryption).
   - **Script & Deceptive Extension Inspection:** Detection of obfuscated PowerShell (`-enc`, hidden window, AMSI tampering), batch scripts (`vssadmin delete shadows`), and deceptive double extensions (`invoice.pdf.exe`).
   - **Contextual Heuristics:** Flags unauthorized executables in `%TEMP%` or `%APPDATA%`, and ransomware note naming conventions.

2. **Ransomware Defense & Canary Tripwire**
   - Automated deployment and continuous integrity auditing of honey-file canaries in user directories.
   - High-volume write and rename burst detection with rolling-window rate limiting.
   - Safe process termination of rogue encryptor processes, with safeguards protecting core Windows processes (`explorer.exe`, `csrss.exe`).

3. **Secure Quarantine Subsystem**
   - Isolated vault storage (`.aegis_quarantine`) with payload obfuscation to prevent accidental execution.
   - Cryptographic SHA-256 pre-quarantine recording and post-restore integrity verification.
   - Overwrite shredding of original malicious files before removal.
   - System integrity guard protecting Windows OS core binaries from automated disruption.

4. **Process & Persistence Security**
   - Process tree auditing, executable origins, Authenticode digital signature verification, and anomalous command-line detection.
   - Full persistence inspection: Registry Run keys (`HKCU`/`HKLM` `Run` and `RunOnce`), Startup folders, and Scheduled Tasks.

5. **Web & Network Protection**
   - Malicious domain and phishing URL reputation checks.
   - Active socket monitoring cross-referencing remote IPs with C2 threat feeds.
   - Windows Advanced Firewall integration for automated or administrator-approved outbound IP containment.

6. **USB & Removable Storage Security**
   - Removable drive detection via Windows APIs.
   - Auto-scan on drive insertion with `autorun.inf` and root-executable exploit inspection.

7. **Central Multi-PC Management & Dashboard (50–100 Workstations)**
   - FastAPI REST API + WebSockets backend with SQLite/PostgreSQL architecture.
   - Embedded single-page Administrator Console (HTML5/CSS/JS) displaying fleet overview, online status, incident history, quarantine vault, and policy controls.
   - **Cryptographically Signed Commands:** Administrative actions are signed with HMAC-SHA256; agents verify signatures and reject unsigned or tampered commands.
   - Multi-office segmentation (Headquarters, Branch Office Alpha, Branch Office Beta).

---

## 🚀 Quick Start Guide

### 1. Requirements & Dependencies
Ensure Python 3.10+ is installed:
```powershell
pip install -r requirements.txt
```

### 2. Run Comprehensive Automated Test Suite
```powershell
python -m pytest -v
```
*Executes all 23 unit and integration tests covering signatures, YARA, PE static analysis, quarantine cycles, ransomware tripwires, network reputation, and signed command security.*

### 3. Launch Central Management Server & Web Console
```powershell
python scripts/run_server.py
```
Open your browser to: **`http://127.0.0.1:8443`**

### 4. Seed Multi-Office Fleet (50-100 Workstations)
In another terminal, populate the management console with distributed office endpoints:
```powershell
python -m cli.aegis_admin seed-fleet --count 60
```

### 5. Local Endpoint Protection CLI
```powershell
# Run a quick scan on critical Windows locations
python -m cli.aegis_cli quick-scan

# Test EICAR antivirus verification and quarantine isolation
python -m cli.aegis_cli test-eicar --quarantine

# View and manage quarantine vault
python -m cli.aegis_cli quarantine list

# Audit running processes and digital signatures
python -m cli.aegis_cli processes

# Audit persistence mechanisms
python -m cli.aegis_cli persistence
```

### 6. Install as a Windows Background Service
From an elevated PowerShell prompt:
```powershell
.\scripts\install_service.ps1
```

---

## 📁 Repository Structure
```
├── aegis/                          # Core AegisShield Antivirus & EDR Package
│   ├── config.py                   # Central settings, paths, defaults
│   ├── engine/                     # Detection Engine
│   │   ├── scanner.py              # On-demand scanner (Quick, Full, Custom)
│   │   ├── signatures.py           # Hash database & EICAR byte matcher
│   │   ├── yara_engine.py          # YARA parser, compiler & rule evaluator
│   │   ├── pe_analyzer.py          # PE static analysis & section entropy
│   │   ├── script_analyzer.py      # PowerShell, VBS, double-extension inspector
│   │   └── heuristics.py           # Anomaly heuristics & ransom note detection
│   ├── realtime/                   # Real-time Protection Subsystem
│   │   ├── monitor.py              # ReadDirectoryChangesW observer
│   │   └── event_handler.py        # Debouncing, event queue, immediate scan
│   ├── ransomware/                 # Ransomware Defense Subsystem
│   │   ├── tripwire.py             # Honey-file canary deployment & verification
│   │   └── process_watcher.py      # Burst rate monitoring & safe kill
│   ├── quarantine/                 # Secure Quarantine Subsystem
│   │   ├── manager.py              # Obfuscation, shredding, restore, safeguards
│   │   └── db.py                   # SQLite quarantine catalog & audit log
│   ├── process_security/           # Process & Startup Inspector
│   │   ├── process_inspector.py    # Process tree, signatures, risk factors
│   │   └── startup_inspector.py    # Run keys, Startup folder, Scheduled tasks
│   ├── network/                    # Web & Network Defense
│   │   ├── reputation.py           # Domain/IP threat intelligence
│   │   ├── firewall.py             # Windows Advanced Firewall manager
│   │   └── conn_monitor.py         # Outbound connection anomaly monitor
│   ├── usb/                        # Removable Storage Security
│   │   └── detector.py             # USB insertion poller & autorun inspector
│   └── agent/                      # Endpoint Agent Service
│       ├── client.py               # Heartbeat, telemetry, signed command runner
│       └── service.py              # Windows Service framework wrapper
├── server/                         # Central Management Server
│   ├── app.py                      # FastAPI REST API & admin router
│   ├── models.py                   # SQLAlchemy fleet & incident schemas
│   ├── database.py                 # SQLite/PostgreSQL engine
│   ├── security.py                 # HMAC-SHA256 command signing authority
│   └── static/                     # Web Dashboard UI (HTML5, CSS, JS)
├── cli/                            # Command Line Interfaces
│   ├── aegis_cli.py                # Local management & scan CLI
│   └── aegis_admin.py              # Fleet administration CLI
├── tests/                          # 23 Automated Pytest Tests
├── scripts/                        # Installation & Deployment Scripts
│   ├── run_server.py
│   ├── install_service.ps1
│   └── uninstall_service.ps1
├── docs/                           # Architecture & Security Documentation
│   ├── ARCHITECTURE.md
│   ├── SECURITY_ASSESSMENT.md
│   └── DEPLOYMENT_GUIDE.md
└── requirements.txt
```

---

## 🔒 Safety and Integrity Guarantee
AegisShield is strictly defensive software designed to protect Windows enterprise endpoints:
- Never disables Windows Defender or native security tooling.
- Never installs unsigned kernel drivers.
- Never performs invasive TLS interception with unauthorized root certificates.
- Never terminates critical operating system binaries.
- All remote administrative actions require cryptographic authentication and audit logging.
