# AegisShield EDR - Technical Architecture Documentation

## 1. System Overview
AegisShield is a production-grade Endpoint Detection and Response (EDR) and Antivirus platform engineered for Windows 10 and Windows 11 (Pro & Enterprise). Designed for centralized defense across 50–100 workstations in distributed office environments, it delivers layered, explainable threat detection, behavioral ransomware mitigation, real-time filesystem observation, and cryptographically signed command orchestration.

```
+---------------------------------------------------------------------------------+
|                         CENTRAL MANAGEMENT SERVER                               |
|   +-------------------------------------------------------------------------+   |
|   | FastAPI REST Engine + WebSockets + SQLite/SQLAlchemy Fleet DB           |   |
|   | HMAC-SHA256 Command Signing Authority (Non-Repudiation)                 |   |
|   | Policy Management & Multi-Office Aggregator (HQ, Branch Alpha/Beta)     |   |
|   | Embedded Admin Console (HTML5/CSS/JS)                                   |   |
|   +-------------------------------------------------------------------------+   |
+----------------------------------------+----------------------------------------+
                                         |  TLS / HTTPS Heartbeat & Telemetry
                                         |  Cryptographic Signed Commands
                                         v
+---------------------------------------------------------------------------------+
|                        WINDOWS 10/11 WORKSTATION AGENT                          |
|                                                                                 |
|   +-------------------------------------------------------------------------+   |
|   | Real-Time Filesystem Monitor (ReadDirectoryChangesW + Watchdog)         |   |
|   +------------------------------------+------------------------------------+   |
|                                        v                                        |
|   +-------------------------------------------------------------------------+   |
|   | Layered Malware Analysis Engine:                                        |   |
|   |   1. Signature Matcher (SHA-256 + Byte Stream Caching)                  |   |
|   |   2. YARA Rule Engine (Hex/Regex/Wide/Ascii Condition Evaluator)        |   |
|   |   3. PE Executable Static Analyzer (Entropy, Sections, High-Risk APIs)  |   |
|   |   4. Script & Deceptive Extension Inspector (PowerShell, VBS, .pdf.exe) |   |
|   |   5. Contextual Heuristic Analyzer (Suspicious Temp/AppData paths)      |   |
|   +------------------------------------+------------------------------------+   |
|                                        v                                        |
|   +-------------------------------------------------------------------------+   |
|   | Ransomware Defense Module:                                              |   |
|   |   - Canary Honey-File Trap Sentinel                                     |   |
|   |   - High-Volume File Write & Rename Rate-Limiter                        |   |
|   |   - Rogue Encryptor Process Neutralization & Safe Termination           |   |
|   +------------------------------------+------------------------------------+   |
|                                        v                                        |
|   +-------------------------------------------------------------------------+   |
|   | Secure Quarantine Vault:                                                |   |
|   |   - Execution Bit Stripping & Payload Obfuscation                       |   |
|   |   - System Integrity Safeguard (Prevents OS Core Binary Disruption)     |   |
|   |   - Cryptographic Restoration & Secure Overwrite Shredding              |   |
|   +-------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------+
```

---

## 2. Core Detection Layers

### A. Layer 1: Cryptographic Signatures
- Computes SHA-256 hashes via streaming chunks (64 KB buffers) to maintain zero memory spikes on gigabyte-sized files.
- High-performance timestamp-keyed LRU cache prevents re-hashing unmodified files.
- Includes pre-compiled databases of known malware families (WannaCry, Locky, Mimikatz, RedLine).
- Direct byte stream pattern matching for instantaneous EICAR verification.

### B. Layer 2: YARA Rule Engine
- Production-grade pattern matcher with support for text, wide-string, ASCII, hex strings (`{ 4D 5A ?? 00 }`), and regular expressions.
- Condition evaluation supporting boolean combinations, counts (`2 of them`), and header assertions (`uint16(0) == 0x5A4D`).
- Pre-loaded with detection rules for ransomware ransom notes, shadow copy deletion commands, Mimikatz credential artifacts, and encoded PowerShell stagers.

### C. Layer 3: PE Executable Static Analysis
- Analyzes Portable Executables (PE32/PE32+) via `pefile` and Shannon entropy calculation.
- High entropy (> 7.2) across code or data sections flags packed binaries, crypters, and encrypted payloads.
- High-risk Windows API import correlation:
  * Process Injection: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`.
  * Evasion: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`.
  * Credential Access: `MiniDumpWriteDump`, `LsaRetrievePrivateData`.
  * Ransomware Encryption: `CryptEncrypt`, `CryptAcquireContext`, `BCryptEncrypt`.

### D. Layer 4: Script & Deceptive Extension Analysis
- Identifies deceptive double extensions (e.g., `Financial_Report.pdf.exe`).
- Analyzes PowerShell scripts (`.ps1`) for Base64 encoded commands (`-enc`), execution policy bypass, memory cradles (`IEX New-Object Net.WebClient`), and AMSI patch attempts.
- Scans Batch and VBScript files for volume shadow copy deletion (`vssadmin delete shadows`) and persistence injection.

### E. Layer 5: Contextual Heuristics
- Flags non-system executables spawned or located in temporary folders (`%TEMP%`, `%APPDATA%`, `C:\Windows\Temp`).
- Detects ransom notes matching standard naming conventions (`readme_to_decrypt.txt`, `how_to_recover.txt`).

---

## 3. Ransomware Protection & Canary Tripwire
1. **Canary Trap Deployment:** Deploys decoy honey-files (`.xlsx`, `.docx`, `.pdf`, `.csv`) in sensitive user directories with recorded cryptographic hashes.
2. **Tripwire Auditing:** Periodically verifies honey-file existence and hash integrity. If an active ransomware process renames, deletes, or encrypts a canary, the tripwire instantly triggers a critical alert.
3. **Burst Rate Limiting:** Tracks file writes and renames over rolling 60-second windows. If write volume exceeds configurable thresholds and entropy surges (> 7.2), the system locates the candidate process.
4. **Safe Termination:** Where authorized in policy, the rogue encryptor process is terminated via Windows process handles, while critical system processes (`explorer.exe`, `csrss.exe`) are guarded against termination.

---

## 4. Secure Quarantine Subsystem
- **Execution Neutralization:** Malicious binaries are passed through a symmetric cipher to neutralize executable headers and prevent double-click invocation.
- **Atomic Isolation:** Quarantined files are moved into the protected vault directory with unique UUIDs (`.aegis_quarantine`).
- **Forensic Shredding:** Original files are overwritten with zeroes prior to deletion to prevent unallocated space recovery.
- **OS Integrity Safeguards:** Hardware and OS core binaries (`ntoskrnl.exe`, `kernel32.dll`, `csrss.exe`, etc.) are protected from automated quarantine to prevent system instability.
- **Cryptographic Restoration:** Upon administrator approval, quarantined files can be decrypted and restored to their original or custom location, verified against the recorded SHA-256 hash.

---

## 5. Centralized Multi-PC Architecture (50-100 Workstations)
- **Device Authentication:** Unique machine UUIDs, hostname, IP, and OS version registered on the central server.
- **Signed Remote Commands:** All administrative actions (scans, signature updates, host isolation) are cryptographically signed with HMAC-SHA256 using the master key. Agents verify the signature before execution; tampered or unsigned commands are rejected.
- **Office Multi-Tenancy:** Endpoints are segmented by office location (e.g. Headquarters, Branch Office Alpha, Branch Office Beta).
- **Lightweight Footprint:** Low background idle CPU (< 1%) and memory footprint (< 60 MB).
