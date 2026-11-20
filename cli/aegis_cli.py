import os
import sys
import argparse
import json
import time

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aegis.engine.scanner import AntivirusScanner
from aegis.quarantine.manager import QuarantineManager
from aegis.process_security.process_inspector import ProcessInspector
from aegis.process_security.startup_inspector import StartupInspector
from aegis.usb.detector import USBSecurityManager
from aegis.engine.signatures import EICAR_BYTE_STRING
from aegis.config import config, APP_DATA_DIR

def cmd_scan(args):
    scanner = AntivirusScanner()
    q_mgr = QuarantineManager()
    path = args.path

    print(f"\n[*] Starting AegisShield Scan on: {path}")
    print("=" * 60)

    def progress(p):
        print(f"\rScanning: {p['files_scanned']}/{p['total_files']} files ({p['progress_percent']}%) - Threats: {p['threats_detected']}", end="")

    res = scanner.scan_path(path, progress_callback=progress)
    print("\n" + "=" * 60)
    print(f"[+] Scan Completed in {res['duration_seconds']}s")
    print(f"    Files Scanned:   {res['files_scanned']}")
    print(f"    Files Skipped:   {res['files_skipped']}")
    print(f"    Threats Found:   {res['threats_detected']}")

    if res['threats_detected'] > 0:
        print("\n[!] DETECTED THREATS:")
        for inf in res['infected_files']:
            print(f"  - File: {inf['filepath']}")
            print(f"    Threat: {inf['threat_name']} [{inf['severity']}] (Confidence: {inf['confidence']}%)")
            print(f"    Method: {inf['detection_method']}")
            print(f"    SHA256: {inf['sha256']}")
            for r in inf['reasons']:
                print(f"    Reason: {r}")

            if args.quarantine:
                q_res = q_mgr.quarantine_file(
                    filepath=inf['filepath'],
                    threat_name=inf['threat_name'],
                    detection_method=inf['detection_method'],
                    severity=inf['severity'],
                    confidence=inf['confidence'],
                    reasons=inf['reasons'],
                    operator="CLI-User",
                )
                if q_res.get("success"):
                    print(f"    -> Successfully Quarantined to Vault (ID: {q_res['quarantine_id']})")
                else:
                    print(f"    -> Quarantine failed: {q_res.get('error')}")

def cmd_quick_scan(args):
    scanner = AntivirusScanner()
    print("\n[*] Running AegisShield Quick Scan on critical Windows paths...")
    res = scanner.run_quick_scan()
    print("\n" + "=" * 60)
    print(f"[+] Quick Scan finished in {res['duration_seconds']}s")
    print(f"    Files Scanned: {res['files_scanned']}")
    print(f"    Threats Found: {res['threats_detected']}")
    for inf in res['infected_files']:
        print(f"  - {inf['threat_name']} in {inf['filepath']}")

def cmd_quarantine(args):
    q_mgr = QuarantineManager()
    sub = args.quarantine_action

    if sub == "list":
        items = q_mgr.list_quarantined_items()
        print(f"\n[+] Quarantine Vault Items ({len(items)} files currently isolated):")
        print("-" * 80)
        for i in items:
            t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(i['quarantined_at']))
            print(f"ID:       {i['id']}")
            print(f"Threat:   {i['threat_name']} [{i['severity']}]")
            print(f"Path:     {i['original_path']}")
            print(f"SHA-256:  {i['sha256']}")
            print(f"Date:     {t}")
            print("-" * 80)

    elif sub == "restore":
        if not args.id:
            print("[-] Error: --id required for restoration.")
            return
        res = q_mgr.restore_file(args.id)
        if res.get("success"):
            print(f"[+] Successfully restored item {args.id} to {res['restored_path']}")
        else:
            print(f"[-] Restoration failed: {res.get('error')}")

    elif sub == "purge":
        if not args.id:
            print("[-] Error: --id required for purge.")
            return
        res = q_mgr.purge_file(args.id)
        if res.get("success"):
            print(f"[+] Securely shredded and purged quarantine item {args.id}")
        else:
            print(f"[-] Purge failed: {res.get('error')}")

def cmd_processes(args):
    print("\n[*] Auditing running processes with security heuristics...")
    procs = ProcessInspector.list_running_processes(check_signatures=args.signatures)
    suspicious = [p for p in procs if p['risk_score'] > 0]
    print(f"[+] Total processes checked: {len(procs)}")
    print(f"[!] Anomalous / Suspicious processes flagged: {len(suspicious)}")
    print("-" * 80)
    for p in suspicious[:15]:
        print(f"PID: {p['pid']} | Name: {p['name']} | Risk: {p['risk_score']}")
        print(f"  Path: {p['exe']}")
        print(f"  Cmd:  {p['cmdline']}")
        for f in p['risk_factors']:
            print(f"  Factor: {f}")
        print("-" * 80)

def cmd_persistence(args):
    print("\n[*] Auditing Windows Persistence Mechanisms (Run keys, Startup, Tasks)...")
    res = StartupInspector.audit_all_persistence()
    print(f"[+] Total persistence mechanisms checked: {res['total_persistence_entries']}")
    print(f"[!] Suspicious startup entries detected:  {res['suspicious_count']}")
    print("\nRegistry Run Keys:")
    for r in res['registry_run_entries']:
        flag = " [!] SUSPICIOUS" if r['suspicious'] else ""
        print(f"  - [{r['location']}] {r['name']}: {r['command']}{flag}")

def cmd_usb(args):
    mgr = USBSecurityManager()
    drives = mgr.get_connected_removable_drives()
    print(f"\n[+] Connected Removable USB Storage Devices ({len(drives)} found):")
    for d in drives:
        print(f"  - Device: {d['device']} (Mountpoint: {d['mountpoint']}, FS: {d['fstype']})")
        if d['usage']:
            print(f"    Capacity: {d['usage']['total_gb']} GB ({d['usage']['free_gb']} GB free)")
        threats = mgr.inspect_drive_threats(d['mountpoint'])
        if threats['threat_count'] > 0:
            print(f"    [!] Root Threats Flagged: {threats['threat_count']}")

def cmd_test_eicar(args):
    """Safely drops the standard EICAR test string and tests immediate scanner detection."""
    test_dir = APP_DATA_DIR / "test_sandbox"
    test_dir.mkdir(parents=True, exist_ok=True)
    eicar_file = test_dir / "eicar_antivirus_test.com"

    print(f"\n[*] Generating standard EICAR Antivirus verification test file at:")
    print(f"    {eicar_file}")
    with open(eicar_file, "wb") as f:
        f.write(EICAR_BYTE_STRING)

    print("[*] Invoking AegisShield scan engine on the test file...")
    scanner = AntivirusScanner()
    res = scanner.scan_file(str(eicar_file))

    print(f"\n[+] VERIFICATION RESULTS:")
    print(f"    Infected Verdict:    {res.is_infected}")
    print(f"    Threat Name:         {res.threat_name}")
    print(f"    Detection Method:    {res.detection_method}")
    print(f"    Severity:            {res.severity}")
    print(f"    Detection Confidence:{res.confidence}%")

    if args.quarantine and res.is_infected:
        q_mgr = QuarantineManager()
        q_res = q_mgr.quarantine_file(
            filepath=str(eicar_file),
            threat_name=res.threat_name,
            detection_method=res.detection_method,
            severity=res.severity,
            confidence=res.confidence,
            reasons=res.reasons,
            operator="EICAR-Test",
        )
        print(f"    Quarantine Vault:    {'SUCCESS' if q_res['success'] else 'FAILED'}")
        if q_res.get("success"):
            print(f"    Quarantine ID:       {q_res['quarantine_id']}")
            print(f"    Vault File Integrity Verified.")
            print(f"    Original File Shredded: {not os.path.exists(str(eicar_file))}")

def main():
    parser = argparse.ArgumentParser(description="AegisShield EDR Endpoint Protection CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Scan command
    p_scan = subparsers.add_parser("scan", help="Scan a file or directory")
    p_scan.add_argument("--path", "-p", required=True, help="Path to file or folder")
    p_scan.add_argument("--quarantine", "-q", action="store_true", help="Automatically quarantine detected threats")

    # Quick scan
    subparsers.add_parser("quick-scan", help="Run rapid scan on critical Windows locations")

    # Quarantine command
    p_quar = subparsers.add_parser("quarantine", help="Manage quarantined files")
    p_quar.add_argument("quarantine_action", choices=["list", "restore", "purge"])
    p_quar.add_argument("--id", help="Quarantine item ID")

    # Processes
    p_proc = subparsers.add_parser("processes", help="Inspect running processes")
    p_proc.add_argument("--signatures", "-s", action="store_true", help="Check Authenticode digital signatures")

    # Persistence
    subparsers.add_parser("persistence", help="Audit startup and persistence mechanisms")

    # USB
    subparsers.add_parser("usb", help="Inspect connected removable storage")

    # Test EICAR
    p_eicar = subparsers.add_parser("test-eicar", help="Test detection using standard EICAR test string")
    p_eicar.add_argument("--quarantine", "-q", action="store_true", help="Also test quarantine isolation and shredding")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "quick-scan":
        cmd_quick_scan(args)
    elif args.command == "quarantine":
        cmd_quarantine(args)
    elif args.command == "processes":
        cmd_processes(args)
    elif args.command == "persistence":
        cmd_persistence(args)
    elif args.command == "usb":
        cmd_usb(args)
    elif args.command == "test-eicar":
        cmd_test_eicar(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
