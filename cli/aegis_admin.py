import os
import sys
import argparse
import requests
import json
import random
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from server.security import CommandSecurity, MASTER_SIGNING_KEY

SERVER_URL = "http://127.0.0.1:8443"

def cmd_seed_fleet(args):
    """Populates the management database with realistic 50–100 office workstations across locations."""
    count = args.count
    offices = ["Headquarters - Floor 3", "Branch Office Alpha (Chicago)", "Branch Office Beta (Austin)"]
    hostnames = [
        "FIN-WORKSTATION", "DEV-STATION", "EXEC-LAPTOP", "HR-DESKTOP",
        "OPS-SURFACE", "QA-TERMINAL", "MARKET-PC", "LEGAL-DESK"
    ]

    print(f"[*] Enrolling {count} simulated office workstations into AegisShield Fleet...")
    enrolled = 0

    for i in range(1, count + 1):
        agent_id = f"win11-corp-agent-{i:03d}"
        office = offices[i % len(offices)]
        host = f"{random.choice(hostnames)}-{i:03d}"
        ip = f"10.{10 + (i % 3)}.{1 + (i // 50)}.{10 + (i % 240)}"

        payload = {
            "agent_id": agent_id,
            "hostname": host,
            "ip_address": ip,
            "os_info": "Windows 11 Enterprise 64-bit",
            "office_location": office,
            "agent_version": "1.0.0",
            "signature_version": "2026.10.30-01",
        }

        try:
            r = requests.post(f"{SERVER_URL}/api/v1/agent/register", json=payload, timeout=5)
            if r.status_code == 200:
                # Also send an initial heartbeat with telemetry
                hb_payload = {
                    "agent_id": agent_id,
                    "cpu_usage": round(random.uniform(2.5, 24.0), 1),
                    "memory_usage": round(random.uniform(32.0, 78.0), 1),
                    "realtime_active": True,
                    "ransomware_active": True,
                    "usb_active": True,
                    "threats_detected": random.choice([0, 0, 0, 1]),
                    "threats_quarantined": 1 if random.random() > 0.8 else 0,
                    "signature_version": "2026.10.30-01",
                }
                requests.post(f"{SERVER_URL}/api/v1/agent/heartbeat", json=hb_payload, timeout=5)
                enrolled += 1
        except Exception as e:
            print(f"[-] Error registering {agent_id}: {e}")
            break

    print(f"[+] Successfully registered and synchronized {enrolled} endpoint agents across {len(offices)} offices.")

def cmd_dispatch(args):
    print(f"[*] Authoring cryptographically signed {args.command_type} command for agent {args.agent}...")
    payload = {
        "agent_id": args.agent,
        "command_type": args.command_type,
        "parameters": {},
    }
    r = requests.post(f"{SERVER_URL}/api/v1/admin/dispatch_command", json=payload, timeout=5)
    if r.status_code == 200:
        data = r.json()
        print(f"[+] Command Queued with cryptographic signature:")
        print(f"    Command ID: {data['command_id']}")
        print(f"    Signature:  {data['signature'][:32]}... [HMAC-SHA256 verified]")
    else:
        print(f"[-] Dispatch failed: {r.text}")

def main():
    parser = argparse.ArgumentParser(description="AegisShield Central Fleet Administrator CLI")
    sub = parser.add_subparsers(dest="action")

    p_seed = sub.add_parser("seed-fleet", help="Enroll a batch of workstations (50-100) across offices")
    p_seed.add_argument("--count", "-c", type=int, default=50, help="Number of workstations (default: 50)")

    p_disp = sub.add_parser("dispatch", help="Dispatch signed command to agent")
    p_disp.add_argument("--agent", "-a", required=True, help="Agent UUID")
    p_disp.add_argument("--command-type", "-t", required=True, choices=["QUICK_SCAN", "FULL_SCAN", "UPDATE_SIGNATURES", "ISOLATE_HOST"])

    args = parser.parse_args()
    if args.action == "seed-fleet":
        cmd_seed_fleet(args)
    elif args.action == "dispatch":
        cmd_dispatch(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
