import os
import sys
import subprocess
import logging
from typing import List, Dict, Any, Optional
import psutil

from aegis.engine.signatures import SignatureDatabase

logger = logging.getLogger("AegisProcessInspector")

# Known legitimate Microsoft and Windows binaries
TRUSTED_SYSTEM_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "explorer.exe",
    "conhost.exe", "taskhostw.exe", "sihost.exe", "runtimebroker.exe",
}

class ProcessInspector:
    """Audits running processes, executable origins, parent-child relationships, and signatures."""

    @staticmethod
    def verify_authenticode_signature(exe_path: str) -> Dict[str, Any]:
        """Verifies digital signature of executable using PowerShell Authenticode check."""
        if not exe_path or not os.path.exists(exe_path):
            return {"is_signed": False, "status": "FILE_NOT_FOUND", "signer": None}

        # Quick check: Windows binaries under System32
        norm = os.path.normpath(exe_path).lower()
        if norm.startswith(r"c:\windows\system32") or norm.startswith(r"c:\windows\syswow64"):
            return {"is_signed": True, "status": "Valid", "signer": "Microsoft Windows"}

        try:
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-AuthenticodeSignature -FilePath '{exe_path}').Status.ToString(); (Get-AuthenticodeSignature -FilePath '{exe_path}').SignerCertificate.Subject",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            status = lines[0] if len(lines) > 0 else "Unknown"
            signer = lines[1] if len(lines) > 1 else None
            is_valid = status == "Valid"
            return {"is_signed": is_valid, "status": status, "signer": signer}
        except Exception:
            return {"is_signed": False, "status": "Error", "signer": None}

    @classmethod
    def list_running_processes(cls, check_signatures: bool = False) -> List[Dict[str, Any]]:
        """Enumerates active processes with security telemetry, parent PIDs, and risk flags."""
        process_list = []

        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "cpu_percent", "memory_info"]):
            try:
                info = proc.info
                pid = info["pid"]
                pname = (info["name"] or "unknown").lower()
                exe = info["exe"] or ""
                cmdline = " ".join(info["cmdline"] or [])
                ppid = info["ppid"]

                # Parent process name
                parent_name = "Unknown"
                try:
                    parent_proc = psutil.Process(ppid)
                    parent_name = parent_proc.name()
                except Exception:
                    pass

                # Risk assessment
                risk_score = 0
                risk_factors = []

                # Executable residing in Temp or AppData
                exe_lower = exe.lower()
                if "\\temp\\" in exe_lower or "\\appdata\\local\\temp" in exe_lower:
                    risk_score += 40
                    risk_factors.append("Process running directly from Temp directory.")

                # Deceptive process name trying to mimic system (e.g. scvhost.exe, svch0st.exe)
                if pname in ("scvhost.exe", "svch0st.exe", "lsas.exe", "csrs.exe"):
                    risk_score += 85
                    risk_factors.append(f"Masquerading process name mimicking system binary: '{pname}'")

                # PowerShell or CMD with hidden or encoded flags
                if pname in ("powershell.exe", "cmd.exe"):
                    cmd_lower = cmdline.lower()
                    if "-enc" in cmd_lower or "-encodedcommand" in cmd_lower:
                        risk_score += 70
                        risk_factors.append("PowerShell executing encoded command line.")
                    if "-w hidden" in cmd_lower or "-windowstyle hidden" in cmd_lower:
                        risk_score += 30
                        risk_factors.append("PowerShell launched with hidden window.")

                # Hash calculation for non-system binaries
                sha256 = None
                if exe and os.path.exists(exe) and pname not in TRUSTED_SYSTEM_PROCESSES:
                    sha256 = SignatureDatabase.calculate_sha256(exe, max_bytes=20 * 1024 * 1024)

                signature_info = None
                if check_signatures and exe and os.path.exists(exe):
                    signature_info = cls.verify_authenticode_signature(exe)

                process_list.append({
                    "pid": pid,
                    "ppid": ppid,
                    "parent_name": parent_name,
                    "name": info["name"],
                    "exe": exe,
                    "cmdline": cmdline,
                    "username": info["username"],
                    "created_at": info["create_time"],
                    "memory_mb": round(info["memory_info"].rss / (1024 * 1024), 1) if info["memory_info"] else 0,
                    "sha256": sha256,
                    "risk_score": risk_score,
                    "risk_factors": risk_factors,
                    "signature": signature_info,
                })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return process_list

    @classmethod
    def inspect_process(cls, pid: int) -> Optional[Dict[str, Any]]:
        """Deep inspection of a single process."""
        try:
            proc = psutil.Process(pid)
            info = proc.as_dict(attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "status", "num_threads"])
            exe = info.get("exe")
            sig = cls.verify_authenticode_signature(exe) if exe else None
            return {
                **info,
                "signature": sig,
                "open_files": [f.path for f in proc.open_files()[:20]] if hasattr(proc, "open_files") else [],
                "connections": [f"{c.laddr.ip}:{c.laddr.port} -> {c.raddr.ip}:{c.raddr.port}" for c in proc.net_connections() if c.raddr],
            }
        except Exception as e:
            logger.error(f"Failed to inspect process {pid}: {e}")
            return None
