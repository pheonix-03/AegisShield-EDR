import os
import sys
import csv
import io
import subprocess
import logging
from typing import List, Dict, Any

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

logger = logging.getLogger("AegisStartupInspector")

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run") if HAS_WINREG else None,
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run") if HAS_WINREG else None,
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce") if HAS_WINREG else None,
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce") if HAS_WINREG else None,
]

class StartupInspector:
    """Audits Windows persistence mechanisms: Registry Run keys, Startup folders, and Scheduled Tasks."""

    @classmethod
    def get_registry_run_entries(cls) -> List[Dict[str, Any]]:
        entries = []
        if not HAS_WINREG:
            return entries

        for item in RUN_KEYS:
            if not item:
                continue
            root_hive, subkey, location_tag = item
            try:
                with winreg.OpenKey(root_hive, subkey, 0, winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            name, value, reg_type = winreg.EnumValue(key, index)
                            index += 1

                            suspicious = False
                            reasons = []
                            val_lower = str(value).lower()
                            if "\\temp\\" in val_lower or "powershell" in val_lower and "-enc" in val_lower:
                                suspicious = True
                                reasons.append("Startup command points to temporary folder or encoded script.")

                            entries.append({
                                "type": "REGISTRY",
                                "name": name,
                                "command": str(value),
                                "location": location_tag,
                                "suspicious": suspicious,
                                "reasons": reasons,
                            })
                        except OSError:
                            break
            except Exception:
                pass

        return entries

    @classmethod
    def get_startup_folder_entries(cls) -> List[Dict[str, Any]]:
        entries = []
        startup_dirs = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]

        for sdir in startup_dirs:
            if os.path.exists(sdir):
                for fname in os.listdir(sdir):
                    fpath = os.path.join(sdir, fname)
                    if os.path.isfile(fpath):
                        ext = os.path.splitext(fname)[1].lower()
                        suspicious = ext in (".bat", ".cmd", ".vbs", ".ps1", ".hta")
                        entries.append({
                            "type": "STARTUP_FOLDER",
                            "name": fname,
                            "command": fpath,
                            "location": sdir,
                            "suspicious": suspicious,
                            "reasons": [f"Script file placed directly in startup directory: {ext}"] if suspicious else [],
                        })

        return entries

    @classmethod
    def get_scheduled_tasks(cls, max_entries: int = 100) -> List[Dict[str, Any]]:
        tasks = []
        try:
            cmd = ["schtasks.exe", "/query", "/fo", "CSV", "/nh"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                reader = csv.reader(io.StringIO(res.stdout))
                for row in reader:
                    if len(row) >= 2:
                        task_name = row[0].strip()
                        next_run = row[1].strip() if len(row) > 1 else ""
                        status = row[2].strip() if len(row) > 2 else ""

                        # Filter out system and update noise
                        lower_name = task_name.lower()
                        if lower_name.startswith("\\microsoft\\"):
                            continue

                        tasks.append({
                            "type": "SCHEDULED_TASK",
                            "name": task_name,
                            "next_run": next_run,
                            "status": status,
                            "suspicious": False,
                            "reasons": [],
                        })
                        if len(tasks) >= max_entries:
                            break
        except Exception as e:
            logger.debug(f"Failed to query scheduled tasks: {e}")

        return tasks

    @classmethod
    def audit_all_persistence(cls) -> Dict[str, Any]:
        """Performs a comprehensive persistence mechanisms audit."""
        reg_entries = cls.get_registry_run_entries()
        folder_entries = cls.get_startup_folder_entries()
        scheduled_tasks = cls.get_scheduled_tasks()

        all_items = reg_entries + folder_entries
        suspicious_items = [item for item in all_items if item.get("suspicious")]

        return {
            "total_persistence_entries": len(all_items) + len(scheduled_tasks),
            "registry_run_entries": reg_entries,
            "startup_folder_entries": folder_entries,
            "scheduled_tasks_count": len(scheduled_tasks),
            "suspicious_count": len(suspicious_items),
            "suspicious_entries": suspicious_items,
        }
