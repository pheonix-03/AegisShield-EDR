import os
import sys
import time
import logging
from typing import List, Dict, Any, Optional, Callable, Set

import psutil

try:
    import win32file
    HAS_WIN32FILE = True
except ImportError:
    HAS_WIN32FILE = False

from aegis.config import config
from aegis.engine.scanner import AntivirusScanner

logger = logging.getLogger("AegisUSB")

class USBSecurityManager:
    """Monitors removable USB storage drives, enforces security policies, and executes scans."""

    def __init__(
        self,
        scanner: Optional[AntivirusScanner] = None,
        on_usb_event: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.scanner = scanner or AntivirusScanner()
        self.on_usb_event = on_usb_event
        self.known_removable_drives: Set[str] = set()
        self.event_history: List[Dict[str, Any]] = []

    def get_connected_removable_drives(self) -> List[Dict[str, Any]]:
        """Identifies active removable / USB storage drives connected to the system."""
        removable = []

        try:
            partitions = psutil.disk_partitions(all=False)
            for part in partitions:
                drive_letter = part.mountpoint
                is_removable = False

                # Check via win32 API
                if HAS_WIN32FILE:
                    try:
                        dtype = win32file.GetDriveType(drive_letter)
                        # DRIVE_REMOVABLE = 2
                        if dtype == 2:
                            is_removable = True
                    except Exception:
                        pass

                # Check via partition opts fallback
                if not is_removable and ("removable" in part.opts.lower() or part.fstype.lower() in ("fat32", "exfat")):
                    # Avoid flagging system C: drive
                    if not drive_letter.lower().startswith("c:"):
                        is_removable = True

                if is_removable:
                    usage = None
                    try:
                        u = psutil.disk_usage(drive_letter)
                        usage = {
                            "total_gb": round(u.total / (1024**3), 2),
                            "free_gb": round(u.free / (1024**3), 2),
                            "percent_used": u.percent,
                        }
                    except Exception:
                        pass

                    removable.append({
                        "device": part.device,
                        "mountpoint": drive_letter,
                        "fstype": part.fstype,
                        "usage": usage,
                    })

        except Exception as e:
            logger.error(f"Error enumerating disk partitions: {e}")

        return removable

    def inspect_drive_threats(self, mountpoint: str) -> Dict[str, Any]:
        """Inspects USB drive root for autorun.inf weaponization and suspicious shortcut exploits."""
        threats_found = []
        autorun_path = os.path.join(mountpoint, "autorun.inf")

        if os.path.exists(autorun_path):
            try:
                with open(autorun_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                threats_found.append({
                    "type": "AUTORUN_INF_PRESENT",
                    "path": autorun_path,
                    "reason": "Removable drive contains autorun.inf persistence script.",
                    "severity": "MEDIUM",
                    "content_snippet": content[:200],
                })
            except Exception:
                pass

        # Check for hidden executable files on root
        try:
            for item in os.listdir(mountpoint):
                item_path = os.path.join(mountpoint, item)
                if os.path.isfile(item_path):
                    ext = os.path.splitext(item)[1].lower()
                    if ext in (".exe", ".scr", ".pif", ".vbs", ".cmd", ".bat"):
                        threats_found.append({
                            "type": "ROOT_EXECUTABLE",
                            "path": item_path,
                            "reason": f"Executable or script present directly on root of USB: {item}",
                            "severity": "HIGH",
                        })
        except Exception:
            pass

        return {
            "mountpoint": mountpoint,
            "root_threats": threats_found,
            "threat_count": len(threats_found),
        }

    def poll_usb_events(self) -> List[Dict[str, Any]]:
        """Checks for newly plugged-in USB storage and handles auto-scanning."""
        current_removable = self.get_connected_removable_drives()
        current_mounts = {d["mountpoint"] for d in current_removable}

        new_drives = current_mounts - self.known_removable_drives
        removed_drives = self.known_removable_drives - current_mounts

        events = []

        # Handle removals
        for r_mount in removed_drives:
            event = {
                "event": "USB_REMOVED",
                "mountpoint": r_mount,
                "timestamp": time.time(),
            }
            self.event_history.append(event)
            events.append(event)
            logger.info(f"Removable storage removed: {r_mount}")

        # Handle insertions
        for n_mount in new_drives:
            event = {
                "event": "USB_INSERTED",
                "mountpoint": n_mount,
                "timestamp": time.time(),
                "scan_results": None,
            }
            logger.info(f"New removable storage detected: {n_mount}")

            # Inspect drive root for autorun/shortcuts
            root_inspect = self.inspect_drive_threats(n_mount)
            event["root_inspection"] = root_inspect

            # Auto-scan if enabled in config
            if config.get("usb_auto_scan", True):
                logger.info(f"Executing automatic antivirus scan on USB drive: {n_mount}")
                scan_res = self.scanner.scan_path(n_mount)
                event["scan_results"] = scan_res

            self.event_history.append(event)
            events.append(event)

            if self.on_usb_event:
                self.on_usb_event(event)

        self.known_removable_drives = current_mounts
        return events
