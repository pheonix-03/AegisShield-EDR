import os
import sys
import time
import logging
from collections import deque
from typing import Dict, Any, List, Optional, Callable

import psutil

from aegis.config import config
from aegis.engine.pe_analyzer import PEAnalyzer

logger = logging.getLogger("AegisRansomwareWatcher")

class RansomwareBehaviorWatcher:
    """Detects rapid file encryption spikes, mass renames, and terminates rogue encryptors."""

    def __init__(self, on_ransomware_detected: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.on_ransomware_detected = on_ransomware_detected
        self.modification_history: deque = deque(maxlen=2000)  # (timestamp, filepath, event_type)
        self.rename_history: deque = deque(maxlen=2000)

        # Thresholds
        tw_cfg = config.get("ransomware_tripwire", {})
        self.max_writes_per_minute = tw_cfg.get("max_writes_per_minute", 40)
        self.max_renames_per_minute = tw_cfg.get("max_renames_per_minute", 20)
        self.auto_kill = tw_cfg.get("auto_kill_process", True)

    def record_activity(self, filepath: str, activity_type: str = "WRITE") -> Optional[Dict[str, Any]]:
        """Records a file modification or rename event and checks for ransomware bursts."""
        now = time.time()
        one_min_ago = now - 60.0

        if activity_type == "WRITE":
            self.modification_history.append((now, filepath))
            # Clean old entries
            while self.modification_history and self.modification_history[0][0] < one_min_ago:
                self.modification_history.popleft()
        elif activity_type == "RENAME":
            self.rename_history.append((now, filepath))
            while self.rename_history and self.rename_history[0][0] < one_min_ago:
                self.rename_history.popleft()

        recent_writes = len(self.modification_history)
        recent_renames = len(self.rename_history)

        is_spike = (recent_writes >= self.max_writes_per_minute) or (recent_renames >= self.max_renames_per_minute)

        if is_spike:
            # Check high entropy on last modified files to distinguish ransomware encryption from benign bulk copy
            high_entropy_count = 0
            sample_files = [f for t, f in list(self.modification_history)[-5:] if os.path.exists(f)]
            for sf in sample_files:
                try:
                    with open(sf, "rb") as f:
                        buf = f.read(65536)
                    if PEAnalyzer.calculate_entropy(buf) >= 7.2:
                        high_entropy_count += 1
                except Exception:
                    pass

            # If write rate is very high or files exhibit high entropy encryption
            if high_entropy_count >= 2 or recent_writes >= (self.max_writes_per_minute * 1.5):
                alert = self._handle_ransomware_outbreak(recent_writes, recent_renames, sample_files)
                return alert

        return None

    def _handle_ransomware_outbreak(self, write_count: int, rename_count: int, sample_files: List[str]) -> Dict[str, Any]:
        """Triages the alert, identifies suspicious running processes, and terminates if authorized."""
        logger.critical(
            f"[RANSOMWARE OUTBREAK DETECTED] Rapid write spike ({write_count} writes/min, {rename_count} renames/min)!"
        )

        suspicious_process = self._find_candidate_encryptor_process()
        terminated = False

        if suspicious_process and self.auto_kill:
            terminated = self.terminate_rogue_process(suspicious_process["pid"])

        alert = {
            "threat_type": "BEHAVIORAL_RANSOMWARE_OUTBREAK",
            "severity": "CRITICAL",
            "confidence": 95,
            "writes_in_last_minute": write_count,
            "renames_in_last_minute": rename_count,
            "sample_files_affected": sample_files,
            "candidate_process": suspicious_process,
            "process_terminated": terminated,
            "timestamp": time.time(),
        }

        # Clear window to avoid spamming alerts in the same minute
        self.modification_history.clear()
        self.rename_history.clear()

        if self.on_ransomware_detected:
            try:
                self.on_ransomware_detected(alert)
            except Exception as e:
                logger.error(f"Error calling ransomware alert callback: {e}")

        return alert

    def _find_candidate_encryptor_process(self) -> Optional[Dict[str, Any]]:
        """Inspects currently running processes for suspicious non-system high-CPU/IO tasks."""
        candidates = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "cpu_percent", "username"]):
            try:
                info = proc.info
                name = (info["name"] or "").lower()
                exe = (info["exe"] or "").lower()

                # Ignore trusted Windows system and IDE processes
                if name in ("svchost.exe", "explorer.exe", "system", "registry", "python.exe", "code.exe"):
                    continue
                if exe.startswith("c:\\windows\\system32"):
                    continue

                candidates.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Return candidate if found
        if candidates:
            return candidates[-1]  # most recent process
        return None

    @staticmethod
    def terminate_rogue_process(pid: int) -> bool:
        """Safely terminates an unauthorized ransomware process using standard process controls."""
        try:
            proc = psutil.Process(pid)
            pname = proc.name()
            # Safety check: Never kill critical OS processes
            if pname.lower() in ("csrss.exe", "explorer.exe", "services.exe", "lsass.exe", "winlogon.exe"):
                logger.warning(f"Refusing to terminate critical OS process {pname} (PID: {pid})")
                return False

            proc.kill()
            logger.info(f"Successfully neutralized rogue process {pname} (PID: {pid})")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Failed to terminate process PID {pid}: {e}")
            return False
