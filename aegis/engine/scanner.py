import os
import sys
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Set

from aegis.config import config, QUARANTINE_DIR, LOGS_DIR
from aegis.engine.signatures import SignatureDatabase
from aegis.engine.yara_engine import YaraEngine
from aegis.engine.pe_analyzer import PEAnalyzer
from aegis.engine.script_analyzer import ScriptAnalyzer
from aegis.engine.heuristics import HeuristicEngine

logger = logging.getLogger("AegisScanner")

# System folders that should never be scanned destructively or traversed pointlessly
SKIP_DIRECTORIES = {
    "$recycle.bin",
    "system volume information",
    "windows\\winsxs",
    "windows\\servicing",
}

class ScanResult:
    """Encapsulates the verdict for a scanned file."""

    def __init__(self, filepath: str, is_infected: bool = False):
        self.filepath = filepath
        self.is_infected = is_infected
        self.threat_name: Optional[str] = None
        self.detection_method: Optional[str] = None  # SIGNATURE, YARA, PE_STATIC, SCRIPT, HEURISTIC
        self.severity: str = "CLEAN"  # CLEAN, LOW, MEDIUM, HIGH, CRITICAL
        self.confidence: int = 0  # 0 to 100
        self.reasons: List[str] = []
        self.sha256: Optional[str] = None
        self.file_size: int = 0
        self.scan_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filepath": self.filepath,
            "is_infected": self.is_infected,
            "threat_name": self.threat_name,
            "detection_method": self.detection_method,
            "severity": self.severity,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "sha256": self.sha256,
            "file_size": self.file_size,
            "scan_time_ms": round(self.scan_time_ms, 2),
        }


class AntivirusScanner:
    """Production-grade multi-engine antivirus and endpoint security scanner."""

    def __init__(self, sig_db: Optional[SignatureDatabase] = None, yara_eng: Optional[YaraEngine] = None):
        self.sig_db = sig_db or SignatureDatabase()
        self.yara_engine = yara_eng or YaraEngine()
        self.pe_analyzer = PEAnalyzer()
        self.script_analyzer = ScriptAnalyzer()
        self.heuristic_engine = HeuristicEngine()
        self.is_cancelled = False

    def scan_file(self, filepath: str) -> ScanResult:
        """Runs layered detection on a single file."""
        t_start = time.perf_counter()
        result = ScanResult(filepath)

        if not os.path.isfile(filepath):
            result.reasons.append("File not found or inaccessible")
            return result

        try:
            stat = os.stat(filepath)
            result.file_size = stat.st_size
        except Exception as e:
            result.reasons.append(f"Stat error: {e}")
            return result

        # Check maximum file size from config (default 100 MB)
        max_bytes = config.get("max_scan_file_size_mb", 100) * 1024 * 1024
        if result.file_size > max_bytes:
            result.reasons.append(f"File skipped: exceeds maximum scan size of {max_bytes // (1024*1024)} MB")
            return result

        # Quick check for raw byte sequence directly in first 1024 bytes
        try:
            with open(filepath, "rb") as f:
                header_bytes = f.read(1024)
            quick_match = self.sig_db.match_content_quick(header_bytes)
            if quick_match:
                result.is_infected = True
                result.threat_name = quick_match["name"]
                result.detection_method = "SIGNATURE_RAW"
                result.severity = quick_match["severity"]
                result.confidence = quick_match["confidence"]
                result.reasons.append(quick_match["description"])
                result.sha256 = self.sig_db.get_cached_or_calculate_hash(filepath)
                result.scan_time_ms = (time.perf_counter() - t_start) * 1000
                return result
        except OSError as e:
            # Check if Windows Defender or OS filesystem filter blocked access due to infection
            if getattr(e, 'errno', None) == 22 or getattr(e, 'winerror', None) == 225 or "virus" in str(e).lower():
                result.is_infected = True
                result.threat_name = "WinDefender.Intercepted.Malware"
                result.detection_method = "WINDOWS_SECURITY_INTERCEPT"
                result.severity = "CRITICAL"
                result.confidence = 100
                result.reasons.append("File access intercepted and blocked by Windows Antivirus security filter.")
                result.scan_time_ms = (time.perf_counter() - t_start) * 1000
                return result
        except Exception:
            pass

        # Layer 1: SHA-256 Hash Signature Match
        sha256 = self.sig_db.get_cached_or_calculate_hash(filepath)
        result.sha256 = sha256
        if sha256:
            sig_match = self.sig_db.match_hash(sha256)
            if sig_match:
                result.is_infected = True
                result.threat_name = sig_match["name"]
                result.detection_method = "SIGNATURE_HASH"
                result.severity = sig_match["severity"]
                result.confidence = sig_match["confidence"]
                result.reasons.append(sig_match["description"])
                result.scan_time_ms = (time.perf_counter() - t_start) * 1000
                return result

        # Layer 2: YARA Rule Matching
        yara_matches = self.yara_engine.scan_file(filepath)
        if yara_matches:
            top_match = max(yara_matches, key=lambda x: x["confidence"])
            result.is_infected = True
            result.threat_name = f"Yara.{top_match['rule']}"
            result.detection_method = "YARA_RULE"
            result.severity = top_match["severity"]
            result.confidence = top_match["confidence"]
            result.reasons.extend([f"Rule '{m['rule']}': {m['description']}" for m in yara_matches])
            result.scan_time_ms = (time.perf_counter() - t_start) * 1000
            return result

        # Layer 3: Script & Deceptive Extension Analysis
        script_eval = self.script_analyzer.analyze_script(filepath)
        if script_eval["suspicious"]:
            result.is_infected = True
            result.threat_name = "Heur.Script.SuspiciousPayload"
            result.detection_method = "SCRIPT_INSPECTION"
            result.severity = "HIGH" if script_eval["score"] >= 60 else "MEDIUM"
            result.confidence = min(90, script_eval["score"])
            result.reasons.extend(script_eval["reasons"])
            result.scan_time_ms = (time.perf_counter() - t_start) * 1000
            return result

        # Layer 4: PE Executable Static Analysis
        if config.get("pe_heuristics_enabled", True):
            pe_eval = self.pe_analyzer.analyze_pe(filepath)
            if pe_eval["suspicious"]:
                result.is_infected = True
                result.threat_name = "Heur.PE.HighRiskBinary"
                result.detection_method = "PE_STATIC"
                result.severity = "HIGH" if pe_eval["score"] >= 70 else "MEDIUM"
                result.confidence = min(92, pe_eval["score"])
                result.reasons.extend(pe_eval["reasons"])
                result.scan_time_ms = (time.perf_counter() - t_start) * 1000
                return result

        # Layer 5: Contextual Location & Ransomware Heuristics
        heur_eval = self.heuristic_engine.evaluate_file_heuristics(filepath, result.file_size)
        if heur_eval["suspicious"]:
            result.is_infected = True
            result.threat_name = "Heur.Context.SuspiciousIndicator"
            result.detection_method = "HEURISTIC"
            result.severity = heur_eval["severity"]
            result.confidence = heur_eval["confidence"]
            result.reasons.extend(heur_eval["reasons"])
            result.scan_time_ms = (time.perf_counter() - t_start) * 1000
            return result

        result.scan_time_ms = (time.perf_counter() - t_start) * 1000
        return result

    def scan_path(
        self,
        target_path: str,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        max_workers: int = 4,
    ) -> Dict[str, Any]:
        """Scans a file or recursively scans a directory with live metrics and cancellation support."""
        self.is_cancelled = False
        start_time = time.time()

        summary: Dict[str, Any] = {
            "target": target_path,
            "status": "RUNNING",
            "files_scanned": 0,
            "files_skipped": 0,
            "threats_detected": 0,
            "threats_quarantined": 0,
            "errors": 0,
            "duration_seconds": 0.0,
            "infected_files": [],
            "error_list": [],
        }

        target = Path(target_path)
        if not target.exists():
            summary["status"] = "FAILED"
            summary["error_list"].append(f"Target path does not exist: {target_path}")
            return summary

        # Collect files to scan
        files_to_scan: List[str] = []
        excluded_paths = [os.path.normpath(p).lower() for p in config.get("excluded_paths", [])]
        excluded_exts = set(config.get("excluded_extensions", []))

        if target.is_file():
            files_to_scan.append(str(target))
        else:
            for root, dirs, files in os.walk(str(target), topdown=True):
                if self.is_cancelled:
                    break

                # Filter out protected / problematic directories
                norm_root = os.path.normpath(root).lower()
                if any(skip in norm_root for skip in SKIP_DIRECTORIES):
                    dirs[:] = []
                    continue
                if any(norm_root.startswith(ex) for ex in excluded_paths):
                    dirs[:] = []
                    continue

                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext in excluded_exts:
                        summary["files_skipped"] += 1
                        continue
                    files_to_scan.append(os.path.join(root, f))

        total_files = len(files_to_scan)
        if total_files == 0:
            summary["status"] = "COMPLETED"
            summary["duration_seconds"] = round(time.time() - start_time, 2)
            return summary

        # Parallel scan using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(self.scan_file, f): f for f in files_to_scan}

            for future in as_completed(future_to_file):
                if self.is_cancelled:
                    executor.shutdown(wait=False, cancel_futures=True)
                    summary["status"] = "CANCELLED"
                    break

                try:
                    res: ScanResult = future.result()
                    summary["files_scanned"] += 1
                    if res.is_infected:
                        summary["threats_detected"] += 1
                        summary["infected_files"].append(res.to_dict())
                except Exception as e:
                    summary["errors"] += 1
                    summary["error_list"].append(str(e))

                if progress_callback:
                    pct = round((summary["files_scanned"] / total_files) * 100, 1)
                    progress_callback({
                        "progress_percent": pct,
                        "files_scanned": summary["files_scanned"],
                        "total_files": total_files,
                        "threats_detected": summary["threats_detected"],
                    })

        if summary["status"] != "CANCELLED":
            summary["status"] = "COMPLETED"

        summary["duration_seconds"] = round(time.time() - start_time, 2)
        return summary

    def cancel_scan(self):
        self.is_cancelled = True

    def run_quick_scan(self, progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Scans high-probability malware staging areas: Downloads, Desktop, Temp, Startup."""
        quick_targets = [
            os.path.expandvars(r"%USERPROFILE%\Downloads"),
            os.path.expandvars(r"%USERPROFILE%\Desktop"),
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]

        overall_summary: Dict[str, Any] = {
            "scan_type": "QUICK_SCAN",
            "status": "COMPLETED",
            "files_scanned": 0,
            "files_skipped": 0,
            "threats_detected": 0,
            "threats_quarantined": 0,
            "duration_seconds": 0.0,
            "infected_files": [],
            "errors": 0,
        }

        t0 = time.time()
        for qpath in quick_targets:
            if os.path.exists(qpath):
                res = self.scan_path(qpath, progress_callback=progress_callback)
                overall_summary["files_scanned"] += res["files_scanned"]
                overall_summary["files_skipped"] += res["files_skipped"]
                overall_summary["threats_detected"] += res["threats_detected"]
                overall_summary["threats_quarantined"] += res["threats_quarantined"]
                overall_summary["infected_files"].extend(res["infected_files"])
                overall_summary["errors"] += res["errors"]

        overall_summary["duration_seconds"] = round(time.time() - t0, 2)
        return overall_summary
