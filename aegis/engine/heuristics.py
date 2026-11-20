import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional

RANSOM_NOTE_REGEX = re.compile(
    r"(readme_to_decrypt|how_to_decrypt|how_to_recover|decrypt_files|restore_files|files_encrypted|ransom_note|readme_for_decrypt|#_readme_#|!-readme-!)",
    re.IGNORECASE,
)

RANSOM_ENCRYPTED_EXTENSIONS = {
    ".locked", ".crypto", ".crypt", ".crypted", ".enc", ".locky", ".wncry",
    ".wannacry", ".mallox", ".blackcat", ".darkside", ".revil", ".ryuk", ".cerber",
}

class HeuristicEngine:
    """Evaluates contextual indicators, file location anomalies, and ransomware traits."""

    @classmethod
    def evaluate_file_heuristics(cls, filepath: str, file_size: int = 0) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "suspicious": False,
            "confidence": 0,
            "severity": "INFO",
            "score": 0,
            "reasons": [],
        }

        norm_path = os.path.normpath(filepath).lower()
        basename = os.path.basename(norm_path)
        ext = os.path.splitext(norm_path)[1]

        # 1. Ransomware note detection
        if RANSOM_NOTE_REGEX.search(basename):
            results["score"] += 80
            results["reasons"].append(f"File matches known ransomware ransom note naming pattern: '{basename}'")
            results["severity"] = "CRITICAL"

        # 2. Known ransomware encrypted extension detection
        if ext in RANSOM_ENCRYPTED_EXTENSIONS:
            results["score"] += 70
            results["reasons"].append(f"File possesses known ransomware encryption extension: '{ext}'")
            if results["severity"] != "CRITICAL":
                results["severity"] = "HIGH"

        # 3. Executable residing directly in Temp, AppData, or Downloads
        is_executable = ext in (".exe", ".dll", ".scr", ".pif", ".cpl", ".vbs", ".ps1")
        if is_executable:
            temp_dirs = [
                os.getenv("TEMP", "").lower(),
                os.getenv("TMP", "").lower(),
                os.path.expandvars(r"%LOCALAPPDATA%\Temp").lower(),
                "c:\\windows\\temp",
            ]
            for tdir in temp_dirs:
                if tdir and norm_path.startswith(tdir):
                    results["score"] += 35
                    results["reasons"].append(f"Executable binary located inside temporary directory: {norm_path}")
                    break

            # Hidden or system attribute on non-system executable
            try:
                import win32file
                import win32con
                attrs = win32file.GetFileAttributesW(filepath)
                if attrs & win32con.FILE_ATTRIBUTE_HIDDEN and not norm_path.startswith(r"c:\windows"):
                    results["score"] += 25
                    results["reasons"].append("Executable file has hidden attribute set outside system directories.")
            except Exception:
                pass

        # 4. Tiny executable (< 10 KB) or huge binary (> 300 MB)
        if ext == ".exe":
            if 0 < file_size < 8192:
                results["score"] += 20
                results["reasons"].append(f"Abnormally small executable binary ({file_size} bytes), possible stager or dropper.")

        # Compute confidence and severity
        if results["score"] >= 80:
            results["suspicious"] = True
            results["confidence"] = min(98, results["score"])
            results["severity"] = "CRITICAL"
        elif results["score"] >= 50:
            results["suspicious"] = True
            results["confidence"] = min(85, results["score"])
            results["severity"] = "HIGH"
        elif results["score"] >= 30:
            results["suspicious"] = False
            results["confidence"] = min(60, results["score"])
            results["severity"] = "MEDIUM"

        return results
