import re
import os
from typing import Dict, Any, List

SUSPICIOUS_SCRIPT_EXTENSIONS = {
    ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta"
}

DOUBLE_EXTENSION_REGEX = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|csv)\.(exe|scr|bat|cmd|vbs|js|ps1|hta|dll|pif)$",
    re.IGNORECASE,
)

POWERSHELL_SUSPICIOUS_PATTERNS = [
    (re.compile(r"-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", re.IGNORECASE), "Base64 encoded PowerShell execution", 45),
    (re.compile(r"-(?:w|windowstyle)\s+hidden", re.IGNORECASE), "Hidden window execution parameter", 20),
    (re.compile(r"-(?:ep|executionpolicy)\s+bypass", re.IGNORECASE), "Execution policy bypass flag", 20),
    (re.compile(r"\[System\.Text\.Encoding\]::.*\.GetString\(\[System\.Convert\]::FromBase64String", re.IGNORECASE), "In-memory Base64 decoding payload", 40),
    (re.compile(r"iex\s*\(\s*(?:new-object|curl|iwr)", re.IGNORECASE), "Invoke-Expression remote code execution", 50),
    (re.compile(r"downloadstring\s*\(", re.IGNORECASE), "Remote cradle DownloadString payload", 35),
    (re.compile(r"set-mppreference\s+-disablerealtime", re.IGNORECASE), "Attempt to disable Windows Defender real-time monitoring", 70),
    (re.compile(r"amsiutils\.getfield", re.IGNORECASE), "AMSI memory patching / bypass attempt", 75),
]

BATCH_SUSPICIOUS_PATTERNS = [
    (re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows", re.IGNORECASE), "Volume Shadow Copy deletion (Ransomware indicator)", 80),
    (re.compile(r"wbadmin(?:\.exe)?\s+delete\s+catalog", re.IGNORECASE), "Windows Backup catalog deletion", 80),
    (re.compile(r"bcdedit(?:\.exe)?\s+/set.*bootstatuspolicy\s+ignoreallfailures", re.IGNORECASE), "Disabling Windows boot failure recovery", 70),
    (re.compile(r"reg\s+add\s+.*\\run(?:\s|$)", re.IGNORECASE), "Modifying Windows Run persistence key", 40),
    (re.compile(r"certutil(?:\.exe)?\s+-urlcache\s+-split\s+-f", re.IGNORECASE), "CertUtil used for malicious file download living-off-the-land", 60),
    (re.compile(r"bitsadmin(?:\.exe)?\s+/transfer", re.IGNORECASE), "BitsAdmin file download living-off-the-land", 40),
]

VBS_JS_SUSPICIOUS_PATTERNS = [
    (re.compile(r"wscript\.shell", re.IGNORECASE), "WScript.Shell command execution object", 25),
    (re.compile(r"adodb\.stream", re.IGNORECASE), "ADODB.Stream binary drop and write object", 35),
    (re.compile(r"msxml2\.xmlhttp|microsoft\.xmlhttp", re.IGNORECASE), "HTTP client dropper in script", 35),
    (re.compile(r"powershell(?:\.exe)?\s+.*-enc", re.IGNORECASE), "Spawning encoded PowerShell from script", 60),
]


class ScriptAnalyzer:
    """Inspects scripts and files for malicious obfuscation, double extensions, and execution cradles."""

    @classmethod
    def check_double_extension(cls, filepath: str) -> Dict[str, Any]:
        basename = os.path.basename(filepath)
        match = DOUBLE_EXTENSION_REGEX.search(basename)
        if match:
            return {
                "detected": True,
                "reason": f"Deceptive double file extension detected: '{basename}' masks executable payload as benign document.",
                "score": 60,
            }
        return {"detected": False, "reason": None, "score": 0}

    @classmethod
    def analyze_script(cls, filepath: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "is_script": False,
            "suspicious": False,
            "score": 0,
            "reasons": [],
            "matched_patterns": [],
        }

        ext = os.path.splitext(filepath)[1].lower()
        # Also check double extension
        de = cls.check_double_extension(filepath)
        if de["detected"]:
            results["score"] += de["score"]
            results["reasons"].append(de["reason"])

        if ext not in SUSPICIOUS_SCRIPT_EXTENSIONS:
            if results["score"] >= 50:
                results["suspicious"] = True
            return results

        results["is_script"] = True

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(512 * 1024)  # Read up to 512 KB
        except Exception:
            return results

        patterns_to_check = []
        if ext == ".ps1":
            patterns_to_check.extend(POWERSHELL_SUSPICIOUS_PATTERNS)
        elif ext in (".bat", ".cmd"):
            patterns_to_check.extend(BATCH_SUSPICIOUS_PATTERNS)
        elif ext in (".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta"):
            patterns_to_check.extend(VBS_JS_SUSPICIOUS_PATTERNS)

        for regex, desc, weight in patterns_to_check:
            if regex.search(content):
                results["score"] += weight
                results["reasons"].append(desc)
                results["matched_patterns"].append(desc)

        if results["score"] >= 50:
            results["suspicious"] = True

        return results
