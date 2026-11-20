import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import plyara
    HAS_PLYARA = True
except ImportError:
    HAS_PLYARA = False


class YaraPattern:
    """Represents a compiled pattern from a YARA string block."""

    def __init__(self, identifier: str, pattern_type: str, value: str, modifiers: List[str] = None):
        self.identifier = identifier
        self.pattern_type = pattern_type  # 'text', 'hex', 'regex'
        self.raw_value = value
        self.modifiers = modifiers or []
        self.regex = self._compile()

    def _compile(self) -> Optional[re.Pattern]:
        try:
            flags = 0
            if "nocase" in self.modifiers:
                flags |= re.IGNORECASE

            if self.pattern_type == "text":
                escaped = re.escape(self.raw_value.encode("utf-8", errors="ignore"))
                if "wide" in self.modifiers and "ascii" in self.modifiers:
                    wide_val = b"".join([bytes([b, 0]) for b in self.raw_value.encode("utf-8", errors="ignore")])
                    combined = f"({escaped.decode('latin1')}|{re.escape(wide_val).decode('latin1')})"
                    return re.compile(combined.encode("latin1"), flags)
                elif "wide" in self.modifiers:
                    wide_val = b"".join([bytes([b, 0]) for b in self.raw_value.encode("utf-8", errors="ignore")])
                    return re.compile(re.escape(wide_val), flags)
                else:
                    return re.compile(re.escape(self.raw_value.encode("latin1", errors="ignore")), flags)

            elif self.pattern_type == "hex":
                # Convert hex string e.g. "4D 5A ?? 00" to regex bytes
                clean = re.sub(r"[\s\r\n]+", " ", self.raw_value.strip("{} \t\r\n"))
                parts = clean.split()
                regex_parts = []
                for p in parts:
                    if p in ("??", "?"):
                        regex_parts.append(b".")
                    else:
                        byte_val = bytes.fromhex(p)
                        regex_parts.append(re.escape(byte_val))
                return re.compile(b"".join(regex_parts), flags)

            elif self.pattern_type == "regex":
                # Raw regex bytes
                cleaned_regex = self.raw_value.strip("/")
                return re.compile(cleaned_regex.encode("latin1", errors="ignore"), flags)

            return None
        except Exception:
            return None

    def match(self, data: bytes) -> bool:
        if not self.regex:
            return False
        return bool(self.regex.search(data))


class CompiledYaraRule:
    """Represents a compiled YARA rule with string matching and condition evaluation."""

    def __init__(self, rule_name: str, meta: Dict[str, Any], strings: List[YaraPattern], condition_raw: str):
        self.rule_name = rule_name
        self.meta = meta or {}
        self.strings = {s.identifier: s for s in strings}
        self.condition_raw = condition_raw.strip() if condition_raw else "any of them"

    def evaluate(self, data: bytes) -> bool:
        """Evaluates whether the input binary buffer matches this rule."""
        if not data:
            return False

        # First, check pre-conditions like MZ header if required
        if "uint16(0) == 0x5a4d" in self.condition_raw.lower() or "uint16(0) == 0x5A4D" in self.condition_raw:
            if len(data) < 2 or data[0:2] != b"MZ":
                return False

        # Check strings
        matched_ids = set()
        for ident, pattern in self.strings.items():
            if pattern.match(data):
                matched_ids.add(ident)

        cond = self.condition_raw.lower()

        # Simple condition evaluator:
        if "all of them" in cond:
            return len(matched_ids) == len(self.strings) and len(self.strings) > 0
        elif "any of them" in cond:
            return len(matched_ids) > 0
        elif " and " in cond:
            # Check if all mentioned string identifiers were matched
            req_ids = [ident for ident in self.strings if ident in self.condition_raw]
            if req_ids:
                return all(ident in matched_ids for ident in req_ids)
            return len(matched_ids) > 0
        elif " or " in cond:
            req_ids = [ident for ident in self.strings if ident in self.condition_raw]
            if req_ids:
                return any(ident in matched_ids for ident in req_ids)
            return len(matched_ids) > 0
        else:
            # Default to checking if any of matched strings matched
            return len(matched_ids) > 0


class YaraEngine:
    """YARA Scanning engine supporting rule parsing, compilation, and file matching."""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules: List[CompiledYaraRule] = []
        if rules_dir and rules_dir.exists():
            self.load_rules_directory(rules_dir)
        else:
            self._load_builtin_rules()

    def _load_builtin_rules(self):
        """Pre-loads default production-grade YARA rules for ransomware, hacktools, and scripts."""
        default_rules = """
rule Ransomware_Generic_Canary {
    meta:
        description = "Detects generic ransomware payment notes and threat terms"
        severity = "CRITICAL"
        family = "Ransomware"
        confidence = 90
    strings:
        $s1 = "All your files have been encrypted" nocase wide ascii
        $s2 = "decrypt your files" nocase wide ascii
        $s3 = "pay bitcoin to the following address" nocase wide ascii
        $s4 = ".onion" nocase ascii
        $s5 = "Tor Browser" nocase ascii
    condition:
        2 of them
}

rule Suspicious_PowerShell_Obfuscation {
    meta:
        description = "Detects hidden encoded powershell execution"
        severity = "HIGH"
        family = "ScriptWeaponization"
        confidence = 85
    strings:
        $p1 = "powershell -enc" nocase ascii
        $p2 = "powershell -encodedcommand" nocase ascii
        $p3 = "powershell -windowstyle hidden" nocase ascii
        $p4 = "FromBase64String" nocase ascii
        $p5 = "IEX (New-Object Net.WebClient)" nocase ascii
    condition:
        2 of them
}

rule HackTool_Mimikatz_Artifacts {
    meta:
        description = "Detects Mimikatz credentials dumping indicators"
        severity = "CRITICAL"
        family = "Mimikatz"
        confidence = 95
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase ascii
        $m2 = "lsadump::sam" nocase ascii
        $m3 = "gentilkiwi" nocase ascii
        $m4 = "mimikatz" nocase ascii
    condition:
        any of them
}

rule Suspicious_Ransomware_ShadowCopy_Deletion {
    meta:
        description = "Detects shadow copy deletion commands used by ransomware"
        severity = "CRITICAL"
        family = "RansomwarePrep"
        confidence = 95
    strings:
        $v1 = "vssadmin delete shadows /all /quiet" nocase ascii
        $v2 = "wmic shadowcopy delete" nocase ascii
        $v3 = "wbadmin delete catalog -quiet" nocase ascii
        $v4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase ascii
    condition:
        any of them
}
"""
        self.load_rules_from_string(default_rules)

    def load_rules_from_string(self, rule_content: str):
        if HAS_PLYARA:
            try:
                parser = plyara.Plyara()
                parsed = parser.parse_string(rule_content)
                for r in parsed:
                    rule_name = r.get("rule_name", "UnknownRule")
                    meta_raw = r.get("metadata", {})
                    meta = {}
                    if isinstance(meta_raw, list):
                        for m in meta_raw:
                            if isinstance(m, dict):
                                meta.update(m)
                    elif isinstance(meta_raw, dict):
                        meta = meta_raw

                    str_patterns = []
                    for s in r.get("strings", []):
                        ident = s.get("name", "")
                        stype = s.get("type", "text")
                        val = s.get("value", "")
                        mods = s.get("modifiers", [])
                        str_patterns.append(YaraPattern(ident, stype, val, mods))

                    cond = r.get("raw_condition", "any of them")
                    self.rules.append(CompiledYaraRule(rule_name, meta, str_patterns, cond))
                return
            except Exception:
                pass

        # Robust regex-based fallback parser
        self._fallback_parse_rules(rule_content)

    def _fallback_parse_rules(self, text: str):
        rule_pattern = re.compile(r"rule\s+([A-Za-z0-9_]+)\s*\{([\s\S]*?)\}", re.MULTILINE)
        for match in rule_pattern.finditer(text):
            rname = match.group(1)
            body = match.group(2)

            # Extract meta
            meta = {}
            meta_match = re.search(r"meta:\s*([\s\S]*?)(?=strings:|condition:|\})", body)
            if meta_match:
                for line in meta_match.group(1).splitlines():
                    kv = line.strip().split("=", 1)
                    if len(kv) == 2:
                        k = kv[0].strip()
                        v = kv[1].strip(' \t\r\n"')
                        meta[k] = v

            # Extract strings
            str_patterns = []
            str_match = re.search(r"strings:\s*([\s\S]*?)(?=condition:|\})", body)
            if str_match:
                for line in str_match.group(1).splitlines():
                    line = line.strip()
                    if not line or not line.startswith("$"):
                        continue
                    m = re.match(r"(\$[A-Za-z0-9_]*)\s*=\s*(.*)", line)
                    if m:
                        ident = m.group(1)
                        rest = m.group(2).strip()
                        modifiers = []
                        if "nocase" in rest:
                            modifiers.append("nocase")
                        if "wide" in rest:
                            modifiers.append("wide")
                        if "ascii" in rest:
                            modifiers.append("ascii")

                        if rest.startswith('"'):
                            end_idx = rest.rfind('"')
                            val = rest[1:end_idx] if end_idx > 0 else rest.strip('"')
                            str_patterns.append(YaraPattern(ident, "text", val, modifiers))
                        elif rest.startswith("{"):
                            end_idx = rest.rfind("}")
                            val = rest[1:end_idx] if end_idx > 0 else rest.strip("{}")
                            str_patterns.append(YaraPattern(ident, "hex", val, modifiers))
                        elif rest.startswith("/"):
                            end_idx = rest.rfind("/")
                            val = rest[1:end_idx] if end_idx > 0 else rest.strip("/")
                            str_patterns.append(YaraPattern(ident, "regex", val, modifiers))

            # Extract condition
            cond_match = re.search(r"condition:\s*([\s\S]*?)$", body)
            cond = cond_match.group(1).strip() if cond_match else "any of them"

            self.rules.append(CompiledYaraRule(rname, meta, str_patterns, cond))

    def load_rules_directory(self, rules_dir: Path):
        count = 0
        for entry in rules_dir.glob("*.yar*"):
            try:
                content = entry.read_text(encoding="utf-8", errors="ignore")
                self.load_rules_from_string(content)
                count += 1
            except Exception:
                pass
        if not self.rules:
            self._load_builtin_rules()

    def scan_data(self, data: bytes) -> List[Dict[str, Any]]:
        """Scans byte data against all loaded compiled YARA rules."""
        matches = []
        for rule in self.rules:
            if rule.evaluate(data):
                matches.append({
                    "rule": rule.rule_name,
                    "description": rule.meta.get("description", "YARA Rule Match"),
                    "severity": rule.meta.get("severity", "HIGH"),
                    "family": rule.meta.get("family", "SuspiciousArtifact"),
                    "confidence": int(rule.meta.get("confidence", 85)),
                })
        return matches

    def scan_file(self, filepath: str, max_size_mb: int = 50) -> List[Dict[str, Any]]:
        """Reads and scans a file up to max_size_mb."""
        try:
            size = os.path.getsize(filepath)
            if size > max_size_mb * 1024 * 1024:
                return []
            with open(filepath, "rb") as f:
                data = f.read(min(size, 20 * 1024 * 1024))
            return self.scan_data(data)
        except Exception:
            return []
