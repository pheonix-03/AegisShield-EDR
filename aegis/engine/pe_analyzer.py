import math
import os
from typing import Dict, Any, List, Optional

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# High-risk Windows API imports indicative of process injection, credential dumping, or evasion
SUSPICIOUS_IMPORTS = {
    "injection": [
        "virtualallocex", "writeprocessmemory", "createremotethread", "setwindowshookex",
        "queueuserapc", "ntunmapviewofsection", "zwunmapviewofsection", "rtlcreatethread",
        "createremotethreadex",
    ],
    "memory_manipulation": [
        "virtualprotect", "virtualprotectex", "readprocessmemory",
    ],
    "evasion_antidebug": [
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "outputdebugstringa", "outputdebugstringw",
    ],
    "credential_access": [
        "minidumpwritedump", "samigetprivatedata", "lsaretrieveprivatedata",
    ],
    "ransomware_encryption": [
        "cryptencrypt", "cryptgenkey", "cryptacquirecontext", "bcryptencrypt",
    ],
    "persistence": [
        "regsetvalueexa", "regsetvalueexw", "createservicea", "createservicew",
    ],
}

KNOWN_PACKER_SECTIONS = [
    ".upx", "upx0", "upx1", "upx2", ".themida", ".vmp0", ".vmp1", ".aspack", ".pecrypt",
]


class PEAnalyzer:
    """Performs static heuristic and structural analysis on Windows Portable Executables (PE)."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon entropy of a byte stream (0.0 to 8.0)."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    @classmethod
    def analyze_pe(cls, filepath: str) -> Dict[str, Any]:
        """Analyzes PE executable file structure, entropy, imports, and packers."""
        results: Dict[str, Any] = {
            "is_pe": False,
            "suspicious": False,
            "score": 0,
            "reasons": [],
            "entropy": 0.0,
            "sections": [],
            "matched_imports": {},
            "subsystem": None,
            "has_overlay": False,
            "is_packed": False,
        }

        if not os.path.exists(filepath):
            return results

        # Quick check for MZ header before heavy parsing
        try:
            with open(filepath, "rb") as f:
                header = f.read(2)
                if header != b"MZ":
                    return results
        except Exception:
            return results

        if not HAS_PEFILE:
            # Fallback basic analysis without pefile library
            try:
                with open(filepath, "rb") as f:
                    content = f.read(5 * 1024 * 1024)
                results["is_pe"] = True
                results["entropy"] = cls.calculate_entropy(content)
                if results["entropy"] > 7.3:
                    results["suspicious"] = True
                    results["score"] += 40
                    results["reasons"].append(f"High global entropy ({results['entropy']}) indicates packing/encryption.")
            except Exception:
                pass
            return results

        try:
            pe = pefile.PE(filepath, fast_load=True)
            results["is_pe"] = True
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            ])

            # 1. Section Analysis and Entropy
            total_entropy = 0.0
            max_section_entropy = 0.0
            section_count = len(pe.sections)

            for sec in pe.sections:
                try:
                    s_name = sec.Name.decode("latin1", errors="ignore").strip("\x00").lower()
                except Exception:
                    s_name = "unknown"

                s_entropy = round(sec.get_entropy(), 3)
                if s_entropy > max_section_entropy:
                    max_section_entropy = s_entropy
                total_entropy += s_entropy

                results["sections"].append({
                    "name": s_name,
                    "entropy": s_entropy,
                    "virtual_size": sec.Misc_VirtualSize,
                    "raw_size": sec.SizeOfRawData,
                })

                # Check known packer section names
                for packer_s in KNOWN_PACKER_SECTIONS:
                    if packer_s in s_name:
                        results["is_packed"] = True
                        results["score"] += 35
                        results["reasons"].append(f"Known packer/crypter section identified: {s_name}")

            if section_count > 0:
                results["entropy"] = round(total_entropy / section_count, 3)

            # High entropy heuristic (> 7.2 in any code or data section)
            if max_section_entropy >= 7.3:
                results["score"] += 35
                results["reasons"].append(f"Section exhibits abnormally high entropy ({max_section_entropy} >= 7.3)")

            # 2. Import Table Analysis
            imported_apis = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            try:
                                api_name = imp.name.decode("latin1", errors="ignore").lower()
                                imported_apis.append(api_name)
                            except Exception:
                                pass

            # Match against suspicious import categories
            for category, apis in SUSPICIOUS_IMPORTS.items():
                found_in_cat = [api for api in apis if api in imported_apis]
                if found_in_cat:
                    results["matched_imports"][category] = found_in_cat
                    if category == "injection" and len(found_in_cat) >= 2:
                        results["score"] += 45
                        results["reasons"].append(f"Process injection API pattern detected: {', '.join(found_in_cat)}")
                    elif category == "credential_access":
                        results["score"] += 50
                        results["reasons"].append(f"Credential extraction API detected: {', '.join(found_in_cat)}")
                    elif category == "ransomware_encryption" and max_section_entropy > 7.0:
                        results["score"] += 30
                        results["reasons"].append(f"High-entropy executable with Cryptographic APIs: {', '.join(found_in_cat)}")

            # 3. Overlay and Embedded Payload Check
            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset is not None:
                overlay_data = pe.get_overlay()
                if overlay_data and len(overlay_data) > 1024:
                    results["has_overlay"] = True
                    overlay_entropy = cls.calculate_entropy(overlay_data)
                    if overlay_entropy > 7.2:
                        results["score"] += 30
                        results["reasons"].append(f"High entropy overlay data detected ({overlay_entropy}), possible appended payload.")

            # Evaluation
            if results["score"] >= 50:
                results["suspicious"] = True

            pe.close()
        except Exception as e:
            results["error"] = str(e)

        return results
