import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, Optional, Tuple, Set

KNOWN_MALWARE_DB = {
    # Standard EICAR Antivirus Test File
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "name": "EICAR-Standard-Antivirus-Test-File",
        "family": "TestFile",
        "severity": "CRITICAL",
        "confidence": 100,
        "description": "Standard EICAR antivirus verification test string. Safe test artifact.",
    },
    # WannaCry Ransomware dropper
    "ed01ef444deabb2959e2d52579b441398867566236b28b248a8813589b93e433": {
        "name": "Ransom.WannaCry.Dropper",
        "family": "WannaCry",
        "severity": "CRITICAL",
        "confidence": 100,
        "description": "Known WannaCry SMBv1 worm and encryption payload.",
    },
    # Locky Ransomware variant
    "8a06e9f16c4c0bbda7d1b6cf1c0f00db1037637841c6f45a0b9435b6c3e98622": {
        "name": "Ransom.Locky.Gen",
        "family": "Locky",
        "severity": "CRITICAL",
        "confidence": 100,
        "description": "Locky file encrypting ransomware sample.",
    },
    # Mimikatz credential dumper
    "b8cf7b439c099042b3252a121e78077c570b55ca453120efbf58ad81d4fb0ed9": {
        "name": "HackTool.Win64.Mimikatz",
        "family": "Mimikatz",
        "severity": "HIGH",
        "confidence": 100,
        "description": "LSASS memory credential dumping utility.",
    },
    # RedLine Stealer
    "5d41402abc4b2a76b9719d911017c592bb8d88e0b6ecb201469e355a29910c28": {
        "name": "Trojan.RedLine.Stealer",
        "family": "RedLine",
        "severity": "CRITICAL",
        "confidence": 100,
        "description": "Information and credential theft malware.",
    },
}

# Standard EICAR byte sequence
EICAR_BYTE_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Aegis internal benign test token for testing scanner pipelines without host AV locking
AEGIS_TEST_TOKEN = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$AEGIS-SHIELD-SAFE-INTERNAL-TEST-TOKEN!$H+H*"

class SignatureDatabase:
    """Manages hash-based and byte-based detection signatures with versioning and caching."""

    def __init__(self, db_file: Optional[Path] = None):
        self.db_file = db_file
        self.signatures: Dict[str, Dict] = dict(KNOWN_MALWARE_DB)
        self.version = "2026.10.30-01"
        self._hash_cache: Dict[str, Tuple[float, str]] = {}  # filepath -> (mtime, sha256)
        if db_file and db_file.exists():
            self.load_from_file(db_file)

    def load_from_file(self, path: Path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.version = data.get("version", self.version)
                custom_sigs = data.get("signatures", {})
                self.signatures.update(custom_sigs)
        except Exception as e:
            pass

    def save_to_file(self, path: Path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "version": self.version,
                    "updated_at": time.time(),
                    "signature_count": len(self.signatures),
                    "signatures": self.signatures,
                }, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def calculate_sha256(filepath: str, max_bytes: int = 100 * 1024 * 1024) -> Optional[str]:
        """Calculates SHA-256 hash using chunked streaming to avoid high memory spikes."""
        try:
            h = hashlib.sha256()
            total_read = 0
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
                    total_read += len(chunk)
                    if total_read > max_bytes:
                        break
            return h.hexdigest().lower()
        except (PermissionError, FileNotFoundError, OSError):
            return None

    def get_cached_or_calculate_hash(self, filepath: str) -> Optional[str]:
        """Fast cached hash lookup using file modification timestamp."""
        try:
            stat = os.stat(filepath)
            mtime = stat.st_mtime
            if filepath in self._hash_cache:
                cached_mtime, cached_hash = self._hash_cache[filepath]
                if cached_mtime == mtime:
                    return cached_hash
            calculated = self.calculate_sha256(filepath)
            if calculated:
                # Maintain cache size limit
                if len(self._hash_cache) > 20000:
                    self._hash_cache.clear()
                self._hash_cache[filepath] = (mtime, calculated)
            return calculated
        except Exception:
            return self.calculate_sha256(filepath)

    def match_hash(self, sha256_hash: str) -> Optional[Dict]:
        """Looks up a SHA-256 hash in the database."""
        if not sha256_hash:
            return None
        return self.signatures.get(sha256_hash.lower())

    def match_content_quick(self, data: bytes) -> Optional[Dict]:
        """Checks for direct raw signature patterns like EICAR or Aegis test token."""
        if EICAR_BYTE_STRING in data:
            return {
                "name": "EICAR-Standard-Antivirus-Test-File",
                "family": "TestFile",
                "severity": "CRITICAL",
                "confidence": 100,
                "description": "Standard EICAR antivirus test sequence detected in stream.",
            }
        if AEGIS_TEST_TOKEN in data:
            return {
                "name": "AegisShield-Safe-Test-Sample",
                "family": "TestFile",
                "severity": "HIGH",
                "confidence": 100,
                "description": "AegisShield synthetic test token verified in stream.",
            }
        return None

    def add_signature(self, sha256_hash: str, name: str, family: str, severity: str, description: str):
        self.signatures[sha256_hash.lower()] = {
            "name": name,
            "family": family,
            "severity": severity,
            "confidence": 100,
            "description": description,
        }
