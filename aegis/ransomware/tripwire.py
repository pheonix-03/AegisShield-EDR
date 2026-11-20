import os
import time
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable

from aegis.config import CANARY_DIR, config

logger = logging.getLogger("AegisRansomwareTripwire")

CANARY_TEMPLATES = [
    ("confidential_payroll_2026.xlsx", b"CANARY_PAYROLL_DATA_TAG_DO_NOT_ALTER_AEGIS_SHIELD_SECURITY_2026"),
    ("executive_board_minutes.docx", b"CANARY_BOARD_MINUTES_AEGIS_RANSOMWARE_TRIPWIRE_SENTINEL_TOKEN_XYZ"),
    ("client_contracts_q3.pdf", b"%PDF-1.4 CANARY_TRIPWIRE_TOKEN_CONTRACTS_AUTHENTICATED_SECURE_TOKEN"),
    ("financial_audit_summary.csv", b"account,balance,status\n1001,45000,CANARY_TRIPWIRE_TAG\n1002,95000,ACTIVE"),
]

class CanaryTripwire:
    """Deploys and audits canary honey-files in critical user directories to catch ransomware in the act."""

    def __init__(self, canary_dir: Path = CANARY_DIR, on_tripwire_tripped: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.canary_dir = canary_dir
        self.canary_dir.mkdir(parents=True, exist_ok=True)
        self.on_tripwire_tripped = on_tripwire_tripped
        self.deployed_canaries: Dict[str, Dict[str, Any]] = {}
        self.setup_canaries()

    def setup_canaries(self):
        """Creates honey-files and tracks their expected hashes and file sizes."""
        self.deployed_canaries.clear()
        for filename, content in CANARY_TEMPLATES:
            target_path = self.canary_dir / filename
            try:
                # Write file if not exists or corrupted
                with open(target_path, "wb") as f:
                    f.write(content)
                sha256 = hashlib.sha256(content).hexdigest()
                self.deployed_canaries[str(target_path)] = {
                    "filename": filename,
                    "expected_hash": sha256,
                    "expected_size": len(content),
                    "created_at": time.time(),
                }
            except Exception as e:
                logger.error(f"Failed to deploy canary {filename}: {e}")

    def verify_canaries(self) -> List[Dict[str, Any]]:
        """Audits canary integrity. Returns list of violations if files are modified, renamed, or encrypted."""
        violations = []
        for path_str, meta in self.deployed_canaries.items():
            if not os.path.exists(path_str):
                # File deleted or renamed!
                violations.append({
                    "path": path_str,
                    "filename": meta["filename"],
                    "violation": "DELETED_OR_RENAMED",
                    "reason": "Canary trap file was deleted or renamed by an active process.",
                    "severity": "CRITICAL",
                })
                continue

            try:
                with open(path_str, "rb") as f:
                    data = f.read()
                current_hash = hashlib.sha256(data).hexdigest()
                if current_hash != meta["expected_hash"]:
                    violations.append({
                        "path": path_str,
                        "filename": meta["filename"],
                        "violation": "CONTENT_TAMPERED_OR_ENCRYPTED",
                        "reason": f"Canary file contents altered or encrypted. Expected hash {meta['expected_hash'][:16]}..., found {current_hash[:16]}...",
                        "severity": "CRITICAL",
                    })
            except Exception as e:
                violations.append({
                    "path": path_str,
                    "filename": meta["filename"],
                    "violation": "READ_ERROR",
                    "reason": f"Could not read canary file (locked by encryptor?): {e}",
                    "severity": "CRITICAL",
                })

        if violations and self.on_tripwire_tripped:
            for v in violations:
                self.on_tripwire_tripped(v)

        return violations

    def reset_canaries(self):
        self.setup_canaries()
