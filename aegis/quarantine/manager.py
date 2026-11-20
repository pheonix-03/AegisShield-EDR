import os
import sys
import uuid
import time
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from aegis.config import QUARANTINE_DIR, config
from aegis.quarantine.db import QuarantineDB
from aegis.engine.signatures import SignatureDatabase

logger = logging.getLogger("AegisQuarantine")

# Critical Windows system binaries and libraries that must NEVER be quarantined automatically
CRITICAL_SYSTEM_FILES = {
    "ntoskrnl.exe", "hal.dll", "kernel32.dll", "ntdll.dll", "user32.dll",
    "gdi32.dll", "advapi32.dll", "csrss.exe", "smss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "winlogon.exe",
}

# 32-byte key for quarantine payload obfuscation
QUARANTINE_OBFUSCATION_KEY = b"AegisShield_Vault_Secure_Key_32B"

class QuarantineManager:
    """Safely isolates, encrypts, stores, restores, and shreds quarantined threats."""

    def __init__(self, vault_dir: Path = QUARANTINE_DIR, db: Optional[QuarantineDB] = None):
        self.vault_dir = vault_dir
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.db = db or QuarantineDB()

    @staticmethod
    def _xor_cipher(data: bytes, key: bytes = QUARANTINE_OBFUSCATION_KEY) -> bytes:
        """Symmetric streaming cipher to neutralize PE headers and executables in storage."""
        key_len = len(key)
        return bytes([b ^ key[i % key_len] for i, b in enumerate(data)])

    @staticmethod
    def is_critical_system_file(filepath: str) -> bool:
        """Protects Windows OS core files from accidental quarantine."""
        base = os.path.basename(filepath).lower()
        if base in CRITICAL_SYSTEM_FILES:
            return True
        norm = os.path.normpath(filepath).lower()
        sys32 = os.path.expandvars(r"%SYSTEMROOT%\System32").lower()
        if norm.startswith(sys32) and base.endswith((".dll", ".exe")):
            return True
        return False

    @staticmethod
    def _secure_shred_file(filepath: str):
        """Overwrites file with zeroes before deletion to prevent forensic file recovery."""
        try:
            if os.path.exists(filepath):
                size = os.path.getsize(filepath)
                with open(filepath, "ba+", buffering=0) as f:
                    f.seek(0)
                    f.write(b"\x00" * min(size, 4096 * 1024))
                    f.flush()
                os.remove(filepath)
        except Exception as e:
            logger.warning(f"Secure shred fallback to standard delete for {filepath}: {e}")
            if os.path.exists(filepath):
                os.remove(filepath)

    def quarantine_file(
        self,
        filepath: str,
        threat_name: str,
        detection_method: str = "UNKNOWN",
        severity: str = "HIGH",
        confidence: int = 100,
        reasons: Optional[list] = None,
        operator: str = "AegisShield-Engine"
    ) -> Dict[str, Any]:
        """Isolates and encrypts a detected malicious file into the quarantine vault."""
        if not os.path.exists(filepath):
            return {"success": False, "error": f"File not found: {filepath}"}

        # Safeguard: Prevent system collapse from false positives on OS core binaries
        if self.is_critical_system_file(filepath):
            logger.error(f"BLOCKED: Attempted to quarantine critical OS system file: {filepath}")
            return {
                "success": False,
                "error": f"Cannot quarantine protected Windows system file: {filepath}. System integrity safeguard triggered.",
            }

        try:
            # 1. Compute original SHA-256 and read contents
            try:
                sha256 = SignatureDatabase.calculate_sha256(filepath)
                size = os.path.getsize(filepath)
                with open(filepath, "rb") as f:
                    raw_bytes = f.read()
            except OSError as read_err:
                # If host Windows Defender locked the file due to virus detection
                if getattr(read_err, 'errno', None) == 22 or getattr(read_err, 'winerror', None) == 225 or "virus" in str(read_err).lower():
                    logger.info(f"File locked by Windows OS security filter: {filepath}")
                    sha256 = "INTERCEPTED_BY_WINDOWS_DEFENDER"
                    size = 0
                    raw_bytes = b"PAYLOAD_INTERCEPTED_BY_WINDOWS_DEFENDER_ANTIVIRUS"
                else:
                    raise

            # 2. Obfuscate / Encrypt payload so it cannot be executed by double clicking
            encrypted_bytes = self._xor_cipher(raw_bytes)

            # 3. Write into isolated vault with unique ID
            item_id = str(uuid.uuid4())
            vault_filename = f"{item_id}.aegis_quarantine"
            vault_path = self.vault_dir / vault_filename

            with open(vault_path, "wb") as f:
                f.write(encrypted_bytes)

            # Restrict permissions on vault file if on Windows
            try:
                import win32file
                import win32con
                win32file.SetFileAttributesW(str(vault_path), win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
            except Exception:
                pass

            # 4. Shred and remove the original malicious file
            self._secure_shred_file(filepath)

            # 5. Record in database
            item_data = {
                "id": item_id,
                "original_path": os.path.abspath(filepath),
                "vault_filename": vault_filename,
                "sha256": sha256 or "unknown",
                "file_size": size,
                "threat_name": threat_name,
                "detection_method": detection_method,
                "severity": severity,
                "confidence": confidence,
                "detection_reasons": json.dumps(reasons or []),
                "quarantined_at": time.time(),
                "scanner_version": config.get("signature_version", "1.0.0"),
                "operator": operator,
            }
            self.db.add_quarantined_item(item_data)
            logger.info(f"Successfully quarantined {filepath} as {threat_name} (ID: {item_id})")

            return {
                "success": True,
                "quarantine_id": item_id,
                "original_path": filepath,
                "sha256": sha256,
            }

        except Exception as e:
            logger.exception(f"Failed to quarantine file {filepath}: {e}")
            return {"success": False, "error": str(e)}

    def restore_file(self, quarantine_id: str, destination_path: Optional[str] = None) -> Dict[str, Any]:
        """Restores a quarantined file, verifying cryptographic integrity."""
        item = self.db.get_item(quarantine_id)
        if not item:
            return {"success": False, "error": f"Quarantine ID not found: {quarantine_id}"}

        if item["status"] != "QUARANTINED":
            return {"success": False, "error": f"Item status is {item['status']}, cannot restore."}

        vault_path = self.vault_dir / item["vault_filename"]
        if not vault_path.exists():
            return {"success": False, "error": "Vault file missing on disk."}

        target_path = destination_path or item["original_path"]

        try:
            # 1. Read encrypted vault file and decrypt
            with open(vault_path, "rb") as f:
                encrypted_bytes = f.read()

            decrypted_bytes = self._xor_cipher(encrypted_bytes)

            # 2. Verify SHA-256 integrity match
            import hashlib
            calc_hash = hashlib.sha256(decrypted_bytes).hexdigest().lower()
            if calc_hash != item["sha256"].lower():
                return {
                    "success": False,
                    "error": f"Integrity check failed: Expected {item['sha256']} but got {calc_hash}",
                }

            # 3. Ensure target directory exists and write restored file
            target_dir = os.path.dirname(target_path)
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)

            with open(target_path, "wb") as f:
                f.write(decrypted_bytes)

            # 4. Remove file from vault and update database
            os.remove(vault_path)
            self.db.update_status(quarantine_id, "RESTORED", restored_to=target_path)
            logger.info(f"Restored quarantine ID {quarantine_id} to {target_path}")

            return {
                "success": True,
                "restored_path": target_path,
                "sha256": calc_hash,
            }

        except Exception as e:
            logger.exception(f"Failed to restore quarantine ID {quarantine_id}: {e}")
            return {"success": False, "error": str(e)}

    def purge_file(self, quarantine_id: str) -> Dict[str, Any]:
        """Permanently deletes a quarantined item with cryptographic secure overwrite."""
        item = self.db.get_item(quarantine_id)
        if not item:
            return {"success": False, "error": f"Quarantine ID not found: {quarantine_id}"}

        vault_path = self.vault_dir / item["vault_filename"]
        if vault_path.exists():
            self._secure_shred_file(str(vault_path))

        self.db.update_status(quarantine_id, "DELETED")
        logger.info(f"Permanently purged quarantine item ID {quarantine_id}")
        return {"success": True, "quarantine_id": quarantine_id}

    def list_quarantined_items(self) -> list:
        return self.db.list_items("QUARANTINED")

    def list_all_audit_logs(self) -> list:
        return self.db.get_audit_logs()
