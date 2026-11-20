import sqlite3
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from aegis.config import LOCAL_DB_PATH

class QuarantineDB:
    """Manages the persistent catalog of quarantined items and audit records."""

    def __init__(self, db_path: Path = LOCAL_DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_vault (
                    id TEXT PRIMARY KEY,
                    original_path TEXT NOT NULL,
                    vault_filename TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    threat_name TEXT NOT NULL,
                    detection_method TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    detection_reasons TEXT NOT NULL,
                    quarantined_at REAL NOT NULL,
                    scanner_version TEXT NOT NULL,
                    status TEXT NOT NULL,  -- QUARANTINED, RESTORED, DELETED
                    restored_at REAL,
                    restored_to TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quarantine_id TEXT NOT NULL,
                    action TEXT NOT NULL,  -- ISOLATE, RESTORE, PURGE
                    performed_by TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    details TEXT
                )
            """)
            conn.commit()

    def add_quarantined_item(self, item: Dict[str, Any]):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO quarantine_vault (
                    id, original_path, vault_filename, sha256, file_size,
                    threat_name, detection_method, severity, confidence,
                    detection_reasons, quarantined_at, scanner_version, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                item["id"],
                item["original_path"],
                item["vault_filename"],
                item["sha256"],
                item["file_size"],
                item["threat_name"],
                item["detection_method"],
                item["severity"],
                item["confidence"],
                item["detection_reasons"],
                item["quarantined_at"],
                item["scanner_version"],
                "QUARANTINED"
            ))
            conn.execute("""
                INSERT INTO quarantine_audit_log (quarantine_id, action, performed_by, timestamp, details)
                VALUES (?, ?, ?, ?, ?)
            """, (
                item["id"],
                "ISOLATE",
                item.get("operator", "AegisShield-AutoEngine"),
                time.time(),
                f"Quarantined threat: {item['threat_name']}"
            ))
            conn.commit()

    def get_item(self, q_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM quarantine_vault WHERE id = ?", (q_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_items(self, status: Optional[str] = "QUARANTINED") -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            if status:
                cursor = conn.execute("SELECT * FROM quarantine_vault WHERE status = ? ORDER BY quarantined_at DESC", (status,))
            else:
                cursor = conn.execute("SELECT * FROM quarantine_vault ORDER BY quarantined_at DESC")
            return [dict(row) for row in cursor.fetchall()]

    def update_status(self, q_id: str, new_status: str, restored_to: Optional[str] = None):
        with self._get_connection() as conn:
            now = time.time()
            conn.execute("""
                UPDATE quarantine_vault
                SET status = ?, restored_at = ?, restored_to = ?
                WHERE id = ?
            """, (new_status, now if new_status == "RESTORED" else None, restored_to, q_id))
            conn.execute("""
                INSERT INTO quarantine_audit_log (quarantine_id, action, performed_by, timestamp, details)
                VALUES (?, ?, ?, ?, ?)
            """, (
                q_id,
                new_status,
                "Administrator",
                now,
                f"Status updated to {new_status}" + (f" (Restored to: {restored_to})" if restored_to else "")
            ))
            conn.commit()

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM quarantine_audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
