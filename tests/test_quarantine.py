import os
import tempfile
import pytest
from pathlib import Path
from aegis.quarantine.manager import QuarantineManager
from aegis.quarantine.db import QuarantineDB
from aegis.engine.signatures import SignatureDatabase

def test_quarantine_and_restore_cycle():
    # Setup temporary vault and db
    temp_dir = tempfile.mkdtemp()
    vault_path = Path(temp_dir) / "vault"
    db_path = Path(temp_dir) / "test_q.db"

    q_db = QuarantineDB(db_path)
    q_mgr = QuarantineManager(vault_dir=vault_path, db=q_db)

    # Create dummy malware sample
    sample_content = b"MALWARE_PAYLOAD_SIMULATED_TEST_STRING_12345"
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(sample_content)
        sample_path = tf.name

    original_hash = SignatureDatabase.calculate_sha256(sample_path)

    try:
        # 1. Quarantine file
        res = q_mgr.quarantine_file(
            filepath=sample_path,
            threat_name="Test.Trojan.Simulator",
            detection_method="UNIT_TEST",
            severity="CRITICAL",
            confidence=100,
            reasons=["Unit test isolation verification"],
        )

        assert res["success"] is True
        q_id = res["quarantine_id"]

        # Original file must no longer exist at original path
        assert not os.path.exists(sample_path)

        # File in vault must be encrypted / neutralized (not equal to raw sample content)
        vault_files = list(vault_path.glob("*.aegis_quarantine"))
        assert len(vault_files) == 1
        with open(vault_files[0], "rb") as vf:
            vault_bytes = vf.read()
        assert vault_bytes != sample_content

        # 2. Restore file
        restore_res = q_mgr.restore_file(q_id, destination_path=sample_path)
        assert restore_res["success"] is True
        assert os.path.exists(sample_path)

        # Restored content must match original byte-for-byte and hash
        with open(sample_path, "rb") as rf:
            restored_bytes = rf.read()
        assert restored_bytes == sample_content
        assert SignatureDatabase.calculate_sha256(sample_path) == original_hash

    finally:
        if os.path.exists(sample_path):
            os.remove(sample_path)

def test_critical_system_file_safeguard():
    temp_dir = tempfile.mkdtemp()
    q_mgr = QuarantineManager(vault_dir=Path(temp_dir) / "vault", db=QuarantineDB(Path(temp_dir) / "q.db"))

    # Attempting to quarantine critical Windows core binary
    res = q_mgr.quarantine_file(
        filepath=r"C:\Windows\System32\ntoskrnl.exe",
        threat_name="FalsePositive.Test",
    )
    assert res["success"] is False
    assert "Cannot quarantine protected Windows system file" in res["error"]
