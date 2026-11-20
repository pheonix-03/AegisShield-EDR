import os
import tempfile
import pytest
from aegis.engine.scanner import AntivirusScanner
from aegis.engine.signatures import AEGIS_TEST_TOKEN, EICAR_BYTE_STRING

def test_scanner_clean_file():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
        tf.write(b"This is a legitimate harmless plain text document.")
        fpath = tf.name

    try:
        scanner = AntivirusScanner()
        res = scanner.scan_file(fpath)
        assert res.is_infected is False
        assert res.severity == "CLEAN"
        assert res.file_size > 0
    finally:
        os.remove(fpath)

def test_scanner_signature_token_detection():
    # Uses synthetic safe token to test detection pipeline without tripping host OS Defender lock
    with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as tf:
        tf.write(AEGIS_TEST_TOKEN)
        fpath = tf.name

    try:
        scanner = AntivirusScanner()
        res = scanner.scan_file(fpath)
        assert res.is_infected is True
        assert res.threat_name == "AegisShield-Safe-Test-Sample"
        assert res.severity == "HIGH"
        assert res.confidence == 100
    finally:
        os.remove(fpath)

def test_scanner_directory_walk():
    temp_dir = tempfile.mkdtemp()
    clean1 = os.path.join(temp_dir, "clean1.txt")
    clean2 = os.path.join(temp_dir, "clean2.txt")
    threat = os.path.join(temp_dir, "test_threat.dat")

    with open(clean1, "wb") as f: f.write(b"Clean content 1")
    with open(clean2, "wb") as f: f.write(b"Clean content 2")
    with open(threat, "wb") as f: f.write(AEGIS_TEST_TOKEN)

    try:
        scanner = AntivirusScanner()
        summary = scanner.scan_path(temp_dir)
        assert summary["status"] == "COMPLETED"
        assert summary["files_scanned"] == 3
        assert summary["threats_detected"] == 1
        assert len(summary["infected_files"]) == 1
        assert summary["infected_files"][0]["threat_name"] == "AegisShield-Safe-Test-Sample"
    finally:
        for p in (clean1, clean2, threat):
            if os.path.exists(p): os.remove(p)
        os.rmdir(temp_dir)
