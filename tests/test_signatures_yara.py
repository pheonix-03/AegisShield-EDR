import os
import tempfile
import pytest
from aegis.engine.signatures import SignatureDatabase, EICAR_BYTE_STRING
from aegis.engine.yara_engine import YaraEngine

def test_signature_hashing():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"Hello AegisShield Antivirus Test")
        tf_path = tf.name

    try:
        h1 = SignatureDatabase.calculate_sha256(tf_path)
        assert h1 is not None
        assert len(h1) == 64

        sig_db = SignatureDatabase()
        h2 = sig_db.get_cached_or_calculate_hash(tf_path)
        assert h1 == h2
    finally:
        os.remove(tf_path)

def test_eicar_signature_detection():
    sig_db = SignatureDatabase()
    match = sig_db.match_content_quick(EICAR_BYTE_STRING)
    assert match is not None
    assert match["name"] == "EICAR-Standard-Antivirus-Test-File"
    assert match["severity"] == "CRITICAL"
    assert match["confidence"] == 100

def test_known_malware_hash_lookup():
    sig_db = SignatureDatabase()
    # WannaCry known hash
    wc_hash = "ed01ef444deabb2959e2d52579b441398867566236b28b248a8813589b93e433"
    match = sig_db.match_hash(wc_hash)
    assert match is not None
    assert "WannaCry" in match["name"]

def test_yara_rule_matching():
    yara_eng = YaraEngine()
    test_data = b"Some harmless preamble and then vssadmin delete shadows /all /quiet and tor browser"
    matches = yara_eng.scan_data(test_data)
    assert len(matches) > 0
    rule_names = [m["rule"] for m in matches]
    assert "Suspicious_Ransomware_ShadowCopy_Deletion" in rule_names
