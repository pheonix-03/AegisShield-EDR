import os
import tempfile
import pytest
from aegis.engine.pe_analyzer import PEAnalyzer
from aegis.engine.script_analyzer import ScriptAnalyzer

def test_entropy_calculation():
    # Low entropy repeating data
    low_data = b"AAAAAA" * 1000
    e_low = PEAnalyzer.calculate_entropy(low_data)
    assert e_low < 1.0

    # High entropy pseudorandom data
    high_data = os.urandom(10000)
    e_high = PEAnalyzer.calculate_entropy(high_data)
    assert e_high > 7.5

def test_double_extension_detection():
    # Deceptive document masking executable
    deceptive = "Quarterly_Financial_Report.pdf.exe"
    res = ScriptAnalyzer.check_double_extension(deceptive)
    assert res["detected"] is True
    assert res["score"] >= 50

    # Normal document
    normal = "Quarterly_Financial_Report.pdf"
    res_norm = ScriptAnalyzer.check_double_extension(normal)
    assert res_norm["detected"] is False

def test_script_analyzer_powershell_payload():
    with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False, mode="w") as tf:
        tf.write("powershell.exe -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=")
        tf_path = tf.name

    try:
        res = ScriptAnalyzer.analyze_script(tf_path)
        assert res["is_script"] is True
        assert res["suspicious"] is True
        assert res["score"] >= 50
    finally:
        os.remove(tf_path)
