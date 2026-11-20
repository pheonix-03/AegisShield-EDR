import os
import tempfile
import pytest
from pathlib import Path
from aegis.ransomware.tripwire import CanaryTripwire
from aegis.ransomware.process_watcher import RansomwareBehaviorWatcher

def test_canary_tripwire_alarm_on_tamper():
    temp_dir = tempfile.mkdtemp()
    canary_dir = Path(temp_dir) / "canary"

    tripped_alerts = []
    def on_tripped(alert):
        tripped_alerts.append(alert)

    tw = CanaryTripwire(canary_dir=canary_dir, on_tripwire_tripped=on_tripped)

    # Initial state: clean
    violations = tw.verify_canaries()
    assert len(violations) == 0

    # Simulate ransomware altering/encrypting one canary
    target_canary = list(tw.deployed_canaries.keys())[0]
    with open(target_canary, "wb") as f:
        f.write(b"ENCRYPTED_BY_RANSOMWARE_PAYLOAD_LOCKED_FILES")

    # Audit again -> must trigger violation
    violations = tw.verify_canaries()
    assert len(violations) >= 1
    assert violations[0]["violation"] == "CONTENT_TAMPERED_OR_ENCRYPTED"
    assert len(tripped_alerts) >= 1

def test_ransomware_behavior_spike_detection():
    detected_alerts = []
    def on_detect(alert):
        detected_alerts.append(alert)

    watcher = RansomwareBehaviorWatcher(on_ransomware_detected=on_detect)
    watcher.max_writes_per_minute = 10
    watcher.auto_kill = False

    # Simulate rapid write burst of 15 files
    for i in range(15):
        watcher.record_activity(f"C:\\Users\\User\\Documents\\file_{i}.docx", "WRITE")

    # Verification of spike handling
    assert len(detected_alerts) >= 1
    assert detected_alerts[0]["threat_type"] == "BEHAVIORAL_RANSOMWARE_OUTBREAK"
