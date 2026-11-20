import os
import time
import tempfile
import pytest
from pathlib import Path
from aegis.realtime.event_handler import RealtimeEventHandler
from aegis.engine.scanner import AntivirusScanner
from aegis.quarantine.manager import QuarantineManager
from aegis.quarantine.db import QuarantineDB
from aegis.engine.signatures import AEGIS_TEST_TOKEN

def test_realtime_event_handler_interception():
    temp_dir = tempfile.mkdtemp()
    vault_dir = Path(temp_dir) / "vault"
    db_file = Path(temp_dir) / "q.db"

    q_mgr = QuarantineManager(vault_dir=vault_dir, db=QuarantineDB(db_file))
    scanner = AntivirusScanner()

    alerts_received = []
    def on_alert(ev):
        alerts_received.append(ev)

    handler = RealtimeEventHandler(
        scanner=scanner,
        quarantine_mgr=q_mgr,
        alert_callback=on_alert,
    )
    handler.start()

    # Drop threat file
    threat_file = os.path.join(temp_dir, "incoming_dropper.bin")
    with open(threat_file, "wb") as f:
        f.write(AEGIS_TEST_TOKEN)

    try:
        # Enqueue event
        handler.enqueue_file_event(threat_file, "CREATED")

        # Allow worker thread to process event
        time.sleep(1.0)

        # File must be quarantined and alert received
        assert len(alerts_received) >= 1
        assert alerts_received[0]["event_type"] == "REALTIME_THREAT_INTERCEPTED"
        assert alerts_received[0]["threat_name"] == "AegisShield-Safe-Test-Sample"
        assert not os.path.exists(threat_file)
    finally:
        handler.stop()
        if os.path.exists(threat_file):
            os.remove(threat_file)
