import os
import tempfile
import pytest
from aegis.usb.detector import USBSecurityManager

def test_usb_autorun_inspection():
    temp_usb_dir = tempfile.mkdtemp()
    autorun_file = os.path.join(temp_usb_dir, "autorun.inf")
    with open(autorun_file, "w") as f:
        f.write("[autorun]\nopen=malware.exe\naction=Run payload\n")

    try:
        usb_mgr = USBSecurityManager()
        res = usb_mgr.inspect_drive_threats(temp_usb_dir)
        assert res["threat_count"] >= 1
        assert res["root_threats"][0]["type"] == "AUTORUN_INF_PRESENT"
    finally:
        if os.path.exists(autorun_file):
            os.remove(autorun_file)
        os.rmdir(temp_usb_dir)
