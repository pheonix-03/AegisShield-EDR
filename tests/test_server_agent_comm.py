import pytest
from fastapi.testclient import TestClient
from server.app import app
from server.security import CommandSecurity, MASTER_SIGNING_KEY

client = TestClient(app)

def test_agent_registration_and_heartbeat():
    agent_id = "test-agent-pytest-001"
    reg_payload = {
        "agent_id": agent_id,
        "hostname": "TEST-HOST-01",
        "ip_address": "192.168.1.50",
        "os_info": "Windows 11 Pro 64-bit",
        "office_location": "Headquarters",
        "agent_version": "1.0.0",
        "signature_version": "2026.10.30-01",
    }

    # 1. Register agent
    resp = client.post("/api/v1/agent/register", json=reg_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ENROLLED"
    assert data["agent_id"] == agent_id
    assert "auth_token" in data
    token = data["auth_token"]

    # 2. Send Heartbeat
    hb_payload = {
        "agent_id": agent_id,
        "cpu_usage": 12.5,
        "memory_usage": 45.0,
        "realtime_active": True,
        "ransomware_active": True,
        "usb_active": True,
        "threats_detected": 0,
        "threats_quarantined": 0,
        "signature_version": "2026.10.30-01",
    }
    headers = {"X-Agent-ID": agent_id, "X-Agent-Token": token}
    hb_resp = client.post("/api/v1/agent/heartbeat", json=hb_payload, headers=headers)
    assert hb_resp.status_code == 200
    assert hb_resp.json()["status"] == "HEARTBEAT_ACK"

def test_cryptographic_command_signing_and_tamper_rejection():
    agent_id = "test-agent-pytest-002"
    cmd_id = "cmd-12345"
    cmd_type = "QUICK_SCAN"
    params = {"target": "C:\\Temp"}

    # Authorize valid signature
    valid_sig = CommandSecurity.generate_command_signature(cmd_id, cmd_type, agent_id, params, MASTER_SIGNING_KEY)
    assert CommandSecurity.verify_command_signature(cmd_id, cmd_type, agent_id, params, valid_sig, MASTER_SIGNING_KEY) is True

    # Tampered signature -> must be rejected!
    tampered_sig = valid_sig[:-4] + "dead"
    assert CommandSecurity.verify_command_signature(cmd_id, cmd_type, agent_id, params, tampered_sig, MASTER_SIGNING_KEY) is False

    # Tampered parameter -> must be rejected!
    altered_params = {"target": "C:\\Windows"}
    assert CommandSecurity.verify_command_signature(cmd_id, cmd_type, agent_id, altered_params, valid_sig, MASTER_SIGNING_KEY) is False

def test_incident_reporting():
    agent_id = "test-agent-pytest-001"
    inc_payload = {
        "agent_id": agent_id,
        "threat_name": "Ransom.WannaCry.Dropper",
        "threat_type": "RANSOMWARE",
        "severity": "CRITICAL",
        "confidence": 100,
        "filepath": "C:\\Users\\User\\Downloads\\invoice.exe",
        "sha256": "ed01ef444deabb2959e2d52579b441398867566236b28b248a8813589b93e433",
        "detection_method": "SIGNATURE_HASH",
        "remediation_status": "QUARANTINED",
    }
    resp = client.post("/api/v1/agent/incidents", json=inc_payload)
    assert resp.status_code == 200
    assert resp.json()["status"] == "RECORDED"
