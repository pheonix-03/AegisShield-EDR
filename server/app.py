import os
import time
import uuid
from typing import List, Dict, Any, Optional
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Header, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from server.database import Base, engine, get_db
from server.models import EndpointAgent, SecurityIncident, AgentCommand, CentralPolicy
from server.security import CommandSecurity, MASTER_SIGNING_KEY

# Initialize database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AegisShield Central Management Platform",
    description="Centralized multi-office endpoint detection, response, and policy management server",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- PYDANTIC SCHEMAS -----------------

class AgentRegisterRequest(BaseModel):
    agent_id: str
    hostname: str
    ip_address: Optional[str] = "127.0.0.1"
    os_info: Optional[str] = "Windows 11 Pro 64-bit"
    office_location: Optional[str] = "Headquarters"
    agent_version: Optional[str] = "1.0.0"
    signature_version: Optional[str] = "2026.10.30-01"

class HeartbeatRequest(BaseModel):
    agent_id: str
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    realtime_active: bool = True
    ransomware_active: bool = True
    usb_active: bool = True
    threats_detected: int = 0
    threats_quarantined: int = 0
    signature_version: str = "2026.10.30-01"

class IncidentReportRequest(BaseModel):
    agent_id: str
    threat_name: str
    threat_type: str = "MALWARE"
    severity: str = "HIGH"
    confidence: int = 90
    filepath: Optional[str] = None
    sha256: Optional[str] = None
    detection_method: str = "SIGNATURE"
    remediation_status: str = "QUARANTINED"
    details: Optional[str] = None

class CommandResultRequest(BaseModel):
    command_id: str
    agent_id: str
    status: str  # COMPLETED, FAILED, REJECTED
    result: Dict[str, Any] = Field(default_factory=dict)

class DispatchCommandRequest(BaseModel):
    agent_id: str
    command_type: str  # QUICK_SCAN, FULL_SCAN, CUSTOM_SCAN, UPDATE_SIGNATURES, ISOLATE_HOST
    parameters: Dict[str, Any] = Field(default_factory=dict)

class PolicyUpdateRequest(BaseModel):
    policy_name: str = "Default_Production_Policy"
    realtime_protection_enabled: bool = True
    ransomware_protection_enabled: bool = True
    usb_auto_scan: bool = True
    usb_block_executables: bool = False
    web_protection_enabled: bool = True
    max_scan_file_size_mb: int = 100
    exclusions: List[str] = Field(default_factory=list)

# ----------------- AGENT API ENDPOINTS -----------------

@app.post("/api/v1/agent/register")
def register_agent(req: AgentRegisterRequest, db: Session = Depends(get_db)):
    """Registers a new or existing endpoint agent and returns enrollment credentials."""
    agent = db.query(EndpointAgent).filter(EndpointAgent.id == req.agent_id).first()
    token = CommandSecurity.generate_agent_token()

    if agent:
        agent.hostname = req.hostname
        agent.ip_address = req.ip_address
        agent.os_info = req.os_info
        agent.office_location = req.office_location
        agent.agent_version = req.agent_version
        agent.signature_version = req.signature_version
        agent.is_online = True
        agent.last_heartbeat = time.time()
        agent.auth_token = token
    else:
        agent = EndpointAgent(
            id=req.agent_id,
            hostname=req.hostname,
            ip_address=req.ip_address,
            os_info=req.os_info,
            office_location=req.office_location,
            agent_version=req.agent_version,
            signature_version=req.signature_version,
            is_online=True,
            last_heartbeat=time.time(),
            registered_at=time.time(),
            auth_token=token,
        )
        db.add(agent)

    db.commit()

    # Get active policy
    policy = db.query(CentralPolicy).first()
    policy_data = {}
    if policy:
        policy_data = {
            "realtime_protection_enabled": policy.realtime_protection_enabled,
            "ransomware_protection_enabled": policy.ransomware_protection_enabled,
            "usb_auto_scan": policy.usb_auto_scan,
            "usb_block_executables": policy.usb_block_executables,
            "web_protection_enabled": policy.web_protection_enabled,
            "max_scan_file_size_mb": policy.max_scan_file_size_mb,
            "exclusions": policy.exclusions,
        }

    return {
        "status": "ENROLLED",
        "agent_id": agent.id,
        "auth_token": token,
        "policy": policy_data,
        "heartbeat_interval_seconds": 15,
    }

@app.post("/api/v1/agent/heartbeat")
def agent_heartbeat(
    req: HeartbeatRequest,
    x_agent_id: Optional[str] = Header(None),
    x_agent_token: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Processes endpoint health telemetry and dispatches pending signed commands."""
    agent = db.query(EndpointAgent).filter(EndpointAgent.id == req.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not registered")

    agent.last_heartbeat = time.time()
    agent.is_online = True
    agent.cpu_usage = req.cpu_usage
    agent.memory_usage = req.memory_usage
    agent.realtime_active = req.realtime_active
    agent.ransomware_active = req.ransomware_active
    agent.usb_active = req.usb_active
    agent.threats_detected = req.threats_detected
    agent.threats_quarantined = req.threats_quarantined
    agent.signature_version = req.signature_version

    # Fetch pending commands
    pending_cmds = db.query(AgentCommand).filter(
        AgentCommand.agent_id == agent.id,
        AgentCommand.status == "PENDING"
    ).all()

    dispatch_list = []
    for cmd in pending_cmds:
        dispatch_list.append({
            "command_id": cmd.id,
            "command_type": cmd.command_type,
            "parameters": cmd.parameters or {},
            "signature": cmd.signature,
        })
        cmd.status = "DISPATCHED"

    db.commit()

    return {
        "status": "HEARTBEAT_ACK",
        "server_time": time.time(),
        "commands": dispatch_list,
    }

@app.post("/api/v1/agent/incidents")
def report_incident(req: IncidentReportRequest, db: Session = Depends(get_db)):
    """Receives and stores threat alerts, canary tripwire trips, and quarantine actions."""
    agent = db.query(EndpointAgent).filter(EndpointAgent.id == req.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not registered")

    inc = SecurityIncident(
        agent_id=req.agent_id,
        timestamp=time.time(),
        threat_name=req.threat_name,
        threat_type=req.threat_type,
        severity=req.severity,
        confidence=req.confidence,
        filepath=req.filepath,
        sha256=req.sha256,
        detection_method=req.detection_method,
        remediation_status=req.remediation_status,
        details=req.details,
    )
    db.add(inc)
    agent.threats_detected += 1
    if req.remediation_status == "QUARANTINED":
        agent.threats_quarantined += 1

    db.commit()
    return {"status": "RECORDED", "incident_id": inc.id}

@app.post("/api/v1/agent/command_result")
def submit_command_result(req: CommandResultRequest, db: Session = Depends(get_db)):
    """Updates status and output of an executed administrative command."""
    cmd = db.query(AgentCommand).filter(AgentCommand.id == req.command_id).first()
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found")

    cmd.status = req.status
    cmd.executed_at = time.time()
    cmd.result = req.result
    db.commit()

    return {"status": "RESULT_SAVED"}

# ----------------- ADMINISTRATOR & DASHBOARD API -----------------

@app.get("/api/v1/admin/stats")
def get_fleet_stats(db: Session = Depends(get_db)):
    """Provides high-level dashboard metrics for the entire managed endpoint fleet."""
    now = time.time()
    agents = db.query(EndpointAgent).all()

    # Consider agent offline if heartbeat older than 45 seconds
    total = len(agents)
    online = 0
    attention = 0
    offices = {}

    for a in agents:
        is_active = (now - a.last_heartbeat) <= 45.0
        if is_active:
            online += 1
        else:
            a.is_online = False

        if a.threats_detected > a.threats_quarantined or not a.realtime_active:
            attention += 1

        loc = a.office_location or "Unknown"
        offices[loc] = offices.get(loc, 0) + 1

    db.commit()

    total_incidents = db.query(SecurityIncident).count()
    critical_incidents = db.query(SecurityIncident).filter(SecurityIncident.severity == "CRITICAL").count()

    return {
        "total_endpoints": total,
        "online_endpoints": online,
        "offline_endpoints": total - online,
        "attention_required": attention,
        "total_threats_logged": total_incidents,
        "critical_threats": critical_incidents,
        "office_distribution": offices,
    }

@app.get("/api/v1/admin/agents")
def list_agents(office: Optional[str] = None, db: Session = Depends(get_db)):
    """Lists registered endpoint computers with status and telemetry."""
    query = db.query(EndpointAgent)
    if office:
        query = query.filter(EndpointAgent.office_location == office)
    agents = query.all()

    now = time.time()
    res = []
    for a in agents:
        is_active = (now - a.last_heartbeat) <= 45.0
        res.append({
            "id": a.id,
            "hostname": a.hostname,
            "ip_address": a.ip_address,
            "os_info": a.os_info,
            "office_location": a.office_location,
            "agent_version": a.agent_version,
            "signature_version": a.signature_version,
            "is_online": is_active,
            "last_heartbeat": a.last_heartbeat,
            "cpu_usage": a.cpu_usage,
            "memory_usage": a.memory_usage,
            "realtime_active": a.realtime_active,
            "ransomware_active": a.ransomware_active,
            "threats_detected": a.threats_detected,
            "threats_quarantined": a.threats_quarantined,
        })
    return res

@app.post("/api/v1/admin/dispatch_command")
def dispatch_signed_command(req: DispatchCommandRequest, db: Session = Depends(get_db)):
    """Dispatches a cryptographically signed administrative command to an endpoint agent."""
    agent = db.query(EndpointAgent).filter(EndpointAgent.id == req.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent ID not found")

    cmd_id = str(uuid.uuid4())

    # Cryptographically sign the command payload
    signature = CommandSecurity.generate_command_signature(
        command_id=cmd_id,
        command_type=req.command_type,
        agent_id=req.agent_id,
        parameters=req.parameters,
        secret_key=MASTER_SIGNING_KEY,
    )

    cmd = AgentCommand(
        id=cmd_id,
        agent_id=req.agent_id,
        command_type=req.command_type,
        parameters=req.parameters,
        status="PENDING",
        signature=signature,
        created_at=time.time(),
    )
    db.add(cmd)
    db.commit()

    return {
        "status": "COMMAND_QUEUED",
        "command_id": cmd_id,
        "signature": signature,
    }

@app.get("/api/v1/admin/incidents")
def list_incidents(limit: int = 100, db: Session = Depends(get_db)):
    """Retrieves security incidents and threat detections across all managed endpoints."""
    incidents = db.query(SecurityIncident).order_by(SecurityIncident.timestamp.desc()).limit(limit).all()
    res = []
    for i in incidents:
        res.append({
            "id": i.id,
            "agent_id": i.agent_id,
            "hostname": i.agent.hostname if i.agent else "Unknown",
            "office_location": i.agent.office_location if i.agent else "Unknown",
            "timestamp": i.timestamp,
            "threat_name": i.threat_name,
            "threat_type": i.threat_type,
            "severity": i.severity,
            "confidence": i.confidence,
            "filepath": i.filepath,
            "sha256": i.sha256,
            "detection_method": i.detection_method,
            "remediation_status": i.remediation_status,
            "details": i.details,
        })
    return res

@app.get("/api/v1/admin/policy")
def get_policy(db: Session = Depends(get_db)):
    """Gets the active central endpoint policy."""
    policy = db.query(CentralPolicy).first()
    if not policy:
        policy = CentralPolicy(policy_name="Default_Production_Policy")
        db.add(policy)
        db.commit()

    return {
        "policy_name": policy.policy_name,
        "realtime_protection_enabled": policy.realtime_protection_enabled,
        "ransomware_protection_enabled": policy.ransomware_protection_enabled,
        "usb_auto_scan": policy.usb_auto_scan,
        "usb_block_executables": policy.usb_block_executables,
        "web_protection_enabled": policy.web_protection_enabled,
        "max_scan_file_size_mb": policy.max_scan_file_size_mb,
        "exclusions": policy.exclusions or [],
    }

@app.post("/api/v1/admin/policy")
def update_policy(req: PolicyUpdateRequest, db: Session = Depends(get_db)):
    """Updates central policy to propagate to all connected office PCs."""
    policy = db.query(CentralPolicy).first()
    if not policy:
        policy = CentralPolicy(policy_name=req.policy_name)
        db.add(policy)

    policy.realtime_protection_enabled = req.realtime_protection_enabled
    policy.ransomware_protection_enabled = req.ransomware_protection_enabled
    policy.usb_auto_scan = req.usb_auto_scan
    policy.usb_block_executables = req.usb_block_executables
    policy.web_protection_enabled = req.web_protection_enabled
    policy.max_scan_file_size_mb = req.max_scan_file_size_mb
    policy.exclusions = req.exclusions
    policy.updated_at = time.time()

    db.commit()
    return {"status": "POLICY_UPDATED", "policy_name": policy.policy_name}

# Serve static dashboard UI
STATIC_DIR = Path(__file__).resolve().parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", response_class=HTMLResponse)
def index_page():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>AegisShield Central Management Server Running</h1>")
