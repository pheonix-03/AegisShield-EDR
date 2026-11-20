import time
from sqlalchemy import Column, Integer, String, Boolean, Float, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from server.database import Base

class EndpointAgent(Base):
    __tablename__ = "agents"

    id = Column(String(64), primary_key=True, index=True)  # Agent UUID
    hostname = Column(String(128), nullable=False)
    ip_address = Column(String(64), nullable=True)
    os_info = Column(String(128), default="Windows 11 Pro 64-bit")
    office_location = Column(String(128), default="Headquarters")
    agent_version = Column(String(32), default="1.0.0")
    signature_version = Column(String(32), default="2026.10.30-01")

    # Status
    is_online = Column(Boolean, default=True)
    last_heartbeat = Column(Float, default=time.time)
    registered_at = Column(Float, default=time.time)
    auth_token = Column(String(128), nullable=False)

    # Telemetry
    cpu_usage = Column(Float, default=0.0)
    memory_usage = Column(Float, default=0.0)
    realtime_active = Column(Boolean, default=True)
    ransomware_active = Column(Boolean, default=True)
    usb_active = Column(Boolean, default=True)
    threats_detected = Column(Integer, default=0)
    threats_quarantined = Column(Integer, default=0)

    # Relationships
    incidents = relationship("SecurityIncident", back_populates="agent", cascade="all, delete-orphan")
    commands = relationship("AgentCommand", back_populates="agent", cascade="all, delete-orphan")


class SecurityIncident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(64), ForeignKey("agents.id"), nullable=False)
    timestamp = Column(Float, default=time.time)
    threat_name = Column(String(256), nullable=False)
    threat_type = Column(String(64), default="MALWARE")  # MALWARE, RANSOMWARE, SUSPICIOUS_SCRIPT, C2_CONN
    severity = Column(String(32), default="HIGH")  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Integer, default=90)
    filepath = Column(String(512), nullable=True)
    sha256 = Column(String(64), nullable=True)
    detection_method = Column(String(64), default="SIGNATURE")
    remediation_status = Column(String(64), default="QUARANTINED")  # QUARANTINED, BLOCKED, PENDING, RESOLVED
    details = Column(Text, nullable=True)

    agent = relationship("EndpointAgent", back_populates="incidents")


class AgentCommand(Base):
    __tablename__ = "commands"

    id = Column(String(64), primary_key=True)
    agent_id = Column(String(64), ForeignKey("agents.id"), nullable=False)
    command_type = Column(String(64), nullable=False)  # QUICK_SCAN, FULL_SCAN, CUSTOM_SCAN, UPDATE_SIGNATURES, ISOLATE_HOST
    parameters = Column(JSON, default=dict)
    status = Column(String(32), default="PENDING")  # PENDING, DISPATCHED, EXECUTING, COMPLETED, FAILED, REJECTED
    signature = Column(String(256), nullable=False)  # Cryptographic HMAC/RSA signature for command verification
    created_at = Column(Float, default=time.time)
    executed_at = Column(Float, nullable=True)
    result = Column(JSON, nullable=True)

    agent = relationship("EndpointAgent", back_populates="commands")


class CentralPolicy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    policy_name = Column(String(128), unique=True, nullable=False)
    realtime_protection_enabled = Column(Boolean, default=True)
    ransomware_protection_enabled = Column(Boolean, default=True)
    usb_auto_scan = Column(Boolean, default=True)
    usb_block_executables = Column(Boolean, default=False)
    web_protection_enabled = Column(Boolean, default=True)
    max_scan_file_size_mb = Column(Integer, default=100)
    exclusions = Column(JSON, default=list)
    updated_at = Column(Float, default=time.time)
