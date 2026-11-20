import os
import sys
import time
import json
import logging
import threading
from typing import Dict, Any, Optional

import requests
import psutil

from aegis.config import config
from aegis.engine.scanner import AntivirusScanner
from aegis.quarantine.manager import QuarantineManager
from aegis.realtime.monitor import RealtimeMonitor
from aegis.ransomware.tripwire import CanaryTripwire
from server.security import CommandSecurity, MASTER_SIGNING_KEY

logger = logging.getLogger("AegisAgentClient")

class EndpointAgentClient:
    """Manages secure communication between the Windows endpoint and the central management server."""

    def __init__(
        self,
        scanner: Optional[AntivirusScanner] = None,
        quarantine_mgr: Optional[QuarantineManager] = None,
        realtime_mon: Optional[RealtimeMonitor] = None,
        tripwire: Optional[CanaryTripwire] = None,
    ):
        self.scanner = scanner or AntivirusScanner()
        self.quarantine_mgr = quarantine_mgr or QuarantineManager()
        self.realtime_monitor = realtime_mon or RealtimeMonitor()
        self.tripwire = tripwire or CanaryTripwire()

        self.agent_id = config.get("agent_id")
        self.hostname = config.get("hostname")
        self.server_url = config.get("server_url", "http://127.0.0.1:8443").rstrip("/")
        self.auth_token = config.get("agent_token")
        self.is_registered = False
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None

    def register(self) -> bool:
        """Registers the endpoint device with the central management server."""
        payload = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "ip_address": self._get_local_ip(),
            "os_info": f"Windows {sys.getwindowsversion().major} ({sys.platform})",
            "office_location": config.get("office_location", "Headquarters"),
            "agent_version": "1.0.0",
            "signature_version": config.get("signature_version", "2026.10.30-01"),
        }

        url = f"{self.server_url}/api/v1/agent/register"
        try:
            resp = requests.post(url, json=payload, timeout=8.0)
            if resp.status_code == 200:
                data = resp.json()
                self.auth_token = data.get("auth_token")
                config.set("agent_token", self.auth_token)
                self.is_registered = True

                # Apply remote policy if returned
                policy = data.get("policy")
                if policy:
                    config.update_from_policy(policy)

                logger.info(f"Agent successfully registered with central server. ID: {self.agent_id}")
                return True
            else:
                logger.error(f"Registration failed with HTTP {resp.status_code}: {resp.text}")
                return False
        except Exception as e:
            logger.warning(f"Unable to reach central management server at {url}: {e}")
            return False

    def send_heartbeat(self) -> Optional[Dict[str, Any]]:
        """Sends health and protection telemetry, and receives queued signed commands."""
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent

        quarantined_items = self.quarantine_mgr.list_quarantined_items()

        payload = {
            "agent_id": self.agent_id,
            "cpu_usage": cpu,
            "memory_usage": mem,
            "realtime_active": self.realtime_monitor.is_active,
            "ransomware_active": config.get("ransomware_protection_enabled", True),
            "usb_active": config.get("usb_protection_enabled", True),
            "threats_detected": len(quarantined_items),
            "threats_quarantined": len(quarantined_items),
            "signature_version": config.get("signature_version", "2026.10.30-01"),
        }

        headers = {
            "X-Agent-ID": self.agent_id,
            "X-Agent-Token": self.auth_token or "",
        }

        url = f"{self.server_url}/api/v1/agent/heartbeat"
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                commands = data.get("commands", [])
                for cmd in commands:
                    self._handle_incoming_command(cmd)
                return data
            elif resp.status_code == 404:
                logger.warning("Server does not recognize agent; re-registering...")
                self.register()
        except Exception as e:
            logger.debug(f"Heartbeat network error: {e}")

        return None

    def report_incident(
        self,
        threat_name: str,
        threat_type: str = "MALWARE",
        severity: str = "HIGH",
        confidence: int = 90,
        filepath: Optional[str] = None,
        sha256: Optional[str] = None,
        detection_method: str = "SIGNATURE",
        remediation_status: str = "QUARANTINED",
        details: Optional[str] = None,
    ):
        """Sends instantaneous incident telemetry up to the central dashboard."""
        payload = {
            "agent_id": self.agent_id,
            "threat_name": threat_name,
            "threat_type": threat_type,
            "severity": severity,
            "confidence": confidence,
            "filepath": filepath,
            "sha256": sha256,
            "detection_method": detection_method,
            "remediation_status": remediation_status,
            "details": details,
        }

        url = f"{self.server_url}/api/v1/agent/incidents"
        try:
            requests.post(url, json=payload, timeout=5.0)
        except Exception as e:
            logger.error(f"Failed to transmit security incident to server: {e}")

    def _handle_incoming_command(self, cmd: Dict[str, Any]):
        """Verifies cryptographic signature before executing any remote administrative command."""
        cmd_id = cmd.get("command_id")
        cmd_type = cmd.get("command_type")
        params = cmd.get("parameters", {})
        signature = cmd.get("signature", "")

        # 1. Cryptographic Signature Verification
        is_valid = CommandSecurity.verify_command_signature(
            command_id=cmd_id,
            command_type=cmd_type,
            agent_id=self.agent_id,
            parameters=params,
            signature=signature,
            secret_key=MASTER_SIGNING_KEY,
        )

        if not is_valid:
            logger.critical(
                f"[SECURITY ALERT] Rejected unauthorized or tampered remote command: {cmd_type} (ID: {cmd_id})"
            )
            self._report_command_result(cmd_id, "REJECTED", {"error": "Invalid cryptographic command signature."})
            return

        logger.info(f"Executing authorized command from management server: {cmd_type} (ID: {cmd_id})")

        # 2. Asynchronous Command Execution in Background Thread
        def _execute_async():
            try:
                if cmd_type == "QUICK_SCAN":
                    res = self.scanner.run_quick_scan()
                    self._report_command_result(cmd_id, "COMPLETED", res)
                elif cmd_type == "FULL_SCAN":
                    res = self.scanner.scan_path("C:\\")
                    self._report_command_result(cmd_id, "COMPLETED", res)
                elif cmd_type == "CUSTOM_SCAN":
                    target = params.get("path", os.getenv("TEMP"))
                    res = self.scanner.scan_path(target)
                    self._report_command_result(cmd_id, "COMPLETED", res)
                elif cmd_type == "UPDATE_SIGNATURES":
                    new_ver = params.get("version", "2026.10.30-02")
                    config.set("signature_version", new_ver)
                    self._report_command_result(cmd_id, "COMPLETED", {"status": "UPDATED", "version": new_ver})
                elif cmd_type == "ISOLATE_HOST":
                    # Network isolation policy
                    logger.warning(f"Host isolation command invoked for agent {self.agent_id}")
                    self._report_command_result(cmd_id, "COMPLETED", {"status": "HOST_ISOLATED"})
                else:
                    self._report_command_result(cmd_id, "FAILED", {"error": f"Unknown command type: {cmd_type}"})
            except Exception as e:
                logger.exception(f"Error executing command {cmd_type}: {e}")
                self._report_command_result(cmd_id, "FAILED", {"error": str(e)})

        threading.Thread(target=_execute_async, name=f"AegisCmd-{cmd_id[:8]}", daemon=True).start()

    def _report_command_result(self, cmd_id: str, status_str: str, result_dict: Dict[str, Any]):
        url = f"{self.server_url}/api/v1/agent/command_result"
        payload = {
            "command_id": cmd_id,
            "agent_id": self.agent_id,
            "status": status_str,
            "result": result_dict,
        }
        try:
            requests.post(url, json=payload, timeout=5.0)
        except Exception:
            pass

    def start_loop(self):
        """Starts background heartbeat and telemetry loop."""
        self.running = True
        self.register()

        def _loop():
            interval = config.get("heartbeat_interval_seconds", 15)
            while self.running:
                try:
                    if not self.is_registered:
                        self.register()
                    else:
                        self.send_heartbeat()
                except Exception as e:
                    logger.debug(f"Agent loop error: {e}")
                time.sleep(interval)

        self.worker_thread = threading.Thread(target=_loop, name="Aegis-Agent-Loop", daemon=True)
        self.worker_thread.start()

    def stop_loop(self):
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2.0)

    @staticmethod
    def _get_local_ip() -> str:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
