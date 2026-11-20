import time
import logging
from typing import List, Dict, Any, Optional, Callable
import psutil

from aegis.network.reputation import NetworkReputationEngine
from aegis.network.firewall import WindowsFirewallManager

logger = logging.getLogger("AegisConnMonitor")

class NetworkConnectionMonitor:
    """Monitors live network connections, identifying outbound connections to suspicious/C2 IPs."""

    def __init__(self, on_threat_detected: Optional[Callable[[Dict[str, Any]], None]] = None, auto_block: bool = False):
        self.on_threat_detected = on_threat_detected
        self.auto_block = auto_block

    def audit_active_connections(self) -> List[Dict[str, Any]]:
        """Audits current active sockets against threat intelligence."""
        alerts = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, Exception) as e:
            logger.debug(f"Unable to query all network connections: {e}")
            return alerts

        for conn in connections:
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            # Check reputation
            rep = NetworkReputationEngine.check_ip(remote_ip)
            if rep["blocked"]:
                # Identify owning process
                pname = "Unknown"
                try:
                    if conn.pid:
                        pname = psutil.Process(conn.pid).name()
                except Exception:
                    pass

                alert = {
                    "alert_type": "MALICIOUS_OUTBOUND_CONNECTION",
                    "pid": conn.pid,
                    "process_name": pname,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "local_port": conn.laddr.port if conn.laddr else None,
                    "status": conn.status,
                    "threat_category": rep["category"],
                    "reason": rep["reason"],
                    "severity": rep["severity"],
                    "timestamp": time.time(),
                }

                if self.auto_block:
                    fw_res = WindowsFirewallManager.block_remote_ip(remote_ip, f"pid_{conn.pid}")
                    alert["firewall_blocked"] = fw_res.get("success", False)

                alerts.append(alert)
                if self.on_threat_detected:
                    self.on_threat_detected(alert)

        return alerts
