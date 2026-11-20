import subprocess
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("AegisFirewall")

RULE_PREFIX = "AegisShield_Block_"

class WindowsFirewallManager:
    """Manages defensive network containment rules via Windows Advanced Firewall."""

    @classmethod
    def block_remote_ip(cls, ip_address: str, rule_name_suffix: str = "") -> Dict[str, Any]:
        """Creates an outbound DROP rule for a malicious remote IP or C2 server."""
        rule_name = f"{RULE_PREFIX}{ip_address.replace('.', '_')}_{rule_name_suffix}".strip("_")
        cmd = [
            "netsh.exe", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"remoteip={ip_address}",
            "description=Defensive block rule deployed by AegisShield Endpoint Protection",
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                logger.info(f"Deployed Windows Firewall block rule for IP: {ip_address} ({rule_name})")
                return {"success": True, "rule_name": rule_name, "blocked_ip": ip_address}
            else:
                logger.warning(f"Firewall rule creation returned code {res.returncode}: {res.stderr}")
                return {"success": False, "error": res.stderr or res.stdout}
        except Exception as e:
            logger.error(f"Failed to execute netsh firewall command: {e}")
            return {"success": False, "error": str(e)}

    @classmethod
    def remove_block_rule(cls, rule_name: str) -> Dict[str, Any]:
        """Safely removes an Aegis-created firewall rule."""
        if not rule_name.startswith(RULE_PREFIX):
            return {"success": False, "error": "Cannot remove non-Aegis firewall rules."}

        cmd = ["netsh.exe", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return {"success": res.returncode == 0, "rule_name": rule_name}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @classmethod
    def list_aegis_rules(cls) -> List[str]:
        """Lists active firewall rules created by AegisShield."""
        cmd = ["netsh.exe", "advfirewall", "firewall", "show", "rule", f"name=all"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            rules = []
            for line in res.stdout.splitlines():
                if "Rule Name:" in line and RULE_PREFIX in line:
                    rname = line.split("Rule Name:", 1)[1].strip()
                    rules.append(rname)
            return rules
        except Exception:
            return []
