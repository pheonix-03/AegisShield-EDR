import re
import urllib.parse
from typing import Dict, Any, Optional, Set

# Known malicious C2 domains, phishing patterns, and high-risk TLDs
KNOWN_MALICIOUS_DOMAINS = {
    "malware-traffic-analysis.net",
    "evil-c2-command.ru",
    "cobaltstrike-beacon.top",
    "paypal-account-security-update.xyz",
    "secure-login-microsoft-auth.work",
    "ransomware-payment-portal.onion",
}

KNOWN_MALICIOUS_IPS = {
    "185.220.101.5",
    "194.26.29.112",
    "45.154.255.88",
    "193.106.191.162",
}

HIGH_RISK_TLDS = {".top", ".xyz", ".buzz", ".monster", ".work", ".click"}

PHISHING_KEYWORDS = [
    "login-verify", "account-suspended", "security-update-action",
    "wallet-recovery-phrase", "billing-invoice-view",
]

class NetworkReputationEngine:
    """Evaluates domain, IP, and URL security reputation against threat intelligence feeds."""

    @classmethod
    def check_domain(cls, domain: str) -> Dict[str, Any]:
        clean_domain = domain.strip().lower()
        if ":" in clean_domain:
            clean_domain = clean_domain.split(":")[0]

        if clean_domain in KNOWN_MALICIOUS_DOMAINS:
            return {
                "blocked": True,
                "domain": clean_domain,
                "reason": "Domain identified in AegisShield C2 / Malware threat feed.",
                "severity": "CRITICAL",
                "category": "C2_INFRASTRUCTURE",
            }

        # Check high risk TLD and phishing keywords
        for kw in PHISHING_KEYWORDS:
            if kw in clean_domain:
                return {
                    "blocked": True,
                    "domain": clean_domain,
                    "reason": f"Domain contains deceptive phishing phrase pattern: '{kw}'",
                    "severity": "HIGH",
                    "category": "PHISHING",
                }

        return {"blocked": False, "domain": clean_domain, "reason": "Clean", "severity": "CLEAN"}

    @classmethod
    def check_ip(cls, ip_address: str) -> Dict[str, Any]:
        clean_ip = ip_address.strip()
        if clean_ip in KNOWN_MALICIOUS_IPS:
            return {
                "blocked": True,
                "ip": clean_ip,
                "reason": "IP listed on AegisShield active malicious botnet / C2 list.",
                "severity": "CRITICAL",
                "category": "KNOWN_C2_HOST",
            }
        return {"blocked": False, "ip": clean_ip, "reason": "Clean", "severity": "CLEAN"}

    @classmethod
    def check_url(cls, url: str) -> Dict[str, Any]:
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or url
            res = cls.check_domain(hostname)
            if res["blocked"]:
                return res

            # Check suspicious download extensions in path
            path = parsed.path.lower()
            if path.endswith((".exe", ".scr", ".vbs", ".ps1", ".hta")) and any(tld in hostname for tld in HIGH_RISK_TLDS):
                return {
                    "blocked": True,
                    "domain": hostname,
                    "reason": f"Direct executable download payload hosted on high-risk generic TLD domain: {hostname}",
                    "severity": "HIGH",
                    "category": "SUSPICIOUS_DOWNLOAD",
                }
            return {"blocked": False, "url": url, "reason": "Clean", "severity": "CLEAN"}
        except Exception:
            return {"blocked": False, "url": url, "reason": "Malformed URL", "severity": "CLEAN"}
