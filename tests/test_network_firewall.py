import pytest
from aegis.network.reputation import NetworkReputationEngine
from aegis.network.firewall import WindowsFirewallManager

def test_c2_domain_reputation():
    # Known malicious C2 domain
    res = NetworkReputationEngine.check_domain("evil-c2-command.ru")
    assert res["blocked"] is True
    assert res["severity"] == "CRITICAL"

    # Known phishing domain
    res_phish = NetworkReputationEngine.check_domain("paypal-account-suspended-login-verify.top")
    assert res_phish["blocked"] is True

    # Benign domain
    res_clean = NetworkReputationEngine.check_domain("microsoft.com")
    assert res_clean["blocked"] is False

def test_c2_ip_reputation():
    # Known botnet IP
    res = NetworkReputationEngine.check_ip("185.220.101.5")
    assert res["blocked"] is True
    assert res["severity"] == "CRITICAL"

    # Benign IP
    res_clean = NetworkReputationEngine.check_ip("8.8.8.8")
    assert res_clean["blocked"] is False
