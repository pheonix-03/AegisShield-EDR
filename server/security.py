import os
import hmac
import hashlib
import json
import secrets
import time
from typing import Dict, Any, Optional

# Master server signing secret for cryptographically signing all dispatched administrative commands
# In production, this can be loaded from an environment secret or KMS
MASTER_SIGNING_KEY = os.getenv("AEGIS_SIGNING_KEY", "AegisShield_Central_Master_Control_Key_2026_Secure")

class CommandSecurity:
    """Provides cryptographic signing and tamper-detection for remote administrative commands."""

    @classmethod
    def generate_command_signature(
        cls,
        command_id: str,
        command_type: str,
        agent_id: str,
        parameters: Dict[str, Any],
        secret_key: str = MASTER_SIGNING_KEY,
    ) -> str:
        """Computes HMAC-SHA256 signature for command integrity and non-repudiation."""
        # Canonical payload representation
        canonical = json.dumps({
            "command_id": command_id,
            "command_type": command_type,
            "agent_id": agent_id,
            "parameters": parameters,
        }, sort_keys=True)

        sig = hmac.new(
            secret_key.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return sig

    @classmethod
    def verify_command_signature(
        cls,
        command_id: str,
        command_type: str,
        agent_id: str,
        parameters: Dict[str, Any],
        signature: str,
        secret_key: str = MASTER_SIGNING_KEY,
    ) -> bool:
        """Verifies that the command was authored and signed by the authorized central management server."""
        expected = cls.generate_command_signature(command_id, command_type, agent_id, parameters, secret_key)
        return hmac.compare_digest(expected, signature)

    @classmethod
    def generate_agent_token(cls) -> str:
        return secrets.token_hex(32)
