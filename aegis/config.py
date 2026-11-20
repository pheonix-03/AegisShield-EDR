import os
import sys
import uuid
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

# Root application directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Base data directory (can be in %ProgramData% in production or ./data for self-contained execution)
PROGRAM_DATA = os.getenv("PROGRAMDATA", "C:\\ProgramData")
APP_DATA_DIR = Path(os.getenv("AEGIS_DATA_DIR", str(BASE_DIR / "data")))
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

# Subdirectories
QUARANTINE_DIR = APP_DATA_DIR / "quarantine_vault"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

CANARY_DIR = APP_DATA_DIR / "canary_vault"
CANARY_DIR.mkdir(parents=True, exist_ok=True)

LOGS_DIR = APP_DATA_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

RULES_DIR = BASE_DIR / "aegis" / "engine" / "rules"
RULES_DIR.mkdir(parents=True, exist_ok=True)

LOCAL_DB_PATH = APP_DATA_DIR / "aegis_local.db"
CONFIG_FILE_PATH = APP_DATA_DIR / "agent_config.json"

# Logging setup
LOG_FILE = LOGS_DIR / "aegis_endpoint.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    handlers=[
        logging.FileHandler(str(LOG_FILE), encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("AegisShield")

class AegisConfig:
    """Manages persistent and runtime configurations for the AegisShield endpoint agent."""

    DEFAULT_CONFIG = {
        "agent_id": str(uuid.uuid4()),
        "hostname": os.getenv("COMPUTERNAME", "UNKNOWN-PC"),
        "office_location": "Headquarters - Floor 3",
        "server_url": "http://127.0.0.1:8443",
        "server_api_key": "aegis-enrollment-secret-key-change-in-prod",
        "agent_token": None,
        "heartbeat_interval_seconds": 15,
        "realtime_protection_enabled": True,
        "ransomware_protection_enabled": True,
        "usb_protection_enabled": True,
        "usb_auto_scan": True,
        "usb_block_executables": False,
        "web_protection_enabled": True,
        "max_scan_file_size_mb": 100,
        "entropy_threshold": 7.2,
        "pe_heuristics_enabled": True,
        "script_heuristics_enabled": True,
        "monitored_paths": [
            os.path.expandvars(r"%USERPROFILE%\Downloads"),
            os.path.expandvars(r"%USERPROFILE%\Desktop"),
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%APPDATA%"),
        ],
        "excluded_paths": [
            str(QUARANTINE_DIR),
            str(LOGS_DIR),
            os.path.expandvars(r"%SYSTEMROOT%\System32\drivers"),
        ],
        "excluded_extensions": [
            ".tmp", ".log", ".etag", ".lock"
        ],
        "ransomware_tripwire": {
            "canary_file_count": 5,
            "max_renames_per_minute": 20,
            "max_writes_per_minute": 40,
            "auto_kill_process": True,
        },
        "signature_version": "2026.10.30-01",
    }

    def __init__(self, config_path: Path = CONFIG_FILE_PATH):
        self.config_path = config_path
        self._data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Merge with default config
                    merged = dict(self.DEFAULT_CONFIG)
                    merged.update(data)
                    return merged
            except Exception as e:
                logger.error(f"Error loading config from {self.config_path}: {e}")
                return dict(self.DEFAULT_CONFIG)
        else:
            self._save_data(self.DEFAULT_CONFIG)
            return dict(self.DEFAULT_CONFIG)

    def _save_data(self, data: Dict[str, Any]):
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving config to {self.config_path}: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any):
        self._data[key] = value
        self._save_data(self._data)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._data)

    def update_from_policy(self, policy_dict: Dict[str, Any]):
        """Update configurable settings received from central management server."""
        for k, v in policy_dict.items():
            if k in self._data and k not in ("agent_id", "hostname"):
                self._data[k] = v
        self._save_data(self._data)
        logger.info("Agent configuration synchronized with central management policy.")

config = AegisConfig()
