# Configuration loading and validation. No side effects beyond reading the file.
import ipaddress
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger("sshbouncer.config")

DEFAULT_CONFIG_PATH = "/etc/sshbouncer/config.json"
DEFAULT_STATE_FILE = "/var/lib/sshbouncer/state.json"
AUTO_AUTH_LOG_CANDIDATES = ("/var/log/auth.log", "/var/log/secure")
VALID_BLOCK_METHODS = ("ufw", "iptables")
VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
SMTP_PASSWORD_ENV_VAR = "SSHBOUNCER_SMTP_PASS"
MAX_PORT = 65535

DEFAULT_CONFIG = {
    "auth_log": "auto",
    "threshold": 5,
    "window_seconds": 300,
    "block_enabled": False,
    "block_method": "ufw",
    "block_duration_minutes": 60,
    "email_enabled": False,
    "email_to": "",
    "email_from": "",
    "smtp_server": "localhost",
    "smtp_port": 25,
    "smtp_tls": False,
    "smtp_user": "",
    "smtp_pass": "",
    "whitelist": ["127.0.0.1"],
    "log_file": "/var/log/sshbouncer.log",
    "log_level": "INFO",
    "cooldown_minutes": 10,
    "state_file": DEFAULT_STATE_FILE,
}


class ConfigError(ValueError):
    """Raised when configuration is missing, unreadable, or invalid."""


def load_config(path: str | None) -> dict:
    """Merge defaults with the JSON file at path and validate the result."""
    config = dict(DEFAULT_CONFIG)

    if path is not None:
        config.update(read_config_file(path))

    apply_environment_overrides(config)
    validate_config(config)
    return config


def read_config_file(path: str) -> dict:
    """Read a JSON object from disk. Missing or malformed files are errors."""
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"config file not found: {path}")

    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as error:
        raise ConfigError(f"config file is not valid JSON: {path}: {error}") from error
    except OSError as error:
        raise ConfigError(f"cannot read config file: {path}: {error}") from error

    if not isinstance(data, dict):
        raise ConfigError(f"config file must contain a JSON object: {path}")

    # "_comment" is documentation only; drop it so it never leaks into validation.
    data.pop("_comment", None)
    return data


def apply_environment_overrides(config: dict) -> None:
    """Secrets come from the environment when present. Config file is the fallback."""
    smtp_password = os.environ.get(SMTP_PASSWORD_ENV_VAR)
    if smtp_password:
        config["smtp_pass"] = smtp_password


def validate_config(config: dict) -> None:
    """Reject bad values early. Every check raises ConfigError with the field name."""
    require_positive_int(config, "threshold")
    require_positive_int(config, "window_seconds")
    require_positive_int(config, "block_duration_minutes")
    require_non_negative_int(config, "cooldown_minutes")
    require_bool(config, "block_enabled")
    require_bool(config, "email_enabled")
    require_bool(config, "smtp_tls")
    require_string(config, "auth_log", allow_empty=False)
    require_string(config, "log_file", allow_empty=False)
    require_string(config, "state_file", allow_empty=False)

    if config["block_method"] not in VALID_BLOCK_METHODS:
        raise ConfigError(
            f"block_method must be one of {VALID_BLOCK_METHODS}, got {config['block_method']!r}"
        )

    if str(config["log_level"]).upper() not in VALID_LOG_LEVELS:
        raise ConfigError(
            f"log_level must be one of {VALID_LOG_LEVELS}, got {config['log_level']!r}"
        )
    config["log_level"] = str(config["log_level"]).upper()

    config["whitelist"] = parse_whitelist(config.get("whitelist", []))

    if config["email_enabled"]:
        validate_email_settings(config)


def validate_email_settings(config: dict) -> None:
    """Email fields are only required when email alerts are on."""
    require_string(config, "email_to", allow_empty=False)
    require_string(config, "smtp_server", allow_empty=False)
    require_string(config, "email_from", allow_empty=True)
    require_string(config, "smtp_user", allow_empty=True)
    require_string(config, "smtp_pass", allow_empty=True)

    port = config.get("smtp_port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= MAX_PORT:
        raise ConfigError(f"smtp_port must be an integer between 1 and {MAX_PORT}")


def parse_whitelist(raw_whitelist) -> list:
    """Turn whitelist strings into ip_network objects. Single IPs become /32 or /128."""
    if not isinstance(raw_whitelist, list):
        raise ConfigError("whitelist must be a list of IP addresses or CIDR networks")

    networks = []
    for entry in raw_whitelist:
        if not isinstance(entry, str) or not entry.strip():
            raise ConfigError(f"whitelist entry must be a non-empty string, got {entry!r}")
        try:
            networks.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError as error:
            raise ConfigError(f"whitelist entry is not a valid IP or network: {entry!r}") from error
    return networks


def resolve_auth_log(configured_path: str) -> str:
    """Map "auto" to the first auth log that exists. Explicit paths are returned as-is."""
    if configured_path != "auto":
        return configured_path

    for candidate in AUTO_AUTH_LOG_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate

    raise ConfigError(
        f"auth_log is \"auto\" but none of {AUTO_AUTH_LOG_CANDIDATES} exist; set auth_log explicitly"
    )


def require_positive_int(config: dict, key: str) -> None:
    value = config.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ConfigError(f"{key} must be an integer >= 1, got {value!r}")


def require_non_negative_int(config: dict, key: str) -> None:
    value = config.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ConfigError(f"{key} must be an integer >= 0, got {value!r}")


def require_bool(config: dict, key: str) -> None:
    if not isinstance(config.get(key), bool):
        raise ConfigError(f"{key} must be true or false, got {config.get(key)!r}")


def require_string(config: dict, key: str, allow_empty: bool) -> None:
    value = config.get(key)
    if not isinstance(value, str):
        raise ConfigError(f"{key} must be a string, got {value!r}")
    if not allow_empty and not value.strip():
        raise ConfigError(f"{key} must not be empty")
