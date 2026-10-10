"""Agent settings.

Precedence, lowest to highest:  built-in defaults  <  config file  <  environment
variables  <  command-line flags.  The environment variable names are the same ones
the original agent used (EAGLEEYE_API_URL, ...), so an existing setup keeps working.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Mapping, Optional


class ConfigError(ValueError):
    """A setting is present but unusable."""


@dataclass
class Settings:
    api_url: str = ""
    api_key: str = ""
    agent_id: str = ""
    poll_interval: int = 30
    heartbeat_interval: int = 30
    passive: bool = False
    passive_interface: str = ""
    passive_interval: int = 60
    fingerbank_key: str = ""
    snmp_user: str = ""
    snmp_auth_key: str = ""
    snmp_priv_key: str = ""
    snmp_auth_protocol: str = "SHA"
    snmp_priv_protocol: str = "AES"
    inventory: bool = True              # collect the endpoint inventory of this machine
    inventory_interval: int = 21600     # seconds between inventories (6 h)
    # Personal data, off by default (data minimisation): per-user software installs
    # and the names of local administrator accounts (only their count is sent).
    inventory_user_software: bool = False
    inventory_admin_names: bool = False

    @property
    def inventory_options(self) -> dict[str, bool]:
        return {"user_software": self.inventory_user_software, "admin_names": self.inventory_admin_names}

    @property
    def snmp_enabled(self) -> bool:
        """SNMPv3 polling needs the full authPriv credential set."""
        return bool(self.snmp_user and self.snmp_auth_key and self.snmp_priv_key)

    def problems(self) -> list[str]:
        """Reasons the agent cannot talk to the server yet (empty list = ready)."""
        out: list[str] = []
        for name in ("api_url", "api_key", "agent_id"):
            if not getattr(self, name):
                out.append(f"{name} is not set")
        if self.api_url and not self.api_url.lower().startswith(("http://", "https://")):
            out.append("api_url must start with http:// or https://")
        for name in ("poll_interval", "heartbeat_interval", "passive_interval"):
            if getattr(self, name) < 5:
                out.append(f"{name} must be at least 5 seconds")
        if self.inventory and self.inventory_interval < 300:
            out.append("inventory_interval must be at least 300 seconds")
        return out

    def redacted(self) -> dict[str, Any]:
        """Settings safe to print: secrets are masked down to their last 4 characters."""
        secret = {"api_key", "fingerbank_key", "snmp_auth_key", "snmp_priv_key"}
        data = asdict(self)
        for key in secret:
            value = data[key]
            data[key] = "" if not value else "****" + value[-4:]
        return data


_ENV_VARS = {
    "api_url": "EAGLEEYE_API_URL",
    "api_key": "EAGLEEYE_API_KEY",
    "agent_id": "EAGLEEYE_AGENT_ID",
    "poll_interval": "EAGLEEYE_POLL_INTERVAL",
    "heartbeat_interval": "EAGLEEYE_HEARTBEAT_INTERVAL",
    "passive": "EAGLEEYE_PASSIVE",
    "passive_interface": "EAGLEEYE_PASSIVE_INTERFACE",
    "passive_interval": "EAGLEEYE_PASSIVE_INTERVAL",
    "fingerbank_key": "EAGLEEYE_FINGERBANK_KEY",
    "snmp_user": "EAGLEEYE_SNMP_USER",
    "snmp_auth_key": "EAGLEEYE_SNMP_AUTH_KEY",
    "snmp_priv_key": "EAGLEEYE_SNMP_PRIV_KEY",
    "snmp_auth_protocol": "EAGLEEYE_SNMP_AUTH_PROTOCOL",
    "snmp_priv_protocol": "EAGLEEYE_SNMP_PRIV_PROTOCOL",
    "inventory": "EAGLEEYE_INVENTORY",
    "inventory_interval": "EAGLEEYE_INVENTORY_INTERVAL",
    "inventory_user_software": "EAGLEEYE_INVENTORY_USER_SOFTWARE",
    "inventory_admin_names": "EAGLEEYE_INVENTORY_ADMIN_NAMES",
}


def config_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "EagleEye"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "EagleEye"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "eagleeye"


def default_config_path(env: Optional[Mapping[str, str]] = None) -> Path:
    env = os.environ if env is None else env
    override = env.get("EAGLEEYE_CONFIG")
    return Path(override) if override else config_dir() / "config.json"


def _coerce(name: str, raw: Any, default: Any) -> Any:
    try:
        if isinstance(default, bool):
            if isinstance(raw, bool):
                return raw
            return str(raw).strip().lower() in ("1", "true", "yes", "on")
        if isinstance(default, int):
            return int(raw)
        return str(raw).strip()
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name}: invalid value {raw!r}") from exc


def load_settings(
    config_path: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
    overrides: Optional[Mapping[str, Any]] = None,
) -> Settings:
    """Merge defaults, config file, environment and explicit overrides (None = unset)."""
    env = os.environ if env is None else env
    settings = Settings()
    defaults = {f.name: getattr(settings, f.name) for f in fields(Settings)}

    path = config_path or default_config_path(env)
    if path.is_file():
        try:
            file_data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read config file {path}: {exc}") from exc
        if not isinstance(file_data, dict):
            raise ConfigError(f"config file {path} must contain a JSON object")
        for name, raw in file_data.items():
            if name in defaults:
                setattr(settings, name, _coerce(name, raw, defaults[name]))

    for name, var in _ENV_VARS.items():
        raw = env.get(var)
        if raw is None or (raw == "" and not isinstance(defaults[name], bool)):
            continue
        setattr(settings, name, _coerce(name, raw, defaults[name]))

    for name, raw in (overrides or {}).items():
        if raw is None or name not in defaults:
            continue
        setattr(settings, name, _coerce(name, raw, defaults[name]))

    return settings


def save_settings(settings: Settings, path: Optional[Path] = None) -> Path:
    """Write settings as JSON. Secrets are stored in plain text, so the file is
    restricted to the current user where the OS supports it (the GUI build will
    move secrets into the OS keychain)."""
    target = path or default_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(asdict(settings), indent=2) + "\n", encoding="utf-8")
    if sys.platform != "win32":
        try:
            target.chmod(0o600)
        except OSError:
            pass
    return target
