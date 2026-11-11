"""Agent settings.

Precedence, lowest to highest:  built-in defaults  <  config file  <  environment
variables  <  command-line flags.  The environment variable names are the same ones
the original agent used (EAGLEEYE_API_URL, ...), so an existing setup keeps working.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping, Optional

from .keychain import SECRET_FIELDS, Keychain

log = logging.getLogger("eagleeye.config")
KEYCHAIN_MARKER = "secrets_in_keychain"
# Layout of the saved config file. 2 (agent 2.2.2): passive_interval defaults to 300 s;
# a version-1 file holding the old default of 60 s is moved to 300 s when it is read.
CONFIG_VERSION = 2
OLD_PASSIVE_INTERVAL = 60


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
    passive_interval: int = 300         # seconds between passive uploads (5 min)
    passive_backend: str = "auto"       # auto = built in (NDIS / packet socket); npcap only on the command line
    fingerbank_key: str = ""
    snmp_user: str = ""
    snmp_auth_key: str = ""
    snmp_priv_key: str = ""
    snmp_auth_protocol: str = "SHA"
    snmp_priv_protocol: str = "AES"
    # The network agent (netagent/): kind "network" reads routers and switches over SNMP
    # instead of looking after this computer. The SNMP credentials stay here; what to read
    # (seeds, allowed ranges, depth, interval) can be set from the dashboard (policy.py).
    kind: str = "host"
    snmp_version: str = "3"             # 3, or 2c with a read-only community
    snmp_community: str = ""
    network_poll: bool = True           # the Collector role
    network_seeds: list[str] = field(default_factory=list)      # routers/switches to start from
    network_ranges: list[str] = field(default_factory=list)     # where the crawl may go
    network_depth: int = 3              # CDP/LLDP hops from a seed
    network_interval: int = 900         # seconds between crawls (15 min)
    # The endpoint inventory of this machine: its software includes what each signed-in user
    # installed for themselves; local administrator accounts are sent only as a count.
    inventory: bool = True              # collect the endpoint inventory of this machine
    inventory_interval: int = 21600     # seconds between inventories (6 h)
    # SBOM of this computer (Syft + Grype, see sbom.py): daily, plus when the dashboard asks.
    sbom: bool = True
    sbom_interval: int = 86400          # seconds between SBOMs (24 h)
    sbom_extra_paths: str = ""          # extra folders to scan, one per line
    sbom_include_binaries: bool = False # also read compiled programs (Go binaries, .exe/.dll, Linux kernel)
    # Active scan engine (stages/scan_own.py): auto = the agent's own engine; nmap (the Nmap
    # stage) and compare (both, with a local report) are evaluation tools for the command line.
    # Port tier ("Scan depth" on the dashboard): base | consumer | wide (engine/ports.py).
    scan_engine: str = "auto"
    scan_ports: str = "base"
    # Local scan schedules (see schedule.py); the dashboard can still trigger scans too.
    schedules: list[dict[str, Any]] = field(default_factory=list)
    # The data-collection notice the person accepted in the GUI (0 = never shown).
    consent_version: int = 0
    consent_at: str = ""
    config_version: int = CONFIG_VERSION

    @property
    def inventory_options(self) -> dict[str, bool]:
        return {"user_software": True, "admin_names": False}

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
        if self.sbom and self.sbom_interval < 3600:
            out.append("sbom_interval must be at least 3600 seconds")
        if self.scan_engine not in ("auto", "nmap", "own", "compare"):
            out.append("scan_engine must be auto, nmap, own or compare")
        if self.scan_ports not in ("base", "consumer", "wide"):
            out.append("scan_ports must be base, consumer or wide")
        if self.passive_backend not in ("auto", "npcap", "native"):
            out.append("passive_backend must be auto, npcap or native")
        if self.kind not in ("host", "network"):
            out.append("kind must be host or network")
        if self.snmp_version not in ("3", "2c"):
            out.append("snmp_version must be 3 or 2c")
        if self.kind == "network" and self.network_interval < 300:
            out.append("network_interval must be at least 300 seconds")
        from .schedule import Schedule
        for raw in self.schedules:
            out += [f"schedule {raw.get('subnet') or '?'}: {p}" for p in Schedule.from_dict(raw).problems()]
        return out

    def redacted(self) -> dict[str, Any]:
        """Settings safe to print: secrets are masked down to their last 4 characters."""
        data = asdict(self)
        for key in SECRET_FIELDS:
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
    "passive_backend": "EAGLEEYE_PASSIVE_BACKEND",
    "fingerbank_key": "EAGLEEYE_FINGERBANK_KEY",
    "snmp_user": "EAGLEEYE_SNMP_USER",
    "snmp_auth_key": "EAGLEEYE_SNMP_AUTH_KEY",
    "snmp_priv_key": "EAGLEEYE_SNMP_PRIV_KEY",
    "snmp_auth_protocol": "EAGLEEYE_SNMP_AUTH_PROTOCOL",
    "snmp_priv_protocol": "EAGLEEYE_SNMP_PRIV_PROTOCOL",
    "inventory": "EAGLEEYE_INVENTORY",
    "inventory_interval": "EAGLEEYE_INVENTORY_INTERVAL",
    "sbom": "EAGLEEYE_SBOM",
    "sbom_interval": "EAGLEEYE_SBOM_INTERVAL",
    "sbom_extra_paths": "EAGLEEYE_SBOM_EXTRA_PATHS",
    "sbom_include_binaries": "EAGLEEYE_SBOM_INCLUDE_BINARIES",
    "scan_engine": "EAGLEEYE_SCAN_ENGINE",
    "scan_ports": "EAGLEEYE_SCAN_PORTS",
    "kind": "EAGLEEYE_KIND",
    "snmp_version": "EAGLEEYE_SNMP_VERSION",
    "snmp_community": "EAGLEEYE_SNMP_COMMUNITY",
    "network_poll": "EAGLEEYE_NETWORK_POLL",
    "network_seeds": "EAGLEEYE_NETWORK_SEEDS",       # comma-separated
    "network_ranges": "EAGLEEYE_NETWORK_RANGES",     # comma-separated
    "network_depth": "EAGLEEYE_NETWORK_DEPTH",
    "network_interval": "EAGLEEYE_NETWORK_INTERVAL",
}

# Settings that are lists of text (addresses, ranges): a JSON list in the config file, a
# comma-separated list in an EAGLEEYE_* variable.
STRING_LISTS = ("network_seeds", "network_ranges")


# What belongs to this computer rather than to the organisation it reports to: kept when the
# computer is connected as a different agent. Everything else (what the dashboard sets, local
# schedules) starts again from the built-in defaults, so a new agent does not carry the old
# one's settings into another tenant (the server adopts an agent's own values once).
LOCAL_FIELDS = (
    "kind", "poll_interval", "heartbeat_interval", "passive_interface", "fingerbank_key",
    "snmp_user", "snmp_auth_key", "snmp_priv_key", "snmp_auth_protocol", "snmp_priv_protocol",
    "snmp_version", "snmp_community", "sbom_extra_paths", "sbom_include_binaries",
    "consent_version", "consent_at",
)


def another_agent(current: Settings, api_url: str, agent_id: str) -> bool:
    """Whether these credentials make an agent that was already connected a different one
    (another agent ID or server). A computer not yet connected keeps what it was set up with."""
    if not current.agent_id:
        return False
    return (current.agent_id.lower() != agent_id.lower()
            or current.api_url.rstrip("/").lower() != api_url.rstrip("/").lower())


def with_credentials(current: Settings, api_url: str, agent_id: str, api_key: str) -> Settings:
    """`current` connected with these credentials; as another agent, from the built-in
    defaults plus what belongs to this computer (LOCAL_FIELDS)."""
    out = current
    if another_agent(current, api_url, agent_id):
        out = Settings(**{name: getattr(current, name) for name in LOCAL_FIELDS})
    out.api_url, out.agent_id, out.api_key = api_url, agent_id, api_key
    return out


def env_value(name: str, env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """An EAGLEEYE_* variable, or the contents of the file named by NAME_FILE (Docker and
    Kubernetes secrets are files: the secret then never sits in the environment)."""
    env = os.environ if env is None else env
    value = env.get(name)
    if value is not None:
        return value
    path = env.get(f"{name}_FILE")
    if not path:
        return None
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"{name}_FILE: cannot read {path}: {exc}") from exc


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


def instance_name(env: Optional[Mapping[str, str]] = None) -> str:
    """Which agent this is when one computer runs several (EAGLEEYE_CONFIG): "" for the
    default config, else the config file's name without "config-", e.g. "production" for
    config-production.json. Each instance gets its own window lock, schedule state and
    logs, so a staging and a production agent on one PC never share them."""
    env = os.environ if env is None else env
    override = env.get("EAGLEEYE_CONFIG")
    if not override:
        return ""
    stem = Path(override).stem
    name = stem[len("config-"):] if stem.lower().startswith("config-") else stem
    if name.lower() in ("", "config"):
        return ""
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in name)[:40]


def state_path(env: Optional[Mapping[str, str]] = None) -> Path:
    """Schedule state (last inventory/SBOM run...) of this instance, next to its config."""
    name = instance_name(env)
    return default_config_path(env).with_name(f"state-{name}.json" if name else "state.json")


def sbom_cache_path(env: Optional[Mapping[str, str]] = None) -> Path:
    """What this instance's SBOM runs learned per folder (sbom.FolderCache), next to its config."""
    name = instance_name(env)
    return default_config_path(env).with_name(f"sbom-cache-{name}.json" if name else "sbom-cache.json")


def _coerce(name: str, raw: Any, default: Any) -> Any:
    try:
        if name in STRING_LISTS:
            value = [p.strip() for p in raw.split(",")] if isinstance(raw, str) else raw
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise TypeError("expected a list of text")
            return [v.strip() for v in value if v.strip()]
        if isinstance(default, list):
            value = json.loads(raw) if isinstance(raw, str) else raw
            if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
                raise TypeError("expected a list of objects")
            return value
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
    keychain: Optional[Keychain] = None,
) -> Settings:
    """Merge defaults, config file, environment and explicit overrides (None = unset).
    Secrets of a config file saved to the OS credential store are read from there."""
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
        if "config_version" not in file_data or settings.config_version < CONFIG_VERSION:
            # Before 2.2.2 every save wrote the 60 s default, so 60 there was not chosen.
            if settings.passive_interval == OLD_PASSIVE_INTERVAL:
                settings.passive_interval = defaults["passive_interval"]
            settings.config_version = CONFIG_VERSION
        if file_data.get(KEYCHAIN_MARKER):
            store = keychain or Keychain()
            if not store.available():
                log.warning("The config file keeps its secrets in the OS credential store, which is not available")
            for name in SECRET_FIELDS:
                if not getattr(settings, name):
                    # Entries are per agent; the unscoped name is the pre-2.0 layout.
                    value = store.get(secret_entry(settings.agent_id, name)) or store.get(name)
                    setattr(settings, name, value or "")

    for name, var in _ENV_VARS.items():
        raw = env_value(var, env)
        if raw is None or (raw == "" and not isinstance(defaults[name], bool)):
            continue
        setattr(settings, name, _coerce(name, raw, defaults[name]))

    for name, raw in (overrides or {}).items():
        if raw is None or name not in defaults:
            continue
        setattr(settings, name, _coerce(name, raw, defaults[name]))

    return settings


def secret_entry(agent_id: str, name: str) -> str:
    """Credential-store entry for one secret of one agent, e.g. "2f5d.../api_key".
    Scoped by agent so two configs (or two agents on one machine) never overwrite
    each other's keys."""
    return f"{agent_id or 'unregistered'}/{name}"


def save_settings(settings: Settings, path: Optional[Path] = None, keychain: Optional[Keychain] = None) -> Path:
    """Write settings as JSON. With a usable `keychain` the secrets go to the OS
    credential store and the file keeps blanks; otherwise they are written in plain
    text, and the file is restricted to the current user where the OS supports it."""
    target = path or default_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = asdict(settings)
    if keychain is not None and keychain.available():
        entries = {name: secret_entry(settings.agent_id, name) for name in SECRET_FIELDS}
        if all(keychain.set(entries[name], data[name]) for name in SECRET_FIELDS):
            data.update({name: "" for name in SECRET_FIELDS})
            data[KEYCHAIN_MARKER] = True
        else:
            log.warning("Secrets could not be stored in the OS credential store; keeping them in %s", target)
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if sys.platform != "win32":
        try:
            target.chmod(0o600)
        except OSError:
            pass
    return target
