"""Settings an administrator sets for this agent from the dashboard (2.4.0).

The server resolves each setting (workers/src/lib/agentPolicy.ts): the agent's own
override > the tenant default > this agent's own setting. Its heartbeat answer carries the
ones an admin set ("managed") and a version. The service applies them between jobs, over
the settings of this computer (config file and GUI), and keeps them in policy.json, so a
restart before the first heartbeat still follows them. The local values are left as they
are: when the admin clears a setting, this computer's own choice applies again. The GUI
shows a managed setting read-only.

Two settings are the server's alone: `scanner` (whether the dashboard sends this agent
scans) and `local_scans` (whether it may start its own, delivered as before).
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import logging
import sys
from pathlib import Path
from typing import Any, Mapping, Optional

from .config import Settings, default_config_path, instance_name

log = logging.getLogger("eagleeye.policy")

KIND = "host"

# Setting -> how to check a value; each is the Settings field of the same name.
FIELDS: dict[str, tuple[str, Any]] = {
    "passive": ("bool", None),
    "passive_interval": ("int", (10, 3600)),
    "inventory": ("bool", None),
    "inventory_interval": ("int", (300, 7 * 86400)),
    "sbom": ("bool", None),
    "sbom_interval": ("int", (3600, 30 * 86400)),
    "scan_ports": ("enum", ("base", "consumer", "wide")),
}

# Not settings any more (2.6): the service always scans with the agent's own engine and listens
# with the built-in capture; the command line can still choose others for evaluation.
PRODUCT = {"scan_engine": "auto", "passive_backend": "auto"}

# The network agent's settings (kind "network", netagent/service.py): what it reads.
NETWORK_FIELDS: dict[str, tuple[str, Any]] = {
    "network_poll": ("bool", None),
    "network_seeds": ("list", ("ip", 16)),
    "network_ranges": ("list", ("cidr", 32)),
    "network_depth": ("int", (0, 6)),
    "network_interval": ("int", (300, 86400)),
}
KIND_FIELDS = {"host": FIELDS, "network": NETWORK_FIELDS}


def fields_of(kind: str) -> dict[str, tuple[str, Any]]:
    return KIND_FIELDS.get(kind, FIELDS)


LABELS = {
    "passive": "Passive listening", "passive_interval": "Passive upload interval",
    "passive_backend": "Packet capture", "inventory": "Inventory", "inventory_interval": "Inventory interval",
    "sbom": "SBOM", "sbom_interval": "SBOM interval", "scan_engine": "Scan engine", "scan_ports": "Scan ports",
    "network_poll": "Read the network", "network_seeds": "Seed devices", "network_ranges": "Allowed ranges",
    "network_depth": "Crawl depth", "network_interval": "Crawl interval",
}

MANAGED_NOTE = "Set by your administrator on the EagleEye dashboard"


def _list_item(item: str, value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        if item == "ip":
            ipaddress.IPv4Address(value)
        else:
            ipaddress.IPv4Network(value, strict=False)
        return "/" in value or item == "ip"
    except ValueError:
        return False


def _valid(key: str, value: Any, table: Mapping[str, tuple[str, Any]] = FIELDS) -> bool:
    kind, rule = table[key]
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "int":
        return isinstance(value, int) and not isinstance(value, bool) and rule[0] <= value <= rule[1]
    if kind == "list":
        item, most = rule
        return isinstance(value, list) and len(value) <= most and all(_list_item(item, v) for v in value)
    return isinstance(value, str) and value in rule


def clean(managed: Any, kind: str = "host") -> dict[str, Any]:
    """The managed settings this agent applies; anything unknown or invalid is ignored."""
    if not isinstance(managed, Mapping):
        return {}
    table = fields_of(kind)
    return {k: v for k, v in managed.items() if k in table and _valid(k, v, table)}


def apply(settings: Settings, managed: Mapping[str, Any], kind: str = "host") -> Settings:
    """What the service runs: the dashboard's values over this computer's settings, with the
    product's engine and capture. A 2.6 server sends every setting, so once it has answered the
    dashboard decides them all; this computer's own values only count until then (and the server
    adopted them as this agent's settings at its first heartbeat: workers/src/lib/agentPolicy.ts)."""
    return dataclasses.replace(settings, **PRODUCT, **clean(managed, kind))


def local_report(settings: Settings, kind: str = "host") -> dict[str, Any]:
    """This computer's own value of each setting (what applies where the admin set none)."""
    out = {}
    table = fields_of(kind)
    for key in table:
        value = getattr(settings, key)
        if key == "scan_engine" and value == "nmap":
            value = "auto"                      # the same engine under its old name
        if _valid(key, value, table):
            out[key] = value
    return out


def capabilities() -> dict[str, Any]:
    """What this agent can do, for the dashboard (all cheap checks)."""
    out: dict[str, Any] = {"os": sys.platform}
    try:
        from . import deps
        out["admin"] = bool(deps.is_admin())
        out["nmap"] = deps.find_nmap() is not None
        from . import sbom
        out["sbom_tools"] = not sbom.missing_tools()        # the dashboard warns when SBOM is on without them
    except Exception:  # noqa: BLE001 - optional information
        pass
    try:
        from .passive.capture import npcap_installed, scapy_available
        out["native_capture"] = sys.platform in ("win32", "darwin") or sys.platform.startswith("linux")
        out["npcap"] = bool(scapy_available() and npcap_installed()) if sys.platform == "win32" else scapy_available()
    except Exception:  # noqa: BLE001
        pass
    return out


def policy_path(env: Optional[Mapping[str, str]] = None) -> Path:
    """This instance's applied policy, next to its config."""
    name = instance_name(env)
    return default_config_path(env).with_name(f"policy-{name}.json" if name else "policy.json")


class PolicyStore:
    """The last policy applied: {"version": str, "managed": {...}, "agent_id": str}. No path =
    memory only. With `agent_id`, a policy another agent applied (this computer connected
    before as another agent, perhaps of another tenant) is not this one's."""

    def __init__(self, path: Optional[Path], kind: str = "host", agent_id: Optional[str] = None) -> None:
        self.path = path
        self.kind = kind
        self.agent_id = agent_id

    def load(self) -> tuple[Optional[str], dict[str, Any]]:
        if self.path is None or not self.path.exists():
            return None, {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("Could not read %s (%s); waiting for the server's settings", self.path, exc)
            return None, {}
        if self.agent_id is not None and (not isinstance(data, dict) or data.get("agent_id") != self.agent_id):
            return None, {}
        version = data.get("version") if isinstance(data, dict) else None
        return (version if isinstance(version, str) else None), clean((data or {}).get("managed"), self.kind)

    def save(self, version: str, managed: Mapping[str, Any]) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            data: dict[str, Any] = {"version": version, "managed": dict(managed)}
            if self.agent_id is not None:
                data["agent_id"] = self.agent_id
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as exc:
            log.warning("Could not save the administrator's settings to %s: %s", self.path, exc)


def describe(managed: Mapping[str, Any]) -> str:
    """"Passive listening, Scan engine" for a notice."""
    return ", ".join(LABELS.get(k, k) for k in managed) or "none"
