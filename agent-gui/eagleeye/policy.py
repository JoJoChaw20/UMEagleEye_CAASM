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
    "passive_backend": ("enum", ("auto", "npcap", "native")),
    "inventory": ("bool", None),
    "inventory_interval": ("int", (300, 7 * 86400)),
    "inventory_user_software": ("bool", None),
    "inventory_admin_names": ("bool", None),
    "sbom": ("bool", None),
    "sbom_interval": ("int", (3600, 30 * 86400)),
    "scan_engine": ("enum", ("auto", "own", "compare")),
    "scan_ports": ("enum", ("base", "consumer", "wide")),
}

LABELS = {
    "passive": "Passive listening", "passive_interval": "Passive upload interval",
    "passive_backend": "Packet capture", "inventory": "Inventory", "inventory_interval": "Inventory interval",
    "inventory_user_software": "Software users installed", "inventory_admin_names": "Administrator account names",
    "sbom": "SBOM", "sbom_interval": "SBOM interval", "scan_engine": "Scan engine", "scan_ports": "Scan ports",
}

MANAGED_NOTE = "Set by your administrator on the EagleEye dashboard"


def _valid(key: str, value: Any) -> bool:
    kind, rule = FIELDS[key]
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "int":
        return isinstance(value, int) and not isinstance(value, bool) and rule[0] <= value <= rule[1]
    return isinstance(value, str) and value in rule


def clean(managed: Any) -> dict[str, Any]:
    """The managed settings this agent applies; anything unknown or invalid is ignored."""
    if not isinstance(managed, Mapping):
        return {}
    return {k: v for k, v in managed.items() if k in FIELDS and _valid(k, v)}


def apply(settings: Settings, managed: Mapping[str, Any]) -> Settings:
    """A copy of `settings` with the managed values in place."""
    return dataclasses.replace(settings, **clean(managed))


def local_report(settings: Settings) -> dict[str, Any]:
    """This computer's own value of each setting (what applies where the admin set none)."""
    out = {}
    for key in FIELDS:
        value = getattr(settings, key)
        if key == "scan_engine" and value == "nmap":
            value = "auto"                      # the same engine under its old name
        if _valid(key, value):
            out[key] = value
    return out


def capabilities() -> dict[str, Any]:
    """What this agent can do, for the dashboard (all cheap checks)."""
    out: dict[str, Any] = {"os": sys.platform}
    try:
        from . import deps
        out["admin"] = bool(deps.is_admin())
        out["nmap"] = deps.find_nmap() is not None
    except Exception:  # noqa: BLE001 - optional information
        pass
    try:
        from .passive.capture import npcap_installed, scapy_available
        out["native_capture"] = sys.platform == "win32" or sys.platform.startswith("linux")
        out["npcap"] = bool(scapy_available() and npcap_installed()) if sys.platform == "win32" else scapy_available()
    except Exception:  # noqa: BLE001
        pass
    return out


def policy_path(env: Optional[Mapping[str, str]] = None) -> Path:
    """This instance's applied policy, next to its config."""
    name = instance_name(env)
    return default_config_path(env).with_name(f"policy-{name}.json" if name else "policy.json")


class PolicyStore:
    """The last policy applied: {"version": str, "managed": {...}}. No path = memory only."""

    def __init__(self, path: Optional[Path]) -> None:
        self.path = path

    def load(self) -> tuple[Optional[str], dict[str, Any]]:
        if self.path is None or not self.path.exists():
            return None, {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("Could not read %s (%s); waiting for the server's settings", self.path, exc)
            return None, {}
        version = data.get("version") if isinstance(data, dict) else None
        return (version if isinstance(version, str) else None), clean((data or {}).get("managed"))

    def save(self, version: str, managed: Mapping[str, Any]) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"version": version, "managed": dict(managed)}, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as exc:
            log.warning("Could not save the administrator's settings to %s: %s", self.path, exc)


def describe(managed: Mapping[str, Any]) -> str:
    """"Passive listening, Scan engine" for a notice."""
    return ", ".join(LABELS.get(k, k) for k in managed) or "none"
