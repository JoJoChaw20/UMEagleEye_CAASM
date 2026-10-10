"""Windows endpoint inventory: runs windows_inventory.ps1 and normalises its output."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .. import VERSION
from ..netinfo import local_ip
from . import CollectorError

SCRIPT = Path(__file__).with_name("windows_inventory.ps1")
TIMEOUT_SECONDS = 180

# SMBIOS chassis types (DMTF DSP0134) grouped into form factors.
_LAPTOP = {8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32}
_DESKTOP = {3, 4, 5, 6, 7, 13, 15, 16, 24, 35, 36}
_SERVER = {17, 23, 28, 29}
_VIRTUAL_MODEL = re.compile(r"virtual machine|vmware|virtualbox|kvm|qemu|hvm domu|parallels", re.I)
_VIRTUAL_NIC = re.compile(
    r"hyper-v|vmware|virtualbox|vethernet|wsl|tap-|wireguard|wintun|loopback|npcap|tunnel|teredo|isatap|"
    r"zerotier|tailscale|docker|wan miniport|vpn|fortinet|cisco anyconnect",
    re.I,
)
_ROLES = {1: "workstation", 2: "domain_controller", 3: "server"}
NEEDS_ADMIN = ("bitlocker", "tpm", "smb1")
_LOCAL_ONLY = re.compile(r"^(127\.|::1$)")


def run_script(user_software: bool = False, admin_names: bool = False, timeout: int = TIMEOUT_SECONDS) -> dict[str, Any]:
    command = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT)]
    if user_software:
        command.append("-IncludeUserSoftware")
    if admin_names:
        command.append("-IncludeAdminNames")
    try:
        proc = subprocess.run(command, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        raise CollectorError("PowerShell is not available") from None
    except subprocess.TimeoutExpired:
        raise CollectorError(f"inventory script did not finish within {timeout}s") from None
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0 or not out:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise CollectorError(f"inventory script failed (exit {proc.returncode}): {err[:300]}")
    try:
        return json.loads(out.lstrip("﻿"))
    except json.JSONDecodeError as exc:
        raise CollectorError(f"inventory script returned invalid JSON: {exc}") from None


# ── helpers ──
def _s(value: Any, limit: int = 255) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _mac(value: Any) -> Optional[str]:
    text = _s(value)
    if not text:
        return None
    hexdigits = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(hexdigits) != 12:
        return None
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2)).upper()


def _parse_dt(value: Any) -> Optional[datetime]:
    text = _s(value)
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _install_date(value: Any) -> Optional[str]:
    """Registry InstallDate is usually yyyyMMdd."""
    text = _s(value, 32)
    if text and re.fullmatch(r"\d{8}", text):
        try:
            return datetime.strptime(text, "%Y%m%d").date().isoformat()
        except ValueError:
            return None
    return None


def form_factor(manufacturer: Any, model: Any, chassis_types: list[Any], system_type: Any) -> str:
    if _VIRTUAL_MODEL.search(f"{manufacturer or ''} {model or ''}"):
        return "virtual"
    types = {int(t) for t in chassis_types if str(t).isdigit()}
    if types & _SERVER:
        return "server"
    if types & _LAPTOP:
        return "laptop"
    if types & _DESKTOP:
        return "desktop"
    return {2: "laptop", 1: "desktop", 3: "desktop", 4: "server", 5: "server", 7: "server"}.get(
        int(system_type or 0), "unknown")


def antivirus_state(product_state: Any) -> dict[str, Optional[bool]]:
    """Decode the SecurityCenter2 productState bit field (0xAABBCC):
    BB = 0x10/0x11 when real-time protection is on, CC = 0x00 when signatures are current."""
    try:
        hexstate = f"{int(product_state):06X}"
    except (TypeError, ValueError):
        return {"enabled": None, "up_to_date": None}
    return {"enabled": hexstate[2:4] in ("10", "11"), "up_to_date": hexstate[4:6] == "00"}


def normalize(raw: dict[str, Any], collected_at: Optional[datetime] = None) -> dict[str, Any]:
    now = collected_at or datetime.now(timezone.utc)
    ident = raw.get("identity") or {}
    hw = raw.get("hardware") or {}
    os_ = raw.get("os") or {}
    patches = raw.get("patches") or {}
    sec = raw.get("security") or {}
    net = raw.get("network") or {}
    is_admin = bool(raw.get("is_admin"))
    options = raw.get("options") or {}

    # Patches: the newest hotfix tells how current the machine is.
    hotfixes = [
        {"id": _s(h.get("id"), 32), "description": _s(h.get("description"), 64), "installed_on": _s(h.get("installed_on"), 40)}
        for h in _list(patches.get("hotfixes")) if isinstance(h, dict)
    ]
    dated = [(d, h) for h in hotfixes if (d := _parse_dt(h["installed_on"]))]
    last = max(dated, key=lambda pair: pair[0]) if dated else None

    # Interfaces: "physical" ones are the identity-grade NICs the server matches on.
    interfaces = []
    for nic in _list(net.get("interfaces")):
        if not isinstance(nic, dict):
            continue
        description = _s(nic.get("description")) or ""
        virtual = bool(nic.get("virtual")) or bool(_VIRTUAL_NIC.search(f"{nic.get('name') or ''} {description}"))
        bluetooth = "bluetooth" in description.lower()
        mac = _mac(nic.get("mac"))
        interfaces.append({
            "name": _s(nic.get("name")),
            "description": description or None,
            "mac": mac,
            "status": _s(nic.get("status"), 32),
            "virtual": virtual,
            "physical": bool(nic.get("hardware")) and not virtual and not bluetooth and mac is not None,
            "speed_bps": nic.get("speed_bps") or None,
            "ipv4": [_s(a, 45) for a in _list(nic.get("ipv4")) if _s(a, 45)],
            "ipv6": [_s(a, 45) for a in _list(nic.get("ipv6")) if _s(a, 45)],
        })

    listening, seen_ports = [], set()
    for entry in _list(net.get("listening")):
        if not isinstance(entry, dict):
            continue
        key = (entry.get("protocol"), entry.get("address"), entry.get("port"))
        if key in seen_ports:
            continue
        seen_ports.add(key)
        address = _s(entry.get("address"), 45)
        # A port bound only to loopback is not reachable from the network, so which
        # program owns it is not needed for security and is left out.
        local_only = bool(address and _LOCAL_ONLY.match(address))
        listening.append({
            "protocol": _s(entry.get("protocol"), 8), "address": address, "port": entry.get("port"),
            "pid": None if local_only else entry.get("pid"),
            "process": None if local_only else _s(entry.get("process"), 128),
            "local_only": local_only,
        })
    listening.sort(key=lambda e: (e["protocol"] or "", e["port"] or 0, e["address"] or ""))

    software, seen_sw = [], set()
    for app in _list(raw.get("software")):
        if not isinstance(app, dict):
            continue
        name = _s(app.get("name"))
        if not name:
            continue
        version = _s(app.get("version"), 100)
        publisher = _s(app.get("publisher"))
        key = (name.lower(), version or "", (publisher or "").lower())
        if key in seen_sw:
            continue
        seen_sw.add(key)
        software.append({
            "name": name, "version": version, "publisher": publisher,
            "install_date": _install_date(app.get("install_date")),
            "scope": _s(app.get("scope"), 16), "arch": _s(app.get("arch"), 16),
        })
    software.sort(key=lambda a: (a["name"].lower(), a["version"] or ""))

    firewall = [{"profile": _s(f.get("profile"), 32), "enabled": bool(f.get("enabled"))}
                for f in _list(sec.get("firewall")) if isinstance(f, dict)]
    antivirus = [{"name": _s(a.get("name")), **antivirus_state(a.get("product_state"))}
                 for a in _list(sec.get("antivirus_products")) if isinstance(a, dict)]

    build = _s(os_.get("build"), 32)
    if build and os_.get("ubr") not in (None, ""):
        build = f"{build}.{os_.get('ubr')}"

    return {
        "schema": 1,
        "platform": "windows",
        "collected_at": now.isoformat(),
        "agent_version": VERSION,
        "is_admin": is_admin,
        "identity": {
            "hostname": _s(ident.get("hostname")),
            "dns_hostname": _s(ident.get("dns_hostname")),
            "domain": _s(ident.get("domain")),
            "part_of_domain": bool(ident.get("part_of_domain")),
            "workgroup": _s(ident.get("workgroup")),
            "machine_guid": _s(ident.get("machine_guid"), 64),
            "smbios_uuid": _s(ident.get("smbios_uuid"), 64),
            "serial_number": _s(ident.get("serial_number"), 128),
        },
        "hardware": {
            "manufacturer": _s(hw.get("manufacturer")),
            "model": _s(hw.get("model")),
            "form_factor": form_factor(hw.get("manufacturer"), hw.get("model"), _list(hw.get("chassis_types")), hw.get("system_type")),
            "memory_bytes": hw.get("memory_bytes") or None,
            "cpus": [c for c in _list(hw.get("cpus")) if isinstance(c, dict)],
            "disks": [d for d in _list(hw.get("disks")) if isinstance(d, dict)],
            "volumes": [v for v in _list(hw.get("volumes")) if isinstance(v, dict)],
            "bios": hw.get("bios") if isinstance(hw.get("bios"), dict) else None,
        },
        "os": {
            "name": _s(os_.get("name")),
            "version": _s(os_.get("version"), 64),
            "build": build,
            "display_version": _s(os_.get("display_version"), 32),
            "edition": _s(os_.get("edition"), 64),
            "architecture": _s(os_.get("architecture"), 32),
            "role": _ROLES.get(int(os_.get("product_type") or 0)),
            "install_date": _s(os_.get("install_date"), 40),
            "last_boot": _s(os_.get("last_boot"), 40),
        },
        "patches": {
            "hotfix_count": len(hotfixes),
            "last_patch_id": last[1]["id"] if last else None,
            "last_patch_date": last[0].isoformat() if last else None,
            "days_since_last_patch": (now - last[0]).days if last else None,
            "pending_reboot": patches.get("pending_reboot"),
            "hotfixes": hotfixes,
        },
        "security": {
            "firewall": firewall,
            "firewall_all_enabled": all(f["enabled"] for f in firewall) if firewall else None,
            "defender": sec.get("defender") if isinstance(sec.get("defender"), dict) else None,
            "antivirus": antivirus,
            "bitlocker": sec.get("bitlocker"),
            "tpm": sec.get("tpm"),
            "secure_boot": sec.get("secure_boot"),
            "uac_enabled": sec.get("uac_enabled"),
            "rdp_enabled": sec.get("rdp_enabled"),
            "smb1_enabled": sec.get("smb1_enabled"),
            "local_admins": [a for a in _list(sec.get("local_admins")) if isinstance(a, dict)],
            "local_admin_count": sec.get("local_admin_count"),
        },
        "network": {
            "primary_ip": local_ip(),
            "interfaces": interfaces,
            "listening": listening,
        },
        "software": software,
        "unavailable": [] if is_admin else list(NEEDS_ADMIN),
        # What the user chose to share beyond the minimised default.
        "privacy": {
            "user_software": bool(options.get("user_software")),
            "admin_names": bool(options.get("admin_names")),
        },
        "errors": [_s(e, 500) for e in _list(raw.get("errors")) if _s(e, 500)],
    }


def collect(user_software: bool = False, admin_names: bool = False) -> dict[str, Any]:
    return normalize(run_script(user_software=user_software, admin_names=admin_names))
