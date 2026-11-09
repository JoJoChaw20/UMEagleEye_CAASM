"""macOS endpoint inventory: the same normalised document as windows.py and linux.py,
gathered from macOS's own tools (system_profiler, sw_vers, ioreg, sysctl, fdesetup,
socketfilterfw, dscl, ifconfig, lsof) and /Library/Receipts/InstallHistory.plist.

Everything goes through a `System` object so tests can replay recorded output (there is no
Mac in the lab: tests/fixtures/macos holds output of the commands as macOS prints it).
Facts macOS keeps away from programs, or that have no macOS equivalent, are reported as
unknown and left out of the posture score, never guessed: Secure Boot and the Secure
Enclave (reading them needs bputil or a recovery boot), UAC and SMBv1 (macOS's SMB server
settings are not readable from a script). Run the agent as root (its launchd daemon is)
for every listening socket and the hardware UUID.
"""

from __future__ import annotations

import json
import os
import plistlib
import platform
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .. import VERSION
from ..netinfo import lan_ip
from .windows import _VIRTUAL_MODEL, _mac, _s, primary_ip

_LOCAL_ONLY = re.compile(r"^(127\.|::1$)")
# Interfaces macOS makes for itself: tunnels (VPN, iCloud Private Relay), Apple Wireless
# Direct Link, low-latency WLAN, Thunderbolt bridges, the Apple T2/Studio Display links,
# Internet Sharing's access point and VMs' NICs.
_TUNNELS = re.compile(r"^(lo|utun|awdl|llw|bridge|gif|stf|anpi|ap\d|vmenet|vnic|feth|ipsec|ppp)", re.I)
_INSTALL_HISTORY = "/Library/Receipts/InstallHistory.plist"
_SETUP_DONE = "/var/db/.AppleSetupDone"
_XPROTECT = ("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
             "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist")
_SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
# Operating system updates in InstallHistory (not the frequent data files such as
# XProtectPlistConfigData or MRTConfigData, which would make an unpatched Mac look current).
_OS_UPDATE = re.compile(r"^(macOS|Mac OS X|OS X)\b|Security (Response|Update|Improvement)|Rapid Security", re.I)
_XPROTECT_DATA = re.compile(r"^XProtect", re.I)
XPROTECT_FRESH_DAYS = 45                # Apple ships XProtect data every few weeks
# Third-party protection, found by the app it installs (its state is not readable from here).
_AV_APPS = {
    "Microsoft Defender": "Microsoft Defender", "Falcon": "CrowdStrike Falcon", "SentinelOne": "SentinelOne",
    "Sophos Endpoint": "Sophos", "Malwarebytes": "Malwarebytes", "Norton 360": "Norton", "Bitdefender": "Bitdefender",
    "ESET Endpoint Security": "ESET", "ESET Cyber Security": "ESET", "Avast": "Avast", "Intego": "Intego",
}
# Major version -> name, for a readable OS name ("macOS Sonoma 14.5").
_MARKETING = {11: "Big Sur", 12: "Monterey", 13: "Ventura", 14: "Sonoma", 15: "Sequoia", 26: "Tahoe"}
_MAX_SOFTWARE = 5000
_MAX_PATCH_RUNS = 50
_MAX_INTERFACES = 64


class System:
    """Real system access. Every method returns None/False/[] instead of raising."""

    def __init__(self) -> None:
        self.is_root = hasattr(os, "geteuid") and os.geteuid() == 0

    def run(self, argv: list[str], timeout: int = 60) -> Optional[str]:
        """stdout of a successful command; None when missing, failing or timing out."""
        if not (shutil.which(argv[0]) or os.path.exists(argv[0])):
            return None
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout,
                                  env={**os.environ, "LC_ALL": "C", "LANG": "C"})
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", errors="replace")

    def read_bytes(self, path: str) -> Optional[bytes]:
        try:
            return Path(path).read_bytes()
        except OSError:
            return None

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def listdir(self, path: str) -> list[str]:
        try:
            return sorted(os.listdir(path))
        except OSError:
            return []

    def stat_mtime(self, path: str) -> Optional[float]:
        try:
            return os.stat(path).st_mtime
        except OSError:
            return None

    def hostname(self) -> str:
        return socket.gethostname()

    def fqdn(self) -> str:
        return socket.getfqdn()

    def machine(self) -> str:
        return platform.machine()

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def primary_ip(self) -> Optional[str]:
        return lan_ip()


# ── small parsers (pure) ──────────────────────────────────────────────────────
def plist(data: Optional[bytes]) -> Any:
    try:
        return plistlib.loads(data) if data else None
    except Exception:  # noqa: BLE001 - a damaged plist is "unknown"
        return None


def parse_ioreg_platform(text: Optional[str]) -> dict[str, str]:
    """`ioreg -rd1 -c IOPlatformExpertDevice` -> {IOPlatformUUID, IOPlatformSerialNumber, ...}."""
    return {m.group(1): m.group(2) for m in re.finditer(r'"(IOPlatform\w+)"\s*=\s*"([^"]*)"', text or "")}


def parse_sw_vers(text: Optional[str]) -> dict[str, str]:
    out = {}
    for line in (text or "").splitlines():
        key, _, value = line.partition(":")
        if value.strip():
            out[key.strip()] = value.strip()
    return out


def parse_boottime(text: Optional[str]) -> Optional[datetime]:
    """`sysctl -n kern.boottime`: "{ sec = 1731100000, usec = 0 } Sat Nov  9 ..."."""
    m = re.search(r"sec\s*=\s*(\d+)", text or "")
    return datetime.fromtimestamp(int(m.group(1)), timezone.utc) if m else None


def parse_hardware_ports(text: Optional[str]) -> dict[str, str]:
    """`networksetup -listallhardwareports` -> {device: port name} ("en0": "Wi-Fi")."""
    out: dict[str, str] = {}
    port = None
    for line in (text or "").splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            out[line.split(":", 1)[1].strip()] = port
    return out


def parse_ifconfig(text: Optional[str]) -> list[dict[str, Any]]:
    """`ifconfig -a` -> [{name, mac, ipv4, prefixes, ipv6, up}] (netmask 0xffffff00 -> 24)."""
    nics: list[dict[str, Any]] = []
    cur: Optional[dict[str, Any]] = None
    for line in (text or "").splitlines():
        head = re.match(r"^([A-Za-z0-9]+):\s+flags=\w+<([^>]*)>", line)
        if head:
            cur = {"name": head.group(1), "mac": None, "ipv4": [], "prefixes": {}, "ipv6": [],
                   "up": "UP" in head.group(2).split(","), "active": None}
            nics.append(cur)
            continue
        if cur is None:
            continue
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "ether" and len(parts) > 1:
            cur["mac"] = parts[1].lower()
        elif parts[0] == "inet" and len(parts) > 1:
            cur["ipv4"].append(parts[1])
            if "netmask" in parts:
                mask = parts[parts.index("netmask") + 1]
                try:
                    cur["prefixes"][parts[1]] = bin(int(mask, 16)).count("1")
                except ValueError:
                    pass
        elif parts[0] == "inet6" and len(parts) > 1:
            cur["ipv6"].append(parts[1].split("%")[0])
        elif parts[0] == "status:" and len(parts) > 1:
            cur["active"] = parts[1] == "active"
    return nics


def parse_lsof(text: Optional[str]) -> list[dict[str, Any]]:
    """`lsof -nP -i -F pcPn` (TCP in LISTEN and bound UDP) -> listening sockets like linux.parse_ss."""
    out: list[dict[str, Any]] = []
    pid: Optional[int] = None
    command: Optional[str] = None
    proto: Optional[str] = None
    for line in (text or "").splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            pid, command, proto = int(value) if value.isdigit() else None, None, None
        elif tag == "c":
            command = value
        elif tag == "P":
            proto = value.lower()
        elif tag == "n" and proto in ("tcp", "udp") and "->" not in value:
            addr, _, port = value.rpartition(":")
            addr = addr.strip("[]").split("%")[0]
            if addr in ("*", ""):
                addr = "0.0.0.0"
            if port.isdigit():
                out.append({"protocol": proto, "address": addr, "port": int(port), "process": command, "pid": pid})
    return out


def publisher_of(app: dict[str, Any]) -> Optional[str]:
    """An app's publisher from its code signature ("Developer ID Application: Google LLC (EQHXZ8M8AV)")."""
    signed = app.get("signed_by") or []
    first = str(signed[0]) if signed else ""
    m = re.match(r"^(?:Developer ID Application|Apple Development|Apple Distribution):\s*(.+?)\s*(?:\([A-Z0-9]{10}\))?$", first)
    if m:
        return _s(m.group(1))
    if app.get("obtained_from") == "apple" or first in ("Software Signing", "Apple Mac OS Application Signing"):
        return "Apple Inc." if app.get("obtained_from") == "apple" or first == "Software Signing" else None
    return None


_ARCH = {"arch_arm_i64": "universal", "arch_arm": "arm64", "arch_i64": "x86_64", "arch_ios": "arm64", "arch_other": None}


# ── sections ─────────────────────────────────────────────────────────────────
def _identity(sys_: System, unavailable: list[str]) -> dict[str, Any]:
    ioreg = parse_ioreg_platform(sys_.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]))
    uuid = ioreg.get("IOPlatformUUID")
    if not uuid:
        unavailable.append("hardware_uuid")
    local = (sys_.run(["scutil", "--get", "LocalHostName"]) or "").strip()
    ad = sys_.run(["dsconfigad", "-show"]) or ""
    m = re.search(r"Active Directory Domain\s*=\s*(\S+)", ad)
    fqdn = sys_.fqdn() or ""
    return {
        "hostname": _s(local or sys_.hostname().split(".")[0]), "dns_hostname": _s(fqdn),
        "domain": _s(m.group(1) if m else None), "part_of_domain": bool(m), "workgroup": None,
        "machine_id": None, "smbios_uuid": _s(uuid, 64),
        "serial_number": _s(ioreg.get("IOPlatformSerialNumber"), 128),
    }


def _hardware(sys_: System) -> dict[str, Any]:
    data = json.loads(sys_.run(["system_profiler", "SPHardwareDataType", "-json"], timeout=60) or "{}")
    hw = (data.get("SPHardwareDataType") or [{}])[0]
    model = hw.get("machine_model") or hw.get("model_number")
    name = hw.get("machine_name") or ""
    virtual = bool(_VIRTUAL_MODEL.search(f"{model or ''} {name}"))
    cpu = hw.get("chip_type") or hw.get("cpu_type") or (sys_.run(["sysctl", "-n", "machdep.cpu.brand_string"]) or "").strip()
    cores = (sys_.run(["sysctl", "-n", "hw.physicalcpu"]) or "").strip()
    threads = (sys_.run(["sysctl", "-n", "hw.logicalcpu"]) or "").strip()
    memory = (sys_.run(["sysctl", "-n", "hw.memsize"]) or "").strip()
    disks: dict[str, dict[str, Any]] = {}
    storage = json.loads(sys_.run(["system_profiler", "SPStorageDataType", "-json"], timeout=60) or "{}")
    for vol in storage.get("SPStorageDataType") or []:
        drive = vol.get("physical_drive") or {}
        dev = drive.get("device_name")
        if not dev or drive.get("is_internal_disk") == "no":
            continue
        size = vol.get("size_in_bytes")
        cur = disks.setdefault(dev, {"model": _s(dev), "size_bytes": None,
                                     "media": {"ssd": "SSD", "rotational": "HDD"}.get(str(drive.get("medium_type")).lower())})
        if isinstance(size, int) and size > (cur["size_bytes"] or 0):
            cur["size_bytes"] = size
    return {
        "manufacturer": "Apple Inc.", "model": _s(f"{name} ({model})" if name and model else name or model),
        "form_factor": "virtual" if virtual else "laptop" if "book" in name.lower() else "desktop" if name else "unknown",
        "memory_bytes": int(memory) if memory.isdigit() else None,
        "cpus": [{"name": _s(cpu), "cores": int(cores) if cores.isdigit() else None,
                  "threads": int(threads) if threads.isdigit() else None}] if cpu else [],
        "disks": list(disks.values()), "volumes": [],
        "bios": {"vendor": "Apple", "version": _s(hw.get("boot_rom_version"))} if hw.get("boot_rom_version") else None,
    }


def _os(sys_: System) -> dict[str, Any]:
    vers = parse_sw_vers(sys_.run(["sw_vers"]))
    version = vers.get("ProductVersion")
    major = int(version.split(".")[0]) if version and version.split(".")[0].isdigit() else None
    product = vers.get("ProductName") or "macOS"
    name = f"{product} {_MARKETING[major]} {version}" if major in _MARKETING else f"{product} {version or ''}".strip()
    boot = parse_boottime(sys_.run(["sysctl", "-n", "kern.boottime"]))
    setup = sys_.stat_mtime(_SETUP_DONE)
    return {
        "name": _s(name), "version": _s(version, 64), "build": _s(vers.get("BuildVersion"), 32),
        "display_version": _s(version, 32), "edition": None, "architecture": _s(sys_.machine(), 32),
        "role": "workstation",                  # macOS is a desktop OS (macOS Server is long gone)
        "install_date": datetime.fromtimestamp(setup, timezone.utc).isoformat() if setup else None,
        "last_boot": boot.replace(microsecond=0).isoformat() if boot else None,
    }


def install_history(sys_: System) -> list[dict[str, Any]]:
    items = plist(sys_.read_bytes(_INSTALL_HISTORY))
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def _when(item: dict[str, Any]) -> Optional[datetime]:
    d = item.get("date")
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)) if isinstance(d, datetime) else None


def _patches(history: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    runs = sorted(((w, i) for i in history if _OS_UPDATE.search(str(i.get("displayName") or ""))
                   for w in [_when(i)] if w), key=lambda x: x[0], reverse=True)
    last = runs[0] if runs else None
    def label(i: dict[str, Any]) -> Optional[str]:
        name, version = str(i.get("displayName") or ""), str(i.get("displayVersion") or "")
        return _s(name if not version or version in name else f"{name} {version}")
    return {
        "hotfix_count": len(runs),
        "last_patch_id": label(last[1]) if last else None,
        "last_patch_date": last[0].isoformat() if last else None,
        "days_since_last_patch": (now - last[0]).days if last else None,
        "pending_reboot": None,                 # only `softwareupdate -l` knows, and it asks Apple's servers
        "hotfixes": [{"id": label(i), "description": None, "installed_on": w.isoformat()} for w, i in runs[:_MAX_PATCH_RUNS]],
    }


def _firewall(sys_: System) -> tuple[list[dict[str, Any]], Optional[bool]]:
    state = sys_.run([_SOCKETFILTERFW, "--getglobalstate"])
    if state is None:
        return [], None
    on = bool(re.search(r"enabled|State = [12]", state, re.I)) and "disabled" not in state.lower()
    return [{"profile": "Application Firewall", "enabled": on}], on


def _antivirus(sys_: System, history: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    out = []
    info = next((p for p in (plist(sys_.read_bytes(f)) for f in _XPROTECT) if isinstance(p, dict)), None)
    if info is not None:
        dates = [w for i in history if _XPROTECT_DATA.match(str(i.get("displayName") or "")) for w in [_when(i)] if w]
        fresh = (now - max(dates)).days <= XPROTECT_FRESH_DAYS if dates else None
        out.append({"name": f"XProtect {info.get('CFBundleShortVersionString') or ''}".strip(), "enabled": True, "up_to_date": fresh})
    apps = set(sys_.listdir("/Applications"))
    for app, product in _AV_APPS.items():
        if f"{app}.app" in apps and not any(a["name"] == product for a in out):
            out.append({"name": product, "enabled": None, "up_to_date": None})
    return out


def _filevault(sys_: System) -> Optional[list[dict[str, Any]]]:
    status = sys_.run(["fdesetup", "status"])
    if status is None:
        return None
    on = bool(re.search(r"FileVault is On", status))
    return [{"volume": "/", "protection": "on" if on and "Decryption in progress" not in status else "off"}]


def _local_admins(sys_: System) -> list[str]:
    out = sys_.run(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"]) or ""
    names = out.split(":", 1)[1].split() if ":" in out else []
    return sorted(n for n in set(names) if n != "root")


def _interfaces(sys_: System) -> list[dict[str, Any]]:
    ports = parse_hardware_ports(sys_.run(["networksetup", "-listallhardwareports"]))
    nics = []
    for n in parse_ifconfig(sys_.run(["ifconfig", "-a"])):
        name = n["name"]
        virtual = bool(_TUNNELS.match(name)) or (name not in ports and not name.startswith("en"))
        port = ports.get(name)
        if port and re.search(r"bridge|thunderbolt bridge", port, re.I):
            virtual = True
        nics.append({
            "name": name, "description": port, "mac": _mac(n["mac"]),
            "status": "Up" if n["active"] or (n["active"] is None and n["up"] and n["ipv4"]) else "Down",
            "virtual": virtual,
            "physical": not virtual and n["mac"] is not None and n["mac"] != "00:00:00:00:00:00",
            "speed_bps": None,
            "ipv4": n["ipv4"][:32], "ipv6": n["ipv6"][:32],
        })
    nics.sort(key=lambda n: (not n["physical"], n["virtual"]))
    return nics[:_MAX_INTERFACES]


def _software(sys_: System, user_software: bool) -> list[dict[str, Any]]:
    apps: list[dict[str, Any]] = []
    data = json.loads(sys_.run(["system_profiler", "SPApplicationsDataType", "-json", "-detailLevel", "mini"],
                               timeout=240) or "{}")
    for app in data.get("SPApplicationsDataType") or []:
        path = str(app.get("path") or "")
        if path.startswith(("/System/", "/Library/Apple/")):
            continue                            # part of macOS: its version is the OS version
        user = path.startswith("/Users/")
        if user and not user_software:
            continue
        modified = app.get("lastModified")
        apps.append({"name": app.get("_name"), "version": app.get("version"), "publisher": publisher_of(app),
                     "install_date": str(modified)[:10] if modified else None,
                     "scope": "user" if user else "machine", "arch": _ARCH.get(str(app.get("arch_kind")))})
    # Homebrew: one folder per formula and version under its Cellar
    for cellar in ("/opt/homebrew/Cellar", "/usr/local/Cellar"):
        for formula in sys_.listdir(cellar):
            versions = sys_.listdir(f"{cellar}/{formula}")
            if versions:
                apps.append({"name": formula, "version": versions[-1], "publisher": "Homebrew",
                             "install_date": None, "scope": "machine", "arch": None})
    return [{**a, "name": _s(a["name"]), "version": _s(a["version"], 100), "publisher": _s(a["publisher"]),
             "arch": _s(a["arch"], 16)} for a in apps if _s(a["name"])][:_MAX_SOFTWARE]


# ── document ─────────────────────────────────────────────────────────────────
def build_inventory(sys_: System, user_software: bool = False, admin_names: bool = False) -> dict[str, Any]:
    now = sys_.now()
    unavailable: list[str] = []
    errors: list[str] = []

    def section(name: str, fn: Any, default: Any) -> Any:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - one broken section never loses the rest
            errors.append(f"{name}: {exc}")
            return default

    history = section("install_history", lambda: install_history(sys_), [])
    identity = section("identity", lambda: _identity(sys_, unavailable), {})
    firewall, firewall_on = section("firewall", lambda: _firewall(sys_), ([], None))
    admins = section("local_admins", lambda: _local_admins(sys_), [])

    raw = sys_.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcPn"]) or ""
    raw += "\n" + (sys_.run(["lsof", "-nP", "-iUDP", "-F", "pcPn"]) or "")
    if not sys_.is_root:
        unavailable.append("listening_other_users")       # lsof shows only this user's sockets
    listening = []
    for entry in section("listening", lambda: parse_lsof(raw), []):
        local_only = bool(_LOCAL_ONLY.match(entry["address"]))
        listening.append({**entry, "pid": None if local_only else entry["pid"],
                          "process": None if local_only else entry["process"], "local_only": local_only})
    listening = sorted({(e["protocol"], e["address"], e["port"]): e for e in listening}.values(),
                       key=lambda e: (e["protocol"], e["port"], e["address"]))
    # Screen Sharing (VNC, 5900) or Apple Remote Desktop (3283) answering beyond this Mac
    remote = any(e["port"] in (5900, 3283) and not e["local_only"] for e in listening) if listening else None

    software = section("software", lambda: _software(sys_, user_software), [])
    seen, unique = set(), []
    for app in software:
        key = (app["name"].lower(), app["version"] or "", (app["publisher"] or "").lower())
        if key not in seen:
            seen.add(key)
            unique.append(app)
    unique.sort(key=lambda a: (a["name"].lower(), a["version"] or ""))

    interfaces = section("interfaces", lambda: _interfaces(sys_), [])
    return {
        "schema": 1,
        "platform": "darwin",
        "collected_at": now.isoformat(),
        "agent_version": VERSION,
        "is_admin": sys_.is_root,
        "identity": identity,
        "hardware": section("hardware", lambda: _hardware(sys_), {}),
        "os": section("os", lambda: _os(sys_), {}),
        "patches": section("patches", lambda: _patches(history, now), {}),
        "security": {
            "firewall": firewall,
            "firewall_all_enabled": firewall_on,
            "antivirus": section("antivirus", lambda: _antivirus(sys_, history, now), []),
            "disk_encryption": section("disk_encryption", lambda: _filevault(sys_), None),
            "tpm": None,                       # Secure Enclave: not readable from a script
            "secure_boot": None,               # needs bputil or a recovery boot
            "uac_enabled": None,               # no macOS equivalent: left out of the score
            "rdp_enabled": remote,
            "smb1_enabled": None,
            "local_admins": [{"name": n} for n in admins] if admin_names else [],
            "local_admin_count": len(admins),
        },
        "network": {
            "primary_ip": primary_ip(sys_.primary_ip(), interfaces),
            "interfaces": interfaces,
            "listening": listening,
        },
        "software": unique,
        "unavailable": unavailable,
        "privacy": {"user_software": bool(user_software), "admin_names": bool(admin_names)},
        "errors": [_s(e, 500) for e in errors],
    }


def collect(user_software: bool = False, admin_names: bool = False) -> dict[str, Any]:
    return build_inventory(System(), user_software=user_software, admin_names=admin_names)
