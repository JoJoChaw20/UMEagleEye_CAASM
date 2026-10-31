"""Linux endpoint inventory (Phase C3): the same normalised document as windows.py,
gathered from /proc, /sys, /etc and standard tools (ss, ip, lsblk, dpkg-query or rpm).

Everything goes through a `System` object so tests can replay recorded files and
command output. Facts that need root (SMBIOS UUID and serial, nftables rules,
process names of other users' sockets) are reported as unavailable when the agent
runs unprivileged; nothing is guessed. The SMBIOS UUID is what the server's VM-clone
guard compares, so run the agent as root (as its systemd service does) for full
identity.
"""

from __future__ import annotations

import gzip
import json
import os
import platform
import re
import shutil
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from .. import VERSION
from ..netinfo import local_ip
from .windows import _mac, _s, form_factor, primary_ip

DMI = "/sys/class/dmi/id"
_VIRTUAL_NIC = re.compile(r"^(lo|docker\d*|veth|br-|virbr|vmnet|vboxnet|tun|tap|wg|zt|tailscale|cni|flannel|vxlan|kube|lxc|lxd|podman|dummy|bond|team|sit|ip6tnl|gre)", re.I)
_LOCAL_ONLY = re.compile(r"^(127\.|::1$)")
_ADMIN_GROUPS = ("sudo", "wheel", "admin")
_SECURE_BOOT_VAR = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
_MAX_SOFTWARE = 5000
_MAX_PATCH_RUNS = 50
_MAX_INTERFACES = 64


class System:
    """Real system access. Every method returns None/False/[] instead of raising."""

    def __init__(self) -> None:
        self.is_root = hasattr(os, "geteuid") and os.geteuid() == 0

    def read(self, path: str) -> Optional[str]:
        try:
            if path.endswith(".gz"):
                with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            return Path(path).read_text(encoding="utf-8", errors="replace")
        except (OSError, EOFError):
            return None

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

    def which(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def run(self, argv: list[str], timeout: int = 60) -> Optional[str]:
        """stdout of a successful command; None when missing, failing or timing out."""
        if not self.which(argv[0]):
            return None
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout,
                                  env={**os.environ, "LC_ALL": "C", "LANG": "C"})
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", errors="replace")

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

    def kernel(self) -> str:
        return platform.release()

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def uptime_seconds(self) -> Optional[float]:
        text = self.read("/proc/uptime")
        try:
            return float(text.split()[0]) if text else None
        except (ValueError, IndexError):
            return None

    def primary_ip(self) -> Optional[str]:
        return local_ip()


# ── small parsers (pure) ──────────────────────────────────────────────────────
def parse_os_release(text: Optional[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def parse_meminfo_total(text: Optional[str]) -> Optional[int]:
    m = re.search(r"^MemTotal:\s+(\d+)\s*kB", text or "", re.M)
    return int(m.group(1)) * 1024 if m else None


def parse_cpuinfo(text: Optional[str]) -> list[dict[str, Any]]:
    blocks = [b for b in (text or "").split("\n\n") if b.strip()]
    if not blocks:
        return []
    fields = [dict((k.strip(), v.strip()) for k, _, v in (ln.partition(":") for ln in b.splitlines()) if k.strip()) for b in blocks]
    by_socket: dict[str, list[dict[str, str]]] = {}
    for f in fields:
        by_socket.setdefault(f.get("physical id", "0"), []).append(f)
    cpus = []
    for procs in by_socket.values():
        first = procs[0]
        cores = int(first["cpu cores"]) if first.get("cpu cores", "").isdigit() else len({p.get("core id") for p in procs}) or len(procs)
        cpus.append({"name": _s(first.get("model name") or first.get("Model") or first.get("Hardware")),
                     "cores": cores, "threads": len(procs)})
    return cpus


def parse_apt_history(texts: list[str]) -> list[datetime]:
    """Start dates of apt runs that upgraded packages (newest first)."""
    runs: list[datetime] = []
    for text in texts:
        for block in text.split("\n\n"):
            m = re.search(r"^Start-Date:\s*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})", block, re.M)
            if m and re.search(r"^Upgrade:", block, re.M):
                try:
                    runs.append(datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}").replace(tzinfo=timezone.utc))
                except ValueError:
                    pass
    return sorted(set(runs), reverse=True)


def parse_dnf_rpm_log(text: Optional[str]) -> list[datetime]:
    runs = set()
    for m in re.finditer(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S*\s+\w+\s+Upgrade[d]?:", text or "", re.M):
        try:
            runs.add(datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc).replace(second=0))
        except ValueError:
            pass
    return sorted(runs, reverse=True)


def parse_ss(text: Optional[str]) -> list[dict[str, Any]]:
    """`ss -H -tulnp` lines -> listening sockets."""
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ("tcp", "udp"):
            continue
        if parts[0] == "tcp" and parts[1] != "LISTEN":
            continue
        local = parts[4]
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%")[0]
        if addr in ("*", ""):
            addr = "0.0.0.0"
        if not port.isdigit():
            continue
        proc = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        out.append({"protocol": parts[0], "address": addr, "port": int(port),
                    "process": proc.group(1) if proc else None, "pid": int(proc.group(2)) if proc else None})
    return out


def _maintainer_name(value: str) -> Optional[str]:
    """'Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>' -> 'Ubuntu Developers' (no addresses)."""
    return _s(re.sub(r"\s*<[^>]*>", "", value or "")) or None


# ── sections ─────────────────────────────────────────────────────────────────
def _identity(sys_: System, unavailable: list[str]) -> dict[str, Any]:
    fqdn = sys_.fqdn() or ""
    hostname = sys_.hostname()
    domain = fqdn.split(".", 1)[1] if "." in fqdn and not fqdn.endswith(".localdomain") else None
    realm = (sys_.run(["realm", "list", "--name-only"]) or "").strip()
    uuid = (sys_.read(f"{DMI}/product_uuid") or "").strip() or None
    if uuid is None:
        unavailable.append("hardware_uuid")
    return {
        "hostname": _s(hostname), "dns_hostname": _s(fqdn), "domain": _s(realm.splitlines()[0] if realm else domain),
        "part_of_domain": bool(realm), "workgroup": None,
        "machine_id": _s((sys_.read("/etc/machine-id") or "").strip(), 64),
        "smbios_uuid": _s(uuid, 64),
        "serial_number": _s((sys_.read(f"{DMI}/product_serial") or "").strip(), 128),
    }


def _hardware(sys_: System) -> dict[str, Any]:
    vendor = (sys_.read(f"{DMI}/sys_vendor") or "").strip() or None
    model = (sys_.read(f"{DMI}/product_name") or "").strip() or None
    chassis = (sys_.read(f"{DMI}/chassis_type") or "").strip()
    disks = []
    lsblk = sys_.run(["lsblk", "-J", "-b", "-d", "-o", "NAME,SIZE,MODEL,ROTA,TYPE"])
    try:
        for dev in (json.loads(lsblk).get("blockdevices") or []) if lsblk else []:
            if dev.get("type") == "disk":
                rota = dev.get("rota")
                disks.append({"model": _s(dev.get("model")), "size_bytes": int(dev.get("size") or 0) or None,
                              "media": None if rota is None else ("HDD" if str(rota) in ("1", "True", "true") else "SSD")})
    except (ValueError, AttributeError):
        pass
    bios_vendor = (sys_.read(f"{DMI}/bios_vendor") or "").strip() or None
    bios_version = (sys_.read(f"{DMI}/bios_version") or "").strip() or None
    return {
        "manufacturer": _s(vendor), "model": _s(model),
        "form_factor": form_factor(vendor, model, [chassis] if chassis else [], None),
        "memory_bytes": parse_meminfo_total(sys_.read("/proc/meminfo")),
        "cpus": parse_cpuinfo(sys_.read("/proc/cpuinfo")),
        "disks": disks, "volumes": [],
        "bios": {"vendor": _s(bios_vendor), "version": _s(bios_version)} if bios_vendor or bios_version else None,
    }


def _os(sys_: System) -> dict[str, Any]:
    rel = parse_os_release(sys_.read("/etc/os-release"))
    # A desktop is installed when there are session files or a display manager. The
    # default systemd target is no evidence: Ubuntu Server also boots graphical.target.
    has_desktop = any(sys_.listdir(d) for d in ("/usr/share/xsessions", "/usr/share/wayland-sessions")) or \
        sys_.exists("/etc/systemd/system/display-manager.service")
    uptime = sys_.uptime_seconds()
    installer = sys_.stat_mtime("/var/log/installer") or sys_.stat_mtime("/root")
    return {
        "name": _s(rel.get("PRETTY_NAME") or rel.get("NAME")),
        "version": _s(rel.get("VERSION_ID"), 64),
        "build": _s(sys_.kernel(), 32),
        "display_version": _s(rel.get("VERSION_ID"), 32),
        "edition": _s(rel.get("VARIANT") or rel.get("ID"), 64),
        "architecture": _s(sys_.machine(), 32),
        # Without a desktop session a Linux machine is run as a server.
        "role": "workstation" if has_desktop else "server",
        "install_date": datetime.fromtimestamp(installer, timezone.utc).isoformat() if installer else None,
        "last_boot": (sys_.now() - timedelta(seconds=round(uptime))).replace(microsecond=0).isoformat() if uptime else None,
    }


def _patches(sys_: System, now: datetime) -> dict[str, Any]:
    runs: list[datetime] = []
    manager = None
    if sys_.exists("/var/log/apt/history.log") or sys_.listdir("/var/log/apt"):
        manager = "apt"
        texts = [t for name in sys_.listdir("/var/log/apt") if name.startswith("history.log")
                 for t in [sys_.read(f"/var/log/apt/{name}")] if t]
        runs = parse_apt_history(texts)
    elif sys_.exists("/var/log/dnf.rpm.log"):
        manager = "dnf"
        runs = parse_dnf_rpm_log(sys_.read("/var/log/dnf.rpm.log"))
    pending: Optional[bool] = None
    if manager == "apt":
        pending = sys_.exists("/var/run/reboot-required") or sys_.exists("/run/reboot-required")
    last = runs[0] if runs else None
    return {
        "hotfix_count": len(runs),
        "last_patch_id": f"{manager} upgrade" if last else None,
        "last_patch_date": last.isoformat() if last else None,
        "days_since_last_patch": (now - last).days if last else None,
        "pending_reboot": pending,
        "hotfixes": [{"id": f"{manager} upgrade", "description": None, "installed_on": r.isoformat()} for r in runs[:_MAX_PATCH_RUNS]],
    }


def _firewall(sys_: System) -> tuple[list[dict[str, Any]], Optional[bool]]:
    profiles = []
    ufw_conf = sys_.read("/etc/ufw/ufw.conf")
    if ufw_conf is not None:
        m = re.search(r"^\s*ENABLED\s*=\s*(\w+)", ufw_conf, re.M)
        profiles.append({"profile": "ufw", "enabled": bool(m and m.group(1).lower() == "yes")})
    if sys_.which("firewall-cmd") or sys_.exists("/usr/lib/systemd/system/firewalld.service"):
        profiles.append({"profile": "firewalld", "enabled": (sys_.run(["systemctl", "is-active", "firewalld"]) or "").strip() == "active"})
    if any(p["enabled"] for p in profiles):
        return profiles, True
    # No front end on: plain nftables rules can still filter (reading them needs root).
    if sys_.is_root:
        ruleset = sys_.run(["nft", "list", "ruleset"]) or ""
        filtering = bool(re.search(r"hook input[^;]*;\s*policy drop", ruleset)) or (
            "hook input" in ruleset and bool(re.search(r"\b(drop|reject)\b", ruleset)))
        profiles.append({"profile": "nftables", "enabled": filtering})
        return profiles, filtering
    return profiles, (False if profiles else None)


def _disk_encryption(sys_: System) -> Optional[list[dict[str, Any]]]:
    """Mounted system/data volumes and whether a LUKS (crypt) layer sits under them."""
    out = sys_.run(["lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINTS"]) or sys_.run(["lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINT"])
    if not out:
        return None
    try:
        tree = json.loads(out).get("blockdevices") or []
    except ValueError:
        return None
    volumes: list[dict[str, Any]] = []

    def walk(node: dict[str, Any], crypt_above: bool) -> None:
        crypt = crypt_above or node.get("type") == "crypt"
        mounts = node.get("mountpoints") if "mountpoints" in node else [node.get("mountpoint")]
        for mp in [m for m in (mounts or []) if m]:
            if mp in ("/", "/home", "/var", "/srv") and not any(v["volume"] == mp for v in volumes):
                volumes.append({"volume": mp, "protection": "on" if crypt else "off"})
        for child in node.get("children") or []:
            walk(child, crypt)

    for dev in tree:
        if dev.get("type") not in ("loop", "rom"):
            walk(dev, False)
    return volumes or None


def _secure_boot(sys_: System) -> Optional[bool]:
    if not sys_.exists("/sys/firmware/efi"):
        return False                       # legacy BIOS boot: Secure Boot is not possible
    state = sys_.run(["mokutil", "--sb-state"])
    if state:
        return "enabled" in state.lower()
    raw = sys_.read_bytes(_SECURE_BOOT_VAR)
    return bool(raw[-1]) if raw else None


def _service_active(sys_: System, *names: str) -> bool:
    return any((sys_.run(["systemctl", "is-active", n]) or "").strip() == "active" for n in names)


def _smb1(sys_: System) -> Optional[bool]:
    if not (sys_.which("smbd") or sys_.exists("/usr/sbin/smbd")):
        return False                       # no SMB server, so no SMBv1
    conf = sys_.read("/etc/samba/smb.conf")
    if conf is None:
        return None
    m = re.search(r"^\s*(?:server\s+)?min\s+protocol\s*=\s*(\S+)", conf, re.M | re.I)
    return bool(m and m.group(1).upper() in ("NT1", "LANMAN1", "LANMAN2", "CORE", "COREPLUS"))


def _local_admins(sys_: System) -> list[str]:
    members: set[str] = set()
    for line in (sys_.read("/etc/group") or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[0] in _ADMIN_GROUPS:
            members.update(m for m in parts[3].split(",") if m)
    return sorted(members)


def _antivirus(sys_: System) -> list[dict[str, Any]]:
    if not (sys_.which("clamscan") or sys_.which("clamd") or sys_.exists("/usr/sbin/clamd")):
        return []
    enabled = _service_active(sys_, "clamav-daemon", "clamd@scan", "clamd")
    updater = _service_active(sys_, "clamav-freshclam", "clamav-freshclam.service")
    return [{"name": "ClamAV", "enabled": enabled, "up_to_date": updater or None}]


def _interfaces(sys_: System) -> list[dict[str, Any]]:
    addrs: dict[str, dict[str, list[str]]] = {}
    out = sys_.run(["ip", "-j", "addr"])
    try:
        for link in json.loads(out) if out else []:
            entry = addrs.setdefault(link.get("ifname", ""), {"ipv4": [], "ipv6": []})
            for a in link.get("addr_info") or []:
                key = "ipv4" if a.get("family") == "inet" else "ipv6"
                if a.get("local"):
                    entry[key].append(a["local"])
    except ValueError:
        pass
    nics = []
    for name in sys_.listdir("/sys/class/net"):
        base = f"/sys/class/net/{name}"
        mac = _mac((sys_.read(f"{base}/address") or "").strip())
        virtual = bool(_VIRTUAL_NIC.match(name)) or not sys_.exists(f"{base}/device")
        wireless = sys_.exists(f"{base}/wireless") or sys_.exists(f"{base}/phy80211")
        speed = (sys_.read(f"{base}/speed") or "").strip()
        status = (sys_.read(f"{base}/operstate") or "").strip()
        nics.append({
            "name": name, "description": "wireless" if wireless else None, "mac": mac,
            "status": {"up": "Up", "down": "Down"}.get(status, status.capitalize() or None),
            "virtual": virtual,
            "physical": not virtual and mac is not None and mac != "00:00:00:00:00:00",
            "speed_bps": int(speed) * 1_000_000 if speed.isdigit() and int(speed) > 0 else None,
            "ipv4": addrs.get(name, {}).get("ipv4", [])[:32], "ipv6": addrs.get(name, {}).get("ipv6", [])[:32],
        })
    # The server accepts at most 64 interfaces: on container hosts keep the real NICs first.
    nics.sort(key=lambda n: (not n["physical"], n["virtual"]))
    return nics[:_MAX_INTERFACES]


def _software(sys_: System) -> list[dict[str, Any]]:
    apps: list[dict[str, Any]] = []
    dpkg = sys_.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\t${Architecture}\t${db:Status-Status}\n"])
    for line in (dpkg or "").splitlines():
        parts = line.split("\t")
        if len(parts) >= 5 and parts[4] == "installed":
            apps.append({"name": parts[0], "version": parts[1], "publisher": _maintainer_name(parts[2]),
                         "install_date": None, "scope": "machine", "arch": parts[3]})
    rpm = None if dpkg else sys_.run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{ARCH}\t%{INSTALLTIME}\n"])
    for line in (rpm or "").splitlines():
        parts = line.split("\t")
        if len(parts) >= 5:
            installed = datetime.fromtimestamp(int(parts[4]), timezone.utc).date().isoformat() if parts[4].isdigit() else None
            apps.append({"name": parts[0], "version": parts[1], "publisher": None if parts[2] == "(none)" else _s(parts[2]),
                         "install_date": installed, "scope": "machine", "arch": parts[3]})
    for line in (sys_.run(["snap", "list"]) or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            apps.append({"name": parts[0], "version": parts[1], "publisher": parts[4].rstrip("✓*"),
                         "install_date": None, "scope": "machine", "arch": None})
    # Field limits match the server's (a longer value would get the whole inventory refused).
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

    identity = section("identity", lambda: _identity(sys_, unavailable), {})
    firewall, firewall_on = section("firewall", lambda: _firewall(sys_), ([], None))
    admins = section("local_admins", lambda: _local_admins(sys_), [])
    tpm_present = sys_.exists("/sys/class/tpm/tpm0")

    listening = []
    for entry in section("listening", lambda: parse_ss(sys_.run(["ss", "-H", "-tulnp"])), []):
        local_only = bool(_LOCAL_ONLY.match(entry["address"]))
        listening.append({**entry, "pid": None if local_only else entry["pid"],
                          "process": None if local_only else entry["process"], "local_only": local_only})
    listening = sorted({(e["protocol"], e["address"], e["port"]): e for e in listening}.values(),
                       key=lambda e: (e["protocol"], e["port"], e["address"]))

    software = section("software", lambda: _software(sys_), [])
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
        "platform": "linux",
        "collected_at": now.isoformat(),
        "agent_version": VERSION,
        "is_admin": sys_.is_root,
        "identity": identity,
        "hardware": section("hardware", lambda: _hardware(sys_), {}),
        "os": section("os", lambda: _os(sys_), {}),
        "patches": section("patches", lambda: _patches(sys_, now), {}),
        "security": {
            "firewall": firewall,
            "firewall_all_enabled": firewall_on,
            "antivirus": section("antivirus", lambda: _antivirus(sys_), []),
            "disk_encryption": section("disk_encryption", lambda: _disk_encryption(sys_), None),
            "tpm": {"present": tpm_present, "ready": tpm_present},
            "secure_boot": section("secure_boot", lambda: _secure_boot(sys_), None),
            "uac_enabled": None,                                  # no Linux equivalent: left out of the score
            "rdp_enabled": section("rdp", lambda: _service_active(sys_, "xrdp", "gnome-remote-desktop", "vncserver"), None),
            "smb1_enabled": section("smb1", lambda: _smb1(sys_), None),
            "local_admins": [{"name": n} for n in admins] if admin_names else [],
            "local_admin_count": len(admins),
        },
        "network": {
            # Not an address on a virtual interface (docker0, virbr0, a tap): same rule as Windows.
            "primary_ip": primary_ip(sys_.primary_ip(), interfaces),
            "interfaces": interfaces,
            "listening": listening,
        },
        "software": unique,
        "unavailable": unavailable,
        # Per-user installs (flatpak --user, ~/.local) are not collected on Linux.
        "privacy": {"user_software": False, "admin_names": bool(admin_names)},
        "errors": [_s(e, 500) for e in errors],
    }


def collect(user_software: bool = False, admin_names: bool = False) -> dict[str, Any]:
    return build_inventory(System(), user_software=user_software, admin_names=admin_names)
