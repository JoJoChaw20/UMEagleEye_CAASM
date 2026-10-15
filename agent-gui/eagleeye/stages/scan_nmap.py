"""Active scan: discover hosts and fingerprint them (ports, services, OS, hostname).

The Nmap invocation and result parsing are a faithful port of the original agent's
run_nmap(), so both produced the same host data (checked by a parity test until the original
agent was retired in 2.0.2; tests/test_scan.py covers the parser).
When Nmap is not installed the stage says so and falls back to a built-in sweep.
"""

from __future__ import annotations

import errno
import ipaddress
import logging
import platform
import re
import shlex
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from xml.etree import ElementTree

from .. import deps
from ..pipeline.record import HostRecord
from ..pipeline.runner import Cancelled, PipelineContext, Stage

log = logging.getLogger("eagleeye.scan")

# Same ports and scripts as the original agent.
NMAP_ARGS = (
    "-sV -T4 "
    "-p 22,23,80,139,161,443,445,3389,8080,8443,3306,5432,6379,27017 "
    "--script smb-os-discovery,banner "
    "--script-timeout 10s"
)
NMAP_TIMEOUT_SECONDS = 3600
MAX_PREFIX = 16            # refuse targets larger than a /16
BUILTIN_MAX_HOSTS = 1024   # the built-in sweep is for small networks only


def validate_target(target: str, max_hosts: Optional[int] = None) -> str:
    """Accept only an IPv4 address or CIDR range. The value reaches the Nmap command
    line, so anything else (names, flags, spaces) is rejected."""
    value = (target or "").strip()
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError(
            f"invalid scan target {target!r}: expected an IPv4 address or CIDR range such as 192.168.1.0/24"
        ) from None
    if net.version != 4:
        raise ValueError("only IPv4 targets are supported")
    if net.prefixlen < MAX_PREFIX:
        raise ValueError(f"target {value} is larger than a /{MAX_PREFIX}; split it into smaller scans")
    if max_hosts is not None and net.num_addresses > max_hosts:
        raise ValueError(
            f"target {value} has {net.num_addresses} addresses; without Nmap the built-in sweep "
            f"is limited to {max_hosts}. Install Nmap or scan a smaller range"
        )
    return value


def parse_smb_os_discovery(script_output: str) -> dict[str, str]:
    """OS/hostname fields from the smb-os-discovery NSE script output."""
    result: dict[str, str] = {}
    if not script_output:
        return result
    for line in script_output.splitlines():
        line = line.strip()
        if line.startswith("OS:"):
            result["name"] = line[3:].strip()
        elif line.startswith("Computer name:"):
            result["smb_computer_name"] = line[14:].strip()
        elif line.startswith("Domain name:"):
            result["smb_domain"] = line[12:].strip()
        elif line.startswith("FQDN:"):
            result["smb_fqdn"] = line[5:].strip()
    return result


# ── Nmap XML ──────────────────────────────────────────────────────────────
# The agent runs Nmap as a separate program and reads its XML report itself
# (python-nmap is not used: its GPL-3.0 licence cannot be combined with scapy's
# GPL-2.0-only in one distributed program). The reading rules below copy
# python-nmap 0.7.1's, so the host data is unchanged.

@dataclass
class _XmlHost:
    state: str = ""
    hostnames: list[dict[str, str]] = field(default_factory=list)
    addresses: dict[str, str] = field(default_factory=dict)
    ports: dict[str, dict[int, dict[str, Any]]] = field(default_factory=dict)   # proto -> port -> info
    osmatch: list[dict[str, str]] = field(default_factory=list)

    def hostname(self) -> str:
        """python-nmap's rule: a 'user' hostname if any, otherwise the first one."""
        for h in self.hostnames:
            if h.get("type") == "user":
                return h.get("name") or ""
        return (self.hostnames[0].get("name") or "") if self.hostnames else ""


def parse_nmap_xml(text: str) -> dict[str, _XmlHost]:
    """Hosts of an Nmap XML report, keyed by IPv4 address."""
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise RuntimeError(f"Nmap returned output that could not be read: {exc}") from None
    hosts: dict[str, _XmlHost] = {}
    for dhost in root.findall("host"):
        h = _XmlHost()
        status = dhost.find("status")
        h.state = status.get("state", "") if status is not None else ""
        key: Optional[str] = None
        for address in dhost.findall("address"):
            kind, addr = address.get("addrtype", ""), address.get("addr", "")
            h.addresses[kind] = addr
            if kind == "ipv4":
                key = addr
        if key is None:
            first = dhost.find("address")
            if first is None:
                continue
            key = first.get("addr", "")
        names = dhost.findall("hostnames/hostname")
        h.hostnames = [{"name": n.get("name", ""), "type": n.get("type", "")} for n in names] or [{"name": "", "type": ""}]
        for dport in dhost.findall("ports/port"):
            proto, portid = dport.get("protocol", ""), int(dport.get("portid", "0"))
            state = dport.find("state")
            info: dict[str, Any] = {"state": state.get("state", "") if state is not None else "",
                                    "name": "", "product": "", "version": ""}
            for service in dport.findall("service"):
                info["name"] = service.get("name")
                if service.get("product"):
                    info["product"] = service.get("product")
                if service.get("version"):
                    info["version"] = service.get("version")
            for script in dport.findall("script"):
                info.setdefault("script", {})[script.get("id")] = script.get("output")
            h.ports.setdefault(proto, {})[portid] = info
        h.osmatch = [{"name": m.get("name", ""), "accuracy": m.get("accuracy", "")} for m in dhost.findall("os/osmatch")]
        hosts[key] = h
    return hosts


def hosts_from_nmap_xml(text: str) -> list[HostRecord]:
    """Turn an Nmap XML report into HostRecords.

    OS: smb-os-discovery (most accurate) -> Nmap osmatch fallback.
    Hostname: SMB computer name (most reliable) -> Nmap reverse DNS, ignoring
    Docker-internal names.
    """
    parsed = parse_nmap_xml(text)
    hosts: list[HostRecord] = []
    for ip in sorted(parsed):                  # python-nmap's all_hosts() order (string sort)
        host = parsed[ip]
        if host.state != "up":
            continue

        ports: list[dict[str, Any]] = []
        for proto in sorted(host.ports):
            for port_num, port_info in host.ports[proto].items():
                if port_info.get("state") == "open":
                    entry: dict[str, Any] = {
                        "port": port_num,
                        "protocol": proto,
                        "service": port_info.get("name", ""),
                        "version": port_info.get("version", ""),
                        "product": port_info.get("product", ""),
                    }
                    script_out = port_info.get("script", {})
                    if "banner" in script_out:
                        entry["banner"] = script_out["banner"][:200]
                    ports.append(entry)

        os_info: dict[str, Any] = {}
        tcp = host.ports.get("tcp", {})
        smb_script = (
            tcp.get(445, {}).get("script", {}).get("smb-os-discovery")
            or tcp.get(139, {}).get("script", {}).get("smb-os-discovery")
        )
        if smb_script:
            os_info = parse_smb_os_discovery(smb_script)
        elif host.osmatch:
            best = host.osmatch[0]
            os_info = {"name": best.get("name", ""), "accuracy": best.get("accuracy", "")}

        smb_computer_name = os_info.get("smb_computer_name") or None
        dns_hostname = host.hostname() or None
        if dns_hostname and ("docker.internal" in dns_hostname or dns_hostname.startswith("docker")):
            dns_hostname = None

        hosts.append(HostRecord(
            ip=ip,
            hostname=smb_computer_name or dns_hostname,
            mac=host.addresses.get("mac") or None,
            ports=ports,
            os=os_info or None,
        ))
    return hosts


def nmap_command(subnet: str, nmap_path: str) -> list[str]:
    """Same command line python-nmap built: nmap -oX - <target> <arguments>."""
    return [nmap_path, "-oX", "-", subnet, *shlex.split(NMAP_ARGS)]


def _execute_nmap(command: list[str], timeout: int) -> str:
    """Run Nmap and return its XML report."""
    try:
        proc = subprocess.run(command, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Nmap did not finish within {timeout // 60} minutes") from None
    except OSError as exc:
        raise RuntimeError(f"Nmap could not be started: {exc}") from None
    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0 or "<nmaprun" not in out:
        raise RuntimeError(f"Nmap failed: {(err or f'exit code {proc.returncode}')[:300]}")
    if err:
        log.debug("Nmap messages: %s", err[:500])
    return out


def run_nmap(subnet: str, nmap_path: str) -> list[HostRecord]:
    log.info("Running Nmap on %s", subnet)
    hosts = hosts_from_nmap_xml(_execute_nmap(nmap_command(subnet, nmap_path), NMAP_TIMEOUT_SECONDS))
    log.info("Nmap found %d hosts on %s", len(hosts), subnet)
    return hosts


# ── Built-in fallback sweep (no Nmap) ────────────────────────────────────────

BUILTIN_PORTS = (445, 139, 135, 22, 80, 443, 3389, 8080, 8443, 23, 161, 3306, 5432, 6379, 27017)
_REFUSED = {errno.ECONNREFUSED, 10061, 111, 61}   # a refusal proves the host is up
_MAC = r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}"


def _norm_mac(raw: str) -> str:
    return ":".join(part.zfill(2) for part in re.split(r"[:-]", raw)).upper()


def parse_arp_table(text: str, network: ipaddress.IPv4Network) -> dict[str, str]:
    """ip -> MAC from `arp -a` (Windows) / `arp -an` (Linux, macOS) output, limited to
    addresses inside `network`. Broadcast, multicast and incomplete entries are dropped."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        mac_m = re.search(_MAC, line)
        if not ip_m or not mac_m:
            continue
        try:
            addr = ipaddress.ip_address(ip_m.group(1))
        except ValueError:
            continue
        if addr not in network or addr.is_multicast or addr == network.broadcast_address:
            continue
        mac = _norm_mac(mac_m.group(0))
        if mac == "FF:FF:FF:FF:FF:FF" or mac.startswith("01:00:5E"):
            continue
        found[str(addr)] = mac
    return found


def _read_arp_cache() -> str:
    command = ["arp", "-a"] if platform.system() == "Windows" else ["arp", "-an"]
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=10).stdout
    except Exception:  # noqa: BLE001
        return ""


def _probe(ip: str, timeout: float) -> tuple[bool, list[int]]:
    alive, open_ports = False, []
    for port in BUILTIN_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            rc = s.connect_ex((ip, port))
        except OSError:
            rc = -1
        finally:
            s.close()
        if rc == 0:
            alive = True
            open_ports.append(port)
        elif rc in _REFUSED:
            alive = True
    return alive, open_ports


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None
    if not name or name == ip or "docker.internal" in name or name.startswith("docker"):
        return None
    return name


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def builtin_sweep(
    subnet: str,
    progress: Callable[[str, Optional[int], Optional[int]], None] = lambda *a: None,
    cancelled: Callable[[], bool] = lambda: False,
    timeout: float = 0.4,
    workers: int = 64,
) -> list[HostRecord]:
    """TCP connect sweep plus the system ARP cache. Finds live hosts and open ports,
    but cannot identify services, versions or operating systems."""
    network = ipaddress.ip_network(subnet, strict=False)
    addresses = [str(a) for a in (network.hosts() if network.num_addresses > 2 else network)]
    live: dict[str, HostRecord] = {}

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe, ip, timeout): ip for ip in addresses}
        for fut in as_completed(futures):
            if cancelled():
                pool.shutdown(wait=False, cancel_futures=True)
                raise Cancelled()
            ip = futures[fut]
            alive, open_ports = fut.result()
            if alive:
                live[ip] = HostRecord(ip=ip, ports=[
                    {"port": p, "protocol": "tcp", "service": _service_name(p), "version": "", "product": ""}
                    for p in sorted(open_ports)
                ])
            done += 1
            if done % 32 == 0 or done == len(addresses):
                progress(f"Probed {done}/{len(addresses)} addresses, {len(live)} up", done, len(addresses))

    # Probing fills the ARP cache, so devices that filtered every port still show up here.
    arp = parse_arp_table(_read_arp_cache(), network)
    for ip, mac in arp.items():
        record = live.setdefault(ip, HostRecord(ip=ip))
        record.mac = mac

    with ThreadPoolExecutor(max_workers=16) as pool:
        for record, name in zip(live.values(), pool.map(_reverse_dns, list(live))):
            record.hostname = name

    return sorted(live.values(), key=lambda h: ipaddress.ip_address(h.ip))


class NmapScanStage(Stage):
    name = "scan"
    label = "Discover and fingerprint hosts"

    def __init__(self, subnet: str) -> None:
        self.subnet = subnet

    def run(self, ctx: PipelineContext) -> None:
        nmap_path = deps.find_nmap()
        if nmap_path:
            target = validate_target(self.subnet)
            ctx.progress(f"Running Nmap on {target} (this can take several minutes)")
            ctx.hosts = run_nmap(target, nmap_path)
            ctx.summary["scanner"] = "nmap"
        else:
            target = validate_target(self.subnet, max_hosts=BUILTIN_MAX_HOSTS)
            ctx.progress("Nmap is not installed - using the built-in sweep (no service, version or OS detail)")
            log.warning("Nmap not found; install it for full results: %s", deps._hint("nmap"))
            ctx.hosts = builtin_sweep(target, ctx.progress, ctx.cancelled)
            ctx.summary["scanner"] = "builtin"
        ctx.progress(f"{len(ctx.hosts)} host(s) up", len(ctx.hosts), None)
