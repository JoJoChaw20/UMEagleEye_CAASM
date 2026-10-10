"""Active scan: discover hosts and fingerprint them (ports, services, OS, hostname).

The Nmap invocation and result parsing are a faithful port of the original agent's
run_nmap(), so both produce the same host data (tests/test_parity.py checks this).
When Nmap is not installed the stage says so and falls back to a built-in sweep.
"""

from __future__ import annotations

import errno
import ipaddress
import logging
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional

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


def hosts_from_scanner(nm: Any) -> list[HostRecord]:
    """Turn a python-nmap PortScanner result into HostRecords.

    OS: smb-os-discovery (most accurate) -> Nmap osmatch fallback.
    Hostname: SMB computer name (most reliable) -> Nmap reverse DNS, ignoring
    Docker-internal names.
    """
    hosts: list[HostRecord] = []
    for ip in nm.all_hosts():
        host = nm[ip]
        if host.state() != "up":
            continue

        ports: list[dict[str, Any]] = []
        for proto in host.all_protocols():
            for port_num, port_info in host[proto].items():
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
        smb_script = (
            host.get("tcp", {}).get(445, {}).get("script", {}).get("smb-os-discovery")
            or host.get("tcp", {}).get(139, {}).get("script", {}).get("smb-os-discovery")
        )
        if smb_script:
            os_info = parse_smb_os_discovery(smb_script)
        elif "osmatch" in host and host["osmatch"]:
            best = host["osmatch"][0]
            os_info = {"name": best.get("name", ""), "accuracy": best.get("accuracy", "")}

        smb_computer_name = os_info.get("smb_computer_name") or None
        dns_hostname = host.hostname() or None
        if dns_hostname and ("docker.internal" in dns_hostname or dns_hostname.startswith("docker")):
            dns_hostname = None

        hosts.append(HostRecord(
            ip=ip,
            hostname=smb_computer_name or dns_hostname,
            mac=host.get("addresses", {}).get("mac") or None,
            ports=ports,
            os=os_info or None,
        ))
    return hosts


def run_nmap(subnet: str, nmap_path: str) -> list[HostRecord]:
    import nmap  # type: ignore  # python-nmap

    log.info("Running Nmap on %s", subnet)
    nm = nmap.PortScanner(nmap_search_path=(nmap_path,))
    try:
        nm.scan(hosts=subnet, arguments=NMAP_ARGS, timeout=NMAP_TIMEOUT_SECONDS)
    except nmap.PortScannerTimeout:
        raise RuntimeError(f"Nmap did not finish within {NMAP_TIMEOUT_SECONDS // 60} minutes") from None
    except nmap.PortScannerError as exc:
        raise RuntimeError(f"Nmap failed: {str(exc).strip()[:300]}") from None
    hosts = hosts_from_scanner(nm)
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
