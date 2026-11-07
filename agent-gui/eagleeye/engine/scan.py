"""The own active engine: presence, port scan, names, into the same HostRecords the Nmap
stage produces (so the server cannot tell which engine ran).

1. presence: ARP for addresses on a network this computer is attached to, ping beyond it;
2. ping ports: routed addresses that ignored ping are tried on a few common ports, and a
   refusal counts as an answer;
3. port scan of every address found up, with the agent's port tier;
4. identification: one probe per open port (probes.py), and two UDP questions per host
   (udp.py: SNMPv3 engine discovery, NetBIOS node status);
5. names: SMB/NTLM computer name, RDP certificate name, NetBIOS name, then reverse DNS once
   per host, through the shared ranking; the SMB/NTLM facts become the host's OS fields.

Facts the upload format has no place for yet (certificates, page titles, SNMP engine,
OS hints) are kept per host in EngineStats.details for the comparison report.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

from ..pipeline.record import HostRecord
from ..pipeline.runner import Cancelled
from . import names as names_mod
from . import portscan, presence, probes as probes_mod, udp
from .ports import PING_PORTS, ports_for, service_name

log = logging.getLogger("eagleeye.engine")

Progress = Callable[[str, Optional[int], Optional[int]], None]

PROBE_WORKERS = 32
LOCAL_TIMEOUT = 0.8      # seconds per connection on an attached network
ROUTED_TIMEOUT = 1.5     # ... beyond it


@dataclass
class EngineStats:
    tier: str
    addresses: int = 0
    up: int = 0
    by_arp: int = 0
    by_ping: int = 0
    by_port: int = 0
    connections: int = 0
    open_ports: int = 0
    seconds: float = 0.0
    cpu_seconds: float = 0.0
    identified: int = 0
    phases: dict[str, float] = field(default_factory=dict)
    details: dict[str, dict[str, Any]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Probes:
    """The network calls the engine makes; tests replace them."""
    networks: Callable[[], list] = presence.local_networks
    arp: Callable[..., dict[str, str]] = presence.arp_sweep
    ping: Callable[..., set[str]] = presence.ping_sweep
    connect: Callable[[str, int, float], str] = portscan.connect_state
    reverse_dns: Callable[..., dict[str, str]] = names_mod.reverse_dns
    identify: Callable[[str, int], Optional[probes_mod.Finding]] = probes_mod.probe
    snmp: Callable[[str], Optional[dict]] = udp.snmp_engine
    netbios: Callable[[str], Optional[dict]] = udp.netbios_status
    own_mac: Callable[[str], Optional[str]] = presence.own_mac


def run_own_scan(
    target: str,
    tier: str = "base",
    progress: Progress = lambda *a: None,
    cancelled: Callable[[], bool] = lambda: False,
    probes: Optional[Probes] = None,
) -> tuple[list[HostRecord], EngineStats]:
    p = probes or Probes()
    ports = ports_for(tier)
    stats = EngineStats(tier=tier)
    t0, cpu0 = time.monotonic(), time.process_time()

    def phase(name: str, since: float) -> float:
        now = time.monotonic()
        stats.phases[name] = round(now - since, 2)
        if cancelled():
            raise Cancelled()
        return now

    net = ipaddress.ip_network(target, strict=False)
    addresses = [str(a) for a in (net.hosts() if net.num_addresses > 2 else net)]
    stats.addresses = len(addresses)
    networks = p.networks()
    own = {src for src, _ in networks if src in set(addresses)}
    local, routed = presence.split_by_link(addresses, networks)

    t = time.monotonic()
    macs: dict[str, str] = {}
    for src, group in local.items():
        progress(f"ARP sweep of {len(group)} addresses", None, None)
        macs.update(p.arp(group, src, cancelled=cancelled))
    t = phase("arp", t)
    pinged = p.ping(routed, cancelled=cancelled) if routed else set()
    t = phase("ping", t)
    silent = [ip for ip in routed if ip not in pinged]
    by_port: set[str] = set()
    if silent:
        progress(f"Trying {len(silent)} silent addresses on {len(PING_PORTS)} common ports", None, None)
        states, n = portscan.scan(silent, PING_PORTS, ROUTED_TIMEOUT, connect=p.connect, cancelled=cancelled)
        stats.connections += n
        by_port = {ip for ip, st in states.items() if any(s != portscan.FILTERED for s in st.values())}
    t = phase("ping_ports", t)

    up = set(macs) | pinged | by_port | own
    stats.by_arp, stats.by_ping, stats.by_port = len(macs), len(pinged), len(by_port)
    stats.up = len(up)
    progress(f"{len(up)} address(es) up; scanning {len(ports)} ports each", None, None)

    order = sorted(up, key=ipaddress.ip_address)
    timeout = ROUTED_TIMEOUT if routed and not local else LOCAL_TIMEOUT
    states, n = portscan.scan(order, ports, timeout, known_up=up, connect=p.connect,
                              progress=progress, cancelled=cancelled)
    stats.connections += n
    t = phase("ports", t)

    open_by_ip = {ip: sorted(port for port, st in states.get(ip, {}).items() if st == portscan.OPEN) for ip in order}
    tasks = [(ip, port) for ip in order for port in open_by_ip[ip]]
    progress(f"Identifying {len(tasks)} open port(s) and asking {len(order)} host(s) SNMP/NetBIOS", None, None)
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS, thread_name_prefix="probe") as pool:
        found = dict(zip(tasks, pool.map(lambda t: _safe(p.identify, *t), tasks)))
        snmp = dict(zip(order, pool.map(lambda ip: _safe(p.snmp, ip), order)))
        netbios = dict(zip(order, pool.map(lambda ip: _safe(p.netbios, ip), order)))
    t = phase("identify", t)

    rdns = p.reverse_dns(order)
    phase("names", t)

    hosts = []
    for ip in order:
        entries, detail = [], {}
        for port in open_by_ip[ip]:
            finding = found.get((ip, port))
            if finding is None:
                entries.append({"port": port, "protocol": "tcp", "service": service_name(port), "version": "", "product": ""})
                continue
            entries.append(finding.port_entry(port))
            stats.identified += bool(finding.product)
            if finding.extra:
                detail.setdefault("ports", {})[str(port)] = finding.extra
        if snmp.get(ip):
            engine = snmp[ip]
            entries.append({"port": 161, "protocol": "udp", "service": "snmp", "version": "",
                            "product": engine.get("vendor", "")})
            detail["snmp_engine"] = engine
        if netbios.get(ip):
            detail["netbios"] = netbios[ip]
        stats.open_ports += len(entries)
        machine = next((f.extra["os"] for port in open_by_ip[ip] if (f := found.get((ip, port))) and "os" in f.extra), None)
        rdp_name = next((f.extra.get("rdp_computer_name") for port in open_by_ip[ip]
                         if (f := found.get((ip, port))) and f.extra.get("rdp_computer_name")), None)
        nb_name = (netbios.get(ip) or {}).get("computer")
        name, source = names_mod.pick_name([((machine or {}).get("smb_computer_name"), "smb"), (rdp_name, "rdp"),
                                            (nb_name, "netbios"), (rdns.get(ip), "rdns")])
        if source:
            detail["name_source"] = source
        if detail:
            stats.details[ip] = detail
        mac = macs.get(ip) or (netbios.get(ip) or {}).get("mac") or (_safe(p.own_mac, ip) if ip in own else None)
        hosts.append(HostRecord(ip=ip, hostname=name, mac=mac, ports=entries, os=dict(machine) if machine else None))
    stats.seconds = round(time.monotonic() - t0, 2)
    stats.cpu_seconds = round(time.process_time() - cpu0, 2)
    return hosts, stats


def _safe(fn: Callable[..., Any], *args: Any) -> Any:
    """A probe that fails must not end the scan: it just learns nothing."""
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001
        log.debug("probe %s%s failed: %s", getattr(fn, "__name__", fn), args, exc)
        return None
