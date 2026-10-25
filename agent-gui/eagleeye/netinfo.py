"""Local network facts the backend uses to scope identity resolution."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from typing import Any, Optional

from .pipeline.record import HostRecord

_IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}")


def local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:  # noqa: BLE001
        return "127.0.0.1"


def parse_default_gateway(system: str, output: str, via: Optional[str] = None) -> Optional[str]:
    """Pull the default gateway out of `route print` (Windows), `ip route` (Linux)
    or `route -n get default` (macOS) output.

    Windows can list several default routes (Wi-Fi plus a VPN or a virtual adapter such
    as the GNS3 KM-TEST loopback) in no fixed order. The one on the adapter holding `via`
    (the address the OS really uses, local_ip()) wins, else the lowest metric: taking
    the first line made the gateway, and with it the router's exposure, flip between
    scans."""
    if system == "Windows":
        routes: list[tuple[bool, int, str]] = []    # (not on `via`, metric, gateway)
        for line in output.splitlines():
            parts = line.split()
            # Active: "0.0.0.0  0.0.0.0  <gateway>  <iface>  <metric>"; persistent:
            # "0.0.0.0  0.0.0.0  <gateway>  <metric>". VPN/virtual adapters can list
            # "On-link" as the gateway, so only accept a real IP.
            if not (len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0"
                    and _IPV4.fullmatch(parts[2]) and parts[2] != "0.0.0.0"):
                continue
            iface = parts[3] if _IPV4.fullmatch(parts[3]) else None
            metric = int(parts[-1]) if parts[-1].isdigit() else 1 << 30
            routes.append((not (via and iface == via), metric, parts[2]))
        return min(routes)[2] if routes else None
    if system == "Darwin":
        m = re.search(r"gateway:\s*(\d{1,3}(?:\.\d{1,3}){3})", output)
        return m.group(1) if m else None
    m = re.search(r"default via ([\d.]+)", output)
    return m.group(1) if m else None


def default_gateway() -> Optional[str]:
    """Best-effort default-gateway IPv4 lookup. Returns None on any failure."""
    system = platform.system()
    command = {
        "Windows": ["route", "print", "-4", "0.0.0.0"],
        "Darwin": ["route", "-n", "get", "default"],
    }.get(system, ["ip", "route"])
    try:
        out = subprocess.run(command, capture_output=True, text=True, timeout=5).stdout
    except Exception:  # noqa: BLE001
        return None
    return parse_default_gateway(system, out, local_ip())


def _slash24(ip: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return None


def network_of(ip: str, routes: list[tuple[Any, ...]]) -> tuple[Optional[str], Optional[str]]:
    """(subnet, default gateway) of the adapter holding `ip`, from a route table in
    scapy's form: (network, netmask, gateway, interface, source address, metric) with
    network and netmask as integers.

    The subnet is the on-link route that holds the address with the longest prefix
    short of /32 (host and broadcast routes), so a /19 campus Wi-Fi or a /22 office LAN
    is reported as it is configured instead of as the /24 around the address. The
    gateway is the lowest-metric default route out of that address."""
    try:
        addr = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return None, None
    best: Optional[tuple[int, int]] = None                 # (prefix length, network)
    gateway: Optional[tuple[int, str]] = None              # (metric, gateway)
    for route in routes:
        try:
            net, mask, gw, _iface, src, metric = route[:6]
            net, mask, metric = int(net), int(mask), int(metric)
        except (TypeError, ValueError):
            continue
        if src != ip:
            continue
        if mask == 0 and net == 0:
            if gw and gw != "0.0.0.0" and _IPV4.fullmatch(str(gw)) and (gateway is None or metric < gateway[0]):
                gateway = (metric, str(gw))
            continue
        prefix = bin(mask).count("1")
        if prefix >= 32 or (gw and gw != "0.0.0.0") or (addr & mask) != (net & mask):
            continue
        if best is None or prefix > best[0]:
            best = (prefix, net & mask)
    subnet = f"{ipaddress.IPv4Address(best[1])}/{best[0]}" if best else None
    return subnet, (gateway[1] if gateway else None)


def _scapy_routes() -> list[tuple[Any, ...]]:
    try:
        from scapy.all import conf  # type: ignore
        try:
            conf.route.resync()
        except Exception:  # noqa: BLE001 - keep scapy's last copy of the table
            pass
        return list(conf.route.routes)
    except Exception:  # noqa: BLE001 - no scapy: fall back to /24
        return []


def local_network(ip: Optional[str] = None) -> dict[str, Optional[str]]:
    """{local_ip, subnet, gateway_ip} of the adapter the OS uses (or of `ip`). The
    subnet falls back to the /24 around the address when the route table is unknown."""
    ip = ip or local_ip()
    subnet, gateway = network_of(ip, _scapy_routes()) if ip and not ip.startswith("127.") else (None, None)
    return {"local_ip": ip, "subnet": subnet or (_slash24(ip) if ip else None), "gateway_ip": gateway}


def local_subnet() -> str:
    """The subnet this computer is on, e.g. 10.179.32.0/19 (192.168.1.0/24 when unknown)."""
    return local_network().get("subnet") or "192.168.1.0/24"


def own_mac(ip: str) -> Optional[str]:
    """MAC of this computer's adapter that holds `ip` (Nmap cannot see its own)."""
    try:
        from scapy.all import conf  # type: ignore
        for iface in conf.ifaces.values():
            ips = list((getattr(iface, "ips", None) or {}).get(4, []) or [])
            if ip in ips or getattr(iface, "ip", None) == ip:
                mac = getattr(iface, "mac", None)
                return str(mac).lower() if mac else None
    except Exception:  # noqa: BLE001
        pass
    return None


def build_network_info(subnet: Optional[str], hosts: list[HostRecord],
                       heard_on: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """The `network` block sent with each ingest: {subnet, lan_subnet, gateway_ip, gateway_mac}.

    - subnet:      the scanned CIDR (active); for passive, the subnet the hosts were
                   heard on, else the local subnet now.
    - lan_subnet:  the subnet of the LAN this computer is on (the one passive hosts were
                   heard on). The server keys device identity by it, so a /22 office LAN
                   is one network, not four /24s; for an active scan `subnet` is only the
                   range that was scanned.
    - gateway_ip:  the gateway of the network the hosts were heard on, else the
                   default gateway now (best effort).
    - gateway_mac: only when the gateway appears among the discovered hosts, so it is
                   never guessed.
    `heard_on` is the network passive hosts were heard on (local_network() at the
    time): hosts buffered before a move to another network are uploaded with the
    network they came from, not with the new one's gateway.
    """
    if heard_on is None:
        gateway_ip = default_gateway()
    else:
        # Today's gateway only while still on the network the hosts were heard on;
        # another network's gateway would flip the old router's exposure.
        gateway_ip = heard_on.get("gateway_ip")
        if not gateway_ip and heard_on.get("local_ip") == local_ip():
            gateway_ip = default_gateway()
    gateway_mac: Optional[str] = None
    if gateway_ip:
        for h in hosts:
            if h.ip == gateway_ip and h.mac:
                gateway_mac = h.mac
                break

    lan_subnet = (heard_on or {}).get("subnet") if heard_on is not None else local_network().get("subnet")
    net_subnet = subnet or lan_subnet

    return {"subnet": net_subnet, "lan_subnet": lan_subnet, "gateway_ip": gateway_ip, "gateway_mac": gateway_mac}
