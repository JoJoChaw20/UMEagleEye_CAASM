"""Local network facts the backend uses to scope identity resolution."""

from __future__ import annotations

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


def parse_default_gateway(system: str, output: str) -> Optional[str]:
    """Pull the default gateway out of `route print` (Windows), `ip route` (Linux)
    or `route -n get default` (macOS) output."""
    if system == "Windows":
        for line in output.splitlines():
            parts = line.split()
            # "0.0.0.0  0.0.0.0  <gateway>  <iface>  <metric>". VPN/virtual adapters
            # can list "On-link" here, so only accept a real IP.
            if (len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0"
                    and _IPV4.fullmatch(parts[2]) and parts[2] != "0.0.0.0"):
                return parts[2]
        return None
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
    return parse_default_gateway(system, out)


def build_network_info(subnet: Optional[str], hosts: list[HostRecord]) -> dict[str, Any]:
    """The `network` block sent with each ingest: {subnet, gateway_ip, gateway_mac}.

    - subnet:      the scanned CIDR (active); for passive, the local /24 when not given.
    - gateway_ip:  default gateway, best effort.
    - gateway_mac: only when the gateway appears among the discovered hosts, so it is
                   never guessed.
    """
    gateway_ip = default_gateway()
    gateway_mac: Optional[str] = None
    if gateway_ip:
        for h in hosts:
            if h.ip == gateway_ip and h.mac:
                gateway_mac = h.mac
                break

    net_subnet = subnet
    if not net_subnet:
        ip = local_ip()
        if ip and ip.count(".") == 3:
            net_subnet = ".".join(ip.split(".")[:3]) + ".0/24"

    return {"subnet": net_subnet, "gateway_ip": gateway_ip, "gateway_mac": gateway_mac}
