"""This computer's network adapters without scapy: {name, description, ips, mac, index,
prefixes, gateway} per adapter, for the InterfaceChooser of the built-in capture, and
the network ({local_ip, subnet, gateway_ip}) an address is on.

  * Windows: GetAdaptersAddresses (friendly name, description, MAC, interface index,
    IPv4 addresses with their on-link prefix, the default gateway).
  * Linux: `ip -j addr` and `ip -j route` (iproute2).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
import sys
from typing import Any, Optional

log = logging.getLogger("eagleeye.passive")


def _mac(raw: bytes) -> Optional[str]:
    return ":".join(f"{b:02x}" for b in raw) if len(raw) == 6 else None


# ── Linux ────────────────────────────────────────────────────────────────────

def parse_ip_addr(data: list[dict[str, Any]], routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """`ip -j addr` and `ip -j route show default` -> adapters."""
    gateways: dict[str, str] = {}
    for route in routes:
        if route.get("dst") == "default" and route.get("gateway") and route.get("dev"):
            gateways.setdefault(route["dev"], route["gateway"])
    out = []
    for link in data:
        name = link.get("ifname")
        if not name:
            continue
        v4 = [a for a in link.get("addr_info") or [] if a.get("family") == "inet" and a.get("local")]
        mac = str(link.get("address") or "").lower() or None
        out.append({"name": name, "description": name, "index": link.get("ifindex"),
                    "mac": mac if mac and mac != "00:00:00:00:00:00" else None,
                    "ips": [a["local"] for a in v4],
                    "prefixes": {a["local"]: int(a.get("prefixlen", 32)) for a in v4},
                    "gateway": gateways.get(name)})
    return out


def _linux_adapters() -> list[dict[str, Any]]:
    def ip_json(*args: str) -> list[dict[str, Any]]:
        out = subprocess.run(["ip", "-j", *args], capture_output=True, text=True, timeout=5).stdout
        return json.loads(out or "[]")
    return parse_ip_addr(ip_json("addr"), ip_json("-4", "route", "show", "default"))


# ── Windows ──────────────────────────────────────────────────────────────────

if sys.platform == "win32":  # pragma: no cover - the ctypes layer runs on Windows only
    import ctypes
    import ctypes.wintypes as wt

    AF_UNSPEC, AF_INET = 0, 2
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_DNS_SERVER = 0x2, 0x4, 0x8
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x80, 0x100
    ERROR_BUFFER_OVERFLOW = 111

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]

    class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
        pass

    IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("Length", wt.ULONG), ("Flags", wt.DWORD), ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("Address", SOCKET_ADDRESS), ("PrefixOrigin", ctypes.c_int), ("SuffixOrigin", ctypes.c_int),
        ("DadState", ctypes.c_int), ("ValidLifetime", wt.ULONG), ("PreferredLifetime", wt.ULONG),
        ("LeaseLifetime", wt.ULONG), ("OnLinkPrefixLength", ctypes.c_uint8)]

    class IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
        pass

    IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
        ("Length", wt.ULONG), ("Reserved", wt.DWORD), ("Next", ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)),
        ("Address", SOCKET_ADDRESS)]

    class IP_ADAPTER_ADDRESSES(ctypes.Structure):
        pass

    IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", wt.ULONG), ("IfIndex", wt.DWORD), ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
        ("AdapterName", ctypes.c_char_p), ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("FirstAnycastAddress", ctypes.c_void_p), ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p), ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p), ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * 8), ("PhysicalAddressLength", wt.ULONG), ("Flags", wt.ULONG),
        ("Mtu", wt.ULONG), ("IfType", wt.ULONG), ("OperStatus", ctypes.c_int), ("Ipv6IfIndex", wt.ULONG),
        ("ZoneIndices", wt.ULONG * 16), ("FirstPrefix", ctypes.c_void_p),
        ("TransmitLinkSpeed", ctypes.c_uint64), ("ReceiveLinkSpeed", ctypes.c_uint64),
        ("FirstWinsServerAddress", ctypes.c_void_p),
        ("FirstGatewayAddress", ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS))]

    _iphlpapi = ctypes.WinDLL("iphlpapi")
    _iphlpapi.GetAdaptersAddresses.argtypes = [wt.ULONG, wt.ULONG, ctypes.c_void_p, ctypes.c_void_p,
                                               ctypes.POINTER(wt.ULONG)]
    _iphlpapi.GetAdaptersAddresses.restype = wt.ULONG

    def _ipv4(sa: SOCKET_ADDRESS) -> Optional[str]:
        if not sa.lpSockaddr or sa.iSockaddrLength < 8:
            return None
        raw = ctypes.string_at(sa.lpSockaddr, 8)
        if int.from_bytes(raw[:2], "little") != AF_INET:
            return None
        return str(ipaddress.IPv4Address(raw[4:8]))

    def _windows_adapters() -> list[dict[str, Any]]:
        # Every family and every interface: adapters with no IPv4 address still have MACs
        # (this computer's own, whose packets are ignored).
        flags = (GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
                 | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES)
        size = wt.ULONG(16 * 1024)
        for _ in range(4):
            buf = ctypes.create_string_buffer(size.value)
            rc = _iphlpapi.GetAdaptersAddresses(AF_UNSPEC, flags, None, buf, ctypes.byref(size))
            if rc != ERROR_BUFFER_OVERFLOW:
                break
        if rc != 0:
            raise OSError(f"GetAdaptersAddresses failed ({rc})")
        out = []
        ptr = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
        while ptr:
            a = ptr.contents
            ips, prefixes = [], {}
            u = a.FirstUnicastAddress
            while u:
                ip = _ipv4(u.contents.Address)
                if ip:
                    ips.append(ip)
                    prefixes[ip] = int(u.contents.OnLinkPrefixLength)
                u = u.contents.Next
            gateway = None
            g = a.FirstGatewayAddress
            while g and gateway is None:
                gateway = _ipv4(g.contents.Address)
                g = g.contents.Next
            mac = _mac(bytes(a.PhysicalAddress[:a.PhysicalAddressLength]))
            out.append({"name": a.FriendlyName or "", "description": a.Description or a.FriendlyName or "",
                        "index": int(a.IfIndex), "mac": mac, "ips": ips, "prefixes": prefixes,
                        "gateway": gateway})
            ptr = a.Next
        return out


def list_adapters() -> list[dict[str, Any]]:
    if sys.platform == "win32":
        return _windows_adapters()
    return _linux_adapters()


def probe() -> tuple[str, list[dict[str, Any]]]:
    """InterfaceChooser's probe: (the address the OS uses to reach the internet, adapters)."""
    from ..netinfo import local_ip
    return local_ip(), list_adapters()


def connected_networks(adapters: Optional[list[dict[str, Any]]] = None) -> list[str]:
    """The IPv4 networks this computer is directly on, e.g. ["192.168.36.0/24"]: real
    adapters only (not VMware/Hyper-V/Docker host networks, loopback or self-assigned
    addresses). The server sends a scan of one of them to this agent (2.5.1)."""
    from .sniffers import _is_virtual_adapter
    out: list[str] = []
    for adapter in adapters if adapters is not None else list_adapters():
        if _is_virtual_adapter(adapter):
            continue
        for ip in adapter.get("ips") or []:
            if ip.startswith(("127.", "169.254.")):
                continue
            prefix = (adapter.get("prefixes") or {}).get(ip)
            if prefix is None or not 8 <= prefix <= 30:
                continue
            net = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
            if net not in out:
                out.append(net)
    return out[:16]


def network_from(ip: str, adapters: list[dict[str, Any]]) -> dict[str, Optional[str]]:
    """{local_ip, subnet, gateway_ip} of the adapter holding `ip` (/24 when unknown)."""
    for a in adapters:
        if ip in (a.get("ips") or []):
            prefix = (a.get("prefixes") or {}).get(ip)
            if prefix is not None and 0 < prefix < 32:
                subnet = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
            else:
                subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            return {"local_ip": ip, "subnet": subnet, "gateway_ip": a.get("gateway")}
    return {"local_ip": ip, "subnet": str(ipaddress.ip_network(f"{ip}/24", strict=False)), "gateway_ip": None}


def network_of(ip: str) -> dict[str, Optional[str]]:
    """InterfaceChooser's network_of."""
    return network_from(ip, list_adapters())
