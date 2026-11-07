"""Which addresses are in use: ARP on the local network, ping beyond it. No admin rights.

On a network this computer is attached to, ARP is the answer: a device must reply to ARP to
use the network at all, so a phone that ignores every port and ping still shows up, with
its MAC. Windows asks with SendARP (iphlpapi), which sends the request itself. Linux sends
one UDP datagram to each address, which makes the kernel resolve it, and then reads
/proc/net/arp. Beyond the local network ARP cannot reach, so Windows pings with
IcmpSendEcho and Linux with an unprivileged ping socket where the system allows it; the
port scan's ping ports cover the rest.
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import logging
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, Optional

log = logging.getLogger("eagleeye.engine")

Network = ipaddress.IPv4Network


def _ulong(ip: str) -> int:
    """An IPv4 address as the in-memory IPAddr value the iphlpapi functions take."""
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def format_mac(raw: bytes) -> Optional[str]:
    """b'\\x7c\\x61...' -> '7C:61:...' (the upper-case form the Nmap stage reports)."""
    if len(raw) != 6 or not any(raw) or raw == b"\xff" * 6:
        return None
    return ":".join(f"{b:02X}" for b in raw)


# ── this computer's IPv4 networks ────────────────────────────────────────────

def _windows_networks() -> list[tuple[str, Network]]:
    class Row(ctypes.Structure):
        _fields_ = [("addr", ctypes.c_uint32), ("index", ctypes.c_uint32), ("mask", ctypes.c_uint32),
                    ("bcast", ctypes.c_uint32), ("reasm", ctypes.c_uint32),
                    ("unused1", ctypes.c_ushort), ("type", ctypes.c_ushort)]
    size = ctypes.c_ulong(0)
    iphlpapi = ctypes.windll.iphlpapi  # type: ignore[attr-defined]
    iphlpapi.GetIpAddrTable(None, ctypes.byref(size), False)
    buf = ctypes.create_string_buffer(size.value)
    if iphlpapi.GetIpAddrTable(buf, ctypes.byref(size), False) != 0:
        return []
    count = struct.unpack_from("<I", buf, 0)[0]
    out = []
    for i in range(count):
        row = Row.from_buffer_copy(buf, 4 + i * ctypes.sizeof(Row))
        ip = socket.inet_ntoa(struct.pack("<I", row.addr))
        mask = socket.inet_ntoa(struct.pack("<I", row.mask))
        if ip.startswith(("127.", "0.", "169.254.")):
            continue
        out.append((ip, ipaddress.ip_network(f"{ip}/{mask}", strict=False)))
    return out


def _linux_networks() -> list[tuple[str, Network]]:
    try:
        data = json.loads(subprocess.run(["ip", "-j", "-4", "addr"], capture_output=True, text=True, timeout=10).stdout)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for link in data:
        for a in link.get("addr_info", []):
            ip, plen = a.get("local"), a.get("prefixlen")
            if ip and plen is not None and not ip.startswith(("127.", "169.254.")):
                out.append((ip, ipaddress.ip_network(f"{ip}/{plen}", strict=False)))
    return out


def local_networks() -> list[tuple[str, Network]]:
    """(this computer's address, its network) for every IPv4 address it holds."""
    try:
        return _windows_networks() if sys.platform == "win32" else _linux_networks()
    except Exception as exc:  # noqa: BLE001
        log.debug("could not read local networks: %s", exc)
        return []


def split_by_link(addresses: Iterable[str], networks: Iterable[tuple[str, Network]]
                  ) -> tuple[dict[str, list[str]], list[str]]:
    """({local source address: addresses on that attached network}, addresses beyond them).
    A target range can straddle both, so each address is placed on its own."""
    nets = list(networks)
    local: dict[str, list[str]] = {}
    routed: list[str] = []
    for ip in addresses:
        addr = ipaddress.ip_address(ip)
        for src, net in nets:
            if addr in net and ip != src:
                local.setdefault(src, []).append(ip)
                break
        else:
            if all(ip != src for src, _ in nets):
                routed.append(ip)
    return local, routed



def parse_ip_addr_macs(data: list) -> dict[str, str]:
    """ip -> this computer's MAC from `ip -j addr` output."""
    out = {}
    for link in data:
        raw = bytes(int(x, 16) for x in str(link.get("address", "")).split(":")) if str(link.get("address", "")).count(":") == 5 else b""
        mac = format_mac(raw)
        for a in link.get("addr_info", []):
            if mac and a.get("family") == "inet" and a.get("local"):
                out[a["local"]] = mac
    return out


def own_mac(ip: str) -> Optional[str]:
    """MAC of this computer's adapter that holds `ip` (no scapy needed): Windows' SendARP
    answers for a local address with the adapter's own MAC; Linux reads `ip -j addr`."""
    try:
        if sys.platform == "win32":
            return send_arp(ip, ip)
        data = json.loads(subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=10).stdout)
        return parse_ip_addr_macs(data).get(ip)
    except Exception:  # noqa: BLE001
        return None


# ── ARP ──────────────────────────────────────────────────────────────────────

def send_arp(ip: str, src: str = "0.0.0.0") -> Optional[str]:
    """MAC of `ip` via Windows' SendARP (it sends the ARP request itself), or None."""
    mac = (ctypes.c_ubyte * 8)()
    length = ctypes.c_ulong(6)
    rc = ctypes.windll.iphlpapi.SendARP(_ulong(ip), _ulong(src), ctypes.byref(mac), ctypes.byref(length))  # type: ignore[attr-defined]
    return format_mac(bytes(mac[:length.value])) if rc == 0 else None


def parse_proc_net_arp(text: str) -> dict[str, str]:
    """ip -> MAC of the complete entries in /proc/net/arp."""
    found = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "0x2":          # ATF_COM: resolved
            raw = bytes(int(x, 16) for x in parts[3].split(":")) if parts[3].count(":") == 5 else b""
            mac = format_mac(raw)
            if mac:
                found[parts[0]] = mac
    return found


def _linux_arp(addresses: list[str], src: str, rounds: int = 2, wait: float = 1.5) -> dict[str, str]:
    found: dict[str, str] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((src, 0))
        for _ in range(rounds):
            for ip in addresses:
                if ip not in found:
                    try:
                        s.sendto(b"", (ip, 9))              # discard port: only the ARP matters
                    except OSError:
                        pass
            time.sleep(wait)
            try:
                with open("/proc/net/arp", encoding="ascii") as f:
                    table = parse_proc_net_arp(f.read())
            except OSError:
                break
            found.update({ip: mac for ip, mac in table.items() if ip in set(addresses)})
    return found


def arp_sweep(addresses: list[str], src: str, workers: int = 128,
              cancelled: Callable[[], bool] = lambda: False) -> dict[str, str]:
    """ip -> MAC for the addresses on the local network that answered ARP."""
    if sys.platform != "win32":
        return _linux_arp(addresses, src)
    found: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="arp") as pool:
        for ip, mac in zip(addresses, pool.map(lambda a: None if cancelled() else send_arp(a, src), addresses)):
            if mac:
                found[ip] = mac
    return found


# ── ping ─────────────────────────────────────────────────────────────────────

def _windows_ping(ip: str, timeout_ms: int) -> bool:
    iphlpapi = ctypes.windll.iphlpapi  # type: ignore[attr-defined]
    iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
    iphlpapi.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_ushort,
                                      ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
    iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    handle = iphlpapi.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        return False
    try:
        data = b"EagleEye"
        reply = ctypes.create_string_buffer(256)
        n = iphlpapi.IcmpSendEcho(handle, _ulong(ip), data, len(data), None, reply, len(reply), timeout_ms)
        return n > 0 and struct.unpack_from("<I", reply, 4)[0] == 0      # ICMP_ECHO_REPLY.Status == IP_SUCCESS
    finally:
        iphlpapi.IcmpCloseHandle(handle)


def _linux_ping(ip: str, timeout_ms: int) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        return False                                   # unprivileged ping not allowed here
    with s:
        s.settimeout(timeout_ms / 1000)
        try:
            s.sendto(struct.pack(">BBHHH", 8, 0, 0, 0, 1) + b"EagleEye", (ip, 0))
            data = s.recv(1024)
            return bool(data) and data[0] == 0
        except OSError:
            return False


def ping(ip: str, timeout_ms: int = 800) -> bool:
    try:
        return _windows_ping(ip, timeout_ms) if sys.platform == "win32" else _linux_ping(ip, timeout_ms)
    except Exception:  # noqa: BLE001
        return False


def ping_sweep(addresses: list[str], timeout_ms: int = 800, workers: int = 64,
               cancelled: Callable[[], bool] = lambda: False) -> set[str]:
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ping") as pool:
        answers = pool.map(lambda a: False if cancelled() else ping(a, timeout_ms), addresses)
        return {ip for ip, ok in zip(addresses, answers) if ok}
