"""Decoding for the built-in capture, without scapy: Ethernet, ARP, IPv4/IPv6, UDP, and
the discovery protocols the sniffers read (mDNS/DNS, NetBIOS name service, DHCP; SSDP
is text and parsed by sniffers.parse_ssdp).

What comes out has the shape the sniffers' logic reads from scapy, so that logic is
shared by both captures: DNS names are bytes with the trailing dot, A/AAAA data are
address strings, DHCP options are keyed by number with scapy's value types. Every
parser returns None on a malformed or truncated packet, never raises.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

from .frames import ETH_ARP, ETH_IPV4, ETH_IPV6, UDP


def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


@dataclass
class Frame:
    src_mac: str
    dst_mac: str
    arp: Optional[tuple[str, str]] = None        # (sender IP, sender MAC)
    ip_src: Optional[str] = None                 # IPv4
    ip6_src: Optional[str] = None
    sport: Optional[int] = None                  # UDP
    dport: Optional[int] = None
    payload: bytes = b""                         # the UDP payload, without Ethernet padding


def frame(data: bytes) -> Optional[Frame]:
    """An untagged Ethernet frame, decoded as far as the sniffers need."""
    if len(data) < 14:
        return None
    etype = struct.unpack_from(">H", data, 12)[0]
    out = Frame(src_mac=mac_str(data[6:12]), dst_mac=mac_str(data[0:6]))
    if etype == ETH_ARP:
        # Ethernet/IPv4 ARP only: hardware type 1, protocol 0x0800, lengths 6 and 4.
        if len(data) < 42 or data[14:20] != b"\x00\x01\x08\x00\x06\x04":
            return out
        out.arp = (str(ipaddress.IPv4Address(data[28:32])), mac_str(data[22:28]))
        return out
    if etype == ETH_IPV4:
        if len(data) < 34 or data[14] >> 4 != 4:
            return out
        ihl = (data[14] & 0x0F) * 4
        total = struct.unpack_from(">H", data, 16)[0]
        out.ip_src = str(ipaddress.IPv4Address(data[26:30]))
        if ihl < 20 or data[23] != UDP or struct.unpack_from(">H", data, 20)[0] & 0x1FFF:
            return out
        end = min(len(data), 14 + total) if total else len(data)
        _udp(out, data, 14 + ihl, end)
        return out
    if etype == ETH_IPV6:
        if len(data) < 54 or data[14] >> 4 != 6:
            return out
        out.ip6_src = str(ipaddress.IPv6Address(data[22:38]))
        if data[20] != UDP:
            return out
        end = min(len(data), 54 + struct.unpack_from(">H", data, 18)[0])
        _udp(out, data, 54, end)
        return out
    return out


def _udp(out: Frame, data: bytes, off: int, end: int) -> None:
    if end < off + 8:
        return
    out.sport, out.dport, length = struct.unpack_from(">HHH", data, off)
    stop = min(end, off + length) if length >= 8 else end
    out.payload = bytes(data[off + 8:stop])


# ── DNS (mDNS) ───────────────────────────────────────────────────────────────

@dataclass
class Question:
    qname: bytes
    qtype: int


@dataclass
class Record:
    rrname: bytes
    type: int
    rdata: Any                                    # str for A/AAAA, bytes name for PTR, raw bytes otherwise


@dataclass
class Dns:
    qr: int
    qd: list[Question] = field(default_factory=list)
    an: list[Record] = field(default_factory=list)
    ns: list[Record] = field(default_factory=list)
    ar: list[Record] = field(default_factory=list)


class _Malformed(Exception):
    pass


def _name(msg: bytes, off: int) -> tuple[bytes, int]:
    """A DNS name at `off` (following compression pointers), as scapy gives it (labels
    joined by dots, trailing dot), and the offset after it in the message."""
    labels: list[bytes] = []
    after: Optional[int] = None
    jumps = 0
    while True:
        if off >= len(msg):
            raise _Malformed("name runs past the end")
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(msg) or jumps > 32:
                raise _Malformed("bad compression pointer")
            if after is None:
                after = off + 2
            off = ((ln & 0x3F) << 8) | msg[off + 1]
            jumps += 1
            continue
        if ln & 0xC0:
            raise _Malformed("unknown label type")
        if off + 1 + ln > len(msg):
            raise _Malformed("label runs past the end")
        labels.append(msg[off + 1:off + 1 + ln])
        off += 1 + ln
    return b".".join(labels) + b".", (after if after is not None else off)


def dns(msg: bytes) -> Optional[Dns]:
    """A DNS-format message (mDNS), or None when it is malformed."""
    if len(msg) < 12:
        return None
    _id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHHHH", msg, 0)
    out = Dns(qr=flags >> 15)
    off = 12
    try:
        for _ in range(qdcount):
            name, off = _name(msg, off)
            if off + 4 > len(msg):
                raise _Malformed("question runs past the end")
            out.qd.append(Question(name, struct.unpack_from(">H", msg, off)[0]))
            off += 4
        for section, count in ((out.an, ancount), (out.ns, nscount), (out.ar, arcount)):
            for _ in range(count):
                name, off = _name(msg, off)
                if off + 10 > len(msg):
                    raise _Malformed("record runs past the end")
                rtype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", msg, off)
                off += 10
                if off + rdlen > len(msg):
                    raise _Malformed("record data runs past the end")
                raw = msg[off:off + rdlen]
                rdata: Any = raw
                if rtype == 1 and rdlen == 4:
                    rdata = str(ipaddress.IPv4Address(raw))
                elif rtype == 28 and rdlen == 16:
                    rdata = str(ipaddress.IPv6Address(raw))
                elif rtype == 12:                         # PTR: a name
                    rdata = _name(msg, off)[0]
                section.append(Record(name, rtype, rdata))
                off += rdlen
    except (_Malformed, struct.error, ValueError):
        return None
    return out


# ── NetBIOS name service ─────────────────────────────────────────────────────

NB, NBSTAT = 0x20, 0x21


def _netbios_name(msg: bytes, off: int) -> tuple[str, int, int]:
    """(name without padding, suffix byte, offset after) of a first-level encoded name
    (length 32, 32 letters A-P, then the scope's terminating 0)."""
    if off + 34 > len(msg) or msg[off] != 32:
        raise _Malformed("not an encoded NetBIOS name")
    enc = msg[off + 1:off + 33]
    if not all(0x41 <= c <= 0x50 for c in enc):
        raise _Malformed("bad NetBIOS name encoding")
    raw = bytes(((enc[i] - 0x41) << 4) | (enc[i + 1] - 0x41) for i in range(0, 32, 2))
    off += 33
    while off < len(msg) and msg[off] != 0:            # scope labels (rare)
        off += 1 + msg[off]
    return raw[:15].decode("latin-1").replace("\x00", " ").strip(), raw[15], off + 1


def _unique(name: str, suffix: int, group: bool) -> str:
    """A device's own name: workstation <00> or server <20>, never a group name."""
    return name if not group and suffix in (0x00, 0x20) and 2 <= len(name) <= 15 else ""


def netbios_names(msg: bytes, src_ip: Optional[str]) -> list[tuple[str, str]]:
    """(ip, name) pairs a NetBIOS name service packet says a device owns: a name
    registration or refresh, a positive name query response, or a node status
    response (the sender's workstation name)."""
    try:
        if len(msg) < 12:
            return []
        _id, flags, qdcount, ancount, _ns, arcount = struct.unpack_from(">HHHHHH", msg, 0)
        response, opcode, rcode = flags >> 15, (flags >> 11) & 0x0F, flags & 0x0F
        off = 12
        if not response and opcode in (5, 8, 9) and qdcount >= 1 and arcount >= 1:
            name, suffix, off = _netbios_name(msg, off)
            off += 4                                   # question type and class
            if off + 2 <= len(msg) and msg[off] & 0xC0 == 0xC0:
                off += 2                               # the record names the question by pointer
            else:
                _n, _s, off = _netbios_name(msg, off)
            rtype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", msg, off)
            off += 10
            if rtype != NB or rdlen < 6:
                return []
            nb_flags = struct.unpack_from(">H", msg, off)[0]
            owner = _unique(name, suffix, bool(nb_flags & 0x8000))
            address = str(ipaddress.IPv4Address(msg[off + 2:off + 6]))
            return [(address or src_ip or "", owner)] if owner else []
        if response and opcode == 0 and rcode == 0 and ancount >= 1:
            name, suffix, off = _netbios_name(msg, off)
            rtype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", msg, off)
            off += 10
            if rtype == NB:
                out = []
                for entry in range(off, off + rdlen - 5, 6):
                    nb_flags = struct.unpack_from(">H", msg, entry)[0]
                    owner = _unique(name, suffix, bool(nb_flags & 0x8000))
                    if owner:
                        out.append((str(ipaddress.IPv4Address(msg[entry + 2:entry + 6])), owner))
                return out
            if rtype == NBSTAT and src_ip and off < len(msg):
                count = msg[off]
                for i in range(count):
                    entry = off + 1 + 18 * i
                    if entry + 18 > len(msg):
                        break
                    node = msg[entry:entry + 15].decode("latin-1").replace("\x00", " ").strip()
                    if msg[entry + 15] == 0x00 and not (msg[entry + 16] & 0x80) and 2 <= len(node) <= 15:
                        return [(src_ip, node)]
        return []
    except (_Malformed, struct.error, ValueError, IndexError):
        return []


# ── DHCP ─────────────────────────────────────────────────────────────────────

DHCP_COOKIE = b"\x63\x82\x53\x63"


@dataclass
class Dhcp:
    chaddr: bytes
    ciaddr: str
    yiaddr: str
    options: dict[int, Any]


def dhcp(msg: bytes) -> Optional[Dhcp]:
    """A BOOTP/DHCP message with options as scapy gives them: message type (53) an int,
    requested address (50) a string, parameter list (55) a list of ints, the rest bytes.
    A repeated option keeps its last value, as DhcpSniffer._options does with scapy's."""
    if len(msg) < 240 or msg[236:240] != DHCP_COOKIE:
        return None
    options: dict[int, Any] = {}
    off = 240
    while off < len(msg):
        code = msg[off]
        if code == 0:
            off += 1
            continue
        if code == 255 or off + 1 >= len(msg):
            break
        ln = msg[off + 1]
        val = msg[off + 2:off + 2 + ln]
        if len(val) < ln:
            break
        off += 2 + ln
        if code == 53 and ln == 1:
            options[code] = val[0]
        elif code == 50 and ln == 4:
            options[code] = str(ipaddress.IPv4Address(val))
        elif code == 55:
            options[code] = list(val)
        else:
            options[code] = bytes(val)
    if 53 not in options:
        return None                                    # BOOTP without DHCP
    return Dhcp(chaddr=bytes(msg[28:34]), ciaddr=str(ipaddress.IPv4Address(msg[12:16])),
                yiaddr=str(ipaddress.IPv4Address(msg[16:20])), options=options)
