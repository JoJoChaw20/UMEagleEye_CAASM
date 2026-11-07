"""Two UDP questions every device is asked once per scan, with no credentials:

SNMPv3 engine discovery (UDP 161): an unauthenticated SNMPv3 request makes any SNMPv3 agent
answer with a report that names its engine: the vendor's enterprise number (often with a
MAC or address after it), how often it rebooted and for how long it has been up. This is
the first step of every SNMPv3 exchange (RFC 3414 4); nothing is read from the device.

NetBIOS node status (UDP 137): Windows machines and Samba answer with their name table
(computer name, workgroup) and their MAC.
"""

from __future__ import annotations

import socket
import struct
from typing import Any, Optional

from . import asn1

# IANA private enterprise numbers of common network and server vendors.
ENTERPRISES = {
    9: "Cisco", 11: "HP", 43: "3Com", 171: "D-Link", 311: "Microsoft", 674: "Dell", 1916: "Extreme Networks",
    1991: "Brocade (Foundry)", 2011: "Huawei", 2021: "net-snmp (UCD)", 2636: "Juniper", 3375: "F5",
    4413: "Broadcom", 4526: "Netgear", 6527: "Nokia (Alcatel-Lucent)", 6876: "VMware", 8072: "net-snmp",
    11863: "TP-Link", 12356: "Fortinet", 14823: "Aruba", 14988: "MikroTik", 25461: "Palo Alto Networks",
    25506: "H3C", 30065: "Arista", 41112: "Ubiquiti", 47196: "Synology", 24681: "QNAP",
}


def _ask(ip: str, port: int, payload: bytes, timeout: float) -> Optional[bytes]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(payload, (ip, port))
            data, addr = s.recvfrom(4096)
        except OSError:
            return None
        return data if addr[0] == ip else None


# ── SNMPv3 engine discovery ──
def snmp_discovery_request(msg_id: int = 0x4545, request_id: int = 0x4546) -> bytes:
    usm = asn1.seq(asn1.octets(b""), asn1.integer(0), asn1.integer(0),
                   asn1.octets(b""), asn1.octets(b""), asn1.octets(b""))
    pdu = asn1.seq(asn1.integer(request_id), asn1.integer(0), asn1.integer(0), asn1.seq(), tag=0xA0)
    return asn1.seq(
        asn1.integer(3),
        asn1.seq(asn1.integer(msg_id), asn1.integer(65507), asn1.octets(b"\x04"), asn1.integer(3)),
        asn1.octets(usm),
        asn1.seq(asn1.octets(b""), asn1.octets(b""), pdu),
    )


def parse_engine_id(engine: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"engine_id": engine.hex()}
    if len(engine) >= 5 and engine[0] & 0x80:
        enterprise = int.from_bytes(engine[:4], "big") & 0x7FFFFFFF
        out["enterprise"] = enterprise
        if enterprise in ENTERPRISES:
            out["vendor"] = ENTERPRISES[enterprise]
        fmt, data = engine[4], engine[5:]
        if fmt == 1 and len(data) == 4:
            out["address"] = socket.inet_ntoa(data)
        elif fmt == 3 and len(data) == 6:
            out["mac"] = ":".join(f"{b:02X}" for b in data)
        elif fmt == 4:
            out["text"] = data.decode("utf-8", "replace")[:64]
    return out


def parse_snmp_report(data: bytes) -> Optional[dict[str, Any]]:
    try:
        _t, msg, _ = asn1.read(data)
        parts = list(asn1.children(msg))
        if len(parts) < 3 or asn1.to_int(parts[0][1]) != 3:
            return None
        _t, usm, _ = asn1.read(parts[2][1])
        fields = list(asn1.children(usm))
        engine = fields[0][1]
        if not engine:
            return None
        out = parse_engine_id(engine)
        out["boots"] = asn1.to_int(fields[1][1])
        out["uptime_seconds"] = asn1.to_int(fields[2][1])
        return out
    except (IndexError, ValueError):
        return None


def snmp_engine(ip: str, timeout: float = 2.0) -> Optional[dict[str, Any]]:
    data = _ask(ip, 161, snmp_discovery_request(), timeout)
    return parse_snmp_report(data) if data else None


# ── NetBIOS node status ──
NBSTAT_REQUEST = struct.pack(">HHHHHH", 0x4242, 0, 1, 0, 0, 0) + b"\x20CK" + b"A" * 30 + b"\x00" + struct.pack(">HH", 0x21, 1)


def parse_node_status(data: bytes) -> Optional[dict[str, Any]]:
    if len(data) < 57:
        return None
    count = data[56]
    names = []
    for i in range(count):
        off = 57 + 18 * i
        if off + 18 > len(data):
            return None
        raw = data[off:off + 15].decode("ascii", "replace").rstrip()
        suffix, flags = data[off + 15], struct.unpack_from(">H", data, off + 16)[0]
        names.append((raw, suffix, bool(flags & 0x8000)))
    mac_off = 57 + 18 * count
    mac = data[mac_off:mac_off + 6]
    computer = next((n for n, sfx, group in names if sfx == 0x00 and not group), None)
    workgroup = next((n for n, sfx, group in names if sfx == 0x00 and group), None)
    out: dict[str, Any] = {"names": sorted({n for n, _s, _g in names})}
    if computer:
        out["computer"] = computer
    if workgroup:
        out["workgroup"] = workgroup
    if len(mac) == 6 and any(mac):
        out["mac"] = ":".join(f"{b:02X}" for b in mac)
    return out


def netbios_status(ip: str, timeout: float = 1.5) -> Optional[dict[str, Any]]:
    data = _ask(ip, 137, NBSTAT_REQUEST, timeout)
    return parse_node_status(data) if data else None
