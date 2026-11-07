"""Byte-level helpers for the built-in packet capture (no Npcap, no libpcap).

The built-in capture hands every frame of the adapter to one dispatcher, which gives each
sniffer only what its BPF filter would have let through (the same rules, written out
here), so the sniffers' tested handlers see exactly what Npcap gave them. Frames are
decoded with scapy only when some sniffer wants them.

On Linux the union of those rules also runs in the kernel (classic BPF on the packet
socket), so the agent is not woken for traffic no sniffer wants.
"""

from __future__ import annotations

import struct
from typing import Optional

ETH_ARP, ETH_IPV4, ETH_IPV6 = 0x0806, 0x0800, 0x86DD
UDP = 17
# Every UDP port a sniffer listens to: DHCP, NetBIOS name service, SSDP, mDNS.
UDP_PORTS = (67, 68, 137, 1900, 5353)


def wifi_to_ethernet(frame: bytes) -> Optional[bytes]:
    """An 802.11 data frame as the Ethernet frame it carries, or None if it is not one.

    Microsoft's capture driver gives a Wi-Fi adapter's frames as 802.11 (already
    decrypted, but the Protected flag stays set). A frame counts as 802.11 only when it
    is a data frame AND an LLC/SNAP header sits where the 802.11 header ends, which an
    Ethernet frame practically never has."""
    if len(frame) < 32:
        return None
    fc0, fc1 = frame[0], frame[1]
    if (fc0 & 0x0C) != 0x08 or (fc0 & 0x03) != 0:        # type data, version 0
        return None
    to_ds, from_ds = bool(fc1 & 0x01), bool(fc1 & 0x02)
    hdr = 24 + (6 if to_ds and from_ds else 0)
    if fc0 & 0x80:                                        # QoS data subtypes
        hdr += 2
        if fc1 & 0x80:                                    # +HTC
            hdr += 4
    if frame[hdr:hdr + 3] != b"\xaa\xaa\x03" or len(frame) < hdr + 8:
        return None
    a1, a2, a3 = frame[4:10], frame[10:16], frame[16:22]
    if not to_ds and not from_ds:
        da, sa = a1, a2
    elif to_ds and not from_ds:
        da, sa = a3, a2
    elif from_ds and not to_ds:
        da, sa = a1, a3
    else:
        da, sa = a3, frame[24:30]
    return da + sa + frame[hdr + 6:hdr + 8] + frame[hdr + 8:]


def ethertype(frame: bytes) -> Optional[int]:
    return struct.unpack_from(">H", frame, 12)[0] if len(frame) >= 14 else None


def udp_ports(frame: bytes) -> Optional[tuple[int, int]]:
    """(source port, destination port) of a UDP datagram in an untagged Ethernet frame,
    or None. As BPF's "udp port N": IPv4 first fragments only, IPv6 without extension
    headers. Lengths are checked exactly where kernel_filter reads, so both agree on
    every frame, cut-off ones included."""
    etype = ethertype(frame)
    if etype == ETH_IPV4:
        if len(frame) < 24 or frame[23] != UDP:
            return None
        if struct.unpack_from(">H", frame, 20)[0] & 0x1FFF:     # a later fragment
            return None
        off = 14 + (frame[14] & 0x0F) * 4
    elif etype == ETH_IPV6:
        if len(frame) < 21 or frame[20] != UDP:
            return None
        off = 54
    else:
        return None
    if len(frame) < off + 4:
        return None
    return struct.unpack_from(">HH", frame, off)


def _has_port(frame: bytes, ports: tuple[int, ...]) -> bool:
    found = udp_ports(frame)
    return found is not None and (found[0] in ports or found[1] in ports)


def arp_or_broadcast(frame: bytes) -> bool:
    """BPF "arp or (ip and (ether broadcast or ether multicast))"."""
    etype = ethertype(frame)
    return etype == ETH_ARP or (etype == ETH_IPV4 and bool(frame[0] & 1))


def mdns_or_netbios(frame: bytes) -> bool:
    """BPF "udp port 5353 or udp port 137"."""
    return _has_port(frame, (5353, 137))


def dhcp(frame: bytes) -> bool:
    """BPF "udp port 67 or udp port 68"."""
    return _has_port(frame, (67, 68))


def ssdp(frame: bytes) -> bool:
    """BPF "udp port 1900"."""
    return _has_port(frame, (1900,))


def wanted(frame: bytes) -> bool:
    """What any sniffer wants (the kernel filter's rule)."""
    return arp_or_broadcast(frame) or _has_port(frame, UDP_PORTS)


# ── Classic BPF for the Linux packet socket ──────────────────────────────────

LD_H_ABS, LD_B_ABS, LD_H_IND, LDX_B_MSH = 0x28, 0x30, 0x48, 0xB1
JEQ, JSET, RET = 0x15, 0x45, 0x06
ACCEPT_BYTES = 0x40000


def _assemble(program: list) -> list[tuple[int, int, int, int]]:
    """[(code, k), (code, k, true_label, false_label), "label", ...] -> sock_filter
    tuples (code, jt, jf, k). A jump label of None is the next instruction."""
    labels, at = {}, 0
    for ins in program:
        if isinstance(ins, str):
            labels[ins] = at
        else:
            at += 1
    out: list[tuple[int, int, int, int]] = []
    for ins in program:
        if isinstance(ins, str):
            continue
        if len(ins) == 2:
            out.append((ins[0], 0, 0, ins[1]))
            continue
        code, k, jt, jf = ins
        here = len(out) + 1
        rel = [0 if t is None else labels[t] - here for t in (jt, jf)]
        if not all(0 <= r <= 255 for r in rel):
            raise ValueError("BPF jump out of range")
        out.append((code, rel[0], rel[1], k))
    return out


def _port_checks(load: int, offset: int) -> list[tuple]:
    return [(load, offset)] + [(JEQ, port, "accept", None) for port in UDP_PORTS]


def kernel_filter() -> list[tuple[int, int, int, int]]:
    """wanted() as classic BPF on untagged Ethernet frames."""
    return _assemble([
        (LD_H_ABS, 12),
        (JEQ, ETH_ARP, "accept", None),
        (JEQ, ETH_IPV4, "ipv4", None),
        (JEQ, ETH_IPV6, "ipv6", "reject"),
        "ipv4",
        (LD_B_ABS, 0),
        (JSET, 1, "accept", None),                # broadcast or multicast destination
        (LD_B_ABS, 23),
        (JEQ, UDP, None, "reject"),
        (LD_H_ABS, 20),
        (JSET, 0x1FFF, "reject", None),           # not the first fragment
        (LDX_B_MSH, 14),
        *_port_checks(LD_H_IND, 16),              # destination port first: both need the whole header
        *_port_checks(LD_H_IND, 14),              # source port
        (RET, 0),
        "ipv6",
        (LD_B_ABS, 20),
        (JEQ, UDP, None, "reject"),
        *_port_checks(LD_H_ABS, 56),
        *_port_checks(LD_H_ABS, 54),
        "reject",
        (RET, 0),
        "accept",
        (RET, ACCEPT_BYTES),
    ])


def run_filter(program: list[tuple[int, int, int, int]], frame: bytes) -> int:
    """Run a classic BPF program (the instructions kernel_filter uses) on a frame, as
    the kernel does: the bytes it keeps, 0 = dropped (also when it reads past the end)."""
    a = x = pc = 0
    while pc < len(program):
        code, jt, jf, k = program[pc]
        pc += 1
        try:
            if code == LD_H_ABS:
                a = struct.unpack_from(">H", frame, k)[0] if k + 2 <= len(frame) else _out()
            elif code == LD_B_ABS:
                a = frame[k] if k < len(frame) else _out()
            elif code == LD_H_IND:
                a = struct.unpack_from(">H", frame, x + k)[0] if x + k + 2 <= len(frame) else _out()
            elif code == LDX_B_MSH:
                x = (frame[k] & 0x0F) * 4 if k < len(frame) else _out()
            elif code == JEQ:
                pc += jt if a == k else jf
            elif code == JSET:
                pc += jt if a & k else jf
            elif code == RET:
                return k
            else:
                raise ValueError(f"unknown BPF instruction {code:#x}")
        except _OutOfFrame:
            return 0
    return 0


class _OutOfFrame(Exception):
    pass


def _out() -> int:
    raise _OutOfFrame
