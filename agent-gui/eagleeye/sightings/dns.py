"""What a DNS answer says this computer looked up: the names (the question and the CNAME
chain) and the addresses they resolved to. An answer repeats its question, so the answers
alone are enough on every system (Linux and macOS captures do not see this computer's own
sent packets); an NXDOMAIN answer still names the domain."""

from __future__ import annotations

from typing import Any, Optional

from ..passive import decode

A, CNAME, AAAA = 1, 5, 28
# Never looked up on the internet: reverse lookups, mDNS-style local names.
LOCAL_SUFFIXES = (".arpa", ".local", ".lan", ".home", ".internal", ".localdomain")


def _text(name: Any) -> str:
    raw = name.decode("ascii", "ignore") if isinstance(name, (bytes, bytearray)) else str(name or "")
    return raw.strip().lower().rstrip(".")


def _wanted(name: str) -> bool:
    return "." in name and not name.endswith(LOCAL_SUFFIXES)


def answers(payload: bytes) -> Optional[tuple[list[str], list[str]]]:
    """(names, addresses) in a DNS response, or None when it is not one."""
    msg = decode.dns(payload)
    if msg is None or msg.qr != 1:
        return None
    names: list[str] = []
    addresses: list[str] = []
    for q in msg.qd:
        name = _text(q.qname)
        if _wanted(name) and name not in names:
            names.append(name)
    for rr in msg.an:
        if rr.type == CNAME:
            for raw in (rr.rrname, rr.rdata):
                name = _text(raw)
                if _wanted(name) and name not in names:
                    names.append(name)
        elif rr.type in (A, AAAA) and isinstance(rr.rdata, str) and rr.rdata not in addresses:
            addresses.append(rr.rdata)
    return names, addresses
