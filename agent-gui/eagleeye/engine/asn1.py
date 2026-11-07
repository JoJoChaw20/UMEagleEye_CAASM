"""Just enough ASN.1 (BER/DER) for the probes: build an SNMPv3 discovery message, read its
report, and read the names and dates in a TLS certificate. Standard library only."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator, Optional

INTEGER, OCTET_STRING, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30


# ── encoding ──
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def integer(n: int) -> bytes:
    body = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True)
    return tlv(INTEGER, body)


def octets(b: bytes) -> bytes:
    return tlv(OCTET_STRING, b)


def seq(*items: bytes, tag: int = SEQUENCE) -> bytes:
    return tlv(tag, b"".join(items))


# ── decoding ──
def read(data: bytes, off: int = 0) -> tuple[int, bytes, int]:
    """(tag, value, offset after it) of the element at off."""
    tag = data[off]
    n = data[off + 1]
    off += 2
    if n & 0x80:
        count = n & 0x7F
        n = int.from_bytes(data[off:off + count], "big")
        off += count
    return tag, data[off:off + n], off + n


def children(value: bytes) -> Iterator[tuple[int, bytes]]:
    off = 0
    while off < len(value):
        tag, v, off = read(value, off)
        yield tag, v


def to_int(v: bytes) -> int:
    return int.from_bytes(v, "big", signed=True) if v else 0


def oid_str(v: bytes) -> str:
    if not v:
        return ""
    parts = [v[0] // 40, v[0] % 40]
    n = 0
    for b in v[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


# ── X.509 certificates ──
_NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C"}


def _name(v: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for _t, rdn in children(v):                    # SET of AttributeTypeAndValue
        for _t2, atv in children(rdn):
            parts = list(children(atv))
            if len(parts) == 2 and parts[0][0] == OID:
                key = _NAME_OIDS.get(oid_str(parts[0][1]))
                if key and key not in out:
                    out[key] = parts[1][1].decode("utf-8", "replace")
    return out


def _time(tag: int, v: bytes) -> Optional[str]:
    text = v.decode("ascii", "replace")
    try:
        fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"
        return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return None


def certificate(der: bytes) -> dict:
    """{subject, issuer, not_before, not_after, san, self_signed} of a DER certificate."""
    _t, cert, _ = read(der)
    _t, tbs, _ = read(cert)
    items = list(children(tbs))
    if items and items[0][0] == 0xA0:              # explicit [0] version
        items = items[1:]
    # serial, signature algorithm, issuer, validity, subject, public key, [extensions]
    issuer, validity, subject = _name(items[2][1]), list(children(items[3][1])), _name(items[4][1])
    out = {
        "subject": subject, "issuer": issuer,
        "not_before": _time(*validity[0]) if validity else None,
        "not_after": _time(*validity[1]) if len(validity) > 1 else None,
        "self_signed": subject == issuer, "san": [],
    }
    for tag, v in items[6:]:
        if tag != 0xA3:                            # [3] extensions
            continue
        _t, exts, _ = read(v)
        for _t2, ext in children(exts):
            parts = list(children(ext))
            if parts and oid_str(parts[0][1]) == "2.5.29.17":       # subjectAltName
                _t3, names, _ = read(parts[-1][1])
                out["san"] = [n.decode("ascii", "replace") for t, n in children(names) if t == 0x82][:10]
    return out
