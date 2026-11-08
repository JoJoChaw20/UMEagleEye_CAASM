"""Our own SNMP client for the network agent: v2c, and v3 with the User-based Security Model.

Read only: GET and GETBULK walks; nothing is ever written to a device.
- v3 authentication: HMAC-MD5-96 / HMAC-SHA-96 (RFC 3414) and HMAC-SHA-2 (RFC 7860), from the
  standard library.
- v3 privacy: AES-128-CFB (RFC 3826) through the `cryptography` package. DES and the
  non-standard AES-192/256 key extensions are not supported.
- Cisco switches keep one MAC table per VLAN: `vlan=` asks for it (context "vlan-N" over v3,
  community "name@N" over v2c).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional, TypeVar, Union

from ..engine import asn1

Oid = tuple[int, ...]
OidLike = Union[str, Oid]
T = TypeVar("T")

GET, GETNEXT, RESPONSE, GETBULK, REPORT = 0xA0, 0xA1, 0xA2, 0xA5, 0xA8
_IP_ADDRESS, _OPAQUE = 0x40, 0x44
_UNSIGNED = (0x41, 0x42, 0x43, 0x46)            # Counter32, Gauge32, TimeTicks, Counter64
_NO_SUCH_OBJECT, _NO_SUCH_INSTANCE, _END_OF_MIB_VIEW = 0x80, 0x81, 0x82


class _Marker:
    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return self.name

    def __bool__(self) -> bool:
        return False


NO_SUCH = _Marker("noSuchObject")               # the device has no such value
END_OF_MIB = _Marker("endOfMibView")            # nothing comes after it


class SnmpError(Exception):
    pass


class SnmpTimeout(SnmpError):
    pass


class SnmpAuthError(SnmpError):
    """Wrong user, password, protocol or security level: retrying will not help."""


class _TooBig(SnmpError):
    pass


# usmStats reports (RFC 3414 5): what the device says when it refuses a v3 request.
_USM_STATS = (1, 3, 6, 1, 6, 3, 15, 1, 1)
_REPORTS = {
    1: "the device does not allow this security level for this user (authPriv / authNoPriv)",
    2: "the device's clock window was missed",
    3: "the device does not know this SNMPv3 user",
    4: "the device's engine ID changed",
    5: "wrong authentication password or protocol",
    6: "wrong privacy password or protocol",
}
_NOT_IN_TIME_WINDOW, _UNKNOWN_ENGINE = 2, 4

AUTH_PROTOCOLS = {                              # name -> (hashlib name, MAC length)
    "MD5": ("md5", 12), "SHA": ("sha1", 12), "SHA1": ("sha1", 12),
    "SHA224": ("sha224", 16), "SHA256": ("sha256", 24), "SHA384": ("sha384", 32), "SHA512": ("sha512", 48),
}
PRIV_PROTOCOLS = ("AES", "AES128")


def privacy_available() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


@dataclass
class Credentials:
    version: str = "3"                          # "3" or "2c"
    community: str = ""                         # v2c only
    user: str = ""
    auth_protocol: str = "SHA"
    auth_key: str = ""
    priv_protocol: str = "AES"                  # "" = authNoPriv
    priv_key: str = ""

    def __repr__(self) -> str:                  # never print a secret
        if self.version == "2c":
            return "Credentials(v2c, community=***)"
        return (f"Credentials(v3, user={self.user!r}, auth={self.auth_protocol}, "
                f"priv={self.priv_protocol or 'none'})")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Credentials":
        known = {k: str(v) for k, v in d.items() if k in cls.__dataclass_fields__ and v is not None}
        return cls(**known)

    @property
    def level(self) -> str:
        if self.version == "2c":
            return "community"
        return "authPriv" if self.priv_protocol else "authNoPriv"

    def check(self) -> None:
        """Raise ValueError naming what is missing or unsupported."""
        if self.version == "2c":
            if not self.community:
                raise ValueError("SNMPv2c needs a community")
            return
        if self.version != "3":
            raise ValueError(f"SNMP version must be 3 or 2c, not {self.version!r}")
        if not self.user:
            raise ValueError("SNMPv3 needs a user name")
        if self.auth_protocol.upper() not in AUTH_PROTOCOLS:
            raise ValueError(f"unsupported authentication protocol {self.auth_protocol!r} "
                             f"(use one of {', '.join(AUTH_PROTOCOLS)})")
        if len(self.auth_key) < 8:
            raise ValueError("the SNMPv3 authentication password must have at least 8 characters")
        if self.priv_protocol:
            if self.priv_protocol.upper() not in PRIV_PROTOCOLS:
                raise ValueError(f"unsupported privacy protocol {self.priv_protocol!r} (only AES-128 is supported)")
            if len(self.priv_key) < 8:
                raise ValueError("the SNMPv3 privacy password must have at least 8 characters")
            if not privacy_available():
                raise ValueError("SNMPv3 privacy (AES) needs the 'cryptography' package: pip install cryptography")


# ── OIDs and values ──
def to_oid(oid: OidLike) -> Oid:
    if isinstance(oid, tuple):
        return oid
    return tuple(int(p) for p in oid.strip().lstrip(".").split("."))


def oid_text(oid: Oid) -> str:
    return "." + ".".join(map(str, oid))


def _base128(n: int) -> bytes:
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.append(0x80 | (n & 0x7F))
        n >>= 7
    return bytes(reversed(out))


def encode_oid(oid: Oid) -> bytes:
    if len(oid) < 2:
        raise ValueError(f"an OID needs at least two parts: {oid}")
    body = _base128(40 * oid[0] + oid[1]) + b"".join(_base128(arc) for arc in oid[2:])
    return asn1.tlv(asn1.OID, body)


def decode_oid(v: bytes) -> Oid:
    arcs: list[int] = []
    n = 0
    for b in v:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(n)
            n = 0
    if not arcs:
        return ()
    first = arcs[0]
    head = (first // 40, first % 40) if first < 80 else (2, first - 80)
    return head + tuple(arcs[1:])


def decode_value(tag: int, v: bytes) -> Any:
    """int (INTEGER, counters, gauges, time ticks), bytes (OCTET STRING, Opaque), str (IpAddress),
    tuple (OBJECT IDENTIFIER), None (NULL), NO_SUCH or END_OF_MIB."""
    if tag == asn1.INTEGER:
        return asn1.to_int(v)
    if tag in _UNSIGNED:
        return int.from_bytes(v, "big")
    if tag in (asn1.OCTET_STRING, _OPAQUE):
        return bytes(v)
    if tag == _IP_ADDRESS:
        return ".".join(str(b) for b in v) if len(v) == 4 else bytes(v)
    if tag == asn1.OID:
        return decode_oid(v)
    if tag in (_NO_SUCH_OBJECT, _NO_SUCH_INSTANCE):
        return NO_SUCH
    if tag == _END_OF_MIB_VIEW:
        return END_OF_MIB
    if tag == asn1.NULL:
        return None
    return bytes(v)


def build_pdu(tag: int, request_id: int, oids: Iterable[Oid], a: int = 0, b: int = 0) -> bytes:
    """A request PDU; a/b are error-status/index, or non-repeaters/max-repetitions for GETBULK."""
    binds = asn1.seq(*(asn1.seq(encode_oid(o), b"\x05\x00") for o in oids))
    return asn1.seq(asn1.integer(request_id), asn1.integer(a), asn1.integer(b), binds, tag=tag)


def parse_pdu(data: bytes) -> tuple[int, int, int, int, list[tuple[Oid, Any]]]:
    """(tag, request id, error status, error index, variable bindings) of a PDU."""
    tag, value, _ = asn1.read(data)
    items = list(asn1.children(value))
    binds = []
    for _t, vb in asn1.children(items[3][1]):
        (_ot, ov), (vt, vv) = list(asn1.children(vb))[:2]
        binds.append((decode_oid(ov), decode_value(vt, vv)))
    return tag, asn1.to_int(items[0][1]), asn1.to_int(items[1][1]), asn1.to_int(items[2][1]), binds


def _spans(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    """(tag, value start, value end) of each element between start and end."""
    out = []
    off = start
    while off < end:
        tag, value, nxt = asn1.read(data, off)
        out.append((tag, nxt - len(value), nxt))
        off = nxt
    return out


# ── v3 keys (RFC 3414 A.2, RFC 7860) ──
_master_keys: dict[tuple[str, str], bytes] = {}


def password_to_key(password: str, hash_name: str) -> bytes:
    """The user's master key: the password repeated to 1 MiB, hashed. Cached (it is slow-ish)."""
    cached = _master_keys.get((hash_name, password))
    if cached is None:
        pw = password.encode("utf-8")
        h = hashlib.new(hash_name)
        h.update((pw * (1048576 // len(pw) + 1))[:1048576])
        cached = _master_keys[(hash_name, password)] = h.digest()
    return cached


def localize_key(master: bytes, engine_id: bytes, hash_name: str) -> bytes:
    return hashlib.new(hash_name, master + engine_id + master).digest()


def _aes_cfb(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:                         # cryptography before 43
        from cryptography.hazmat.primitives.ciphers.modes import CFB  # type: ignore[no-redef]
    cipher = Cipher(algorithms.AES(key), CFB(iv))
    op = cipher.encryptor() if encrypt else cipher.decryptor()
    return op.update(data) + op.finalize()


# ── a session with one device ──
class Session:
    """GET and walk one device. Not thread-safe: one session per device."""

    def __init__(self, host: str, creds: Credentials, port: int = 161, timeout: float = 2.0,
                 retries: int = 1, max_repetitions: int = 25) -> None:
        creds.check()
        self.host, self.port, self.creds = host, port, creds
        self.timeout, self.retries, self.max_repetitions = timeout, retries, max_repetitions
        self.requests = 0                       # what this session cost the network
        self.bytes_received = 0
        self._sock: Optional[socket.socket] = None
        self._id = int.from_bytes(os.urandom(3), "big")
        self._salt = int.from_bytes(os.urandom(8), "big")
        self._engine: Optional[bytes] = None
        self._boots = self._time = 0
        self._clock_at = 0.0
        self._auth_key = self._priv_key = b""

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    @property
    def engine_id(self) -> Optional[bytes]:
        return self._engine

    # ── public ──
    def get(self, oids: Iterable[OidLike], vlan: Optional[int] = None) -> dict[Oid, Any]:
        """{oid: value}; a value the device does not have is None."""
        wanted = [to_oid(o) for o in oids]
        binds = self._request(GET, wanted, 0, 0, vlan)
        return {oid: (None if value is NO_SUCH or value is END_OF_MIB else value) for oid, value in binds}

    def walk(self, base: OidLike, vlan: Optional[int] = None, limit: int = 100_000) -> list[tuple[Oid, Any]]:
        """Every (oid, value) under base, in order, read with GETBULK."""
        root = to_oid(base)
        out: list[tuple[Oid, Any]] = []
        cur, reps = root, self.max_repetitions
        while len(out) < limit:
            try:
                binds = self._request(GETBULK, [cur], 0, reps, vlan)
            except _TooBig:
                if reps == 1:
                    raise SnmpError(f"{self.host}: the answer is too big even one value at a time")
                reps = max(1, reps // 2)
                continue
            if not binds:
                return out
            for oid, value in binds:
                if value is END_OF_MIB or oid[:len(root)] != root:
                    return out
                if oid <= cur:
                    raise SnmpError(f"{self.host} returned values out of order at {oid_text(oid)}")
                out.append((oid, value))
                cur = oid
        return out

    # ── one request ──
    def _next_id(self) -> int:
        self._id = (self._id + 1) & 0x7FFFFFFF
        return self._id

    def _request(self, tag: int, oids: list[Oid], a: int, b: int, vlan: Optional[int]) -> list[tuple[Oid, Any]]:
        if self.creds.version == "2c":
            community = self.creds.community + (f"@{vlan}" if vlan is not None else "")
            rid = self._next_id()
            msg = asn1.seq(asn1.integer(1), asn1.octets(community.encode()), build_pdu(tag, rid, oids, a, b))
            pdu = self._exchange(msg, lambda d: self._parse_v2c(d, rid))
            return self._result(pdu)
        if self._engine is None:
            self._discover()
        context = f"vlan-{vlan}" if vlan is not None else ""
        for attempt in range(2):
            msg_id = self._next_id()
            msg = self._v3_message(msg_id, build_pdu(tag, msg_id, oids, a, b), context)
            pdu = self._exchange(msg, lambda d: self._parse_v3(d, msg_id))
            if pdu[0] != REPORT:
                return self._result(pdu)
            report = pdu[4][0][0] if pdu[4] else ()
            kind = report[len(_USM_STATS)] if report[:len(_USM_STATS)] == _USM_STATS and len(report) > len(_USM_STATS) else 0
            if attempt == 0 and kind == _NOT_IN_TIME_WINDOW:
                continue                        # the report carried the device's clock: try again
            if attempt == 0 and kind == _UNKNOWN_ENGINE:
                self._engine = None
                self._discover()
                continue
            raise SnmpAuthError(f"{self.host}: {_REPORTS.get(kind, 'the device refused the request')}")
        raise SnmpAuthError(f"{self.host}: {_REPORTS[_NOT_IN_TIME_WINDOW]}")

    def _result(self, pdu: tuple[int, int, int, int, list]) -> list[tuple[Oid, Any]]:
        _tag, _rid, status, index, binds = pdu
        if status == 1:
            raise _TooBig(self.host)
        if status == 2:                         # noSuchName (an SNMPv1-style answer)
            return [(oid, NO_SUCH) for oid, _v in binds]
        if status:
            raise SnmpError(f"{self.host} answered with error {status} (variable {index})")
        return binds

    def _exchange(self, msg: bytes, parse: Callable[[bytes], Optional[T]]) -> T:
        if self._sock is None:
            family, _t, _p, _c, addr = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM)[0]
            self._sock = socket.socket(family, socket.SOCK_DGRAM)
            self._sock.connect(addr)
        for _attempt in range(self.retries + 1):
            self.requests += 1
            try:
                self._sock.send(msg)
            except OSError as exc:
                raise SnmpError(f"{self.host}: {exc}") from exc
            deadline = time.monotonic() + self.timeout
            while (left := deadline - time.monotonic()) > 0:
                self._sock.settimeout(left)
                try:
                    data = self._sock.recv(65535)
                except socket.timeout:
                    break
                except (ConnectionResetError, ConnectionRefusedError) as exc:   # ICMP port unreachable
                    raise SnmpError(f"{self.host}: nothing answers on UDP {self.port} (no SNMP service)") from exc
                except OSError as exc:
                    raise SnmpError(f"{self.host}: {exc}") from exc
                self.bytes_received += len(data)
                result = parse(data)
                if result is not None:
                    return result               # anything else: a late answer to an earlier try
        raise SnmpTimeout(f"no answer from {self.host}")

    # ── v2c ──
    @staticmethod
    def _parse_v2c(data: bytes, rid: int) -> Optional[tuple]:
        try:
            _t, msg, _ = asn1.read(data)
            parts = list(asn1.children(msg))
            pdu = parse_pdu(asn1.tlv(*parts[2]))
        except (IndexError, ValueError):
            return None
        return pdu if pdu[1] == rid and pdu[0] == RESPONSE else None

    # ── v3 ──
    def _clock(self) -> tuple[int, int]:
        return self._boots, self._time + int(time.monotonic() - self._clock_at)

    def _set_clock(self, boots: int, engine_time: int) -> None:
        self._boots, self._time, self._clock_at = boots, engine_time, time.monotonic()

    def _discover(self) -> None:
        """RFC 3414 4: an unauthenticated request makes the device report its engine ID and clock."""
        msg_id = self._next_id()
        usm = asn1.seq(asn1.octets(b""), asn1.integer(0), asn1.integer(0),
                       asn1.octets(b""), asn1.octets(b""), asn1.octets(b""))
        msg = asn1.seq(
            asn1.integer(3),
            asn1.seq(asn1.integer(msg_id), asn1.integer(65507), asn1.octets(b"\x04"), asn1.integer(3)),
            asn1.octets(usm),
            asn1.seq(asn1.octets(b""), asn1.octets(b""), build_pdu(GET, msg_id, [])),
        )

        def parse(data: bytes) -> Optional[tuple[bytes, int, int]]:
            try:
                header, fields = self._split_v3(data)
            except (IndexError, ValueError):
                return None
            if header[0] != msg_id or not fields[0]:
                return None
            return fields[0], asn1.to_int(fields[1]), asn1.to_int(fields[2])

        engine, boots, engine_time = self._exchange(msg, parse)
        self._engine = engine
        self._set_clock(boots, engine_time)
        hash_name = AUTH_PROTOCOLS[self.creds.auth_protocol.upper()][0]
        self._auth_key = localize_key(password_to_key(self.creds.auth_key, hash_name), engine, hash_name)
        if self.creds.priv_protocol:
            self._priv_key = localize_key(password_to_key(self.creds.priv_key, hash_name), engine, hash_name)[:16]

    def _v3_message(self, msg_id: int, pdu: bytes, context: str) -> bytes:
        assert self._engine is not None
        hash_name, mac_len = AUTH_PROTOCOLS[self.creds.auth_protocol.upper()]
        priv = bool(self.creds.priv_protocol)
        scoped = asn1.seq(asn1.octets(self._engine), asn1.octets(context.encode()), pdu)
        boots, engine_time = self._clock()
        if priv:
            self._salt = (self._salt + 1) & 0xFFFFFFFFFFFFFFFF
            salt = self._salt.to_bytes(8, "big")
            iv = boots.to_bytes(4, "big") + engine_time.to_bytes(4, "big") + salt
            body = asn1.octets(_aes_cfb(self._priv_key, iv, scoped, encrypt=True))
        else:
            salt, body = b"", scoped
        prefix = (asn1.octets(self._engine) + asn1.integer(boots) + asn1.integer(engine_time)
                  + asn1.octets(self.creds.user.encode()))
        auth_tlv, priv_tlv = asn1.octets(b"\x00" * mac_len), asn1.octets(salt)
        usm = asn1.seq(prefix, auth_tlv, priv_tlv)
        usm_tlv = asn1.octets(usm)
        flags = 0x04 | 0x01 | (0x02 if priv else 0)          # reportable, auth, priv
        head = asn1.integer(3) + asn1.seq(asn1.integer(msg_id), asn1.integer(65507),
                                          asn1.octets(bytes([flags])), asn1.integer(3))
        content = head + usm_tlv + body
        msg = asn1.seq(content)
        pos = ((len(msg) - len(content)) + len(head) + (len(usm_tlv) - len(usm))
               + (len(usm) - len(prefix) - len(auth_tlv) - len(priv_tlv)) + len(prefix) + 2)
        mac = hmac.new(self._auth_key, msg, hash_name).digest()[:mac_len]
        return msg[:pos] + mac + msg[pos + mac_len:]

    @staticmethod
    def _split_v3(data: bytes) -> tuple[tuple[int, int], list[bytes]]:
        """((msgID, flags), the six USM fields) of a v3 message."""
        _tag, start, end = _spans(data, 0, len(data))[0]
        version, header, usm = _spans(data, start, end)[:3]
        if asn1.to_int(data[version[1]:version[2]]) != 3:
            raise ValueError("not SNMPv3")
        h = _spans(data, header[1], header[2])
        msg_id, flags = asn1.to_int(data[h[0][1]:h[0][2]]), data[h[2][1]]
        _t, us, ue = _spans(data, usm[1], usm[2])[0]
        fields = [data[s:e] for _t2, s, e in _spans(data, us, ue)]
        return (msg_id, flags), fields

    def _parse_v3(self, data: bytes, msg_id: int) -> Optional[tuple]:
        try:
            _tag, start, end = _spans(data, 0, len(data))[0]
            parts = _spans(data, start, end)
            (got_id, flags), fields = self._split_v3(data)
            if got_id != msg_id or len(parts) < 4:
                return None
            if fields[0] != self._engine:
                return None
            hash_name, mac_len = AUTH_PROTOCOLS[self.creds.auth_protocol.upper()]
            if flags & 0x01:
                # check the device's MAC: the same HMAC over the message with the MAC zeroed
                _t, us, ue = _spans(data, parts[2][1], parts[2][2])[0]
                _a, ms, me = _spans(data, us, ue)[4]
                blank = data[:ms] + b"\x00" * (me - ms) + data[me:]
                expected = hmac.new(self._auth_key, blank, hash_name).digest()[:mac_len]
                if not hmac.compare_digest(expected, data[ms:me]):
                    raise SnmpAuthError(f"{self.host}: the answer failed authentication (wrong authentication password?)")
            body_tag, bs, be = parts[3]
            if flags & 0x02:
                if not flags & 0x01 or body_tag != asn1.OCTET_STRING:
                    return None
                boots, engine_time, salt = asn1.to_int(fields[1]), asn1.to_int(fields[2]), fields[5]
                iv = boots.to_bytes(4, "big") + engine_time.to_bytes(4, "big") + salt
                scoped = _aes_cfb(self._priv_key, iv, data[bs:be], encrypt=False)
                _t, ss, se = _spans(scoped, 0, len(scoped))[0]
            else:
                scoped, ss, se = data, bs, be
            # contextEngineID, contextName, then the PDU, which starts where the name ends
            items = _spans(scoped, ss, se)
            pdu = parse_pdu(scoped[items[1][2]:items[2][2]])
        except SnmpAuthError:
            raise
        except (IndexError, ValueError):
            return None
        if pdu[0] == REPORT:
            # a report carries the device's clock (notInTimeWindow) - take it
            self._set_clock(asn1.to_int(fields[1]), asn1.to_int(fields[2]))
            return pdu
        if pdu[0] != RESPONSE or pdu[1] != msg_id:
            return None
        if flags & 0x01:
            self._set_clock(asn1.to_int(fields[1]), asn1.to_int(fields[2]))
        return pdu
