"""SMB (445) and RDP (3389): who the machine is, without logging in.

SMB: an SMB2 NEGOTIATE (dialect, whether signing is required), then the first message of an
NTLM login. The server's NTLM CHALLENGE names the machine (NetBIOS and DNS computer and
domain names) and carries the Windows version and build. The exchange stops there: no
credentials are sent and no session is created. This works where Nmap's smb-os-discovery
does not, because that script needs SMBv1, which current Windows has switched off.

RDP: an X.224 connection request offering TLS and CredSSP. The answer says which security
the server insists on (CredSSP means Network Level Authentication), and the TLS
certificate Windows makes for Remote Desktop is named after the computer.
"""

from __future__ import annotations

import socket
import ssl
import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from . import asn1

SMB2_MAGIC = b"\xfeSMB"
NTLMSSP = b"NTLMSSP\x00"
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302)
DIALECT_NAMES = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}

# Windows builds that name one release; the ones shared by a client and a server release
# are named for both. NTLM reports the base build of a servicing family, not the installed
# one (Windows 11 25H2, build 26200, says 26100), and never the update revision, so this is
# a family name, not a patch level: the patch check needs the host agent's build + UBR.
WINDOWS_BUILDS = {
    7600: "Windows 7 / Server 2008 R2", 7601: "Windows 7 SP1 / Server 2008 R2 SP1", 9200: "Windows 8 / Server 2012",
    9600: "Windows 8.1 / Server 2012 R2", 14393: "Windows 10 1607 / Server 2016", 17763: "Windows 10 1809 / Server 2019",
    20348: "Windows Server 2022", 26100: "Windows 11 24H2 or later / Server 2025",
}


def windows_name(major: int, minor: int, build: int) -> Optional[str]:
    """'Windows 11' for 10.0.26300; None when the numbers are not a Windows version (Samba)."""
    if not build or major < 5:
        return None
    if build in WINDOWS_BUILDS:
        return WINDOWS_BUILDS[build]
    if (major, minor) == (10, 0):
        return "Windows 11" if build >= 22000 else "Windows 10"
    return f"Windows {major}.{minor}"


def _nbss(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def _smb2_header(command: int, message_id: int) -> bytes:
    return (SMB2_MAGIC + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, command, 31, 0, 0, message_id, 0, 0, 0) + b"\x00" * 16)


def negotiate_request() -> bytes:
    body = struct.pack("<HHHHI", 36, len(DIALECTS), 1, 0, 0) + uuid.uuid4().bytes + b"\x00" * 8
    body += b"".join(struct.pack("<H", d) for d in DIALECTS)
    return _nbss(_smb2_header(0, 0) + body)


def ntlm_negotiate() -> bytes:
    flags = 0x00000001 | 0x00000004 | 0x00000200 | 0x00008000 | 0x00080000 | 0x00800000 | 0x02000000 | 0x20000000 | 0x80000000
    return NTLMSSP + struct.pack("<II", 1, flags) + b"\x00" * 16 + bytes([6, 1]) + struct.pack("<H", 7601) + b"\x00\x00\x00\x0f"


def spnego_init(token: bytes) -> bytes:
    """GSS-API NegTokenInit offering only NTLMSSP, with the NTLM NEGOTIATE as mechToken."""
    ntlm_oid = asn1.tlv(asn1.OID, bytes.fromhex("2b06010401823702020a"))     # 1.3.6.1.4.1.311.2.2.10
    spnego_oid = asn1.tlv(asn1.OID, bytes.fromhex("2b0601050502"))           # 1.3.6.1.5.5.2
    init = asn1.seq(asn1.tlv(0xA0, asn1.seq(ntlm_oid)), asn1.tlv(0xA2, asn1.octets(token)))
    return asn1.tlv(0x60, spnego_oid + asn1.tlv(0xA0, init))


def session_setup_request() -> bytes:
    blob = spnego_init(ntlm_negotiate())
    body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 64 + 24, len(blob), 0) + blob
    return _nbss(_smb2_header(1, 1) + body)


def parse_negotiate(msg: bytes) -> Optional[dict[str, Any]]:
    if len(msg) < 64 + 65 or msg[:4] != SMB2_MAGIC:
        return None
    b = msg[64:]
    security_mode, dialect = struct.unpack_from("<HH", b, 2)
    system_time = struct.unpack_from("<Q", b, 40)[0]
    out: dict[str, Any] = {"smb_dialect": DIALECT_NAMES.get(dialect, hex(dialect)),
                           "signing_required": bool(security_mode & 0x2),
                           "server_guid": str(uuid.UUID(bytes_le=b[8:24]))}
    if system_time:
        out["server_time"] = (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=system_time // 10)).isoformat()
    return out


def parse_challenge(data: bytes) -> Optional[dict[str, Any]]:
    """Names and version from an NTLM CHALLENGE found anywhere in `data`."""
    at = data.find(NTLMSSP + b"\x02\x00\x00\x00")
    if at < 0 or len(data) < at + 56:
        return None
    m = data[at:]
    out: dict[str, Any] = {}
    flags = struct.unpack_from("<I", m, 20)[0]
    info_len, _max, info_off = struct.unpack_from("<HHI", m, 40)
    if flags & 0x02000000 and len(m) >= 56:                      # NEGOTIATE_VERSION: version present
        major, minor, build = m[48], m[49], struct.unpack_from("<H", m, 50)[0]
        out["ntlm_version"] = f"{major}.{minor}.{build}"
        name = windows_name(major, minor, build)
        if name:
            out["name"] = name
    keys = {1: "smb_computer_name", 2: "smb_netbios_domain", 3: "smb_fqdn", 4: "smb_domain", 5: "smb_forest"}
    off, end = info_off, min(len(m), info_off + info_len)
    while off + 4 <= end:
        av_id, av_len = struct.unpack_from("<HH", m, off)
        if av_id == 0:
            break
        value = m[off + 4:off + 4 + av_len]
        if av_id in keys:
            out[keys[av_id]] = value.decode("utf-16-le", "replace")
        off += 4 + av_len
    out = {k: v for k, v in out.items() if v != ""}
    if out.get("smb_domain", "").lower() in (out.get("smb_fqdn", "").lower(), out.get("smb_computer_name", "").lower()):
        out.pop("smb_domain", None)                             # not in a domain: Windows repeats its own name
    return out or None


def _recv_nbss(s: socket.socket) -> bytes:
    head = _read_exact(s, 4)
    return _read_exact(s, struct.unpack(">I", head)[0] & 0xFFFFFF) if len(head) == 4 else b""


def _read_exact(s: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def smb_probe(ip: str, port: int = 445, timeout: float = 3.0) -> Optional[dict[str, Any]]:
    """{smb_dialect, signing_required, ..., name, smb_computer_name, smb_domain, ...} or None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(negotiate_request())
            neg = parse_negotiate(_recv_nbss(s))
            if neg is None:
                return None
            s.sendall(session_setup_request())
            reply = _recv_nbss(s)
            if len(reply) >= 64 and struct.unpack_from("<I", reply, 8)[0] == STATUS_MORE_PROCESSING_REQUIRED:
                neg.update(parse_challenge(reply) or {})
            return neg
    except (OSError, struct.error):
        return None


# ── RDP ──
def x224_request(protocols: int) -> bytes:
    cookie = b"Cookie: mstshash=eagleeye\r\n"
    neg = struct.pack("<BBHI", 1, 0, 8, protocols)
    x224 = bytes([6 + len(cookie) + len(neg), 0xE0, 0, 0, 0, 0, 0]) + cookie + neg
    return struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224


def parse_x224_confirm(data: bytes) -> Optional[dict[str, Any]]:
    """{'selected': 'tls'|'credssp'|'rdp'} or {'failure': code} from an X.224 Connection Confirm."""
    if len(data) < 11 or data[0] != 3 or data[5] != 0xD0:
        return None
    neg = data[11:19]
    if len(neg) < 8:
        return {"selected": "rdp"}                             # no negotiation: classic RDP security
    kind, _flags, _len, value = struct.unpack("<BBHI", neg)
    if kind == 2:
        return {"selected": {0: "rdp", 1: "tls", 2: "credssp", 8: "rdstls"}.get(value, str(value))}
    if kind == 3:
        return {"failure": value}
    return None


def rdp_probe(ip: str, port: int = 3389, timeout: float = 3.0) -> Optional[dict[str, Any]]:
    out: dict[str, Any] = {}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(x224_request(0x3))                          # TLS or CredSSP
            confirm = parse_x224_confirm(s.recv(64))
            if confirm is None:
                return None
            out.update(confirm)
            if confirm.get("selected") in ("tls", "credssp"):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                with ctx.wrap_socket(s, server_hostname=None) as t:
                    der = t.getpeercert(binary_form=True)
                    if der:
                        cert = asn1.certificate(der)
                        out["certificate"] = cert
                        cn = cert.get("subject", {}).get("CN")
                        if cn:
                            out["rdp_computer_name"] = cn.split(".")[0]
        if out.get("selected") == "credssp":
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(x224_request(0x1))                      # TLS only: refused when NLA is required
                second = parse_x224_confirm(s.recv(64)) or {}
                out["nla_required"] = second.get("failure") == 5    # HYBRID_REQUIRED_BY_SERVER
        return out
    except (OSError, ssl.SSLError, IndexError, ValueError):
        return out or None
