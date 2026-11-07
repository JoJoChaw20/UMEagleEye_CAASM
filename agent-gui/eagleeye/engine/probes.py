"""What runs on an open TCP port: one connection, the greeting or handshake an ordinary
client would send, nothing that logs in or changes anything.

    SSH, FTP, SMTP, POP3, IMAP, Telnet   read the greeting the server sends first
    HTTP                                 GET / (capped): Server header, page title, login realm
    TLS                                  handshake: certificate names and dates, then HTTP inside
    MySQL                                read the handshake (it carries the exact version)
    PostgreSQL                           ask for TLS: the 'S'/'N' answer is PostgreSQL's alone
    Redis                                INFO server (read-only; Redis answers it without login
                                         only when no password is set)
    MongoDB                              buildInfo (allowed without login; carries the version)

Products are recognised with this module's own patterns (not Nmap's probe database).
    SMB (445), RDP (3389)                msproto.py: computer name, domain, Windows build
"""

from __future__ import annotations

import re
import socket
import ssl
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

from . import asn1, msproto
from .ports import service_name

TLS_PORTS = {443, 465, 636, 993, 995, 2376, 4443, 5986, 6443, 8443, 8883, 9443, 10250}
HTTP_PORTS = {80, 2375, 2869, 3000, 5000, 5601, 5985, 7000, 7001, 8000, 8001, 8008, 8060, 8080, 8081,
              8088, 8090, 8181, 8888, 9000, 9001, 9090, 9200, 10000, 15672, 49152, 49153}
GREETING_PORTS = {21: "ftp", 23: "telnet", 25: "smtp", 110: "pop3", 143: "imap", 587: "smtp"}
NAME_ONLY_PORTS = {135: "msrpc", 139: "netbios-ssn"}
OS_KEYS = ("name", "smb_computer_name", "smb_domain", "smb_fqdn", "ntlm_version")
READ_LIMIT = 65536


@dataclass
class Finding:
    service: str
    product: str = ""
    version: str = ""
    banner: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def port_entry(self, port: int, protocol: str = "tcp") -> dict[str, Any]:
        entry = {"port": port, "protocol": protocol, "service": self.service, "version": self.version, "product": self.product}
        if self.banner:
            entry["banner"] = self.banner[:200]
        return entry


# ── socket helpers ──
def _open(ip: str, port: int, timeout: float) -> socket.socket:
    s = socket.create_connection((ip, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def _recv(s: Any, limit: int = READ_LIMIT, until: Optional[bytes] = None) -> bytes:
    data = b""
    while len(data) < limit:
        try:
            chunk = s.recv(min(8192, limit - len(data)))
        except (socket.timeout, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        data += chunk
        if until is not None and until in data:
            break
    return data


def printable(data: bytes) -> str:
    text = data.decode("utf-8", "replace")
    return "".join(ch if ch.isprintable() or ch in "\t" else " " for ch in text).strip()


def strip_telnet(data: bytes) -> bytes:
    """Remove Telnet IAC option negotiation (0xFF sequences) from a greeting."""
    out, i = bytearray(), 0
    while i < len(data):
        if data[i] == 0xFF and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd == 0xFA:                                # subnegotiation until IAC SE
                end = data.find(b"\xff\xf0", i + 2)
                i = len(data) if end < 0 else end + 2
            elif cmd in (0xFB, 0xFC, 0xFD, 0xFE):
                i += 3
            else:
                i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


# ── recognisers (pure: tested with recorded replies) ──
def parse_ssh(banner: str) -> Finding:
    f = Finding("ssh", banner=banner)
    m = re.match(r"SSH-[\d.]+-(\S+)(?:\s+(.*))?", banner)
    if not m:
        return f
    software, comment = m.group(1), (m.group(2) or "").strip()
    for pattern, product in ((r"OpenSSH_([\w.]+)", "OpenSSH"), (r"dropbear_([\w.]+)", "Dropbear sshd"),
                             (r"Cisco-([\w.]+)", "Cisco SSH"), (r"libssh_?([\w.]+)", "libssh"),
                             (r"ROSSSH", "MikroTik RouterOS sshd"), (r"OpenSSH_for_Windows_([\w.]+)", "OpenSSH for Windows")):
        mm = re.match(pattern, software)
        if mm:
            f.product, f.version = product, (mm.group(1) if mm.groups() else "")
            break
    else:
        f.product = software
    if comment:
        f.extra["comment"] = comment
        os_m = re.match(r"(Ubuntu|Debian|Raspbian|FreeBSD|NetBSD)\b", comment)
        if os_m:
            f.extra["os_hint"] = os_m.group(1)
    return f


_SERVERS = (("nginx", "nginx"), ("Apache", "Apache httpd"), ("Microsoft-IIS", "Microsoft IIS httpd"),
            ("Microsoft-HTTPAPI", "Microsoft HTTPAPI httpd"), ("lighttpd", "lighttpd"), ("openresty", "OpenResty"),
            ("Jetty", "Jetty"), ("Caddy", "Caddy"), ("Boa", "Boa HTTPd"), ("mini_httpd", "mini_httpd"),
            ("GoAhead-Webs", "GoAhead WebServer"), ("uhttpd", "uhttpd"), ("BusyBox", "BusyBox httpd"),
            ("Werkzeug", "Werkzeug httpd"), ("gunicorn", "Gunicorn"), ("Kestrel", "Kestrel"))


def server_product(header: str) -> tuple[str, str, str]:
    """('nginx', '1.28.3', 'Ubuntu') from 'nginx/1.28.3 (Ubuntu)'."""
    m = re.match(r"\s*([^/\s(]+)(?:/([\w.\-]+))?\s*(?:\(([^)]*)\))?", header or "")
    if not m:
        return "", "", ""
    token, version, comment = m.group(1), m.group(2) or "", m.group(3) or ""
    for prefix, product in _SERVERS:
        if token.lower().startswith(prefix.lower()):
            return product, version, comment
    return token, version, comment


def parse_http(data: bytes, service: str = "http") -> Optional[Finding]:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
    if not m:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers.setdefault(k.strip().lower(), v.strip())
    f = Finding(service)
    f.extra["status"] = int(m.group(1))
    if headers.get("server"):
        f.product, f.version, comment = server_product(headers["server"])
        f.extra["server"] = headers["server"][:120]
        if comment:
            f.extra["os_hint"] = comment
    if headers.get("x-powered-by"):
        f.extra["powered_by"] = headers["x-powered-by"][:80]
    realm = re.search(r'realm="([^"]*)"', headers.get("www-authenticate", ""), re.I)
    if realm:
        f.extra["realm"] = realm.group(1)[:80]
    if headers.get("location"):
        f.extra["location"] = headers["location"][:160]
    t = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if t:
        f.extra["title"] = " ".join(printable(t.group(1)).split())[:100]
    return f


def parse_mysql(data: bytes) -> Optional[Finding]:
    if len(data) < 5:
        return None
    payload = data[4:]
    if payload[0] == 0x0A:                                 # protocol 10 handshake
        version = payload[1:payload.find(b"\x00", 1)].decode("ascii", "replace")
        if "MariaDB" in version:
            return Finding("mysql", "MariaDB", re.sub(r"^5\.5\.5-", "", version).split("-MariaDB")[0])
        return Finding("mysql", "MySQL", version.split("-")[0], extra={"version_string": version})
    if payload[0] == 0xFF:                                 # e.g. "Host ... is not allowed"
        return Finding("mysql", "MySQL", extra={"error": printable(payload[3:])[:120]})
    return None


def parse_redis(data: bytes) -> Optional[Finding]:
    text = data.decode("utf-8", "replace")
    if text.startswith("$") or "redis_version:" in text:
        m = re.search(r"redis_version:([\w.]+)", text)
        f = Finding("redis", "Redis", m.group(1) if m else "")
        os_m = re.search(r"\bos:([^\r\n]+)", text)
        if os_m:
            f.extra["os_hint"] = os_m.group(1).strip()
        return f
    if text.startswith(("-NOAUTH", "-ERR", "-DENIED", "-WRONGPASS")):
        return Finding("redis", "Redis", extra={"note": text.strip()[:120]})
    return None


def bson_doc(fields: list[tuple[str, Any]]) -> bytes:
    body = b""
    for name, value in fields:
        key = name.encode() + b"\x00"
        if isinstance(value, int):
            body += b"\x10" + key + struct.pack("<i", value)
        else:
            raw = str(value).encode() + b"\x00"
            body += b"\x02" + key + struct.pack("<i", len(raw)) + raw
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def bson_strings(doc: bytes) -> dict[str, str]:
    """Top-level string fields of a BSON document (stops at a type it cannot skip)."""
    out: dict[str, str] = {}
    off, end = 4, min(len(doc), struct.unpack_from("<i", doc, 0)[0]) - 1
    sizes = {0x01: 8, 0x07: 12, 0x08: 1, 0x09: 8, 0x0A: 0, 0x10: 4, 0x11: 8, 0x12: 8}
    while off < end:
        kind = doc[off]
        name_end = doc.index(b"\x00", off + 1)
        name = doc[off + 1:name_end].decode("utf-8", "replace")
        off = name_end + 1
        if kind == 0x02:
            n = struct.unpack_from("<i", doc, off)[0]
            out[name] = doc[off + 4:off + 3 + n].decode("utf-8", "replace")
            off += 4 + n
        elif kind in (0x03, 0x04):
            off += struct.unpack_from("<i", doc, off)[0]
        elif kind == 0x05:
            off += 5 + struct.unpack_from("<i", doc, off)[0]
        elif kind in sizes:
            off += sizes[kind]
        else:
            break
    return out


def mongo_build_info_request(request_id: int = 0x45454545) -> bytes:
    body = struct.pack("<I", 0) + b"\x00" + bson_doc([("buildInfo", 1), ("$db", "admin")])
    return struct.pack("<iiii", 16 + len(body), request_id, 0, 2013) + body


def parse_mongo(data: bytes) -> Optional[Finding]:
    if len(data) < 21 or struct.unpack_from("<i", data, 12)[0] != 2013:
        return None
    fields = bson_strings(data[21:])
    return Finding("mongodb", "MongoDB", fields.get("version", ""),
                   extra={k: fields[k] for k in ("gitVersion",) if k in fields})


def parse_greeting(port: int, data: bytes) -> Finding:
    service = GREETING_PORTS.get(port) or service_name(port) or "unknown"
    if service == "telnet":
        data = strip_telnet(data)
    banner = printable(data)
    f = Finding(service, banner=banner)
    for pattern, product in ((r"\b(vsFTPd)\s+([\d.]+)", None), (r"\b(ProFTPD)\s+([\d.]+)", None),
                             (r"\b(Pure-FTPd)", None), (r"\b(FileZilla Server)\s*([\d.]+)?", None),
                             (r"(Microsoft FTP Service)", None), (r"\b(Postfix)\b", None),
                             (r"\b(Exim)\s+([\d.]+)", None), (r"(Microsoft ESMTP MAIL Service)", None),
                             (r"\b(Dovecot)\b", None)):
        m = re.search(pattern, banner)
        if m:
            f.product = product or m.group(1)
            f.version = m.group(2) if m.lastindex and m.lastindex >= 2 and m.group(2) else ""
            break
    return f


# ── probes (network) ──
def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE                       # we read the certificate, we do not trust it
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1        # old devices
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


def _http_request(ip: str, port: int) -> bytes:
    host = ip if port in (80, 443) else f"{ip}:{port}"
    return (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: EagleEye-Agent\r\nAccept: */*\r\n"
            f"Connection: close\r\n\r\n").encode()


def probe_tls(ip: str, port: int, timeout: float) -> Optional[Finding]:
    try:
        raw = _open(ip, port, timeout)
    except OSError:
        return None
    try:
        with _tls_context().wrap_socket(raw, server_hostname=None) as s:
            der = s.getpeercert(binary_form=True)
            tls = {"tls_version": s.version()}
            if der:
                try:
                    tls["certificate"] = asn1.certificate(der)
                except (IndexError, ValueError):
                    tls["certificate"] = None
            if port in GREETING_PORTS or port in (465, 993, 995):
                f = parse_greeting(port, _recv(s, 1024, b"\n"))
            else:
                s.sendall(_http_request(ip, port))
                f = parse_http(_recv(s), "https") or Finding(service_name(port) or "ssl")
            f.extra.update(tls)
            return f
    except (ssl.SSLError, OSError):
        return None


def probe(ip: str, port: int, timeout: float = 3.0) -> Optional[Finding]:
    """Identify the service on one open TCP port; None when nothing could be learned."""
    if port in NAME_ONLY_PORTS:
        return Finding(NAME_ONLY_PORTS[port])
    if port == 445:
        return smb_finding(msproto.smb_probe(ip, port, timeout))
    if port == 3389:
        return rdp_finding(msproto.rdp_probe(ip, port, timeout))
    if port in TLS_PORTS:
        return probe_tls(ip, port, timeout) or Finding(service_name(port))
    try:
        with _open(ip, port, timeout) as s:
            if port == 3306:
                return parse_mysql(_recv(s, 1024)) or Finding("mysql")
            if port == 5432:
                s.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")         # SSLRequest
                reply = _recv(s, 1)
                return Finding("postgresql", "PostgreSQL" if reply in (b"S", b"N") else "",
                               extra={"tls": reply == b"S"} if reply in (b"S", b"N") else {})
            if port == 6379:
                s.sendall(b"INFO server\r\n")
                return parse_redis(_recv(s, 16384, b"\r\n\r\n")) or Finding("redis")
            if port == 27017:
                s.sendall(mongo_build_info_request())
                return parse_mongo(_recv(s, 16384)) or Finding("mongodb")
            if port == 22:
                return _ssh(s)
            if port in HTTP_PORTS:
                s.sendall(_http_request(ip, port))
                data = _recv(s)
                if data.startswith(b"\x15\x03"):                      # a TLS alert: speak TLS instead
                    return probe_tls(ip, port, timeout)
                return parse_http(data) or Finding(service_name(port) or "http", banner=printable(data[:200]))
            s.settimeout(min(timeout, 2.0))
            greeting = _recv(s, 1024, b"\n")
            if greeting:
                return parse_greeting(port, greeting)
    except OSError:
        return None
    if port not in GREETING_PORTS:                    # a silent unknown port: maybe it speaks HTTP
        try:
            with _open(ip, port, timeout) as s:
                s.sendall(_http_request(ip, port))
                return parse_http(_recv(s))
        except OSError:
            return None
    return None


def smb_finding(info: Optional[dict[str, Any]]) -> Finding:
    """The SMB probe's answer as a port finding; its machine facts go to extra['os']."""
    if not info:
        return Finding("microsoft-ds")
    windows = bool(info.get("name"))
    f = Finding("microsoft-ds", "Microsoft Windows SMB" if windows else "SMB server",
                info.get("ntlm_version", "") if windows else "")
    f.extra = {k: v for k, v in info.items() if k not in OS_KEYS}
    machine = {k: info[k] for k in OS_KEYS if info.get(k)}
    if machine:
        f.extra["os"] = machine
    return f


def rdp_finding(info: Optional[dict[str, Any]]) -> Finding:
    if not info:
        return Finding("ms-wbt-server")
    return Finding("ms-wbt-server", "Microsoft Terminal Services" if "selected" in info else "", extra=dict(info))


def _ssh(s: socket.socket) -> Finding:
    line = printable(_recv(s, 255, b"\n")).splitlines()
    return parse_ssh(line[0]) if line else Finding("ssh")
