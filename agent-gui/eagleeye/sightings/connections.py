"""This computer's outbound TCP connections (open, or being opened), read from the
operating system's connection table, and the program behind one.

  * Windows: GetExtendedTcpTable (IPv4 and IPv6, with the owning process id).
  * Linux: /proc/net/tcp and tcp6 (the socket inode; the process is found from it).
  * macOS: netstat -an -p tcp (the process from lsof, only for a match).

A connection being opened (SYN sent) counts too: a contact a firewall blocks is still an
attempt. The program is looked up only for a connection that matched (S3), so polling stays
cheap. Every parser takes the raw table, so it is tested on recorded examples.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("eagleeye.sightings")


@dataclass(frozen=True)
class Conn:
    remote: str                     # compressed IP address
    port: int                       # remote port
    local_port: int
    pid: Optional[int] = None       # Windows
    inode: Optional[int] = None     # Linux

    @property
    def key(self) -> tuple[str, int, int]:
        """One connection (a reconnect gets another local port)."""
        return (self.remote, self.port, self.local_port)


def _public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global


# ── Linux ────────────────────────────────────────────────────────────────────
LINUX_STATES = {"01", "02"}         # ESTABLISHED, SYN_SENT


def _proc_ip(hexaddr: str) -> str:
    raw = bytes.fromhex(hexaddr)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    # IPv6: four 32-bit words, each in host (little-endian) order
    return ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))).compressed


def parse_proc_net_tcp(text: str) -> list[Conn]:
    """/proc/net/tcp or tcp6: connections to public addresses."""
    out: list[Conn] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10 or parts[3] not in LINUX_STATES:
            continue
        try:
            local, remote = parts[1].split(":"), parts[2].split(":")
            ip = _proc_ip(remote[0])
            port, local_port, inode = int(remote[1], 16), int(local[1], 16), int(parts[9])
        except (ValueError, IndexError):
            continue
        if _public(ip):
            out.append(Conn(ip, port, local_port, inode=inode))
    return out


def linux_connections() -> list[Conn]:  # pragma: no cover - reads the live system
    out: list[Conn] = []
    for name in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(name, encoding="ascii", errors="replace") as fh:
                out.extend(parse_proc_net_tcp(fh.read()))
        except OSError:
            continue
    return out


def linux_process(inode: Optional[int], proc: str = "/proc") -> Optional[str]:
    """The program holding socket `inode` (needs root to see other users' programs)."""
    if not inode:
        return None
    target = f"socket:[{inode}]"
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return None
    for pid in pids:
        fd_dir = os.path.join(proc, pid, "fd")
        try:
            for fd in os.listdir(fd_dir):
                if os.readlink(os.path.join(fd_dir, fd)) == target:
                    with open(os.path.join(proc, pid, "comm"), encoding="utf-8", errors="replace") as fh:
                        return fh.read().strip() or None
        except OSError:
            continue
    return None


# ── macOS ────────────────────────────────────────────────────────────────────
MAC_STATES = {"ESTABLISHED", "SYN_SENT"}


def _split_port(address: str) -> Optional[tuple[str, int]]:
    """netstat's "1.2.3.4.443" / "2001:db8::1.443" as (ip, port)."""
    host, _, port = address.rpartition(".")
    if not host or not port.isdigit():
        return None
    return host.split("%")[0], int(port)


def parse_macos_netstat(text: str) -> list[Conn]:
    """netstat -an -p tcp: connections to public addresses."""
    out: list[Conn] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[0].startswith("tcp") or parts[5] not in MAC_STATES:
            continue
        local, remote = _split_port(parts[3]), _split_port(parts[4])
        if not local or not remote:
            continue
        try:
            ip = ipaddress.ip_address(remote[0]).compressed
        except ValueError:
            continue
        if _public(ip):
            out.append(Conn(ip, remote[1], local[1]))
    return out


def macos_connections() -> list[Conn]:  # pragma: no cover - runs netstat
    try:
        result = subprocess.run(["netstat", "-an", "-p", "tcp"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("netstat failed: %s", exc)
        return []
    return parse_macos_netstat(result.stdout)


def parse_lsof(text: str) -> Optional[str]:
    """lsof -F c output: the first program name ("c<name>" line)."""
    for line in text.splitlines():
        if line.startswith("c") and len(line) > 1:
            return line[1:].strip()
    return None


def macos_process(conn: Conn) -> Optional[str]:  # pragma: no cover - runs lsof
    host = f"[{conn.remote}]" if ":" in conn.remote else conn.remote
    try:
        result = subprocess.run(["lsof", "-nP", f"-iTCP@{host}:{conn.port}", "-F", "c"],
                                capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_lsof(result.stdout)


# ── Windows ──────────────────────────────────────────────────────────────────
WIN_STATES = {3, 5}                 # SYN_SENT, ESTABLISHED (MIB_TCP_STATE)
ROW4, ROW6 = 24, 56                 # MIB_TCPROW_OWNER_PID, MIB_TCP6ROW_OWNER_PID


def parse_tcp_table_v4(buf: bytes) -> list[Conn]:
    """A MIB_TCPTABLE_OWNER_PID: a count, then rows of state, local address and port,
    remote address and port (network order in the low two bytes), owning process id."""
    if len(buf) < 4:
        return []
    count = struct.unpack_from("<I", buf, 0)[0]
    out: list[Conn] = []
    for i in range(count):
        off = 4 + i * ROW4
        if off + ROW4 > len(buf):
            break
        state = struct.unpack_from("<I", buf, off)[0]
        if state not in WIN_STATES:
            continue
        ip = str(ipaddress.IPv4Address(buf[off + 12:off + 16]))
        local_port = struct.unpack_from(">H", buf, off + 8)[0]
        port = struct.unpack_from(">H", buf, off + 16)[0]
        pid = struct.unpack_from("<I", buf, off + 20)[0]
        if _public(ip):
            out.append(Conn(ip, port, local_port, pid=pid))
    return out


def parse_tcp_table_v6(buf: bytes) -> list[Conn]:
    """A MIB_TCP6TABLE_OWNER_PID: rows of local address, scope and port, remote address,
    scope and port, state, owning process id."""
    if len(buf) < 4:
        return []
    count = struct.unpack_from("<I", buf, 0)[0]
    out: list[Conn] = []
    for i in range(count):
        off = 4 + i * ROW6
        if off + ROW6 > len(buf):
            break
        state = struct.unpack_from("<I", buf, off + 48)[0]
        if state not in WIN_STATES:
            continue
        ip = ipaddress.IPv6Address(buf[off + 24:off + 40]).compressed
        local_port = struct.unpack_from(">H", buf, off + 20)[0]
        port = struct.unpack_from(">H", buf, off + 44)[0]
        pid = struct.unpack_from("<I", buf, off + 52)[0]
        if _public(ip):
            out.append(Conn(ip, port, local_port, pid=pid))
    return out


def windows_connections() -> list[Conn]:  # pragma: no cover - needs Windows
    import ctypes
    from ctypes import wintypes as wt
    iphlpapi = ctypes.WinDLL("iphlpapi")
    get_table = iphlpapi.GetExtendedTcpTable
    get_table.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL, wt.ULONG, ctypes.c_int, wt.ULONG]
    get_table.restype = wt.DWORD
    TCP_TABLE_OWNER_PID_CONNECTIONS, ERROR_INSUFFICIENT_BUFFER = 4, 122
    out: list[Conn] = []
    for family, parse in ((2, parse_tcp_table_v4), (23, parse_tcp_table_v6)):   # AF_INET, AF_INET6
        size = wt.DWORD(0)
        get_table(None, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
        for _ in range(3):                      # the table can grow between the two calls
            buf = ctypes.create_string_buffer(size.value + 4096)
            size = wt.DWORD(len(buf))
            rc = get_table(buf, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
            if rc == 0:
                out.extend(parse(buf.raw[:size.value]))
                break
            if rc != ERROR_INSUFFICIENT_BUFFER:
                log.debug("GetExtendedTcpTable(%d) failed: %d", family, rc)
                break
    return out


def windows_process(pid: Optional[int]) -> Optional[str]:  # pragma: no cover - needs Windows
    if not pid:
        return None
    import ctypes
    from ctypes import wintypes as wt
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wt.DWORD(len(buf))
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return None
        return re.split(r"[\\/]", buf.value)[-1] or None
    finally:
        kernel32.CloseHandle(handle)


# ── this system ──────────────────────────────────────────────────────────────
def poll() -> list[Conn]:  # pragma: no cover - reads the live system
    if sys.platform == "win32":
        return windows_connections()
    if sys.platform == "darwin":
        return macos_connections()
    if sys.platform.startswith("linux"):
        return linux_connections()
    return []


def process_of(conn: Conn) -> Optional[str]:  # pragma: no cover - reads the live system
    try:
        if sys.platform == "win32":
            return windows_process(conn.pid)
        if sys.platform == "darwin":
            return macos_process(conn)
        if sys.platform.startswith("linux"):
            return linux_process(conn.inode)
    except Exception as exc:  # noqa: BLE001 - the program name is optional
        log.debug("Could not find the program behind %s:%d: %s", conn.remote, conn.port, exc)
    return None
