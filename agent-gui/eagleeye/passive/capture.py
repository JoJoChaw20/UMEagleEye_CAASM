"""Built-in packet capture: frames for the sniffers without Npcap or libpcap.

  * Windows: Microsoft's own NDIS capture driver (the one netsh trace and PktMon use),
    read live through an Event Tracing for Windows (ETW) session this agent starts. Spike
    D (2026-11-06): the session on its own makes the driver deliver every packet, and it
    heard 100% of the discovery traffic Npcap heard, at under 2% of one CPU core.
  * Linux: a packet socket (AF_PACKET) bound to the adapter, with the sniffers' rules as
    a kernel filter.

Both need Administrator/root, as Npcap capture does. One capture serves all the
sniffers (CaptureHub): the ETW session is one per computer, and one socket is cheaper
than four. The old per-sniffer Npcap/libpcap capture (scapy's sniff) is untouched and
still used when passive_backend is "npcap".
"""

from __future__ import annotations

import ctypes
import logging
import socket
import struct
import sys
import threading
import time
import uuid
from collections import Counter
from typing import Any, Callable, Optional

from . import frames

log = logging.getLogger("eagleeye.passive")

_REFRESH_SECONDS = 5          # how often the hub asks the chooser which adapter to use
BACKENDS = ("auto", "npcap", "native")


def npcap_installed() -> bool:
    from ..deps import _packet_capture_library
    return _packet_capture_library()[0]


def resolve_backend(setting: str, platform: str = sys.platform,
                    has_npcap: Optional[Callable[[], bool]] = None) -> str:
    """"npcap" (scapy's sniff on Npcap/libpcap), "ndis" or "packet" (built-in).

    Automatic keeps Npcap on Windows where it is installed (the capture the agent has
    always used) and uses Microsoft's driver otherwise; Linux uses its packet socket,
    which needs neither libpcap nor tcpdump. Other systems only have libpcap."""
    native = "ndis" if platform == "win32" else "packet" if platform.startswith("linux") else None
    if setting == "npcap" or native is None:
        return "npcap"
    if setting == "native":
        return native
    if platform == "win32" and (has_npcap or npcap_installed)():
        return "npcap"
    return native


# ── Windows: NDIS-PacketCapture through ETW ──────────────────────────────────

NDISCAP = uuid.UUID("2ED6006E-4729-4609-B423-3EE7BCD678EF")
SESSION = "EagleEye-Passive"
FRAGMENT_EVENT = 1001
ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS = 5, 183


def parse_fragment(data: bytes) -> Optional[tuple[int, int, bytes]]:
    """Event 1001's payload -> (MiniportIfIndex, LowerIfIndex, frame) or None."""
    if len(data) < 12:
        return None
    miniport, lower, size = struct.unpack_from("<III", data, 0)
    frame = data[12:12 + size]
    return (miniport, lower, frame) if frame else None


def as_ethernet(frame: bytes) -> bytes:
    """A Wi-Fi adapter's 802.11 frame as Ethernet; an Ethernet frame as it is."""
    return frames.wifi_to_ethernet(frame) or frame


if sys.platform == "win32":  # pragma: no cover - the ctypes layer runs on Windows only
    import ctypes.wintypes as wt

    EVENT_TRACE_REAL_TIME_MODE = 0x00000100
    WNODE_FLAG_TRACED_GUID = 0x00020000
    PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
    PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
    EVENT_TRACE_CONTROL_STOP = 1
    EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
    TRACE_LEVEL_INFORMATION = 4
    INVALID_TRACE = 0xFFFFFFFFFFFFFFFF

    class GUID(ctypes.Structure):
        _fields_ = [("Data", ctypes.c_ubyte * 16)]

        @classmethod
        def of(cls, u: uuid.UUID) -> "GUID":
            g = cls()
            ctypes.memmove(g.Data, u.bytes_le, 16)
            return g

    class WNODE_HEADER(ctypes.Structure):
        _fields_ = [("BufferSize", wt.ULONG), ("ProviderId", wt.ULONG), ("HistoricalContext", ctypes.c_uint64),
                    ("TimeStamp", ctypes.c_int64), ("Guid", GUID), ("ClientContext", wt.ULONG), ("Flags", wt.ULONG)]

    class EVENT_TRACE_PROPERTIES(ctypes.Structure):
        _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", wt.ULONG), ("MinimumBuffers", wt.ULONG),
                    ("MaximumBuffers", wt.ULONG), ("MaximumFileSize", wt.ULONG), ("LogFileMode", wt.ULONG),
                    ("FlushTimer", wt.ULONG), ("EnableFlags", wt.ULONG), ("AgeLimit", wt.LONG),
                    ("NumberOfBuffers", wt.ULONG), ("FreeBuffers", wt.ULONG), ("EventsLost", wt.ULONG),
                    ("BuffersWritten", wt.ULONG), ("LogBuffersLost", wt.ULONG), ("RealTimeBuffersLost", wt.ULONG),
                    ("LoggerThreadId", wt.HANDLE), ("LogFileNameOffset", wt.ULONG), ("LoggerNameOffset", wt.ULONG)]

    class EVENT_DESCRIPTOR(ctypes.Structure):
        _fields_ = [("Id", wt.USHORT), ("Version", ctypes.c_ubyte), ("Channel", ctypes.c_ubyte),
                    ("Level", ctypes.c_ubyte), ("Opcode", ctypes.c_ubyte), ("Task", wt.USHORT),
                    ("Keyword", ctypes.c_uint64)]

    class EVENT_HEADER(ctypes.Structure):
        _fields_ = [("Size", wt.USHORT), ("HeaderType", wt.USHORT), ("Flags", wt.USHORT),
                    ("EventProperty", wt.USHORT), ("ThreadId", wt.ULONG), ("ProcessId", wt.ULONG),
                    ("TimeStamp", ctypes.c_int64), ("ProviderId", GUID), ("EventDescriptor", EVENT_DESCRIPTOR),
                    ("ProcessorTime", ctypes.c_uint64), ("ActivityId", GUID)]

    class EVENT_RECORD(ctypes.Structure):
        _fields_ = [("EventHeader", EVENT_HEADER), ("BufferContext", wt.ULONG), ("ExtendedDataCount", wt.USHORT),
                    ("UserDataLength", wt.USHORT), ("ExtendedData", ctypes.c_void_p), ("UserData", ctypes.c_void_p),
                    ("UserContext", ctypes.c_void_p)]

    class EVENT_TRACE_HEADER(ctypes.Structure):
        _fields_ = [("Size", wt.USHORT), ("FieldTypeFlags", wt.USHORT), ("Version", wt.ULONG),
                    ("ThreadId", wt.ULONG), ("ProcessId", wt.ULONG), ("TimeStamp", ctypes.c_int64), ("Guid", GUID),
                    ("ProcessorTime", ctypes.c_uint64)]

    class EVENT_TRACE(ctypes.Structure):
        _fields_ = [("Header", EVENT_TRACE_HEADER), ("InstanceId", wt.ULONG), ("ParentInstanceId", wt.ULONG),
                    ("ParentGuid", GUID), ("MofData", ctypes.c_void_p), ("MofLength", wt.ULONG),
                    ("ClientContext", wt.ULONG)]

    class SYSTEMTIME(ctypes.Structure):
        _fields_ = [(n, wt.WORD) for n in ("wYear", "wMonth", "wDayOfWeek", "wDay", "wHour", "wMinute",
                                           "wSecond", "wMs")]

    class TIME_ZONE_INFORMATION(ctypes.Structure):
        _fields_ = [("Bias", wt.LONG), ("StandardName", wt.WCHAR * 32), ("StandardDate", SYSTEMTIME),
                    ("StandardBias", wt.LONG), ("DaylightName", wt.WCHAR * 32), ("DaylightDate", SYSTEMTIME),
                    ("DaylightBias", wt.LONG)]

    class TRACE_LOGFILE_HEADER(ctypes.Structure):
        _fields_ = [("BufferSize", wt.ULONG), ("Version", wt.ULONG), ("ProviderVersion", wt.ULONG),
                    ("NumberOfProcessors", wt.ULONG), ("EndTime", ctypes.c_int64), ("TimerResolution", wt.ULONG),
                    ("MaximumFileSize", wt.ULONG), ("LogFileMode", wt.ULONG), ("BuffersWritten", wt.ULONG),
                    ("LogInstanceGuid", GUID), ("LoggerName", ctypes.c_void_p), ("LogFileName", ctypes.c_void_p),
                    ("TimeZone", TIME_ZONE_INFORMATION), ("BootTime", ctypes.c_int64), ("PerfFreq", ctypes.c_int64),
                    ("StartTime", ctypes.c_int64), ("ReservedFlags", wt.ULONG), ("BuffersLost", wt.ULONG)]

    EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))
    BUFFER_CALLBACK = ctypes.WINFUNCTYPE(wt.ULONG, ctypes.c_void_p)

    class EVENT_TRACE_LOGFILEW(ctypes.Structure):
        _fields_ = [("LogFileName", wt.LPWSTR), ("LoggerName", wt.LPWSTR), ("CurrentTime", ctypes.c_int64),
                    ("BuffersRead", wt.ULONG), ("ProcessTraceMode", wt.ULONG), ("CurrentEvent", EVENT_TRACE),
                    ("LogfileHeader", TRACE_LOGFILE_HEADER), ("BufferCallback", BUFFER_CALLBACK),
                    ("BufferSize", wt.ULONG), ("Filled", wt.ULONG), ("EventsLost", wt.ULONG),
                    ("EventRecordCallback", EVENT_RECORD_CALLBACK), ("IsKernelTrace", wt.ULONG),
                    ("Context", ctypes.c_void_p)]

    _advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    _advapi.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_uint64), wt.LPCWSTR, ctypes.c_void_p]
    _advapi.StartTraceW.restype = wt.ULONG
    _advapi.ControlTraceW.argtypes = [ctypes.c_uint64, wt.LPCWSTR, ctypes.c_void_p, wt.ULONG]
    _advapi.ControlTraceW.restype = wt.ULONG
    _advapi.EnableTraceEx2.argtypes = [ctypes.c_uint64, ctypes.POINTER(GUID), wt.ULONG, ctypes.c_ubyte,
                                       ctypes.c_uint64, ctypes.c_uint64, wt.ULONG, ctypes.c_void_p]
    _advapi.EnableTraceEx2.restype = wt.ULONG
    _advapi.OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]
    _advapi.OpenTraceW.restype = ctypes.c_uint64
    _advapi.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_uint64), wt.ULONG, ctypes.c_void_p, ctypes.c_void_p]
    _advapi.ProcessTrace.restype = wt.ULONG
    _advapi.CloseTrace.argtypes = [ctypes.c_uint64]
    _advapi.CloseTrace.restype = wt.ULONG
    _NDISCAP_BYTES = NDISCAP.bytes_le

    def _properties() -> Any:
        # 64 KB buffers, 4 to 32 of them: at most 2 MB of kernel memory, flushed every second.
        size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 2 * (len(SESSION) + 1) + 64
        buf = ctypes.create_string_buffer(size)
        p = EVENT_TRACE_PROPERTIES.from_buffer(buf)
        p.Wnode.BufferSize = size
        p.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        p.Wnode.ClientContext = 1                       # QueryPerformanceCounter timestamps
        p.BufferSize = 64
        p.MinimumBuffers, p.MaximumBuffers = 4, 32
        p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        p.FlushTimer = 1
        p.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        return buf

    def _stop_session() -> int:
        return _advapi.ControlTraceW(0, SESSION, _properties(), EVENT_TRACE_CONTROL_STOP)


class NdisSource:  # pragma: no cover - needs Windows and Administrator; checked by packaging/check_capture.py
    """Our real-time ETW session on the NDIS-PacketCapture provider. The driver reports
    every adapter's packets; only the selected adapter's are delivered."""

    name = "Microsoft NDIS capture (built in)"

    def __init__(self) -> None:
        self.error: Optional[str] = None
        self.index: Optional[int] = None
        self.seen: Counter[tuple[int, int]] = Counter()     # packets per (miniport, lower) index, for diagnosis
        self._deliver: Optional[Callable[[bytes], None]] = None
        self._cb = EVENT_RECORD_CALLBACK(self._on_event)
        self._thread: Optional[threading.Thread] = None
        self._trace = INVALID_TRACE

    def _on_event(self, rec_ptr: Any) -> None:
        try:
            rec = rec_ptr.contents
            hdr = rec.EventHeader
            if hdr.EventDescriptor.Id != FRAGMENT_EVENT or bytes(hdr.ProviderId.Data) != _NDISCAP_BYTES:
                return
            if not rec.UserData or rec.UserDataLength < 12:
                return
            index = self.index
            miniport, lower = struct.unpack_from("<II", ctypes.string_at(rec.UserData, 8))
            self.seen[(miniport, lower)] += 1
            if index is None or index not in (miniport, lower):
                return
            found = parse_fragment(ctypes.string_at(rec.UserData, rec.UserDataLength))
            if found is not None and self._deliver is not None:
                self._deliver(as_ethernet(found[2]))
        except Exception as exc:  # noqa: BLE001 - an exception must never reach the ETW callback
            log.debug("NDIS event skipped: %s", exc)

    def open(self, deliver: Callable[[bytes], None]) -> bool:
        self._deliver = deliver
        handle = ctypes.c_uint64(0)
        rc = _advapi.StartTraceW(ctypes.byref(handle), SESSION, _properties())
        if rc == ERROR_ALREADY_EXISTS:
            # Left behind by an agent that did not stop cleanly (a real-time session
            # outlives its process). Only one agent runs per computer: replace it.
            log.info("Replacing a leftover %s capture session", SESSION)
            _stop_session()
            rc = _advapi.StartTraceW(ctypes.byref(handle), SESSION, _properties())
        if rc != 0:
            self.error = "requires Administrator" if rc == ERROR_ACCESS_DENIED else f"could not start capture ({rc})"
            return False
        guid = GUID.of(NDISCAP)
        rc = _advapi.EnableTraceEx2(handle.value, ctypes.byref(guid), EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                    TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFF, 0, 0, None)
        if rc != 0:
            self.error = f"could not switch on the NDIS capture driver ({rc})"
            _stop_session()
            return False
        logfile = EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = SESSION
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        logfile.EventRecordCallback = self._cb
        self._trace = _advapi.OpenTraceW(ctypes.byref(logfile))
        if self._trace == INVALID_TRACE:
            self.error = f"could not read the capture session ({ctypes.get_last_error()})"
            _stop_session()
            return False
        handles = (ctypes.c_uint64 * 1)(self._trace)
        self._thread = threading.Thread(target=lambda: _advapi.ProcessTrace(handles, 1, None, None),
                                        daemon=True, name="ndis-capture")
        self._thread.start()
        self.error = None
        return True

    def select(self, adapter: Optional[dict[str, Any]]) -> None:
        index = (adapter or {}).get("index")
        self.index = int(index) if isinstance(index, int) and index > 0 else None

    def pump(self, stop: threading.Event, seconds: float) -> bool:
        """Frames arrive on ETW's own thread; wait. False when the session ended (stopped
        from outside, e.g. logman stop), so the hub opens it again."""
        stop.wait(seconds)
        return self._thread is not None and self._thread.is_alive()

    def close(self) -> None:
        _stop_session()                       # ends ProcessTrace
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._trace != INVALID_TRACE:
            _advapi.CloseTrace(self._trace)
            self._trace = INVALID_TRACE
        self._thread = None


# ── Linux: packet socket ─────────────────────────────────────────────────────

ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
PACKET_OUTGOING = 4


def attach_filter(sock: Any, program: list[tuple[int, int, int, int]]) -> None:
    """Load a classic BPF program on a packet socket (struct sock_fprog)."""
    code = b"".join(struct.pack("HBBI", *ins) for ins in program)
    buf = ctypes.create_string_buffer(code, len(code))
    fprog = struct.pack("HL", len(program), ctypes.addressof(buf))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)


class PacketSocketSource:
    """AF_PACKET socket on the selected adapter, re-opened when the adapter changes."""

    name = "Linux packet socket (built in)"

    def __init__(self, make_socket: Optional[Callable[[], Any]] = None) -> None:
        self.error: Optional[str] = None
        self._make = make_socket or self._socket
        self._deliver: Optional[Callable[[bytes], None]] = None
        self._sock: Any = None
        self._bound: Optional[str] = None

    @staticmethod
    def _socket() -> Any:  # pragma: no cover - needs Linux and root
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))  # type: ignore[attr-defined]
        attach_filter(sock, frames.kernel_filter())
        sock.settimeout(1.0)
        return sock

    def open(self, deliver: Callable[[bytes], None]) -> bool:
        self._deliver = deliver
        try:
            self._make().close()               # can we at all (root or CAP_NET_RAW)?
        except PermissionError:
            self.error = "requires root (or the CAP_NET_RAW capability)"
            return False
        except OSError as exc:
            self.error = f"could not open a packet socket ({exc})"
            return False
        self.error = None
        return True

    def select(self, adapter: Optional[dict[str, Any]]) -> None:
        name = (adapter or {}).get("name")
        if name == self._bound and self._sock is not None:
            return
        self._close_socket()
        if not name:
            return
        try:
            sock = self._make()
            sock.bind((name, 0))
        except OSError as exc:
            log.warning("Cannot listen on %s (%s); trying again", name, exc)
            return
        self._sock, self._bound = sock, name

    def pump(self, stop: threading.Event, seconds: float) -> bool:
        if self._sock is None:
            stop.wait(seconds)
            return True
        until = time.monotonic() + seconds
        while not stop.is_set() and time.monotonic() < until:
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:              # the adapter went away
                log.warning("Packet socket on %s failed (%s); trying again", self._bound, exc)
                self._close_socket()
                return True
            if len(addr) > 2 and addr[2] == PACKET_OUTGOING:
                continue                        # sent by this computer
            if self._deliver is not None:
                self._deliver(data)
        return True

    def _close_socket(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock, self._bound = None, None

    def close(self) -> None:
        self._close_socket()


# ── One capture for every sniffer ────────────────────────────────────────────

def make_source(backend: str) -> Any:
    if backend == "ndis":
        return NdisSource()
    if backend == "packet":
        return PacketSocketSource()
    raise ValueError(f"no built-in capture called {backend!r}")


class CaptureHub:
    """Runs one capture on the adapter the InterfaceChooser picks (re-checked every 5 s)
    and gives each registered sniffer the frames its filter would let through, decoded
    once by scapy (which needs no Npcap for decoding)."""

    def __init__(self, source: Any, chooser: Any, decode: Optional[Callable[[bytes], Any]] = None) -> None:
        self.source = source
        self.chooser = chooser
        self._decode = decode
        self._sniffers: list[tuple[Callable[[bytes], bool], Callable[[Any], None]]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.error: Optional[str] = None
        self.frames = 0                  # frames from the selected adapter
        self.dispatched = 0              # of which some sniffer wanted

    @property
    def label(self) -> str:
        return self.source.name

    def add(self, wants: Callable[[bytes], bool], handler: Callable[[Any], None]) -> None:
        with self._lock:
            self._sniffers = self._sniffers + [(wants, handler)]

    def remove(self, handler: Callable[[Any], None]) -> None:
        with self._lock:
            self._sniffers = [s for s in self._sniffers if s[1] is not handler]

    def deliver(self, frame: bytes) -> None:
        """One frame of the selected adapter, from the source's thread."""
        self.frames += 1
        pkt = None
        for wants, handler in self._sniffers:
            if not wants(frame):
                continue
            if pkt is None:
                pkt = self._decoder()(frame)
                self.dispatched += 1
            try:
                handler(pkt)
            except Exception as exc:  # noqa: BLE001 - one bad packet never stops the capture
                log.debug("packet skipped: %s", exc)

    def _decoder(self) -> Callable[[bytes], Any]:
        if self._decode is None:
            from scapy.layers.l2 import Ether  # type: ignore
            self._decode = Ether
        return self._decode

    def start(self) -> bool:
        if not self.source.open(self.deliver):
            self.error = self.source.error
            log.error("Built-in capture (%s) could not start: %s", self.source.name, self.error)
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="capture-hub")
        self._thread.start()
        log.info("Passive capture: %s", self.source.name)
        return True

    def _selected(self) -> Optional[dict[str, Any]]:
        name = self.chooser.refresh()
        if name is None:
            return None
        return {"name": name, "index": getattr(self.chooser, "index", None)}

    def _loop(self) -> None:
        try:
            while not self._stop.is_set():
                self.source.select(self._selected())
                if not self.source.pump(self._stop, _REFRESH_SECONDS) and not self._stop.is_set():
                    log.warning("The capture session ended; starting it again")
                    self.source.close()
                    if not self.source.open(self.deliver):
                        self.error = self.source.error
                        log.error("Built-in capture stopped: %s", self.error)
                        return
        except Exception as exc:  # noqa: BLE001
            self.error = str(exc)
            log.error("Built-in capture error: %s", exc)
        finally:
            self.source.close()

    def stop(self) -> None:
        self._stop.set()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
