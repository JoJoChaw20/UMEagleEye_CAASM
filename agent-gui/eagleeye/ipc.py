"""The local channel between the agent service and the agent app (2.5.0).

One JSON request per connection, one JSON answer, each a single line:
  {"cmd": "status"}                          -> the service's state (ServiceHost.status)
  {"cmd": "request", "what": "inventory"}    -> inventory | sbom | scan (with "subnet")
  {"cmd": "reload"}                          -> read the settings again (after a change)

Windows: a named pipe local clients only, open to SYSTEM, administrators and signed-in
(interactive) users; network users never. Linux: a Unix socket next to the service's
files, open to local users. Changing settings is not a command: the settings file is
written by an administrator (the app asks Windows for elevation), then "reload".
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger("eagleeye.ipc")

MAX_MESSAGE = 1 << 20
NO_PIPE_GRACE = 0.5          # seconds a missing pipe is waited for (see call)
# SYSTEM and Administrators: full; interactive users: read and write (status, requests).
PIPE_SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"


def address(instance: str = "") -> str:
    suffix = f"-{instance}" if instance else ""
    if sys.platform == "win32":
        return rf"\\.\pipe\EagleEyeAgent{suffix}"
    from .machine import machine_dir
    return str(machine_dir() / f"agent{suffix}.sock")


def _answer(handler: Callable[[dict[str, Any]], Any], raw: bytes) -> bytes:
    try:
        request = json.loads(raw.decode("utf-8"))
        if not isinstance(request, dict):
            raise ValueError("a request is a JSON object")
        result: Any = {"ok": True, "result": handler(request)}
    except Exception as exc:  # noqa: BLE001 - every answer is JSON
        result = {"ok": False, "error": str(exc)}
    return json.dumps(result, default=str).encode("utf-8") + b"\n"


# ── server ───────────────────────────────────────────────────────────────────

class Server:
    """Answers requests on a background thread until stop()."""

    def __init__(self, handler: Callable[[dict[str, Any]], Any], addr: Optional[str] = None) -> None:
        self.handler = handler
        self.address = addr or address()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    def start(self) -> None:
        target = self._serve_pipe if sys.platform == "win32" else self._serve_socket
        if sys.platform != "win32":
            path = Path(self.address)
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                path.unlink()
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # type: ignore[attr-defined]
            self._sock.bind(str(path))
            os.chmod(path, 0o666)
            self._sock.listen(8)
        self._thread = threading.Thread(target=target, daemon=True, name="ipc")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if sys.platform == "win32":
            try:                                 # unblock the waiting ConnectNamedPipe
                with open(self.address, "r+b", buffering=0) as f:
                    f.write(b'{"cmd":"noop"}\n')
            except OSError:
                pass
        elif self._sock is not None:
            self._sock.close()

    def _serve_socket(self) -> None:  # pragma: no cover - Linux
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                data = b""
                try:
                    while not data.endswith(b"\n") and len(data) < MAX_MESSAGE:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    conn.sendall(_answer(self.handler, data))
                except OSError as exc:
                    log.debug("IPC request failed: %s", exc)

    def _serve_pipe(self) -> None:  # pragma: no cover - exercised by tests on Windows
        import ctypes
        import ctypes.wintypes as wt
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        adv = ctypes.WinDLL("advapi32", use_last_error=True)

        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("nLength", wt.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wt.BOOL)]

        k32.CreateNamedPipeW.restype = wt.HANDLE
        k32.CreateNamedPipeW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD,
                                         ctypes.POINTER(SECURITY_ATTRIBUTES)]
        k32.ConnectNamedPipe.argtypes = [wt.HANDLE, ctypes.c_void_p]
        k32.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
        k32.WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
        for fn in (k32.FlushFileBuffers, k32.DisconnectNamedPipe, k32.CloseHandle):
            fn.argtypes = [wt.HANDLE]
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wt.LPCWSTR, wt.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        sd = ctypes.c_void_p()
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(PIPE_SDDL, 1, ctypes.byref(sd), None):
            log.error("IPC: bad security descriptor (%s)", ctypes.get_last_error())
            return
        sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)
        PIPE_ACCESS_DUPLEX, PIPE_REJECT_REMOTE_CLIENTS, ERROR_PIPE_CONNECTED = 0x3, 0x8, 535
        INVALID = wt.HANDLE(-1).value
        buf = ctypes.create_string_buffer(65536)
        while not self._stop.is_set():
            h = k32.CreateNamedPipeW(self.address, PIPE_ACCESS_DUPLEX, PIPE_REJECT_REMOTE_CLIENTS, 255,
                                     65536, 65536, 0, ctypes.byref(sa))
            if not h or h == INVALID:
                log.error("IPC: cannot create %s (%s)", self.address, ctypes.get_last_error())
                time.sleep(5)
                continue
            try:
                if not k32.ConnectNamedPipe(h, None) and ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
                    continue
                data = b""
                got = wt.DWORD()
                while not data.endswith(b"\n") and len(data) < MAX_MESSAGE:
                    if not k32.ReadFile(h, buf, len(buf), ctypes.byref(got), None) or got.value == 0:
                        break
                    data += buf.raw[:got.value]
                if self._stop.is_set():
                    break
                out = _answer(self.handler, data)
                sent = wt.DWORD()
                k32.WriteFile(h, out, len(out), ctypes.byref(sent), None)
                k32.FlushFileBuffers(h)
                k32.DisconnectNamedPipe(h)
            finally:
                k32.CloseHandle(h)


# ── client ───────────────────────────────────────────────────────────────────

class ServiceUnavailable(Exception):
    """No agent service answers (not installed, stopped, or starting)."""


def call(request: dict[str, Any], addr: Optional[str] = None, timeout: float = 5.0) -> Any:
    """Send one request to the agent service and return its result."""
    target = addr or address()
    payload = json.dumps(request).encode("utf-8") + b"\n"
    deadline = time.monotonic() + timeout
    data = b""
    if sys.platform == "win32":
        while True:
            try:
                with open(target, "r+b", buffering=0) as f:
                    f.write(payload)
                    while not data.endswith(b"\n") and len(data) < MAX_MESSAGE:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        data += chunk
                break
            except FileNotFoundError as exc:
                # Between two requests the service opens the next pipe: a moment without one.
                if time.monotonic() > deadline - timeout + NO_PIPE_GRACE:
                    raise ServiceUnavailable("the agent service is not running") from exc
                time.sleep(0.02)
            except OSError as exc:                     # all pipe instances busy: try again shortly
                if time.monotonic() > deadline:
                    raise ServiceUnavailable(f"the agent service does not answer ({exc})") from exc
                time.sleep(0.05)
    else:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:  # type: ignore[attr-defined]
                s.settimeout(timeout)
                s.connect(target)
                s.sendall(payload)
                while not data.endswith(b"\n") and len(data) < MAX_MESSAGE:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            raise ServiceUnavailable("the agent service is not running") from exc
        except OSError as exc:
            raise ServiceUnavailable(f"the agent service does not answer ({exc})") from exc
    try:
        answer = json.loads(data.decode("utf-8"))
    except ValueError as exc:
        raise ServiceUnavailable("the agent service sent an unreadable answer") from exc
    if not answer.get("ok"):
        raise RuntimeError(answer.get("error") or "the agent service refused the request")
    return answer.get("result")
