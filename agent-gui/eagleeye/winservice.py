"""The Windows service control layer (2.5.0): what lets eagleeye.exe run under the
Service Control Manager, through advapi32 with ctypes (no pywin32).

`eagleeye service scm` calls run(): StartServiceCtrlDispatcher hands a thread to
_service_main, which reports START_PENDING, starts the ServiceHost, reports RUNNING, and
waits. Stop, shutdown and pre-shutdown stop the host; the service reports STOP_PENDING
(with a wait hint, so Windows gives the final passive upload time) and then STOPPED.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import threading
from typing import Any, Callable, Optional

log = logging.getLogger("eagleeye.winservice")

SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_STOPPED, SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_RUNNING = 1, 2, 3, 4
SERVICE_CONTROL_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN = 1, 4, 5
SERVICE_CONTROL_PRESHUTDOWN = 0xF
SERVICE_ACCEPT_STOP, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_PRESHUTDOWN = 0x1, 0x4, 0x100
NO_ERROR, ERROR_CALL_NOT_IMPLEMENTED = 0, 120
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063
STOP_WAIT_HINT_MS = 45_000


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [("dwServiceType", wt.DWORD), ("dwCurrentState", wt.DWORD), ("dwControlsAccepted", wt.DWORD),
                ("dwWin32ExitCode", wt.DWORD), ("dwServiceSpecificExitCode", wt.DWORD),
                ("dwCheckPoint", wt.DWORD), ("dwWaitHint", wt.DWORD)]


SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wt.DWORD, ctypes.POINTER(wt.LPWSTR))
HANDLER_EX = ctypes.WINFUNCTYPE(wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_void_p, ctypes.c_void_p)


class SERVICE_TABLE_ENTRYW(ctypes.Structure):
    _fields_ = [("lpServiceName", wt.LPWSTR), ("lpServiceProc", SERVICE_MAIN)]


_advapi = ctypes.WinDLL("advapi32", use_last_error=True) if hasattr(ctypes, "WinDLL") else None
if _advapi is not None:
    _advapi.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRYW)]
    _advapi.StartServiceCtrlDispatcherW.restype = wt.BOOL
    _advapi.RegisterServiceCtrlHandlerExW.argtypes = [wt.LPCWSTR, HANDLER_EX, ctypes.c_void_p]
    _advapi.RegisterServiceCtrlHandlerExW.restype = ctypes.c_void_p
    _advapi.SetServiceStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(SERVICE_STATUS)]
    _advapi.SetServiceStatus.restype = wt.BOOL


class _Service:
    """One service in this process: the SCM callbacks around a host (run(), stop())."""

    def __init__(self, name: str, make_host: Callable[[], Any]) -> None:
        self.name = name
        self.make_host = make_host
        self.host: Any = None
        self.handle: Optional[int] = None
        self.status = SERVICE_STATUS(SERVICE_WIN32_OWN_PROCESS, SERVICE_START_PENDING, 0, NO_ERROR, 0, 0, 10_000)
        self.stopped = threading.Event()
        # Kept referenced: the SCM calls them for as long as the service runs.
        self.main_cb = SERVICE_MAIN(self._main)
        self.handler_cb = HANDLER_EX(self._handler)

    def _set(self, state: int, wait_hint: int = 0, exit_code: int = NO_ERROR) -> None:
        self.status.dwCurrentState = state
        self.status.dwWaitHint = wait_hint
        self.status.dwWin32ExitCode = exit_code
        self.status.dwControlsAccepted = 0 if state in (SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_STOPPED) \
            else SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN
        self.status.dwCheckPoint = 0 if state in (SERVICE_RUNNING, SERVICE_STOPPED) else self.status.dwCheckPoint + 1
        if self.handle:
            _advapi.SetServiceStatus(self.handle, ctypes.byref(self.status))

    def _handler(self, control: int, event_type: int, event_data: Any, context: Any) -> int:
        if control in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_PRESHUTDOWN):
            log.info("Windows asked the service to stop (control %d)", control)
            self._set(SERVICE_STOP_PENDING, STOP_WAIT_HINT_MS)
            if self.host is not None:
                self.host.stop()
            return NO_ERROR
        if control == SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR
        return ERROR_CALL_NOT_IMPLEMENTED

    def _main(self, argc: int, argv: Any) -> None:
        self.handle = _advapi.RegisterServiceCtrlHandlerExW(self.name, self.handler_cb, None)
        if not self.handle:
            log.error("RegisterServiceCtrlHandlerEx failed (%d)", ctypes.get_last_error())
            return
        self._set(SERVICE_START_PENDING, 10_000)
        try:
            self.host = self.make_host()
            worker = threading.Thread(target=self.host.run, daemon=True, name="service-host")
            worker.start()
            self._set(SERVICE_RUNNING)
            while worker.is_alive():
                worker.join(1.0)
                if self.status.dwCurrentState == SERVICE_STOP_PENDING:
                    self._set(SERVICE_STOP_PENDING, STOP_WAIT_HINT_MS)     # still stopping: next checkpoint
            self._set(SERVICE_STOPPED)
        except Exception as exc:  # noqa: BLE001 - report the failure to Windows
            log.error("The service failed: %s", exc, exc_info=True)
            self._set(SERVICE_STOPPED, exit_code=1066)               # ERROR_SERVICE_SPECIFIC_ERROR
        finally:
            self.stopped.set()


def run(name: str, make_host: Callable[[], Any]) -> int:
    """Hand this process to the Service Control Manager; returns when the service stops.
    2 when this process was not started by the SCM (run `eagleeye service run` instead)."""
    service = _Service(name, make_host)
    table = (SERVICE_TABLE_ENTRYW * 2)(SERVICE_TABLE_ENTRYW(name, service.main_cb), SERVICE_TABLE_ENTRYW(None, SERVICE_MAIN()))
    if not _advapi.StartServiceCtrlDispatcherW(table):
        err = ctypes.get_last_error()
        if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            print("This command is run by Windows' Service Control Manager. "
                  "To run the agent in this window, use: eagleeye service run")
            return 2
        log.error("StartServiceCtrlDispatcher failed (%d)", err)
        return 1
    return 0
