"""The agent app as a client of the agent service (2.5.0).

When the agent is installed as a service, the app no longer runs the agent: it shows
the service's state (ipc.py), passes on "Collect inventory" and the like, and changes
the service's settings through an elevated helper (`eagleeye service apply`, after a
Windows administrator prompt). Closing the app leaves the agent running.

ServiceController has the interface of controller.AgentController, RemoteService the
part of AgentService the pages read, and ServiceStore that of app.Store, so the pages
work the same in both modes. Without a service the app runs the agent itself as before.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .. import ipc
from ..config import ConfigError, Settings, config_dir, load_settings
from ..machine import machine_config_path, machine_log_dir, service_name
from ..service import RunRecord
from ..serviceinstall import SAVED_SECRET
from .controller import Listeners, gui_call

log = logging.getLogger("eagleeye.gui")

POLL_SECONDS = 2.0


def service_installed(instance: str = "") -> bool:
    """Is the agent installed as a service on this computer (running or not)?"""
    if os.environ.get("EAGLEEYE_EMBEDDED") == "1":           # run the agent in the app, as before
        return False
    try:
        if sys.platform == "win32":
            r = subprocess.run(["sc.exe", "query", service_name(instance)], capture_output=True, timeout=10,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return r.returncode == 0
        if sys.platform.startswith("linux"):
            from ..serviceinstall import unit_name
            return Path(f"/etc/systemd/system/{unit_name(instance)}.service").exists()
        if sys.platform == "darwin":
            from ..serviceinstall import launchd_plist
            return launchd_plist(instance).exists()
    except (OSError, subprocess.SubprocessError):
        pass
    return False


# ── running a command as an administrator ────────────────────────────────────

def _cli() -> tuple[str, list[str], Optional[str]]:
    """(program, leading arguments, working folder) of the command-line agent."""
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).with_name("eagleeye.exe" if sys.platform == "win32" else "eagleeye")), [], None
    return sys.executable, ["-m", "eagleeye"], str(Path(__file__).resolve().parents[2])


def run_elevated(args: list[str]) -> Optional[int]:
    """Run `eagleeye <args>` as an administrator and wait for it: its exit code, or None
    when the prompt was declined. Windows asks with its UAC prompt, macOS with its own
    password prompt (osascript), Linux with pkexec."""
    program, lead, cwd = _cli()
    if sys.platform == "darwin":
        import shlex
        line = " ".join(shlex.quote(a) for a in [program, *lead, *args])
        if cwd:
            line = f"cd {shlex.quote(cwd)} && {line}"
        script = 'do shell script "' + line.replace("\\", "\\\\").replace('"', '\\"') + '" with administrator privileges'
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
        return None if r.returncode != 0 and "-128" in r.stderr else r.returncode   # -128: Cancel pressed
    if sys.platform != "win32":
        r = subprocess.run(["pkexec", program, *lead, *args], cwd=cwd)
        return None if r.returncode in (126, 127) else r.returncode
    import ctypes
    import ctypes.wintypes as wt

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wt.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wt.HWND), ("lpVerb", wt.LPCWSTR),
                    ("lpFile", wt.LPCWSTR), ("lpParameters", wt.LPCWSTR), ("lpDirectory", wt.LPCWSTR),
                    ("nShow", ctypes.c_int), ("hInstApp", wt.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                    ("lpClass", wt.LPCWSTR), ("hkeyClass", wt.HKEY), ("dwHotKey", wt.DWORD),
                    ("hIconOrMonitor", wt.HANDLE), ("hProcess", wt.HANDLE)]

    SEE_MASK_NOCLOSEPROCESS, SW_HIDE, ERROR_CANCELLED = 0x40, 0, 1223
    info = SHELLEXECUTEINFOW(cbSize=ctypes.sizeof(SHELLEXECUTEINFOW), fMask=SEE_MASK_NOCLOSEPROCESS,
                             lpVerb="runas", lpFile=program, lpParameters=subprocess.list2cmdline([*lead, *args]),
                             lpDirectory=cwd, nShow=SW_HIDE)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    kernel32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        if ctypes.get_last_error() == ERROR_CANCELLED:
            return None
        raise OSError(f"could not start the elevated helper ({ctypes.get_last_error()})")
    try:
        kernel32.WaitForSingleObject(info.hProcess, 120_000)
        code = wt.DWORD()
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        return int(code.value)
    finally:
        kernel32.CloseHandle(info.hProcess)


# ── the service, as the pages see it ─────────────────────────────────────────

class RemoteSuite:
    def __init__(self, data: dict[str, Any]) -> None:
        self.listening_on = data.get("listening_on") or ""
        self.capture = data.get("capture") or ""
        self.arp = object() if data.get("running") else None
        self._problems = list(data.get("problems") or [])

    def problems(self) -> list[str]:
        return self._problems


def _when(value: Any) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value) if value else None
    except (TypeError, ValueError):
        return None


class RemoteService:
    """What the service reported in its last status answer."""

    def __init__(self, status: dict[str, Any], instance: str = "") -> None:
        self.status = status
        self.instance = instance
        self.last_heartbeat_at = _when(status.get("last_heartbeat_at"))
        self.last_heartbeat_ok = status.get("last_heartbeat_ok")
        self.rejected = status.get("rejected")
        self.current = status.get("current")
        self.active_running = bool(status.get("active_running"))
        self.inventory_running = bool(status.get("inventory_running"))
        self.sbom_running = bool(status.get("sbom_running"))
        self.local_scans_allowed = bool(status.get("local_scans_allowed", True))
        self.managed = dict(status.get("managed") or {})
        self.applied_policy_version = status.get("applied_policy_version")
        passive = status.get("passive")
        self.suite = RemoteSuite(passive) if isinstance(passive, dict) else None
        self.history = []
        for raw in status.get("history") or []:
            try:
                self.history.append(RunRecord(**{**raw, "finished_at": _when(raw.get("finished_at")) or datetime.now()}))
            except TypeError:
                continue
        self.schedules_enabled = False

    def next_scheduled(self, now: Optional[datetime] = None) -> list:
        return []

    def _request(self, what: str, **extra: Any) -> None:
        def send() -> None:
            try:
                ipc.call({"cmd": "request", "what": what, **extra}, ipc.address(self.instance))
            except Exception as exc:  # noqa: BLE001 - shown in the log
                log.warning("The agent service did not take the request (%s): %s", what, exc)
        threading.Thread(target=send, daemon=True).start()

    def request_inventory(self) -> None:
        self._request("inventory")

    def request_sbom(self) -> None:
        self._request("sbom")

    def request_scan(self, subnet: str) -> None:
        self._request("scan", subnet=subnet)


class ServiceController:
    """AgentController's interface over the agent service."""

    applies_settings_itself = True       # a saved change reaches the service by itself (app.settings_changed)

    def __init__(self, instance: str = "") -> None:
        self.instance = instance
        self.event = Listeners()
        self.log_line = Listeners()
        self.running_changed = Listeners()
        self.service: Optional[RemoteService] = None
        self.state = "unknown"               # the service's state, or "unavailable"
        self.problems: list[str] = []
        self.error: Optional[str] = None
        self._stop = threading.Event()
        self._running = False
        threading.Thread(target=self._poll, daemon=True, name="service-status").start()
        threading.Thread(target=self._tail_log, daemon=True, name="service-log").start()

    @property
    def running(self) -> bool:
        return self._running

    def refresh_now(self) -> None:
        try:
            status = ipc.call({"cmd": "status"}, ipc.address(self.instance), timeout=3)
            self.state, self.problems, self.error = status.get("state", "unknown"), list(status.get("problems") or []), None
            self.service = RemoteService(status, self.instance) if self.state == "running" else None
        except ipc.ServiceUnavailable as exc:
            self.state, self.service, self.error = "unavailable", None, str(exc)
        except Exception as exc:  # noqa: BLE001
            self.state, self.service, self.error = "unavailable", None, str(exc)
        running = self.service is not None
        if running != self._running:
            self._running = running
            gui_call(self.running_changed.emit, running)

    def _poll(self) -> None:
        while not self._stop.is_set():
            self.refresh_now()
            self._stop.wait(POLL_SECONDS)

    def _tail_log(self) -> None:
        """New lines of the service's log, for the Log page (Users may read it)."""
        path = machine_log_dir(self.instance) / "agent.log"
        offset: Optional[int] = None
        while not self._stop.wait(1.0):
            try:
                size = path.stat().st_size
                if offset is None or size < offset:            # first look, or the log rotated
                    offset = max(0, size - 20_000) if offset is None else 0
                if size > offset:
                    with path.open("rb") as f:
                        f.seek(offset)
                        chunk = f.read(size - offset)
                    offset = size
                    for line in chunk.decode("utf-8", "replace").splitlines():
                        if line.strip():
                            gui_call(self.log_line.emit, logging.INFO, line)
            except OSError:
                continue

    def _control(self, action: str) -> Optional[str]:
        args = ["service", action] + (["--instance", self.instance] if self.instance else [])
        try:
            code = run_elevated(args)
        except OSError as exc:
            return str(exc)
        if code is None:
            return "the administrator prompt was declined"
        threading.Timer(1.5, self.refresh_now).start()
        return None if code == 0 else f"`eagleeye service {action}` ended with code {code}"

    def start(self, settings: Settings) -> Optional[str]:
        """Start the service (an administrator prompt). Returns why it did not, or None."""
        if self.state == "not_set_up":
            return "save the server details on the Setup page first"
        return self._control("start")

    def stop(self) -> Optional[str]:
        return self._control("stop")

    def tools(self) -> list[dict[str, Any]]:
        """What the service itself finds (Syft, Grype, the account it runs as): the Setup page. Raises
        when the service does not answer (stopped, or older than this window)."""
        return list(ipc.call({"cmd": "tools"}, ipc.address(self.instance), timeout=45).get("tools") or [])

    def detach(self) -> None:
        """The app closes: the service keeps running."""
        self._stop.set()

    def apply_live(self, settings: Settings) -> None:
        pass


# ── settings of the service ──────────────────────────────────────────────────

class _ServiceSecrets:
    """The app's view of the service's secrets: it knows they are saved, not what they are."""

    def available(self) -> bool:
        return True

    def get(self, name: str) -> Optional[str]:
        return SAVED_SECRET if name.endswith("/api_key") else None

    def set(self, name: str, value: str) -> bool:
        return False


class SaveDeclined(Exception):
    """The administrator prompt was declined, or the helper failed."""


class ServiceStore:
    """app.Store's interface over the service's settings: readable by everyone, saved
    by an administrator through `eagleeye service apply`."""

    def __init__(self, instance: str = "") -> None:
        self.instance = instance
        self.path = machine_config_path(instance)
        self.keychain = _ServiceSecrets()
        self.load_error: Optional[str] = None
        self.settings = Settings()
        self.reload()

    def reload(self) -> None:
        try:
            self.settings = load_settings(self.path, env={}, keychain=self.keychain)
            self.load_error = None
        except ConfigError as exc:
            self.load_error = str(exc)

    def save(self) -> None:
        data = asdict(self.settings)
        handle, name = tempfile.mkstemp(prefix="eagleeye-settings-", suffix=".dat")
        try:
            raw = json.dumps(data).encode("utf-8")
            if sys.platform == "win32":
                from ..machine import protect
                raw = protect(raw, machine=False)          # only this user (also when elevated) can read it
            with os.fdopen(handle, "wb") as f:
                f.write(raw)
            args = ["service", "apply", "--from-config", name] + (["--instance", self.instance] if self.instance else [])
            code = run_elevated(args)
            if code is None:
                raise SaveDeclined("Not saved: the administrator prompt was declined.")
            if code != 0:
                raise SaveDeclined(f"Not saved: the helper ended with code {code} (see the service log).")
        finally:
            try:
                os.remove(name)
            except OSError:
                pass
        self.reload()


# ── the notice, per user ─────────────────────────────────────────────────────

def _notice_path() -> Path:
    return config_dir() / "notice.json"


def notice_read() -> int:
    """The notice version this user has read (with the service, the notice is per user:
    the settings belong to the service)."""
    try:
        return int(json.loads(_notice_path().read_text(encoding="utf-8")).get("version", 0))
    except (OSError, ValueError, AttributeError):
        return 0


def record_notice(version: int) -> None:
    path = _notice_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": version,
                                "read_at": datetime.now().astimezone().isoformat(timespec="seconds")}), encoding="utf-8")
