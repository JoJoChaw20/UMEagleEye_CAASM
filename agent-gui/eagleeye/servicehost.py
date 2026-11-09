"""The agent as a system service (2.5.0): runs AgentService from the machine settings,
answers the agent app over ipc.py, and starts the agent again when the settings change.

Used by the Windows service (winservice.py) and, in the foreground, by systemd on Linux
(`eagleeye service run`). Without settings (not set up yet) it waits, answering status,
until an administrator saves them and asks it to reload.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import asdict
from datetime import datetime
from typing import Any, Callable, Optional

from . import VERSION, ipc
from .config import ConfigError, Settings, load_settings, sbom_cache_path, state_path
from .machine import MachineSecrets, machine_config_path, machine_log_dir
from .policy import policy_path

log = logging.getLogger("eagleeye.servicehost")

RESTART_AFTER_FAILURE_SECONDS = 30
FINAL_UPLOAD_SECONDS = 40   # an upload took 30 s on staging (2026-11-07); Windows allows 60 s at shutdown
NOT_SET_UP_RECHECK_SECONDS = 60


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat(timespec="seconds") if value else None


class ServiceHost:
    def __init__(self, instance: str = "", make_service: Optional[Callable[[Settings], Any]] = None,
                 load: Optional[Callable[[], Settings]] = None, ipc_address: Optional[str] = None) -> None:
        self.instance = instance
        self.config_path = machine_config_path(instance)
        # Its state, SBOM cache and applied policy live next to this config (config.py).
        os.environ["EAGLEEYE_CONFIG"] = str(self.config_path)
        self._load = load or (lambda: load_settings(self.config_path, keychain=MachineSecrets()))
        self._make = make_service or self._agent_service
        self.service: Any = None
        self.state = "starting"            # starting | running | not_set_up | failed | stopped
        self.problems: list[str] = []
        self.started_at = datetime.now()
        self._stopping = False
        self._changed = threading.Event()
        self.server = ipc.Server(self.handle, ipc_address or ipc.address(instance))

    @staticmethod
    def _agent_service(settings: Settings) -> Any:
        if settings.kind == "network":               # reads routers and switches (netagent/)
            from .netagent.service import NetworkAgentService
            from .vendor import mac_vendor
            return NetworkAgentService(settings, state_path=state_path(), policy_path=policy_path(), vendor=mac_vendor)
        from .service import AgentService
        return AgentService(settings, state_path=state_path(), sbom_cache_path=sbom_cache_path(),
                            policy_path=policy_path())

    # ── lifecycle ──
    def run(self) -> None:
        """Run until stop(): start the agent, start it again after a reload or a crash."""
        self.server.start()
        log.info("EagleEye Agent service %s started (settings: %s)", VERSION, self.config_path)
        try:
            while not self._stopping:
                self._changed.clear()
                try:
                    settings = self._load()
                    self.problems = settings.problems()
                except ConfigError as exc:
                    settings, self.problems = None, [str(exc)]
                if self.problems or settings is None:
                    if self.state != "not_set_up":
                        log.warning("Not set up yet: %s", "; ".join(self.problems))
                    self.state = "not_set_up"
                    self._changed.wait(NOT_SET_UP_RECHECK_SECONDS)
                    continue
                self._run_agent(settings)
        finally:
            self.server.stop()
            self.state = "stopped"
            log.info("EagleEye Agent service stopped")

    def _run_agent(self, settings: Settings) -> None:
        service = self._make(settings)
        self.service, self.state = service, "running"
        thread = threading.Thread(target=service.run_forever, daemon=True, name="agent")
        thread.start()
        while not self._changed.wait(1.0):
            if not thread.is_alive():
                log.error("The agent stopped unexpectedly; starting it again in %d s", RESTART_AFTER_FAILURE_SECONDS)
                self.state = "failed"
                self._changed.wait(RESTART_AFTER_FAILURE_SECONDS)
                break
        if thread.is_alive():
            log.info("Stopping the agent" if self._stopping else "Settings changed; starting the agent again")
            service.stop()
            # What passive listening heard goes up before the service stops (Windows waits up
            # to 45 s on stop, 60 s at shutdown); the app, by contrast, never waits for it.
            wait = getattr(service, "wait_final_flush", None)
            if wait is not None:
                wait(FINAL_UPLOAD_SECONDS)
            thread.join(30)
        self.service = None

    def reload(self) -> None:
        self._changed.set()

    def stop(self) -> None:
        self._stopping = True
        self._changed.set()

    # ── requests from the agent app ──
    def handle(self, request: dict[str, Any]) -> Any:
        cmd = request.get("cmd")
        if cmd == "status":
            return self.status()
        if cmd == "reload":
            self.reload()
            return {"reloading": True}
        if cmd == "request":
            svc = self.service
            if svc is None:
                raise RuntimeError("the agent is not running")
            what = request.get("what")
            if what == "inventory":
                svc.request_inventory()
            elif what == "sbom":
                svc.request_sbom()
            elif what == "crawl":
                svc.request_crawl()
            elif what == "scan":
                subnet = str(request.get("subnet") or "")
                if not subnet:
                    raise ValueError("a scan needs a subnet")
                svc.request_scan(subnet)
            else:
                raise ValueError(f"unknown request {what!r}")
            return {"queued": what}
        if cmd == "noop":
            return {}
        if cmd == "tools":                  # the window's Setup page: what THIS process (the service) finds
            from dataclasses import asdict as _asdict
            from .deps import agent_tools
            return {"tools": [_asdict(t) for t in agent_tools(service=True)]}
        raise ValueError(f"unknown command {cmd!r}")

    def status(self) -> dict[str, Any]:
        svc = self.service
        out: dict[str, Any] = {
            "version": VERSION, "instance": self.instance, "state": self.state, "problems": self.problems,
            "pid": os.getpid(), "started_at": _iso(self.started_at), "config_path": str(self.config_path),
            "log_path": str(machine_log_dir(self.instance) / "agent.log"),
        }
        if svc is None:
            return out
        suite = getattr(svc, "suite", None)
        out.update({
            "last_heartbeat_at": _iso(getattr(svc, "last_heartbeat_at", None)),
            "last_heartbeat_ok": getattr(svc, "last_heartbeat_ok", None),
            "current": getattr(svc, "current", None),
            "active_running": bool(getattr(svc, "active_running", False)),
            "inventory_running": bool(getattr(svc, "inventory_running", False)),
            "sbom_running": bool(getattr(svc, "sbom_running", False)),
            "local_scans_allowed": bool(getattr(svc, "local_scans_allowed", True)),
            "managed": dict(getattr(svc, "managed", {}) or {}),
            "applied_policy_version": getattr(svc, "applied_policy_version", None),
            "passive": None if suite is None else {
                "listening_on": suite.listening_on, "capture": getattr(suite, "capture", ""),
                "running": suite.arp is not None, "problems": suite.problems(),
            },
            "history": [{**asdict(r), "finished_at": _iso(r.finished_at)} for r in list(getattr(svc, "history", []))[-30:]],
        })
        return out


def setup_logging(instance: str = "") -> None:
    """The service's log, in the machine folder (Users may read it: the app shows it)."""
    import logging.handlers
    log_dir = machine_log_dir(instance)
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(log_dir / "agent.log", maxBytes=1_000_000, backupCount=5,
                                                   encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)


def run_foreground(instance: str = "") -> int:
    """`eagleeye service run`: the service in this process until Ctrl+C or SIGTERM (systemd)."""
    import signal
    host = ServiceHost(instance)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda *_: host.stop())
        except (ValueError, OSError):
            pass
    worker = threading.Thread(target=host.run, daemon=True, name="service-host")
    worker.start()
    while worker.is_alive():
        time.sleep(0.5)
    return 0
