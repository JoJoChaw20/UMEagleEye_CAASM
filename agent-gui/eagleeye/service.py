"""The long-running agent: heartbeat, poll the dashboard for scans, run pipelines.

Same behaviour as the original agent's main loop:
  * a heartbeat thread keeps the dashboard status green;
  * every poll interval, pending scans are fetched and dispatched;
  * active scans run one at a time in a background worker;
  * passive scans and the periodic passive flush run on the polling thread.

Differences: SBOM scans are declined with a visible reason instead of being run
(SBOM is out of scope for this version), and every run reports pipeline events.

Added for the GUI: local schedules and "Scan now" / "Collect inventory now"
requests. Requests may come from any thread; they are queued and handled on the
polling thread, which they wake up.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from .api import AgentClient
from .config import Settings
from .passive import PassiveSuite
from .pipeline import EventKind, Pipeline, PipelineContext, PipelineEvent, PipelineResult
from .schedule import Schedule, ScheduleState
from .stages.scan_nmap import validate_target
from .stages import (
    InventoryUploadStage, LocalInventoryStage, NmapScanStage, PassiveCollectStage, PassiveEnrichStage,
    SnmpPollStage, UploadStage,
)

log = logging.getLogger("eagleeye.service")
event_log = logging.getLogger("eagleeye.pipeline")


def log_event(event: PipelineEvent) -> None:
    """Default event handler: write pipeline progress to the log."""
    where = f"[{event.pipeline}]"
    if event.kind is EventKind.STAGE_STARTED:
        event_log.info("%s %s", where, event.message)
    elif event.kind is EventKind.STAGE_PROGRESS:
        event_log.info("%s   %s", where, event.message)
    elif event.kind is EventKind.STAGE_FAILED:
        event_log.warning("%s %s failed: %s", where, event.stage, event.message)
    elif event.kind is EventKind.PIPELINE_FINISHED:
        event_log.info("%s finished: %s", where, event.message)


def throttled(fn: Callable[[], bool], interval: float) -> Callable[[], bool]:
    """Call fn at most once per `interval` seconds, returning the last answer between
    calls. Keeps the cancellation check from hammering the API inside tight loops."""
    state = {"at": 0.0, "value": False}

    def wrapper() -> bool:
        now = time.monotonic()
        if now - state["at"] >= interval:
            state["at"] = now
            state["value"] = fn()
        return state["value"]

    return wrapper


SCHEDULE_RETRY_SECONDS = 300
# Local schedules are switched off for now (decision pending: editing them crashed the
# desktop app under PySide6 6.12). The code and tests stay so they can be re-enabled.
SCHEDULES_ENABLED = False


@dataclass(frozen=True)
class RunRecord:
    """One finished pipeline run, for the GUI's recent-activity list."""
    pipeline: str
    trigger: str            # dashboard | schedule | manual | auto
    target: str
    status: str
    hosts: int
    seconds: float
    error: Optional[str]
    finished_at: datetime


class AgentService:
    def __init__(
        self,
        settings: Settings,
        client: Optional[AgentClient] = None,
        on_event: Callable[[PipelineEvent], None] = log_event,
        state_path: Optional[Path] = None,
    ) -> None:
        self.settings = settings
        self.client = client or AgentClient(settings.api_url, settings.api_key, settings.agent_id)
        self.on_event = on_event
        self.suite: Optional[PassiveSuite] = None
        self.schedule_state = ScheduleState(state_path)
        self.schedules_enabled = SCHEDULES_ENABLED
        self.history: deque[RunRecord] = deque(maxlen=50)
        self.last_heartbeat_at: Optional[datetime] = None
        self.last_heartbeat_ok: Optional[bool] = None
        self.current: Optional[str] = None             # what the active worker is doing, for display
        self._requests: "queue.Queue[tuple[str, str]]" = queue.Queue()
        self._wake = threading.Event()
        self._schedule_retry_at = 0.0
        self._stop = threading.Event()
        self._active_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="active")
        self._active_future: Optional[Future[None]] = None
        self._inventory_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="inventory")
        self._inventory_future: Optional[Future[PipelineResult]] = None
        self._last_inventory = 0.0           # 0 = collect on the first poll
        self._inventory_supported = True
        self._last_flush = time.time()

    # ── pipelines ──
    def _active_pipeline(self, subnet: str) -> Pipeline:
        stages: list[Any] = [NmapScanStage(subnet)]
        if self.settings.snmp_enabled:
            stages.append(SnmpPollStage(self.settings))
        stages.append(UploadStage(self.client, "active"))
        return Pipeline("active", stages, self.on_event)

    def _passive_pipeline(self) -> Pipeline:
        assert self.suite is not None
        return Pipeline("passive", [
            PassiveCollectStage(self.suite),
            PassiveEnrichStage(self.suite),
            UploadStage(self.client, "passive"),
        ], self.on_event)

    def _record(self, pipeline: str, trigger: str, target: str, result: PipelineResult) -> None:
        self.history.appendleft(RunRecord(
            pipeline, trigger, target, result.status, result.hosts, result.seconds, result.error, datetime.now(),
        ))

    def run_active(self, scan_id: Optional[str], subnet: str, trigger: str = "dashboard") -> PipelineResult:
        cancelled = throttled(lambda: self.client.get_scan_status(scan_id) == "cancelled", 3.0) if scan_id else (lambda: False)
        ctx = PipelineContext("active", scan_id=scan_id, subnet=subnet, scan_type="active", cancelled=cancelled)
        self.current = f"Scanning {subnet}"
        try:
            result = self._active_pipeline(subnet).run(ctx)
        finally:
            self.current = None
        self._finish(scan_id, result)
        self._record("active", trigger, subnet, result)
        return result

    def run_passive(self, scan_id: Optional[str]) -> PipelineResult:
        ctx = PipelineContext("passive", scan_id=scan_id, scan_type="passive")
        result = self._passive_pipeline().run(ctx)
        if result.ok and ctx.hosts:
            self._last_flush = time.time()
        self._finish(scan_id, result)
        self._record("passive", "dashboard" if scan_id else "auto", "local network", result)
        return result

    def run_inventory(self, trigger: str = "auto") -> PipelineResult:
        ctx = PipelineContext("inventory", scan_type="inventory")
        result = Pipeline("inventory", [
            LocalInventoryStage(options=self.settings.inventory_options), InventoryUploadStage(self.client),
        ], self.on_event).run(ctx)
        if result.status == "failed" and "not available on" in (result.error or ""):
            # Linux/macOS until their collectors exist: report it once, then stop trying.
            self._inventory_supported = False
        self._record("inventory", trigger, "this computer", result)
        return result

    def _maybe_inventory(self, force: bool = False) -> None:
        if not self.settings.inventory or not self._inventory_supported:
            if force:
                log.warning("Inventory is switched off (or not supported on this system); nothing collected")
            return
        if self._inventory_future is not None:
            if not self._inventory_future.done():
                if force:
                    log.info("An inventory is already being collected")
                return
            try:
                self._inventory_future.result()
            except Exception as exc:  # noqa: BLE001
                log.error("Inventory worker failed: %s", exc, exc_info=True)
            self._inventory_future = None
        if self._stop.is_set():
            return
        if force or time.time() - self._last_inventory >= self.settings.inventory_interval:
            self._last_inventory = time.time()
            try:
                self._inventory_future = self._inventory_pool.submit(self.run_inventory, "manual" if force else "auto")
            except RuntimeError:        # stopped (settings saved) while this poll was running
                pass

    @property
    def inventory_running(self) -> bool:
        return self._inventory_future is not None and not self._inventory_future.done()

    @property
    def active_running(self) -> bool:
        return self._active_future is not None and not self._active_future.done()

    # ── scans started on this machine ──
    def _start_local_scan(self, subnet: str, trigger: str) -> Optional[str]:
        """Start an active scan that this machine initiated. Returns None when it
        started, otherwise the reason it did not."""
        try:
            subnet = validate_target(subnet)
        except ValueError as exc:
            return str(exc)
        if self._active_future is not None:
            return "another active scan is still running"
        if self._stop.is_set():
            return "the agent is stopping"
        scan_id, error = self.client.start_local_scan(subnet, trigger)
        if not scan_id:
            return error or "the server did not start the scan"
        log.info("Processing ACTIVE scan %s subnet=%s (%s)", scan_id[:8], subnet,
                 "scheduled" if trigger == "schedule" else "started on this computer")
        try:
            self._active_future = self._active_pool.submit(self.run_active, scan_id, subnet, trigger)
        except RuntimeError:            # stopped meanwhile: don't leave the record running
            self.client.mark_scan_failed(scan_id, "The agent was stopped before the scan started")
            return "the agent is stopping"
        return None

    def _maybe_schedules(self, now: Optional[datetime] = None) -> None:
        if not self.schedules_enabled:
            return
        now = now or datetime.now()
        schedules = [Schedule.from_dict(raw) for raw in self.settings.schedules]
        self.schedule_state.forget_except({s.id for s in schedules})
        if self._active_future is not None or time.time() < self._schedule_retry_at:
            return
        for sched in schedules:
            if not sched.is_due(self.schedule_state.last_run(sched.id, now), now):
                continue
            reason = self._start_local_scan(sched.subnet, "schedule")
            if reason is None:
                self.schedule_state.mark(sched.id, now)
                return                      # one active scan at a time; others wait
            if reason.startswith("could not reach"):
                log.warning("Scheduled scan of %s postponed: %s", sched.subnet, reason)
                self._schedule_retry_at = time.time() + SCHEDULE_RETRY_SECONDS
                return
            log.warning("Scheduled scan of %s skipped: %s", sched.subnet, reason)
            self.schedule_state.mark(sched.id, now)

    def next_scheduled(self, now: Optional[datetime] = None) -> list[tuple[Schedule, Optional[datetime]]]:
        """Each schedule with its next run time, for display."""
        now = now or datetime.now()
        out = []
        for raw in self.settings.schedules:
            sched = Schedule.from_dict(raw)
            last = self.schedule_state.last_runs.get(sched.id, now)
            out.append((sched, sched.next_run(last, now)))
        return out

    # ── requests from the GUI (any thread) ──
    def request_scan(self, subnet: str) -> None:
        self._requests.put(("scan", subnet))
        self._wake.set()

    def request_inventory(self) -> None:
        self._requests.put(("inventory", ""))
        self._wake.set()

    def _handle_requests(self) -> None:
        while True:
            try:
                kind, arg = self._requests.get_nowait()
            except queue.Empty:
                return
            if kind == "inventory":
                self._maybe_inventory(force=True)
            elif kind == "scan":
                reason = self._start_local_scan(arg, "manual")
                if reason:
                    log.warning("Scan of %s not started: %s", arg, reason)

    def _finish(self, scan_id: Optional[str], result: PipelineResult) -> None:
        if result.status == "failed" and scan_id:
            self.client.mark_scan_failed(scan_id, result.error or "Scan failed on the agent")
        elif result.status == "cancelled" and scan_id:
            log.info("Scan %s cancelled by the user", scan_id[:8])

    # ── dispatch ──
    def _reap_active(self) -> None:
        if self._active_future is not None and self._active_future.done():
            try:
                self._active_future.result()
            except Exception as exc:  # noqa: BLE001
                log.error("Background active-scan worker failed: %s", exc, exc_info=True)
            self._active_future = None

    def _decline(self, scan_id: Optional[str], reason: str) -> None:
        log.warning("Declining scan %s: %s", (scan_id or "?")[:8], reason)
        if scan_id:
            self.client.mark_scan_failed(scan_id, reason)

    def _dispatch(self, scan: dict[str, Any]) -> None:
        scan_id = scan.get("scan_id") or scan.get("scanId")
        scan_type = scan.get("scan_type") or scan.get("scanType") or "active"
        subnet = scan.get("subnet") or "192.168.1.0/24"
        if scan.get("status", "pending") == "cancelled":
            return
        if self._stop.is_set():          # leave it pending for the restarted agent
            return

        if scan_type == "passive":
            if self.suite is None or self.suite.arp is None:
                self._decline(scan_id, "This agent is not running in passive mode. "
                                       "Restart it with passive mode enabled (as Administrator/root) to sniff.")
                return
            log.info("Processing PASSIVE scan %s", (scan_id or "?")[:8])
            self.run_passive(scan_id)
        elif scan_type == "active":
            if self._active_future is not None:
                log.info("Leaving ACTIVE scan %s queued while another active scan runs", (scan_id or "?")[:8])
                return
            log.info("Processing ACTIVE scan %s subnet=%s", (scan_id or "?")[:8], subnet)
            if scan_id:
                self.client.mark_scan_running(scan_id)
            self._active_future = self._active_pool.submit(self.run_active, scan_id, subnet)
        elif scan_type == "sbom":
            self._decline(scan_id, "SBOM scanning is not supported by this agent version (EagleEye Agent 2.x).")
        else:
            self._decline(scan_id, f"Unsupported scan type '{scan_type}'.")

    def poll_once(self) -> None:
        """One polling cycle: requests from the GUI, pending dashboard scans, local
        schedules, the periodic passive flush and the periodic endpoint inventory."""
        self._reap_active()
        self._handle_requests()
        self._maybe_inventory()
        pending = self.client.get_pending_scans()
        if pending:
            log.info("Found %d pending scan(s)", len(pending))
            for scan in pending:
                self._dispatch(scan)
        else:
            log.info("No pending scans")
        self._maybe_schedules()

        if self.settings.passive and self.suite is not None and self.suite.arp is not None:
            if time.time() - self._last_flush >= self.settings.passive_interval:
                self._last_flush = time.time()
                if self.suite.arp.pending():
                    self.run_passive(None)
                else:
                    log.debug("Passive flush: nothing new heard")

    # ── lifecycle ──
    def _heartbeat(self) -> None:
        self.last_heartbeat_ok = self.client.send_heartbeat()
        self.last_heartbeat_at = datetime.now()

    def _heartbeat_loop(self) -> None:
        log.info("Heartbeat thread started (interval=%ss)", self.settings.heartbeat_interval)
        while not self._stop.wait(self.settings.heartbeat_interval):
            self._heartbeat()

    def start(self) -> None:
        """Send the first heartbeat, start the heartbeat thread and (if enabled) the sniffers."""
        self._stop.clear()
        self._heartbeat()
        interrupted = self.client.reset_interrupted_scans()
        if interrupted:
            log.warning("%d active scan(s) from an earlier run never finished; marked as interrupted", interrupted)
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="heartbeat").start()
        if self.settings.passive:
            self.suite = PassiveSuite(self.settings.passive_interface or None, self.settings.fingerbank_key or None)
            self.suite.start()
            self._last_flush = time.time()

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.is_set():
                self._wake.clear()          # before polling, so a request made meanwhile wakes the next wait
                try:
                    self.poll_once()
                except Exception as exc:  # noqa: BLE001 - one bad cycle must not kill the agent
                    log.error("Unexpected error: %s", exc, exc_info=True)
                self._wake.wait(self.settings.poll_interval)
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self.suite:
            self.suite.stop()
        self._active_pool.shutdown(wait=False, cancel_futures=True)
        self._inventory_pool.shutdown(wait=False, cancel_futures=True)
