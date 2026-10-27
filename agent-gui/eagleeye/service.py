"""The long-running agent: heartbeat, poll the dashboard for scans, run pipelines.

Same behaviour as the original agent's main loop:
  * a heartbeat thread keeps the dashboard status green;
  * every poll interval, pending scans are fetched and dispatched;
  * active scans run one at a time in a background worker;
  * the periodic passive flush and passive scans run one at a time in their own
    worker, so a slow upload never holds up polling; what a failed upload held goes
    back into the buffer for the next flush, and stopping tries one last flush.

Every run reports pipeline events. The SBOM of this computer (Syft + Grype) runs in its
own worker so it never holds up scans: daily (15 minutes after the agent starts, then
every 24 hours), as a full run once a week, and whenever someone asks (dashboard or
the agent's "Build SBOM now", always full). Asking never moves the daily or weekly
times. One SBOM runs at a time: a request made during a daily run starts a full one
right after it; one made during a full run is answered by that run when it succeeds.
A daily or weekly run that comes due during a full run is answered by it the same way,
and the next one stays on its own time.

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

from . import sbom as sbom_tools
from .api import TRY_AGAIN_LATER, AgentClient
from .config import Settings
from .passive import PassiveSuite
from .pipeline import EventKind, Pipeline, PipelineContext, PipelineEvent, PipelineResult
from .schedule import Schedule, ScheduleState
from .stages.scan_nmap import validate_target
from .stages import (
    CveCheckStage, InventoryUploadStage, LocalInventoryStage, NmapScanStage, PassiveCollectStage,
    PassiveEnrichStage, SbomBuildStage, SbomUploadStage, SnmpPollStage, UploadStage,
)

LOCAL_SCANS_OFF = ("your administrator has turned off scans started on this computer; "
                   "active scans are started from the EagleEye dashboard")

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
# The first daily SBOM waits this long after the agent starts (the inventory, which links
# this computer to its asset, goes first; and start-up stays light).
SBOM_FIRST_DELAY = 15 * 60
SBOM_RETRY_SECONDS = 3600
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
        sbom_cache_path: Optional[Path] = None,
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
        self._passive_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="passive")
        self._passive_future: Optional[Future[Optional[PipelineResult]]] = None
        self._final_flush_started = False
        self._sbom_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sbom")
        self._sbom_future: Optional[Future[Optional[PipelineResult]]] = None
        self._next_sbom = time.time() + SBOM_FIRST_DELAY     # the daily run (in memory: a restart starts over)
        self.sbom_cache = sbom_tools.FolderCache(sbom_cache_path)   # also holds the weekly run's time
        self.sbom_mode: Optional[str] = None                 # full | quick while an SBOM runs
        self._sbom_last: Optional[tuple[str, bool]] = None   # (mode, succeeded) of the run that just ended
        self._sbom_wanted: Optional[str] = None              # "queued" | "covered": a Build SBOM now waiting
        self._sbom_due_waiting: Optional[float] = None       # a daily/weekly run that came due during a run

    # ── pipelines ──
    def _active_pipeline(self, subnet: str) -> Pipeline:
        stages: list[Any] = [NmapScanStage(subnet)]
        if self.settings.snmp_enabled:
            stages.append(SnmpPollStage(self.settings))
        stages.append(UploadStage(self.client, "active"))
        return Pipeline("active", stages, self.on_event)

    def _passive_pipeline(self, batch: Optional[tuple[Any, list[Any]]] = None) -> Pipeline:
        assert self.suite is not None
        return Pipeline("passive", [
            PassiveCollectStage(self.suite, batch),
            PassiveEnrichStage(self.suite),
            UploadStage(self.client, "passive"),
        ], self.on_event)

    def _record(self, pipeline: str, trigger: str, target: str, result: PipelineResult) -> None:
        self.history.appendleft(RunRecord(
            pipeline, trigger, target, result.status, result.hosts, result.seconds, result.error, datetime.now(),
        ))

    def run_active(self, scan_id: Optional[str], subnet: str, trigger: str = "dashboard") -> PipelineResult:
        # Active scans cannot be cancelled from the dashboard, so there is nothing to poll.
        ctx = PipelineContext("active", scan_id=scan_id, subnet=subnet, scan_type="active")
        self.current = f"Scanning {subnet}"
        try:
            result = self._active_pipeline(subnet).run(ctx)
        finally:
            self.current = None
        self._finish(scan_id, result)
        self._record("active", trigger, subnet, result)
        return result

    def run_passive(self, scan_id: Optional[str]) -> Optional[PipelineResult]:
        """Upload what was heard since the last flush, one upload per network it was
        heard on (several only after moving to another network). A batch whose upload
        failed goes back into the buffer. A scan the dashboard asked for is answered
        with the current network's batch, or with an empty upload that closes it."""
        assert self.suite is not None and self.suite.arp is not None
        arp = self.suite.arp
        batches = arp.drain_batches()
        if scan_id and not batches:
            batches = [(None, [])]
        result: Optional[PipelineResult] = None
        for i, batch in enumerate(batches):
            batch_scan_id = scan_id if i == len(batches) - 1 else None
            ctx = PipelineContext("passive", scan_id=batch_scan_id, scan_type="passive")
            result = self._passive_pipeline(batch).run(ctx)
            if result.status == "failed" and batch[1]:
                arp.restore(batch[0], batch[1])
                log.info("Passive upload failed; %d host(s) kept for the next flush", len(batch[1]))
            self._finish(batch_scan_id, result)
            self._record("passive", "dashboard" if batch_scan_id else "auto", "local network", result)
        return result

    @property
    def passive_running(self) -> bool:
        return self._passive_future is not None and not self._passive_future.done()

    def _reap_passive(self) -> None:
        if self._passive_future is not None and self._passive_future.done():
            try:
                self._passive_future.result()
            except Exception as exc:  # noqa: BLE001
                log.error("Passive flush failed: %s", exc, exc_info=True)
            self._passive_future = None

    def _submit_passive(self, scan_id: Optional[str]) -> bool:
        if self._stop.is_set():
            return False
        try:
            self._passive_future = self._passive_pool.submit(self.run_passive, scan_id)
        except RuntimeError:            # stopped (settings saved) while this poll was running
            return False
        return True

    def _maybe_flush_passive(self) -> None:
        """Every passive interval, counted from the start of the last flush so rounds
        stay on time: upload what was heard. A flush still uploading is never doubled;
        what was heard meanwhile waits in the buffer for the next round."""
        if not (self.settings.passive and self.suite is not None and self.suite.arp is not None):
            return
        self._reap_passive()
        if time.time() - self._last_flush < self.settings.passive_interval:
            return
        if self.passive_running:
            log.debug("Passive flush skipped: the previous one is still uploading")
            return
        self._last_flush = time.time()
        if self.suite.arp.pending():
            self._submit_passive(None)
        else:
            log.debug("Passive flush: nothing new heard")

    def run_inventory(self, trigger: str = "auto", scan_id: Optional[str] = None) -> PipelineResult:
        """Collect and upload this computer's inventory. scan_id is the dashboard's
        "Collect inventory" job; the server completes it when the inventory arrives."""
        ctx = PipelineContext("inventory", scan_id=scan_id, scan_type="inventory")
        result = Pipeline("inventory", [
            LocalInventoryStage(options=self.settings.inventory_options), InventoryUploadStage(self.client),
        ], self.on_event).run(ctx)
        if result.status == "failed" and "not available on" in (result.error or ""):
            # Linux/macOS until their collectors exist: report it once, then stop trying.
            self._inventory_supported = False
        self._finish(scan_id, result)
        self._record("inventory", trigger, "this computer", result)
        return result

    def run_sbom(self, scan_id: Optional[str] = None, trigger: str = "schedule",
                 full: bool = True) -> Optional[PipelineResult]:
        """Build this computer's SBOM and upload it with its CVE findings. scan_id is the
        dashboard's job; without one the server creates a record for this run. A daily
        run (full=False) lists only the folders that changed; a scheduled full run that
        succeeds is this week's full run."""
        started_at = time.time()
        started_id, reason = self.client.start_sbom(trigger, scan_id, "full" if full else "quick")
        if not started_id:
            log.warning("SBOM not started: %s", reason)
            if scan_id:      # leave a reason on the dashboard's job instead of letting it expire
                self.client.mark_scan_failed(scan_id, reason or "The agent could not start the SBOM scan")
            return None
        # Stops Syft/Grype within seconds when the agent stops, and within ~15 s of a
        # Cancel on the dashboard's SBOM page.
        dashboard_cancelled = throttled(lambda: self.client.sbom_status(started_id) == "cancelled", 15.0)
        ctx = PipelineContext("sbom", scan_id=started_id, scan_type="sbom",
                              cancelled=lambda: self._stop.is_set() or dashboard_cancelled())
        result = Pipeline("sbom", [
            SbomBuildStage(self.settings.sbom_extra_paths, include_binaries=self.settings.sbom_include_binaries,
                           cache=self.sbom_cache, full=full),
            CveCheckStage(), SbomUploadStage(self.client),
        ], self.on_event).run(ctx)
        if result.ok and trigger == "schedule" and ctx.summary.get("sbom_full", full):
            self.sbom_cache.last_full = started_at      # only a scheduled one: Run now never moves the week
            self.sbom_cache.save()
        self._finish(started_id, result)
        if result.status == "cancelled":    # no-op when the dashboard already cancelled it
            self.client.mark_scan_failed(started_id, "The agent was stopped before the SBOM scan finished")
        self._record("sbom", trigger, "this computer", result)
        return result

    @property
    def sbom_running(self) -> bool:
        return self._sbom_future is not None and not self._sbom_future.done()

    def _reap_sbom(self) -> None:
        if self._sbom_future is not None and self._sbom_future.done():
            ok = False
            try:
                result = self._sbom_future.result()
                ok = result is not None and result.ok
            except Exception as exc:  # noqa: BLE001
                log.error("SBOM worker failed: %s", exc, exc_info=True)
            self._sbom_last = (self.sbom_mode or "full", ok)
            self._sbom_future = None
            self.sbom_mode = None

    def _submit_sbom(self, scan_id: Optional[str], trigger: str, full: bool = True) -> bool:
        if self._stop.is_set():
            return False
        try:
            self._sbom_future = self._sbom_pool.submit(self.run_sbom, scan_id, trigger, full)
        except RuntimeError:            # stopped (settings saved) while this poll was running
            return False
        self.sbom_mode, self._sbom_last = ("full" if full else "quick"), None
        return True

    def _maybe_sbom(self, force: bool = False) -> None:
        """The daily and weekly SBOM, and "Build SBOM now" on this computer (force)."""
        self._reap_sbom()
        if not self.settings.sbom:
            if force:
                log.warning("SBOM is switched off on this computer (Privacy page); nothing built")
            return
        if force:
            if not self.sbom_running:
                self._submit_sbom(None, "manual", True)
            elif self.sbom_mode == "full":
                self._sbom_wanted = "covered"
                log.info("Build SBOM now: a full SBOM is already running; its result will appear when it finishes")
            else:
                self._sbom_wanted = "queued"
                log.info("Build SBOM now: queued, a full SBOM starts when the current daily SBOM finishes")
            return
        if self.sbom_running:
            if self._sbom_due_waiting is None and time.time() >= self._next_sbom:
                self._sbom_due_waiting = self._next_sbom
                log.info("The scheduled SBOM came due while another SBOM runs; it waits for that one")
            return
        finished_full = self._sbom_last == ("full", True)
        if self._sbom_wanted is not None:
            wanted, self._sbom_wanted = self._sbom_wanted, None
            if wanted == "covered" and finished_full:
                log.info("Build SBOM now: answered by the full SBOM that just finished")
            else:                       # queued behind a daily run, or the full run failed
                self._submit_sbom(None, "manual", True)
                return
        if self._sbom_due_waiting is not None:
            due, self._sbom_due_waiting = self._sbom_due_waiting, None
            if finished_full:
                # Answered by that run. The schedule keeps its own times: the next daily run
                # 24 h after this one was due, and a weekly run that was due counts as done then.
                if self.sbom_cache.weekly_due(due):
                    self.sbom_cache.last_full = due
                    self.sbom_cache.save()
                self._next_sbom = due + self.settings.sbom_interval
                log.info("The scheduled SBOM was answered by the full SBOM that just finished")
                return
        now = time.time()
        if now < self._next_sbom:
            return
        if not (sbom_tools.find_tool("syft") and sbom_tools.find_tool("grype")):
            log.info("Daily SBOM skipped: Syft and Grype are not both installed (see Dependencies)")
            self._next_sbom = now + self.settings.sbom_interval
            return
        if self._submit_sbom(None, "schedule", full=self.sbom_cache.weekly_due(now)):
            self._next_sbom = now + self.settings.sbom_interval

    def _maybe_inventory(self, force: bool = False, trigger: Optional[str] = None,
                         scan_id: Optional[str] = None) -> None:
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
                self._inventory_future = self._inventory_pool.submit(
                    self.run_inventory, trigger or ("manual" if force else "auto"), scan_id)
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
        if not self.local_scans_allowed:
            return LOCAL_SCANS_OFF
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

    @property
    def local_scans_allowed(self) -> bool:
        """False when the tenant's admin keeps active scans to the dashboard (heartbeat policy)."""
        return getattr(self.client, "local_scans_allowed", True)

    def _maybe_schedules(self, now: Optional[datetime] = None) -> None:
        if not self.schedules_enabled or not self.local_scans_allowed:
            return                      # not marked: they run again once the admin allows it
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
            if reason.startswith(TRY_AGAIN_LATER):
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

    def request_sbom(self) -> None:
        self._requests.put(("sbom", ""))
        self._wake.set()

    def _handle_requests(self) -> None:
        while True:
            try:
                kind, arg = self._requests.get_nowait()
            except queue.Empty:
                return
            if kind == "inventory":
                self._maybe_inventory(force=True)
            elif kind == "sbom":
                self._maybe_sbom(force=True)
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
            self._reap_passive()
            if self.passive_running:     # leave it pending; the next poll takes it
                log.info("Leaving PASSIVE scan %s queued while a flush uploads", (scan_id or "?")[:8])
                return
            log.info("Processing PASSIVE scan %s", (scan_id or "?")[:8])
            self._last_flush = time.time()
            self._submit_passive(scan_id)
        elif scan_type == "active":
            if self._active_future is not None:
                log.info("Leaving ACTIVE scan %s queued while another active scan runs", (scan_id or "?")[:8])
                return
            info = scan.get("network_info") or scan.get("networkInfo") or {}
            new_device = isinstance(info, dict) and info.get("trigger") == "new_device"
            log.info("Processing ACTIVE scan %s subnet=%s%s", (scan_id or "?")[:8], subnet,
                     " (investigating a new device)" if new_device else "")
            if scan_id:
                self.client.mark_scan_running(scan_id)
            self._active_future = self._active_pool.submit(
                self.run_active, scan_id, subnet, "new_device" if new_device else "dashboard")
        elif scan_type == "sbom":
            if not self.settings.sbom:
                self._decline(scan_id, "SBOM is switched off on this computer (agent Privacy page).")
                return
            self._reap_sbom()
            if self.sbom_running:
                log.info("Leaving SBOM job %s queued while an SBOM is being built", (scan_id or "?")[:8])
                return
            log.info("Processing SBOM job %s", (scan_id or "?")[:8])
            self._submit_sbom(scan_id, "dashboard", True)      # always full; the schedule stays as it is
        elif scan_type == "inventory":
            if not self.settings.inventory or not self._inventory_supported:
                self._decline(scan_id, "Inventory collection is switched off on this computer "
                                       "(agent Privacy page) or not supported on this system.")
                return
            if self.inventory_running:   # its upload completes this job too
                log.info("Inventory job %s: an inventory is already being collected", (scan_id or "?")[:8])
                return
            log.info("Processing INVENTORY job %s", (scan_id or "?")[:8])
            if scan_id:
                self.client.mark_scan_running(scan_id)
            self._maybe_inventory(force=True, trigger="dashboard", scan_id=scan_id)
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
        self._maybe_sbom()              # after the dashboard's jobs: a full run they asked for goes first
        self._maybe_schedules()
        self._maybe_flush_passive()

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

    def _final_flush(self) -> None:
        """Stopping: upload what was heard since the last flush, on a daemon thread so
        neither the window nor quitting waits for it (lost if the app quits first)."""
        if self._final_flush_started or not (self.settings.passive and self.suite is not None
                                             and self.suite.arp is not None and self.suite.arp.pending()):
            return
        self._final_flush_started = True
        log.info("Uploading what passive listening heard before stopping")
        threading.Thread(target=self.run_passive, args=(None,), daemon=True, name="passive-final").start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        try:
            self._final_flush()
        except Exception as exc:  # noqa: BLE001 - stopping must not fail
            log.warning("Final passive flush not started: %s", exc)
        if self.suite:
            self.suite.stop()
        self._passive_pool.shutdown(wait=False, cancel_futures=True)
        self._active_pool.shutdown(wait=False, cancel_futures=True)
        self._inventory_pool.shutdown(wait=False, cancel_futures=True)
        self._sbom_pool.shutdown(wait=False, cancel_futures=True)
