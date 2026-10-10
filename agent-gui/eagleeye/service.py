"""The long-running agent: heartbeat, poll the dashboard for scans, run pipelines.

Same behaviour as the original agent's main loop:
  * a heartbeat thread keeps the dashboard status green;
  * every poll interval, pending scans are fetched and dispatched;
  * active scans run one at a time in a background worker;
  * passive scans and the periodic passive flush run on the polling thread.

Differences: SBOM scans are declined with a visible reason instead of being run
(SBOM is out of scope for this version), and every run reports pipeline events.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable, Optional

from .api import AgentClient
from .config import Settings
from .passive import PassiveSuite
from .pipeline import EventKind, Pipeline, PipelineContext, PipelineEvent, PipelineResult
from .stages import (
    NmapScanStage, PassiveCollectStage, PassiveEnrichStage, SnmpPollStage, UploadStage,
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


class AgentService:
    def __init__(
        self,
        settings: Settings,
        client: Optional[AgentClient] = None,
        on_event: Callable[[PipelineEvent], None] = log_event,
    ) -> None:
        self.settings = settings
        self.client = client or AgentClient(settings.api_url, settings.api_key, settings.agent_id)
        self.on_event = on_event
        self.suite: Optional[PassiveSuite] = None
        self._stop = threading.Event()
        self._active_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="active")
        self._active_future: Optional[Future[None]] = None
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

    def run_active(self, scan_id: Optional[str], subnet: str) -> PipelineResult:
        cancelled = throttled(lambda: self.client.get_scan_status(scan_id) == "cancelled", 3.0) if scan_id else (lambda: False)
        ctx = PipelineContext("active", scan_id=scan_id, subnet=subnet, scan_type="active", cancelled=cancelled)
        result = self._active_pipeline(subnet).run(ctx)
        self._finish(scan_id, result)
        return result

    def run_passive(self, scan_id: Optional[str]) -> PipelineResult:
        ctx = PipelineContext("passive", scan_id=scan_id, scan_type="passive")
        result = self._passive_pipeline().run(ctx)
        if result.ok and ctx.hosts:
            self._last_flush = time.time()
        self._finish(scan_id, result)
        return result

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
        """One polling cycle: dispatch pending scans, then the periodic passive flush."""
        self._reap_active()
        pending = self.client.get_pending_scans()
        if pending:
            log.info("Found %d pending scan(s)", len(pending))
            for scan in pending:
                self._dispatch(scan)
        else:
            log.info("No pending scans")

        if self.settings.passive and self.suite is not None and self.suite.arp is not None:
            if time.time() - self._last_flush >= self.settings.passive_interval:
                self._last_flush = time.time()
                self.run_passive(None)

    # ── lifecycle ──
    def _heartbeat_loop(self) -> None:
        log.info("Heartbeat thread started (interval=%ss)", self.settings.heartbeat_interval)
        while not self._stop.wait(self.settings.heartbeat_interval):
            self.client.send_heartbeat()

    def start(self) -> None:
        """Send the first heartbeat, start the heartbeat thread and (if enabled) the sniffers."""
        self._stop.clear()
        self.client.send_heartbeat()
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="heartbeat").start()
        if self.settings.passive:
            self.suite = PassiveSuite(self.settings.passive_interface or None, self.settings.fingerbank_key or None)
            self.suite.start()
            self._last_flush = time.time()

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.is_set():
                try:
                    self.poll_once()
                except Exception as exc:  # noqa: BLE001 - one bad cycle must not kill the agent
                    log.error("Unexpected error: %s", exc, exc_info=True)
                self._stop.wait(self.settings.poll_interval)
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        if self.suite:
            self.suite.stop()
        self._active_pool.shutdown(wait=False, cancel_futures=True)
