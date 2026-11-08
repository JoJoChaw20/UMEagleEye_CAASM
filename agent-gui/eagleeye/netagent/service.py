"""The network agent as a service (kind "network"): heartbeat, the administrator's settings,
and a crawl of the routers and switches every network_interval seconds and whenever the
dashboard asks ("Run now"), each uploaded in two parts (upload.py).

It has the parts of AgentService that servicehost.py and `eagleeye run` use (run_forever,
stop, status attributes), so it runs the same way: a Windows service, a systemd unit, a
Docker container. Its SNMP credentials come from its own settings and never leave it.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from .. import policy
from ..api import AgentClient
from ..config import Settings
from ..schedule import ScheduleState
from ..service import RunRecord
from .crawl import CrawlResult, crawl, parse_ranges
from .snmp import Credentials, Session, privacy_available
from .upload import ingest_hosts, topology_payload

log = logging.getLogger("eagleeye.netagent")
KIND = "network"
JOB = "network"                                 # ScheduleState job name: when the last crawl started


def credentials_of(settings: Settings) -> Credentials:
    priv = "" if settings.snmp_priv_protocol.lower() in ("", "none") else settings.snmp_priv_protocol
    return Credentials(version=settings.snmp_version, community=settings.snmp_community, user=settings.snmp_user,
                       auth_protocol=settings.snmp_auth_protocol, auth_key=settings.snmp_auth_key,
                       priv_protocol=priv, priv_key=settings.snmp_priv_key)


class NetworkAgentService:
    def __init__(self, settings: Settings, client: Optional[AgentClient] = None,
                 on_event: Optional[Callable[[Any], None]] = None, policy_path: Optional[Path] = None,
                 state_path: Optional[Path] = None, open_session: Optional[Callable[[str], Any]] = None,
                 vendor: Optional[Callable[[Optional[str]], Optional[str]]] = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.local_settings = settings
        self.policy_store = policy.PolicyStore(policy_path, kind=KIND)
        self.applied_policy_version, self.managed = self.policy_store.load()
        self.settings = policy.apply(settings, self.managed, KIND)
        self.client = client or AgentClient(settings.api_url, settings.api_key, settings.agent_id)
        self.client.kind = KIND
        self.state = ScheduleState(state_path)
        self._open_session = open_session
        self._vendor = vendor
        self._clock = clock
        self._stop, self._wake = threading.Event(), threading.Event()
        self.last_heartbeat_at: Optional[datetime] = None
        self.last_heartbeat_ok: Optional[bool] = None
        self.current: Optional[str] = None
        self.history: deque[RunRecord] = deque(maxlen=50)
        self.last_crawl: Optional[dict[str, Any]] = None
        self.suite = None                       # no passive listening (servicehost status reads it)
        self._requested = False
        # For a container's health check (health.py): written after every heartbeat.
        self.status_path = state_path.with_name("netagent-status.json") if state_path else None

    # ── what the heartbeat says ──
    def _report(self) -> dict[str, Any]:
        caps: dict[str, Any] = {"os": sys.platform, "snmp_version": self.settings.snmp_version,
                                "snmp_privacy": privacy_available()}
        try:
            credentials_of(self.settings).check()
            caps["snmp_ready"] = True
        except ValueError:
            caps["snmp_ready"] = False
        report: dict[str, Any] = {"kind": KIND, "settings": policy.local_report(self.local_settings, KIND),
                                  "capabilities": caps}
        if self.applied_policy_version:
            report["policy_version"] = self.applied_policy_version
        return report

    def _heartbeat(self) -> None:
        try:
            self.last_heartbeat_ok = self.client.send_heartbeat(self._report())
        except Exception as exc:  # noqa: BLE001 - the loop must go on
            log.warning("Heartbeat failed: %s", exc)
            self.last_heartbeat_ok = False
        self.last_heartbeat_at = datetime.now()
        self._write_status()
        if getattr(self.client, "jobs_in_heartbeat", False) and self.client.has_jobs():
            self._wake.set()

    def _write_status(self) -> None:
        if self.status_path is None:
            return
        status = {"heartbeat_ok": self.last_heartbeat_ok, "heartbeat_at": self._clock(),
                  "heartbeat_interval": self.settings.heartbeat_interval, "last_crawl": self.last_crawl,
                  "last_crawl_at": self.state.job_time(JOB) or None}
        try:
            tmp = self.status_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(status), encoding="utf-8")
            tmp.replace(self.status_path)
        except OSError as exc:
            log.debug("Could not write %s: %s", self.status_path, exc)

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.settings.heartbeat_interval):
            self._heartbeat()

    def _maybe_apply_policy(self) -> None:
        """Settings from the dashboard; a crawl never runs while this changes (one thread)."""
        version = getattr(self.client, "policy_version", None)
        if not isinstance(version, str) or version == self.applied_policy_version:
            return
        managed = policy.clean(getattr(self.client, "policy_managed", {}), KIND)
        self.settings = policy.apply(self.local_settings, managed, KIND)
        self.managed, self.applied_policy_version = managed, version
        self.policy_store.save(version, managed)
        log.info("Applied the administrator's settings (managed: %s)", policy.describe(managed))

    # ── crawling ──
    @property
    def active_running(self) -> bool:
        return self.current is not None

    def request_crawl(self) -> None:
        self._requested = True
        self._wake.set()

    def _due(self) -> bool:
        s = self.settings
        if not (s.network_poll and s.network_seeds):
            return False
        return self._clock() - self.state.job_time(JOB) >= s.network_interval

    def _session_factory(self) -> Callable[[str], Any]:
        if self._open_session is not None:
            return self._open_session
        creds = credentials_of(self.settings)
        creds.check()
        return lambda address: Session(address, creds)

    def crawl_once(self, scan_id: Optional[str] = None, trigger: str = "schedule") -> Optional[CrawlResult]:
        """Crawl, then upload. A dashboard job (scan_id) is marked failed with the reason."""
        s = self.settings
        started = self._clock()
        self.state.mark_job(JOB, started)
        target = ", ".join(s.network_seeds) or "-"

        def failed(reason: str) -> None:
            log.warning("Crawl not done: %s", reason)
            if scan_id:
                self.client.mark_scan_failed(scan_id, reason)
            self.history.append(RunRecord("network", trigger, target, "failed", 0, round(self._clock() - started, 1),
                                          reason, datetime.now()))

        if not s.network_seeds:
            failed("no seed devices are set (dashboard: Agents, this agent's settings)")
            return None
        try:
            open_session = self._session_factory()
        except ValueError as exc:
            failed(f"SNMP credentials on the agent: {exc}")
            return None
        if scan_id:
            self.client.mark_scan_running(scan_id)
        self.current = f"crawl from {target}"
        try:
            result = crawl(s.network_seeds, open_session, parse_ranges(s.network_ranges), depth=s.network_depth,
                           progress=lambda m: log.info("  %s", m))
        except ValueError as exc:                # a bad range in the local settings
            failed(str(exc))
            return None
        finally:
            self.current = None
        if not result.devices:
            failed("no seed device answered: " + "; ".join(u["error"] for u in result.unreachable[:5]))
            return result
        hosts = ingest_hosts(result, self._vendor)
        ingest = self.client.ingest("snmp", hosts, scan_id=scan_id)
        if not ingest.ok:
            failed(ingest.error or "the server did not take the addresses")
            return result
        ok, detail = self.client.send_topology(topology_payload(result, ingest.scan_id or scan_id))
        if not ok:
            log.warning("Topology not stored: %s", detail)
        log.info("Crawl: %d device(s), %d link(s), %d address(es) in %.1fs (%d requests); %s",
                 len(result.devices), len(result.links), len(hosts), result.seconds, result.requests, detail)
        self.last_crawl = {"devices": len(result.devices), "links": len(result.links), "addresses": len(hosts),
                           "seconds": result.seconds, "requests": result.requests, "topology": detail}
        self.history.append(RunRecord("network", trigger, target, "completed" if ok else "partial", len(hosts),
                                      round(self._clock() - started, 1), None if ok else detail, datetime.now()))
        return result

    def poll_once(self) -> None:
        self._maybe_apply_policy()
        jobs = self.client.take_jobs() if getattr(self.client, "jobs_in_heartbeat", False) else []
        for job in jobs or []:
            if job.get("scanType") == "snmp" and job.get("scanId"):
                if not self.settings.network_poll:
                    self.client.mark_scan_failed(job["scanId"], "This network agent's Collector role is off")
                    continue
                self.crawl_once(job["scanId"], trigger="dashboard")
            elif job.get("scanId"):
                self.client.mark_scan_failed(job["scanId"], f"A network agent does not run {job.get('scanType')} jobs")
        if self._requested:
            self._requested = False
            self.crawl_once(trigger="manual")
        elif self._due():
            self.crawl_once()

    # ── lifecycle ──
    def run_forever(self) -> None:
        self._stop.clear()
        self._heartbeat()
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="heartbeat").start()
        log.info("Network agent started (seeds %s, ranges %s, depth %d, every %ds)", self.settings.network_seeds,
                 self.settings.network_ranges, self.settings.network_depth, self.settings.network_interval)
        while not self._stop.is_set():
            self._wake.clear()
            try:
                self.poll_once()
            except Exception as exc:  # noqa: BLE001 - one bad cycle must not kill the agent
                log.error("Unexpected error: %s", exc, exc_info=True)
            self._wake.wait(self.settings.poll_interval)

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
