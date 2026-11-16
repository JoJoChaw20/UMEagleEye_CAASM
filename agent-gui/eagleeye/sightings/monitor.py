"""Runs threat sightings while the setting is on: the list sync, a capture that takes only
DNS answers, the 30-second connection poll and the uploads (see the package notes)."""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from ..passive.frames import dns_answer
from . import connections, dns
from .indicators import IndicatorList, ListSync
from .recorder import HitRecorder

log = logging.getLogger("eagleeye.sightings")

CONNECTION_POLL = 30
UPLOAD_FRESH = 60           # a first contact goes up within a minute
UPLOAD_EVERY = 300          # repeats every 5 minutes
TICK = 5


class SightingsMonitor:
    def __init__(
        self,
        client: Any,
        agent_id: str,
        list_path: Optional[Path] = None,
        make_hub: Optional[Callable[[], Any]] = None,
        poll_connections: Callable[[], list[connections.Conn]] = connections.poll,
        process_of: Callable[[connections.Conn], Optional[str]] = connections.process_of,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.client = client
        self.list = IndicatorList.load(list_path, agent_id)
        self.sync = ListSync(self.list, client.sightings_indicators, list_path, agent_id, clock)
        self.recorder = HitRecorder(clock)
        self._make_hub = make_hub
        self._poll_connections = poll_connections
        self._process_of = process_of
        self._clock = clock
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._seen_connections: set[tuple[str, int, int]] = set()
        self._last_upload = clock()
        self._last_poll = 0.0
        self.hub: Any = None
        self.uploaded = 0               # contacts the server has
        self.last_upload_error: Optional[str] = None

    # ── matching ──
    def on_dns(self, pkt: Any) -> None:
        """A DNS answer from the capture (its thread): record each listed name and address."""
        found = dns.answers(getattr(pkt, "payload", b""))
        if found is None:
            return
        names, addresses = found
        for name in names:
            listed = self.list.match_domain(name)
            if listed:
                self.recorder.record(name, "domain", "dns")
        for address in addresses:
            ip = self.list.match_ip(address)
            if ip:
                self.recorder.record(ip, "ip", "dns")

    def poll_connections_once(self) -> int:
        """Record each new connection to a listed IP, with the program behind it. Returns how many."""
        current = self._poll_connections()
        keys = {c.key for c in current}
        hits = 0
        for conn in current:
            if conn.key in self._seen_connections:
                continue                # still the same connection: counted when it opened
            ip = self.list.match_ip(conn.remote)
            if ip:
                self.recorder.record(ip, "ip", "connection", self._process_of(conn), conn.port)
                hits += 1
        self._seen_connections = keys
        return hits

    # ── uploads ──
    def upload_due(self) -> bool:
        if not self.recorder.pending():
            return False
        waited = self._clock() - self._last_upload
        return waited >= UPLOAD_EVERY or (self.recorder.fresh() and waited >= UPLOAD_FRESH)

    def upload(self) -> bool:
        entries = self.recorder.take()
        self._last_upload = self._clock()
        if not entries:
            return True
        ok, message = self.client.send_sightings([e.payload() for e in entries])
        if ok:
            self.recorder.sent(entries)
            self.uploaded += sum(e.count for e in entries)
            self.last_upload_error = None
            log.info("Threat sightings sent: %s", message)
        else:
            self.recorder.restore(entries)
            self.last_upload_error = message
            log.warning("Threat sightings upload failed (%s); kept for the next one", message)
        return ok

    # ── running ──
    def start(self) -> None:
        self._stop.clear()
        log.info("Threat sightings: %d listed domain(s) and IP(s) loaded", len(self.list))
        if self._make_hub is not None:
            try:
                hub = self._make_hub()
                hub.add(dns_answer, self.on_dns)
                if hub.start():
                    self.hub = hub
                else:
                    log.warning("Threat sightings: no DNS capture (%s); connections are still checked", hub.error)
                    self.hub = hub          # kept for problems()
            except Exception as exc:  # noqa: BLE001 - connections still work without the capture
                log.warning("Threat sightings: DNS capture could not start (%s)", exc)
        for name, target in (("sightings-sync", self._sync_loop), ("sightings", self._loop)):
            thread = threading.Thread(target=target, daemon=True, name=name)
            thread.start()
            self._threads.append(thread)

    def _sync_loop(self) -> None:
        while not self._stop.is_set():
            if self.sync.due():
                done = self.sync.sync()
                if done:
                    log.info("Threat list updated (%s); %d value(s) in all", "; ".join(done), len(self.list))
            self._stop.wait(60)

    def _loop(self) -> None:
        while not self._stop.wait(TICK):
            try:
                if self._clock() - self._last_poll >= CONNECTION_POLL:
                    self._last_poll = self._clock()
                    if len(self.list):
                        self.poll_connections_once()
                if self.upload_due():
                    self.upload()
            except Exception as exc:  # noqa: BLE001 - one bad round must not stop sightings
                log.warning("Threat sightings round failed: %s", exc, exc_info=True)

    def stop(self, flush: bool = True) -> None:
        """Stop; `flush` sends what is waiting, on a daemon thread so stopping never waits for it."""
        self._stop.set()
        if self.hub is not None:
            self.hub.stop()
        if flush and self.recorder.pending():
            def last() -> None:
                try:
                    self.upload()
                except Exception as exc:  # noqa: BLE001
                    log.warning("Last threat sightings upload failed: %s", exc)
            threading.Thread(target=last, daemon=True, name="sightings-final").start()

    @property
    def running(self) -> bool:
        return any(t.is_alive() for t in self._threads) and not self._stop.is_set()

    def problems(self) -> list[str]:
        out = []
        if self.hub is not None and getattr(self.hub, "error", None):
            out.append(f"DNS capture: {self.hub.error}")
        if self.sync.last_error:
            out.append(f"threat list: {self.sync.last_error}")
        if self.last_upload_error:
            out.append(f"upload: {self.last_upload_error}")
        return out

    def status(self) -> dict[str, Any]:
        """For the agent window and the log."""
        return {
            "listed": len(self.list), "list_updated": self.list.feeds_at or None,
            "dns_capture": bool(self.hub is not None and not getattr(self.hub, "error", None)),
            "waiting": self.recorder.pending(), "sent": self.uploaded, "problems": self.problems(),
        }


class DnsAdapters:
    """Where sightings listens for DNS answers. Not passive listening's adapter: the answers
    arrive on whichever adapter reaches the DNS server (the lab VMs, 17 Nov: passive listened on
    the lab network while DNS went through the NAT adapter, and no lookup was seen). So every
    adapter where the capture can (Linux, Windows); on macOS, whose BPF device takes one, the
    adapter with the default route (a pinned one, EAGLEEYE_PASSIVE_INTERFACE, when there is none)."""

    REFRESH = 60.0

    def __init__(self, pinned: Optional[str] = None, platform: Optional[str] = None,
                 list_adapters: Optional[Callable[[], list[dict[str, Any]]]] = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        import sys
        self.platform = platform or sys.platform
        self.pinned = pinned or None
        self._list = list_adapters
        self._clock = clock
        self._at = -self.REFRESH
        self._name: Optional[str] = None
        self.index: Optional[int] = None
        self.label = "every adapter"

    def refresh(self) -> Optional[str]:
        from ..passive.capture import ANY, ANY_INDEX
        if self.platform != "darwin":
            self.index = ANY_INDEX
            return ANY
        if self._clock() - self._at >= self.REFRESH:          # ifconfig and netstat: not every 5 s
            self._at = self._clock()
            if self._list is None:
                from ..passive.adapters import list_adapters
                self._list = list_adapters
            try:
                found = [a for a in self._list() if a.get("gateway") and a.get("ips")]
            except Exception as exc:  # noqa: BLE001 - keep the last one
                log.debug("Could not list the adapters: %s", exc)
                found = None
            if found is not None:
                self._name = found[0]["name"] if found else self.pinned
                self.index = found[0].get("index") if found else None
                self.label = self._name or "no adapter with a default route"
        return self._name


def make_dns_hub(interface: Optional[str], backend: str = "auto") -> Optional[Callable[[], Any]]:
    """A factory for sightings' own capture (DNS answers only), or None on a system with no
    built-in capture."""
    from ..passive.capture import CaptureHub, make_source, resolve_backend
    name = resolve_backend(backend)
    if name == "npcap":
        return None

    def make() -> Any:
        return CaptureHub(make_source(name, dns_only=True), DnsAdapters(interface))
    return make
