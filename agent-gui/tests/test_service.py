from __future__ import annotations

import time

import pytest

from eagleeye.api import IngestResult
from eagleeye.config import Settings
from eagleeye.pipeline.record import HostRecord
from eagleeye.service import AgentService, throttled
from eagleeye.stages import scan_nmap, upload


class FakeClient:
    def __init__(self, pending=None, statuses=None, ingest_ok=True):
        self.pending = pending or []
        self.statuses = statuses or {}
        self.ingest_ok = ingest_ok
        self.failed, self.running, self.ingested = [], [], []

    def send_heartbeat(self):
        return True

    def get_pending_scans(self):
        return self.pending

    def mark_scan_running(self, scan_id):
        self.running.append(scan_id)

    def get_scan_status(self, scan_id):
        return self.statuses.get(scan_id, "running")

    def mark_scan_failed(self, scan_id, reason):
        self.failed.append((scan_id, reason))

    def reset_interrupted_scans(self):
        self.resets = getattr(self, "resets", 0) + 1
        return 0

    def start_local_scan(self, subnet, trigger):
        self.started = getattr(self, "started", []) + [(subnet, trigger)]
        if getattr(self, "start_error", None):
            return None, self.start_error
        return f"local-{len(self.started)}", None

    def ingest(self, scan_type, hosts, scan_id=None, network=None):
        self.ingested.append({"scan_type": scan_type, "hosts": hosts, "scan_id": scan_id, "network": network})
        return IngestResult(True, len(hosts), len(hosts)) if self.ingest_ok else IngestResult(False, error="server rejected the results (HTTP 400)")


@pytest.fixture(autouse=True)
def no_network_lookups(monkeypatch):
    monkeypatch.setattr(upload, "build_network_info", lambda subnet, hosts: {"subnet": subnet, "gateway_ip": None, "gateway_mac": None})


@pytest.fixture
def fake_scan(monkeypatch):
    """Active scans return two hosts instead of running Nmap."""
    def run(self, ctx):
        ctx.hosts = [HostRecord(ip="192.168.1.10", hostname="a"), HostRecord(ip="192.168.1.11")]
        ctx.summary["scanner"] = "nmap"
    monkeypatch.setattr(scan_nmap.NmapScanStage, "run", run)


def service(client, **settings):
    return AgentService(Settings(api_url="http://x", api_key="k", agent_id="a", **{"inventory": False, **settings}), client=client, on_event=lambda e: None)


def wait_idle(svc, timeout=5):
    deadline = time.time() + timeout
    while svc._active_future is not None and time.time() < deadline:
        svc._reap_active()
        time.sleep(0.01)
    assert svc._active_future is None


def test_active_scan_runs_and_uploads(fake_scan):
    client = FakeClient(pending=[{"scanId": "s1", "scanType": "active", "subnet": "192.168.1.0/24", "status": "pending"}])
    svc = service(client)
    svc.poll_once()
    wait_idle(svc)
    assert client.running == ["s1"]
    assert len(client.ingested) == 1
    sent = client.ingested[0]
    assert sent["scan_type"] == "active" and sent["scan_id"] == "s1"
    assert [h["ip"] for h in sent["hosts"]] == ["192.168.1.10", "192.168.1.11"]
    assert sent["network"]["subnet"] == "192.168.1.0/24"
    assert client.failed == []


def test_snake_case_pending_keys_are_accepted(fake_scan):
    client = FakeClient(pending=[{"scan_id": "s2", "scan_type": "active", "subnet": "10.0.0.0/24"}])
    svc = service(client)
    svc.poll_once()
    wait_idle(svc)
    assert client.ingested[0]["scan_id"] == "s2"


def test_failed_upload_marks_the_scan_failed_with_the_reason(fake_scan):
    client = FakeClient(pending=[{"scanId": "s3", "scanType": "active", "subnet": "10.0.0.0/24"}], ingest_ok=False)
    svc = service(client)
    svc.poll_once()
    wait_idle(svc)
    assert client.failed == [("s3", "Upload results failed: server rejected the results (HTTP 400)")]


def test_invalid_subnet_fails_the_scan_without_running_nmap(monkeypatch):
    monkeypatch.setattr(scan_nmap.deps, "find_nmap", lambda: "nmap")
    client = FakeClient(pending=[{"scanId": "s4", "scanType": "active", "subnet": "10.0.0.0/24; calc"}])
    svc = service(client)
    svc.poll_once()
    wait_idle(svc)
    assert client.ingested == []
    assert len(client.failed) == 1 and "invalid scan target" in client.failed[0][1]


class SbomClient(FakeClient):
    def __init__(self, start_error=None, **kw):
        super().__init__(**kw)
        self.start_error = start_error
        self.sbom_starts, self.sboms, self.cve_uploads = [], [], []

    def sbom_status(self, scan_id):
        return getattr(self, "sbom_statuses", {}).get(scan_id, "running")

    def start_sbom(self, trigger, scan_id=None):
        self.sbom_starts.append((trigger, scan_id))
        if self.start_error:
            return None, self.start_error
        return scan_id or "own-1", None

    def send_sbom(self, scan_id, document, scope):
        self.sboms.append((scan_id, document, scope))
        return True, "1 package(s) stored"

    def send_cve_findings(self, scan_id, findings):
        self.cve_uploads.append((scan_id, findings))
        return True, "alerts: 1 new"


@pytest.fixture
def fake_sbom(monkeypatch):
    """The SBOM stages produce one package and one finding instead of running Syft/Grype."""
    from eagleeye.stages import sbom as sbom_stages

    def build(self, ctx):
        ctx.summary.update(grype="grype", sbom={"specVersion": "1.6", "components": [{"type": "library", "name": "a", "version": "1"}]},
                           sbom_scope=["/apps"])

    def check(self, ctx):
        ctx.summary["findings"] = [{"cve_id": "CVE-1", "package_name": "a"}]
    monkeypatch.setattr(sbom_stages.SbomBuildStage, "run", build)
    monkeypatch.setattr(sbom_stages.CveCheckStage, "run", check)


def wait_sbom(svc, timeout=5):
    deadline = time.time() + timeout
    while svc.sbom_running and time.time() < deadline:
        time.sleep(0.01)
    svc._reap_sbom()


def test_dashboard_sbom_job_runs_on_its_own_worker_and_uploads_to_that_record(fake_sbom):
    client = SbomClient(pending=[{"scanId": "sb1", "scanType": "sbom", "subnet": "asset-id"}])
    svc = service(client)
    svc.poll_once()
    wait_sbom(svc)
    assert client.sbom_starts == [("dashboard", "sb1")]
    assert client.sboms[0][0] == "sb1" and client.sboms[0][2] == ["/apps"]
    assert client.cve_uploads == [("sb1", [{"cve_id": "CVE-1", "package_name": "a"}])]
    assert client.failed == [] and svc.history[0].pipeline == "sbom"


def test_sbom_job_is_declined_when_sbom_is_switched_off():
    client = SbomClient(pending=[{"scanId": "sb1", "scanType": "sbom"}])
    service(client, sbom=False).poll_once()
    assert client.failed[0][0] == "sb1" and "switched off" in client.failed[0][1]
    assert client.sbom_starts == []


def test_sbom_job_the_server_refuses_to_start_gets_the_reason(fake_sbom):
    client = SbomClient(start_error="This computer's inventory has not reached the server yet",
                        pending=[{"scanId": "sb1", "scanType": "sbom"}])
    svc = service(client)
    svc.poll_once()
    wait_sbom(svc)
    assert client.failed == [("sb1", "This computer's inventory has not reached the server yet")]
    assert client.sboms == []


def test_failed_sbom_run_marks_its_record_failed(monkeypatch):
    from eagleeye.stages import sbom as sbom_stages
    from eagleeye.pipeline.runner import StageError

    def build(self, ctx):
        raise StageError("Syft not installed on this computer.")
    monkeypatch.setattr(sbom_stages.SbomBuildStage, "run", build)
    client = SbomClient()
    svc = service(client)
    svc.request_sbom()
    svc.poll_once()
    wait_sbom(svc)
    assert client.sbom_starts == [("manual", None)]
    assert client.failed[0][0] == "own-1" and "Syft not installed" in client.failed[0][1]


def test_daily_sbom_waits_for_its_first_delay_and_needs_both_tools(fake_sbom, monkeypatch):
    from eagleeye import sbom as sbom_tools
    client = SbomClient()
    svc = service(client)
    svc.poll_once()
    assert client.sbom_starts == []                          # not before the first delay
    svc._next_sbom = 0
    monkeypatch.setattr(sbom_tools, "find_tool", lambda name: None)
    svc.poll_once()
    assert client.sbom_starts == [] and svc._next_sbom > time.time()   # tools missing: skipped until tomorrow
    svc._next_sbom = 0
    monkeypatch.setattr(sbom_tools, "find_tool", lambda name: name)
    svc.poll_once()
    wait_sbom(svc)
    assert client.sbom_starts == [("schedule", None)] and client.sboms[0][0] == "own-1"


def test_unknown_scan_type_is_declined():
    client = FakeClient(pending=[{"scanId": "u1", "scanType": "weird"}])
    service(client).poll_once()
    assert client.failed[0][0] == "u1" and "Unsupported scan type" in client.failed[0][1]


def test_passive_scan_fails_clearly_when_not_in_passive_mode():
    client = FakeClient(pending=[{"scanId": "p1", "scanType": "passive", "subnet": "arp-discovery"}])
    service(client).poll_once()
    assert client.failed[0][0] == "p1" and "passive mode" in client.failed[0][1]


def test_cancelled_scan_is_skipped(fake_scan):
    client = FakeClient(pending=[{"scanId": "c1", "scanType": "active", "status": "cancelled"}])
    svc = service(client)
    svc.poll_once()
    assert client.running == [] and client.ingested == [] and client.failed == []


def test_second_active_scan_waits_while_one_is_running(monkeypatch):
    release = []

    def slow_run(self, ctx):
        while not release:
            time.sleep(0.01)
        ctx.hosts = []
    monkeypatch.setattr(scan_nmap.NmapScanStage, "run", slow_run)

    client = FakeClient(pending=[
        {"scanId": "a1", "scanType": "active", "subnet": "10.0.0.0/24"},
        {"scanId": "a2", "scanType": "active", "subnet": "10.0.1.0/24"},
    ])
    svc = service(client)
    svc.poll_once()
    assert client.running == ["a1"]            # a2 stays pending for the next poll
    release.append(1)
    wait_idle(svc)


def test_cancellation_during_run_does_not_fail_or_upload(monkeypatch):
    def run(self, ctx):
        ctx.hosts = [HostRecord(ip="192.168.1.10")]
    monkeypatch.setattr(scan_nmap.NmapScanStage, "run", run)
    client = FakeClient(statuses={"x1": "cancelled"})
    svc = service(client)
    result = svc.run_active("x1", "192.168.1.0/24")
    assert result.status == "cancelled"
    assert client.ingested == [] and client.failed == []


class FakeArp:
    def __init__(self, seen):
        self.seen = seen

    def pending(self):
        return len(self.seen)

    def drain(self):
        out, self.seen = [HostRecord(ip=ip) for ip in self.seen], []
        return out


class FakeSuite:
    def __init__(self, seen):
        self.arp, self.mdns, self.dhcp = FakeArp(seen), None, None


def test_autonomous_flush_is_skipped_when_nothing_was_heard():
    events = []
    client = FakeClient()
    svc = AgentService(Settings(api_url="http://x", api_key="k", agent_id="a", passive=True, inventory=False),
                       client=client, on_event=events.append)
    svc.suite = FakeSuite([])
    svc._last_flush = 0
    svc.poll_once()
    assert events == [] and client.ingested == []


def test_autonomous_flush_uploads_without_a_scan_id():
    client = FakeClient()
    svc = service(client, passive=True)
    svc.suite = FakeSuite(["192.168.1.40"])
    svc._last_flush = 0
    svc.poll_once()
    assert len(client.ingested) == 1
    sent = client.ingested[0]
    assert sent["scan_type"] == "passive" and sent["scan_id"] is None
    assert [h["ip"] for h in sent["hosts"]] == ["192.168.1.40"]


def test_throttled_limits_calls():
    calls = []
    check = throttled(lambda: calls.append(1) or False, 60)
    for _ in range(50):
        check()
    assert len(calls) == 1


# ── scans started on this machine (GUI "Scan now" and local schedules) ──

def test_scan_now_request_creates_a_server_record_and_uploads_to_it(fake_scan):
    client = FakeClient()
    svc = service(client)
    svc.request_scan("192.168.1.0/24")
    svc.poll_once()
    wait_idle(svc)
    assert client.started == [("192.168.1.0/24", "manual")]
    assert client.ingested[0]["scan_id"] == "local-1"
    assert client.running == []                       # the record is created already running
    rec = svc.history[0]
    assert (rec.pipeline, rec.trigger, rec.status, rec.hosts) == ("active", "manual", "ok", 2)


def test_scan_now_with_a_bad_target_never_reaches_the_server():
    client = FakeClient()
    svc = service(client)
    svc.request_scan("10.0.0.0/8")
    svc.poll_once()
    assert getattr(client, "started", []) == [] and svc._active_future is None


def test_scan_now_refused_by_the_server_is_not_run(fake_scan):
    client = FakeClient()
    client.start_error = "the server did not start the scan (Another active scan from this agent is still running)"
    svc = service(client)
    svc.request_scan("192.168.1.0/24")
    svc.poll_once()
    assert svc._active_future is None and client.ingested == []


def test_inventory_request_runs_even_between_intervals(monkeypatch):
    calls = []
    client = FakeClient()
    svc = service(client, inventory=True)
    monkeypatch.setattr(svc, "run_inventory", lambda trigger="auto": calls.append(trigger))
    svc._last_inventory = time.time()                 # not due yet
    svc.request_inventory()
    svc.poll_once()
    deadline = time.time() + 5
    while not calls and time.time() < deadline:
        time.sleep(0.01)
    assert calls == ["manual"]


def test_inventory_request_is_ignored_when_inventory_is_off(monkeypatch):
    svc = service(FakeClient(), inventory=False)
    svc.request_inventory()
    svc.poll_once()
    assert svc._inventory_future is None


def _sched_service(client, tmp_path, **sched):
    raw = {"id": "s1", "subnet": "192.168.1.0/24", "mode": "interval", "hours": 1, **sched}
    svc = AgentService(Settings(api_url="http://x", api_key="k", agent_id="a", inventory=False, schedules=[raw]),
                       client=client, on_event=lambda e: None, state_path=tmp_path / "state.json")
    svc.schedules_enabled = True          # schedules are off by default for now; the logic is still tested
    return svc


def test_schedules_are_off_by_default(fake_scan, tmp_path):
    from datetime import datetime, timedelta
    client = FakeClient()
    svc = _sched_service(client, tmp_path)
    svc.schedules_enabled = False
    now = datetime(2026, 10, 11, 10, 0)
    svc._maybe_schedules(now)
    svc._maybe_schedules(now + timedelta(days=2))
    assert getattr(client, "started", []) == []


def test_new_schedule_does_not_fire_immediately_then_fires_when_due(fake_scan, tmp_path):
    from datetime import datetime, timedelta
    client = FakeClient()
    svc = _sched_service(client, tmp_path)
    now = datetime(2026, 10, 11, 10, 0)
    svc._maybe_schedules(now)
    assert getattr(client, "started", []) == []
    svc._maybe_schedules(now + timedelta(hours=1))
    wait_idle(svc)
    assert client.started == [("192.168.1.0/24", "schedule")]
    assert svc.schedule_state.last_runs["s1"] == now + timedelta(hours=1)
    assert svc.history[0].trigger == "schedule"


def test_unreachable_server_postpones_the_schedule_without_marking_it(tmp_path):
    from datetime import datetime, timedelta
    client = FakeClient()
    client.start_error = "could not reach the server: timeout"
    svc = _sched_service(client, tmp_path)
    now = datetime(2026, 10, 11, 10, 0)
    svc._maybe_schedules(now)
    svc._maybe_schedules(now + timedelta(hours=2))
    assert svc.schedule_state.last_runs["s1"] == now   # still due; retried later
    svc._maybe_schedules(now + timedelta(hours=2))     # inside the retry delay: no new attempt
    assert len(client.started) == 1


def test_schedule_waits_while_another_active_scan_runs(tmp_path):
    from datetime import datetime, timedelta
    client = FakeClient()
    svc = _sched_service(client, tmp_path)
    now = datetime(2026, 10, 11, 10, 0)
    svc._maybe_schedules(now)
    svc._active_future = object()                      # a dashboard scan is running
    svc._maybe_schedules(now + timedelta(hours=3))
    assert getattr(client, "started", []) == []


def test_requests_wake_the_polling_loop(fake_scan):
    client = FakeClient()
    svc = service(client, poll_interval=3600)
    import threading
    t = threading.Thread(target=svc.run_forever, daemon=True)
    t.start()
    time.sleep(0.2)                                    # first poll done; now waiting an hour
    svc.request_scan("192.168.1.0/24")
    deadline = time.time() + 5
    while not client.ingested and time.time() < deadline:
        time.sleep(0.02)
    svc.stop()
    t.join(timeout=5)
    assert client.ingested and not t.is_alive()


def test_start_tells_the_server_to_mark_interrupted_scans():
    client = FakeClient()
    svc = service(client)
    svc.start()
    svc.stop()
    assert client.resets == 1


def test_dashboard_cancel_stops_the_sbom_run_without_uploading(monkeypatch):
    from eagleeye.stages import sbom as sbom_stages
    from eagleeye.pipeline.runner import Cancelled

    def build(self, ctx):
        client.sbom_statuses = {"sb1": "cancelled"}
        if ctx.cancelled():
            raise Cancelled("the scan was cancelled")
    monkeypatch.setattr(sbom_stages.SbomBuildStage, "run", build)
    monkeypatch.setattr("eagleeye.service.throttled", lambda fn, interval: fn)
    client = SbomClient(pending=[{"scanId": "sb1", "scanType": "sbom"}])
    svc = service(client)
    svc.poll_once()
    wait_sbom(svc)
    assert client.sboms == [] and svc.history[0].status == "cancelled"
