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
    return AgentService(Settings(api_url="http://x", api_key="k", agent_id="a", **settings), client=client, on_event=lambda e: None)


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


def test_sbom_scan_is_declined_with_a_visible_reason():
    client = FakeClient(pending=[{"scanId": "sb1", "scanType": "sbom", "subnet": "asset-id"}])
    service(client).poll_once()
    assert len(client.failed) == 1
    assert client.failed[0][0] == "sb1" and "SBOM" in client.failed[0][1]
    assert client.running == []


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


def test_throttled_limits_calls():
    calls = []
    check = throttled(lambda: calls.append(1) or False, 60)
    for _ in range(50):
        check()
    assert len(calls) == 1
