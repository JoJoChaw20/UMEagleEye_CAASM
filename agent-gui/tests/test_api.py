from __future__ import annotations

import json

from eagleeye import httpclient

from eagleeye import VERSION
from eagleeye.api import AgentClient

AGENT = "11111111-1111-4111-8111-111111111111"


class FakeResponse:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {}

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        return self._body

    def raise_for_status(self):
        if not self.ok:
            raise httpclient.HTTPError(f"{self.status_code}", response=self)


class FakeSession:
    """Replays queued responses/exceptions and records every request."""

    def __init__(self, *queue):
        self.queue = list(queue)
        self.calls = []
        self.headers = {}

    def _next(self):
        item = self.queue.pop(0) if self.queue else FakeResponse()
        if isinstance(item, Exception):
            raise item
        return item

    def request(self, method, url, timeout=None, **kwargs):
        self.calls.append((method, url, kwargs))
        return self._next()

    def get(self, url, timeout=None, **kw):
        self.calls.append(("GET", url, kw))
        return self._next()

    def post(self, url, timeout=None, **kw):
        self.calls.append(("POST", url, kw))
        return self._next()


def client(*queue):
    sleeps = []
    session = FakeSession(*queue)
    c = AgentClient("https://api.example/api/v1/", "secret-key", AGENT, session=session, sleep=sleeps.append)
    return c, session, sleeps


def test_headers_identify_the_agent():
    c, session, _ = client()
    assert session.headers["Authorization"] == "Bearer secret-key"
    assert session.headers["X-Agent-ID"] == AGENT
    assert session.headers["User-Agent"] == f"EagleEye-Agent/{VERSION}"
    assert c.api_url == "https://api.example/api/v1"            # trailing slash trimmed


def test_ingest_active_payload_shape():
    c, session, _ = client(FakeResponse(200, {"hosts_discovered": 2, "assets_upserted": 2}))
    hosts = [{"ip": "192.168.1.5", "hostname": None, "mac": None, "ports": [], "os": None}]
    result = c.ingest("active", hosts, scan_id="scan-1", network={"subnet": "192.168.1.0/24", "gateway_ip": None, "gateway_mac": None})
    assert result.ok and (result.hosts_discovered, result.assets_upserted) == (2, 2)
    method, url, kwargs = session.calls[0]
    assert (method, url) == ("POST", "https://api.example/api/v1/scans/ingest")
    body = json.loads(kwargs["data"])
    assert body == {
        "agent_id": AGENT, "scan_type": "active", "scan_id": "scan-1", "hosts": hosts,
        "network": {"subnet": "192.168.1.0/24", "gateway_ip": None, "gateway_mac": None},
    }


def test_ingest_passive_without_scan_id_omits_it():
    c, session, _ = client(FakeResponse(200, {}))
    c.ingest("passive", [{"ip": "1.2.3.4"}])
    body = json.loads(session.calls[0][2]["data"])
    assert "scan_id" not in body and "network" not in body and body["scan_type"] == "passive"


def test_retries_connection_errors_then_succeeds():
    c, session, sleeps = client(httpclient.ConnectionError("down"), httpclient.Timeout("slow"), FakeResponse(200, {"hosts_discovered": 1}))
    assert c.ingest("active", [], scan_id="s").ok
    assert len(session.calls) == 3 and sleeps == [2.0, 5.0]


def test_retries_5xx_then_gives_up_with_a_reason():
    c, session, sleeps = client(FakeResponse(502), FakeResponse(503), FakeResponse(500))
    result = c.ingest("active", [], scan_id="s")
    # The server answered, so this is a server error, not an unreachable server (27 Oct log).
    assert not result.ok and result.error == "server error (HTTP 500) after 3 tries"
    assert len(session.calls) == 3


def test_no_answer_on_every_try_says_unreachable():
    c, _, _ = client(httpclient.ConnectionError("down"), httpclient.ConnectionError("down"), httpclient.Timeout("slow"))
    result = c.ingest("active", [], scan_id="s")
    assert not result.ok and result.error == "could not reach the server: slow"


def test_4xx_is_not_retried_and_reports_the_server_detail():
    c, session, sleeps = client(FakeResponse(401, {"detail": "Invalid API key"}))
    result = c.ingest("active", [], scan_id="s")
    assert not result.ok and "Invalid API key" in result.error
    assert len(session.calls) == 1 and sleeps == []


def test_heartbeat_payload_and_failure(monkeypatch):
    monkeypatch.setattr("eagleeye.api.local_ip", lambda: "192.168.1.20")
    monkeypatch.setattr("eagleeye.api.default_gateway", lambda: "192.168.1.1")
    c, session, _ = client(FakeResponse(200))
    assert c.send_heartbeat()
    method, url, kwargs = session.calls[0]
    assert url.endswith(f"/agents/{AGENT}/heartbeat")
    assert json.loads(kwargs["data"]) == {"version": VERSION, "gateway_ip": "192.168.1.20", "default_gateway": "192.168.1.1"}

    c2, _, _ = client(httpclient.ConnectionError("x"), httpclient.ConnectionError("x"), httpclient.ConnectionError("x"))
    assert c2.send_heartbeat() is False


def test_heartbeat_answer_carries_the_local_scan_policy(monkeypatch):
    monkeypatch.setattr("eagleeye.api.local_ip", lambda: "192.168.1.20")
    monkeypatch.setattr("eagleeye.api.default_gateway", lambda: None)
    c, _, _ = client(FakeResponse(200, {"ok": True, "policy": {"local_scans": False}}),
                     FakeResponse(200, {"ok": True}), FakeResponse(200, {"ok": True, "policy": {"local_scans": True}}))
    assert c.local_scans_allowed is True                   # until a server says otherwise
    assert c.send_heartbeat() and c.local_scans_allowed is False
    assert c.send_heartbeat() and c.local_scans_allowed is False   # an older server: unchanged
    assert c.send_heartbeat() and c.local_scans_allowed is True


def test_pending_scans_and_failures_are_tolerated():
    c, _, _ = client(FakeResponse(200, {"scans": [{"scanId": "a"}]}))
    assert c.get_pending_scans() == [{"scanId": "a"}]
    c2, _, _ = client(httpclient.ConnectionError("x"), httpclient.ConnectionError("x"), httpclient.ConnectionError("x"))
    assert c2.get_pending_scans() == []


def test_mark_failed_truncates_the_reason():
    c, session, _ = client(FakeResponse(200))
    c.mark_scan_failed("scan-1", "x" * 5000)
    body = json.loads(session.calls[0][2]["data"])
    assert body["scan_id"] == "scan-1" and body["agent_id"] == AGENT and len(body["reason"]) == 1000


def test_start_sbom_marks_the_dashboard_job_or_creates_one():
    c, session, _ = client(FakeResponse(200, {"scan_id": "sb1"}), FakeResponse(201, {"scan_id": "own"}))
    assert c.start_sbom("dashboard", "sb1") == ("sb1", None)
    assert c.start_sbom("schedule", mode="quick") == ("own", None)
    (m1, u1, k1), (_, _, k2) = session.calls
    assert (m1, u1) == ("POST", "https://api.example/api/v1/sboms/agent-start")
    assert json.loads(k1["data"]) == {"trigger": "dashboard", "scan_id": "sb1", "mode": "full"}
    assert json.loads(k2["data"]) == {"trigger": "schedule", "mode": "quick"}


def test_start_sbom_refused_returns_the_servers_reason():
    c, _, _ = client(FakeResponse(409, {"detail": "inventory first"}))
    assert c.start_sbom("schedule") == (None, "inventory first")


def test_sbom_and_findings_go_to_their_endpoints():
    c, session, _ = client(FakeResponse(201, {"dependencies_inserted": 3}),
                           FakeResponse(201, {"events_created": 2, "events_updated": 1, "events_resolved": 0, "kev_matches": 1}))
    assert c.send_sbom("sb1", {"components": []}, ["/apps"]) == (True, "3 package(s) stored")
    ok, detail = c.send_cve_findings("sb1", [])
    assert ok and "2 new" in detail and "1 on CISA KEV" in detail
    (_, u1, k1), (_, u2, k2) = session.calls
    assert u1.endswith("/sboms/ingest") and json.loads(k1["data"])["scope"] == ["/apps"]
    assert u2.endswith("/sboms/ingest-cve") and json.loads(k2["data"]) == {"agent_id": AGENT, "scan_id": "sb1", "findings": [], "total_findings": 0}


def test_a_large_report_sends_the_top_findings_and_every_key():
    c, session, _ = client(FakeResponse(201, {"events_created": 2, "findings_dropped": 1}))
    findings = [{"cve_id": f"CVE-{i}", "package_name": "p", "epss": i / 10, "cvss_base_score": 5.0} for i in range(3)]
    ok, detail = c.send_cve_findings("sb1", findings, max_upload=2)
    body = json.loads(session.calls[0][2]["data"])
    assert [f["cve_id"] for f in body["findings"]] == ["CVE-2", "CVE-1"]
    assert body["total_findings"] == 3 and body["present_keys"] == ["CVE-0::p", "CVE-1::p", "CVE-2::p"]
    assert ok and "1 lower-priority" in detail


# `route print -4 0.0.0.0` on a PC with Wi-Fi and the GNS3 KM-TEST loopback, which also
# has a default gateway. Windows lists the two default routes in no fixed order.
ROUTES_WIFI = "          0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.139     55\n"
ROUTES_LOOP = "          0.0.0.0          0.0.0.0      142.19.0.11       142.19.0.1    281\n"
ROUTES_HEAD = "Active Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n"


def test_default_gateway_is_the_one_on_the_adapter_in_use_whatever_the_order():
    from eagleeye.netinfo import parse_default_gateway

    for table in (ROUTES_HEAD + ROUTES_WIFI + ROUTES_LOOP, ROUTES_HEAD + ROUTES_LOOP + ROUTES_WIFI):
        assert parse_default_gateway("Windows", table, "192.168.0.139") == "192.168.0.1"
        assert parse_default_gateway("Windows", table) == "192.168.0.1"          # lowest metric
    # The adapter in use wins even over a lower metric (e.g. a VPN that is not routing).
    vpn = ROUTES_HEAD + ROUTES_WIFI + "          0.0.0.0          0.0.0.0       10.8.0.1       10.8.0.5      5\n"
    assert parse_default_gateway("Windows", vpn, "192.168.0.139") == "192.168.0.1"
    on_link = ROUTES_HEAD + "          0.0.0.0          0.0.0.0         On-link       10.8.0.5      5\n" + ROUTES_WIFI
    assert parse_default_gateway("Windows", on_link) == "192.168.0.1"
    assert parse_default_gateway("Windows", ROUTES_HEAD) is None
