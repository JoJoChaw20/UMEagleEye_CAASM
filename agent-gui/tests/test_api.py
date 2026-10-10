from __future__ import annotations

import json

import requests

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
            raise requests.HTTPError(f"{self.status_code}", response=self)


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
    c, session, sleeps = client(requests.ConnectionError("down"), requests.Timeout("slow"), FakeResponse(200, {"hosts_discovered": 1}))
    assert c.ingest("active", [], scan_id="s").ok
    assert len(session.calls) == 3 and sleeps == [2.0, 5.0]


def test_retries_5xx_then_gives_up_with_a_reason():
    c, session, sleeps = client(FakeResponse(502), FakeResponse(503), FakeResponse(500))
    result = c.ingest("active", [], scan_id="s")
    assert not result.ok and "could not reach the server" in result.error
    assert len(session.calls) == 3


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

    c2, _, _ = client(requests.ConnectionError("x"), requests.ConnectionError("x"), requests.ConnectionError("x"))
    assert c2.send_heartbeat() is False


def test_pending_scans_and_failures_are_tolerated():
    c, _, _ = client(FakeResponse(200, {"scans": [{"scanId": "a"}]}))
    assert c.get_pending_scans() == [{"scanId": "a"}]
    c2, _, _ = client(requests.ConnectionError("x"), requests.ConnectionError("x"), requests.ConnectionError("x"))
    assert c2.get_pending_scans() == []


def test_mark_failed_truncates_the_reason():
    c, session, _ = client(FakeResponse(200))
    c.mark_scan_failed("scan-1", "x" * 5000)
    body = json.loads(session.calls[0][2]["data"])
    assert body["scan_id"] == "scan-1" and body["agent_id"] == AGENT and len(body["reason"]) == 1000
