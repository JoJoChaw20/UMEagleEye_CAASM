"""The standard-library HTTP client, against a real local HTTP server."""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from eagleeye import VERSION, httpclient
from eagleeye.api import AgentClient

seen: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        seen.append({"method": self.command, "path": self.path,
                     "headers": {k.lower(): v for k, v in self.headers.items()},   # names are case-insensitive
                     "body": self.rfile.read(length) if length else b""})

    def do_GET(self):
        self._record()
        if self.path.startswith("/json"):
            return self._reply(200, json.dumps({"hello": "world"}).encode())
        if self.path == "/missing":
            return self._reply(404, json.dumps({"detail": "Scan not found"}).encode())
        if self.path == "/broken":
            return self._reply(500, b"boom", "text/plain")
        if self.path == "/redirect":
            return self._reply(302, b"", extra={"Location": "/json?after=redirect"})
        if self.path == "/slow":
            time.sleep(2)
            return self._reply(200, b"{}")
        if self.path == "/big":
            return self._reply(200, b"x" * 300_000, "application/octet-stream")
        if self.path == "/text":
            return self._reply(200, b"not json", "text/plain")
        return self._reply(404, b"{}")

    def do_POST(self):
        self._record()
        if self.path.startswith("/redirect"):
            return self._reply(302, b"", extra={"Location": "http://elsewhere.example/steal"})
        if self.path.endswith("/heartbeat"):
            return self._reply(200, b'{"ok": true}')
        if self.path.endswith("/scans/ingest"):
            # first attempt fails with 503, the retry succeeds
            attempts = sum(1 for s in seen if s["path"].endswith("/scans/ingest"))
            if attempts == 1:
                return self._reply(503, b'{"detail": "busy"}')
            return self._reply(200, b'{"hosts_discovered": 3, "assets_upserted": 3}')
        return self._reply(200, b"{}")


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture(autouse=True)
def clear():
    seen.clear()


def test_get_json_sends_session_headers_and_params(server):
    s = httpclient.Session()
    s.headers["Authorization"] = "Bearer k"
    r = s.get(f"{server}/json", params={"a": "1 2"}, timeout=5)
    assert r.ok and r.status_code == 200 and r.json() == {"hello": "world"}
    assert seen[0]["path"] == "/json?a=1+2" and seen[0]["headers"]["authorization"] == "Bearer k"


def test_post_json_and_data(server):
    s = httpclient.Session()
    s.post(f"{server}/x", json={"a": 1}, timeout=5)
    s.post(f"{server}/x", data='{"b": 2}', timeout=5)
    assert json.loads(seen[0]["body"]) == {"a": 1} and seen[0]["headers"]["content-type"] == "application/json"
    assert json.loads(seen[1]["body"]) == {"b": 2}


def test_error_statuses_are_returned_not_raised(server):
    s = httpclient.Session()
    r = s.get(f"{server}/missing", timeout=5)
    assert (r.status_code, r.ok, r.json()["detail"]) == (404, False, "Scan not found")
    with pytest.raises(httpclient.HTTPError) as err:
        r.raise_for_status()
    assert err.value.response is r
    assert s.get(f"{server}/broken", timeout=5).status_code == 500


def test_non_json_body_raises_value_error(server):
    with pytest.raises(ValueError):
        httpclient.Session().get(f"{server}/text", timeout=5).json()


def test_redirects_followed_only_when_allowed(server):
    followed = httpclient.Session().get(f"{server}/redirect", timeout=5)
    assert followed.status_code == 200 and followed.url.endswith("/json?after=redirect")
    seen.clear()
    with pytest.raises(httpclient.HTTPError, match="redirected to /json"):
        httpclient.Session(follow_redirects=False).get(f"{server}/redirect", timeout=5)
    assert [s["path"] for s in seen] == ["/redirect"]           # the target was never requested


def test_timeout_and_refused_connection():
    with pytest.raises(httpclient.Timeout):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            httpclient.Session().get(f"http://127.0.0.1:{srv.server_address[1]}/slow", timeout=0.5)
        finally:
            srv.shutdown()
    with socket.socket() as sock:                # a port nobody listens on
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with pytest.raises(httpclient.ConnectionError):
        httpclient.Session().get(f"http://127.0.0.1:{port}/", timeout=10)   # Windows retries ~2 s first


def test_streamed_download(server):
    with httpclient.Session().get(f"{server}/big", stream=True, timeout=5) as r:
        assert r.headers.get("Content-Length") == "300000"
        chunks = list(r.iter_content(chunk_size=65536))
    assert sum(len(c) for c in chunks) == 300_000 and len(chunks) > 1


def test_only_http_and_https():
    with pytest.raises(httpclient.RequestException):
        httpclient.Session().get("file:///C:/Windows/win.ini")


def test_agent_client_end_to_end_with_retry(server):
    sleeps = []
    c = AgentClient(server, "secret", "agent-1", sleep=sleeps.append)
    assert c.send_heartbeat()
    hb = seen[0]
    assert hb["headers"]["x-agent-id"] == "agent-1" and hb["headers"]["user-agent"] == f"EagleEye-Agent/{VERSION}"
    result = c.ingest("active", [{"ip": "10.0.0.1"}], scan_id="s1")
    assert result.ok and result.hosts_discovered == 3 and sleeps == [2.0]   # 503 retried once


def test_api_client_does_not_follow_redirects(server):
    c = AgentClient(f"{server}/redirect?", "secret", "agent-1", sleep=lambda _: None)
    ok, message = c.check_connection()
    assert not ok and "redirected" in message
    assert all(s["path"].startswith("/redirect") for s in seen)     # the key went nowhere else


def test_unreachable_address_is_skipped_quickly_and_the_working_family_remembered(server, monkeypatch):
    port = int(server.rsplit(":", 1)[1])
    real = socket.getaddrinfo
    dead = ("10.255.255.1", 9)                       # a black-hole address: connect never completes

    def fake_getaddrinfo(host, p, *a, **k):
        if host == "dual.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", dead),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return real(host, p, *a, **k)

    monkeypatch.setattr(httpclient, "CONNECT_ATTEMPT_SECONDS", 0.5)
    monkeypatch.setattr(httpclient.socket, "getaddrinfo", fake_getaddrinfo)
    started = time.time()
    sock = httpclient._create_connection(("dual.example", 0), timeout=30)
    sock.close()
    assert time.time() - started < 5                 # not the OS connect timeout (~21 s)
    assert httpclient._preferred_family["dual.example"] == socket.AF_INET


def test_default_user_agent_identifies_the_agent(server):
    httpclient.Session().get(f"{server}/json", timeout=5)
    assert seen[0]["headers"]["user-agent"] == f"EagleEye-Agent/{VERSION}"
