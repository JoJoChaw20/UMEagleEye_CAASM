"""Install codes ("EE2."): one code for many computers, each exchanging it once for an agent of
its own (enrol.py, `service enrol`, `config init`, `run`). A local fake server answers
POST /enrolment/enrol like workers/src/routes/enrolment.ts; never the real credential store."""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from eagleeye import cli, serviceinstall
from eagleeye.config import ConfigError, Settings, load_settings
from eagleeye.enrol import (
    ConnectionCodeError, credentials_from_code, exchange_install_code, is_install_code, parse_install_code,
)

TOKEN = "ab" * 32


def code_for(url: str, token: str = TOKEN) -> str:
    return "EE2." + base64.urlsafe_b64encode(json.dumps({"u": url, "t": token}).encode()).decode().rstrip("=")


class NoKeychain:
    def available(self):
        return False

    def set(self, *_a):
        return False

    def get(self, *_a):
        return None


@pytest.fixture()
def server():
    calls = []
    state = {"next": 0, "refuse": None}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append((self.path, body))
            if state["refuse"]:
                status, answer = 403, {"detail": state["refuse"]}
            else:
                state["next"] += 1
                status, answer = 201, {"agent_id": f"00000000-0000-4000-8000-{state['next']:012d}", "api_key": f"key-{state['next']}"}
            data = json.dumps(answer).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}/api/v1", calls, state
    httpd.shutdown()


def test_an_install_code_is_read_and_checked():
    url, token = parse_install_code(f"  {code_for('https://api.example/api/v1/')}\n")
    assert (url, token) == ("https://api.example/api/v1", TOKEN)
    assert is_install_code('"EE2.xyz"') and not is_install_code("EE1.xyz")
    for bad in ("EE2.", "EE2.!!!", code_for("ftp://x"), code_for("https://x", "short")):
        with pytest.raises(ConnectionCodeError, match="install code"):
            parse_install_code(bad)


def test_each_computer_gets_its_own_agent_and_keeps_it(server):
    url, calls, state = server
    code = code_for(url)
    assert exchange_install_code(code, "LAB-WIN11", "host")[1:] == ("00000000-0000-4000-8000-000000000001", "key-1")
    assert calls == [("/api/v1/enrolment/enrol", {"token": TOKEN, "name": "LAB-WIN11", "kind": "host"})]
    # a reinstall with the credentials already saved for that server: nothing is registered
    have = Settings(api_url=url, agent_id="00000000-0000-4000-8000-000000000001", api_key="key-1")
    assert credentials_from_code(code, "LAB-WIN11", existing=have)[3] is False and len(calls) == 1
    # saved credentials for another server do not count
    other = Settings(api_url="https://elsewhere/api/v1", agent_id="x", api_key="y")
    assert credentials_from_code(code, "LAB-WIN11", existing=other)[3] is True and len(calls) == 2
    state["refuse"] = "This install code has expired. Ask your administrator for a new one."
    with pytest.raises(ConnectionCodeError, match="expired"):
        exchange_install_code(code, "PC-2")


def test_config_init_registers_once_and_other_commands_refuse(server, tmp_path, monkeypatch):
    url, calls, _state = server
    monkeypatch.setattr(cli, "Keychain", NoKeychain)
    monkeypatch.setenv("EAGLEEYE_AGENT_NAME", "PC-7")
    for var in ("EAGLEEYE_CONNECTION_CODE", "EAGLEEYE_API_KEY", "EAGLEEYE_AGENT_ID", "EAGLEEYE_API_URL"):
        monkeypatch.delenv(var, raising=False)
    cfg = tmp_path / "config.json"
    code = code_for(url)
    assert cli.main(["config", "init", "--config", str(cfg), "--connection-code", code]) == 0
    assert cli.main(["config", "init", "--config", str(cfg), "--connection-code", code]) == 0
    s = load_settings(cfg, env={})
    assert (s.api_url, s.agent_id, s.api_key) == (url, "00000000-0000-4000-8000-000000000001", "key-1")
    assert len(calls) == 1 and calls[0][1]["name"] == "PC-7"                 # the second init kept it
    with pytest.raises(ConfigError, match="registers this computer"):
        cli._settings_from(cli.build_parser().parse_args(["scan", "10.0.0.1", "--connection-code", code]))


def test_service_enrol_writes_the_service_settings(server, tmp_path, monkeypatch):
    from eagleeye.machine import MachineSecrets
    url, calls, _state = server
    target = tmp_path / "machine" / "config.json"
    monkeypatch.setattr(serviceinstall, "machine_config_path", lambda instance="": target)
    monkeypatch.setattr(serviceinstall, "MachineSecrets", lambda: MachineSecrets(tmp_path / "secrets.json", restrict=False))
    monkeypatch.setattr(serviceinstall, "secure", lambda *a, **k: None)
    monkeypatch.setattr(serviceinstall, "is_admin", lambda: True)
    monkeypatch.setenv("EAGLEEYE_AGENT_NAME", "SRV-9")
    (tmp_path / "code.txt").write_text(code_for(url) + "\n")
    assert cli.main(["service", "enrol", "--connection-code-file", str(tmp_path / "code.txt"), "--kind", "network"]) == 0
    s = load_settings(target, env={}, keychain=MachineSecrets(tmp_path / "secrets.json", restrict=False))
    assert (s.kind, s.agent_id, s.api_key) == ("network", "00000000-0000-4000-8000-000000000001", "key-1")
    assert calls[0][1] == {"token": TOKEN, "name": "SRV-9", "kind": "network"}
    assert "api_key" not in json.loads(target.read_text()) or not json.loads(target.read_text())["api_key"]
    # running it again (an upgrade, a second deployment) keeps the agent
    assert cli.main(["service", "enrol", "--connection-code-file", str(tmp_path / "code.txt")]) == 0
    assert len(calls) == 1
