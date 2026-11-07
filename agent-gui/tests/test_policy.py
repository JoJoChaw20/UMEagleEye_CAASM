"""Settings an administrator sets from the dashboard (policy.py, 2.4.0): what the
heartbeat reports and receives, and how the service applies them between jobs."""

from __future__ import annotations

import json
from concurrent.futures import Future

from eagleeye import policy
from eagleeye.config import Settings
from eagleeye.service import AgentService
from tests.test_api import FakeResponse, client


def settings(**kw):
    return Settings(api_url="http://x", api_key="k", agent_id="a", **{"inventory": False, **kw})


def test_managed_values_are_checked_and_applied_over_a_copy():
    local = settings(passive=False, scan_ports="base", sbom_interval=86400)
    managed = policy.clean({"passive": True, "scan_ports": "wide", "sbom_interval": 60, "scanner": False, "x": 1})
    assert managed == {"passive": True, "scan_ports": "wide"}             # bad interval and server-only keys dropped
    applied = policy.apply(local, managed)
    assert (applied.passive, applied.scan_ports, applied.sbom_interval) == (True, "wide", 86400)
    assert (local.passive, local.scan_ports) == (False, "base")           # this computer's own choice is kept
    assert policy.clean(None) == {} and policy.clean(["passive"]) == {}


def test_the_report_has_this_computers_own_values():
    report = policy.local_report(settings(passive=True, scan_engine="nmap", inventory_interval=7200))
    assert report["passive"] is True and report["scan_engine"] == "auto" and report["inventory_interval"] == 7200
    assert set(report) == set(policy.FIELDS)


def test_the_store_survives_a_restart_and_a_broken_file(tmp_path):
    store = policy.PolicyStore(tmp_path / "policy.json")
    assert store.load() == (None, {})
    store.save("0a1b2c3d", {"passive": True})
    assert policy.PolicyStore(tmp_path / "policy.json").load() == ("0a1b2c3d", {"passive": True})
    (tmp_path / "policy.json").write_text("{not json")
    assert store.load() == (None, {})
    assert policy.PolicyStore(None).load() == (None, {})                 # memory only


def test_policy_path_is_per_instance(tmp_path):
    assert policy.policy_path({"EAGLEEYE_CONFIG": str(tmp_path / "config-production.json")}).name == "policy-production.json"
    assert policy.policy_path({"EAGLEEYE_CONFIG": str(tmp_path / "config.json")}).name == "policy.json"


def test_heartbeat_sends_the_report_and_reads_the_managed_settings(monkeypatch):
    monkeypatch.setattr("eagleeye.api.local_ip", lambda: "192.168.0.139")
    monkeypatch.setattr("eagleeye.api.default_gateway", lambda: None)
    answer = {"ok": True, "policy": {"local_scans": False, "managed": {"passive": True}, "version": "0a1b2c3d"}}
    c, session, _ = client(FakeResponse(200, answer), FakeResponse(200, {"ok": True, "policy": {"local_scans": True}}))
    assert c.send_heartbeat({"kind": "host", "settings": {"passive": False}, "policy_version": "ffffffff"})
    sent = json.loads(session.calls[0][2]["data"])
    assert sent["kind"] == "host" and sent["settings"] == {"passive": False} and sent["policy_version"] == "ffffffff"
    assert (c.policy_managed, c.policy_version, c.local_scans_allowed) == ({"passive": True}, "0a1b2c3d", False)
    assert c.send_heartbeat()                                           # a server before 2.4.0: kept as it was
    assert (c.policy_managed, c.policy_version) == ({"passive": True}, "0a1b2c3d")


class Client:
    def __init__(self):
        self.policy_managed, self.policy_version, self.reports = {}, None, []

    def send_heartbeat(self, report=None):
        self.reports.append(report)
        return True

    def get_pending_scans(self):
        return []


def make(tmp_path, **kw):
    c = Client()
    svc = AgentService(settings(**kw), client=c, on_event=lambda e: None, policy_path=tmp_path / "policy.json")
    svc._maybe_sbom = svc._maybe_schedules = svc._maybe_flush_passive = lambda: None
    return svc, c


def test_new_settings_are_applied_between_jobs_and_kept(tmp_path):
    svc, c = make(tmp_path, scan_ports="base", sbom=False)
    c.policy_managed, c.policy_version = {"scan_ports": "wide", "sbom": True}, "0a1b2c3d"
    busy: Future = Future()
    svc._active_future = busy                                           # a scan is running
    svc.poll_once()
    assert svc.settings.scan_ports == "base" and svc.applied_policy_version is None
    busy.set_result(None)
    svc.poll_once()
    assert (svc.settings.scan_ports, svc.settings.sbom, svc.applied_policy_version) == ("wide", True, "0a1b2c3d")
    assert svc.local_settings.scan_ports == "base"                     # this computer's own value is kept
    # a restart applies them before any heartbeat
    again, _ = make(tmp_path, scan_ports="base")
    assert again.settings.scan_ports == "wide" and again.applied_policy_version == "0a1b2c3d"
    # the admin clears them: this computer's own values are back
    c.policy_managed, c.policy_version = {}, "811c9dc5"
    svc.poll_once()
    assert (svc.settings.scan_ports, svc.settings.sbom) == ("base", False)


def test_the_heartbeat_reports_what_the_agent_runs(tmp_path):
    svc, c = make(tmp_path, passive=True)
    svc._capabilities = {"os": "win32"}
    svc._heartbeat()
    assert c.reports[-1] == {"kind": "host", "settings": policy.local_report(svc.local_settings),
                             "capabilities": {"os": "win32"}}
    c.policy_managed, c.policy_version = {"passive": False}, "0a1b2c3d"
    svc._maybe_apply_policy()
    svc._heartbeat()
    assert c.reports[-1]["policy_version"] == "0a1b2c3d"
    assert c.reports[-1]["settings"]["passive"] is True                # its own value, not the managed one


def test_passive_listening_follows_the_administrator(tmp_path, monkeypatch):
    started, stopped = [], []

    class Suite:
        def __init__(self, interface, key, backend="npcap"):
            self.backend, self.arp = backend, None

        def start(self):
            started.append(self.backend)
            return True

        def stop(self):
            stopped.append(self.backend)

    monkeypatch.setattr("eagleeye.service.PassiveSuite", Suite)
    svc, c = make(tmp_path, passive=False)
    c.policy_managed, c.policy_version = {"passive": True, "passive_backend": "native"}, "0a1b2c3d"
    svc._maybe_apply_policy()
    assert started == ["native"] and svc.suite is not None
    c.policy_managed, c.policy_version = {"passive": True, "passive_backend": "native", "passive_interval": 60}, "1a1b2c3d"
    svc._maybe_apply_policy()
    assert started == ["native"] and stopped == []                     # an interval change needs no restart
    assert svc.settings.passive_interval == 60
    c.policy_managed, c.policy_version = {"passive": False}, "2a1b2c3d"
    svc._maybe_apply_policy()
    assert stopped == ["native"] and svc.suite is None
