"""The network agent as a service (netagent/service.py, upload.py): its settings, what it
uploads from a crawl, and its loop: heartbeat, the administrator's settings, crawls on time
and on request. The GNS3 lab recordings answer instead of the network; a fake client
stands in for the server."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eagleeye import policy
from eagleeye.api import IngestResult
from eagleeye.config import ConfigError, Settings, load_settings
from eagleeye.netagent.crawl import crawl, parse_ranges
from eagleeye.netagent.recorded import RecordedSession
from eagleeye.netagent.service import NetworkAgentService, credentials_of
from eagleeye.netagent.upload import ingest_hosts, topology_payload

LAB = Path(__file__).parent / "fixtures" / "gns3"
SEEDS, RANGES = ["10.99.0.1"], ["10.10.0.0/16", "10.99.0.0/24"]
# The topology upload of the lab crawl, also read by the server's test of its schema
# (workers/src/lib/networkTopology.test.ts): the two sides agree on the format.
CONTRACT = LAB / "topology-upload.json"


def lab_session(address):
    return RecordedSession.from_dir(LAB, address)


def lab_result():
    return crawl(SEEDS, lab_session, parse_ranges(RANGES))


def settings(**kw):
    base = dict(api_url="http://x", api_key="k", agent_id="a", kind="network", network_seeds=SEEDS,
                network_ranges=RANGES, snmp_user="eagleeye", snmp_auth_key="EagleEyeAuth1", snmp_priv_key="EagleEyePriv1")
    return Settings(**{**base, **kw})


# ── settings ──
def test_lists_come_from_the_file_and_from_variables(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"kind": "network", "network_seeds": ["10.99.0.1"], "network_depth": 2}))
    s = load_settings(cfg, env={"EAGLEEYE_NETWORK_RANGES": "10.10.0.0/16, 10.99.0.0/24", "EAGLEEYE_SNMP_VERSION": "2c"})
    assert (s.kind, s.network_seeds, s.network_ranges, s.network_depth, s.snmp_version) == \
        ("network", ["10.99.0.1"], ["10.10.0.0/16", "10.99.0.0/24"], 2, "2c")
    assert Settings(kind="router").problems()[-1] == "kind must be host or network"
    cfg.write_text(json.dumps({"network_seeds": [1, 2]}))
    with pytest.raises(ConfigError, match="network_seeds"):
        load_settings(cfg, env={})
    assert "snmp_community" in Settings(snmp_community="LabRO").redacted() and \
        Settings(snmp_community="LabRO").redacted()["snmp_community"] == "****abRO"


def test_the_network_settings_are_checked():
    managed = policy.clean({"network_seeds": ["10.99.0.1"], "network_ranges": ["10.0.0.0/8"], "network_depth": 9,
                            "passive": True, "network_interval": 900}, "network")
    assert managed == {"network_seeds": ["10.99.0.1"], "network_ranges": ["10.0.0.0/8"], "network_interval": 900}
    assert policy.clean({"network_seeds": ["10.99.0"]}, "network") == {}
    assert policy.clean({"network_ranges": ["10.0.0.1"]}, "network") == {}       # a range needs its /bits
    assert policy.clean({"network_seeds": ["10.0.0.1"] * 17}, "network") == {}
    assert policy.clean({"network_seeds": ["10.99.0.1"]}) == {}                  # not a host agent's setting
    assert set(policy.local_report(settings(), "network")) == set(policy.NETWORK_FIELDS)
    assert credentials_of(settings(snmp_priv_protocol="none")).level == "authNoPriv"


# ── the uploads ──
def test_each_polled_device_is_one_host_with_its_snmp_facts():
    hosts = ingest_hosts(lab_result(), vendor=lambda mac: "Private" if mac and mac.startswith("00:50:79") else None)
    by_ip = {h["ip"]: h for h in hosts}
    r1 = by_ip["10.99.0.1"]
    assert (r1["mac"], r1["hostname"], r1["snmp_sysname"], r1["os"]["name"]) == \
        ("0C:59:A9:EF:00:00", "R1", "R1.lab.local", "Cisco IOS 15.9(3)M12")
    assert "Gi0/1.10" in r1["snmp_interfaces"] and r1["snmp_sysdescr"].startswith("Cisco IOS Software")
    assert by_ip["10.10.99.3"]["mac"] == "0C:7C:50:61:80:63"                     # SW2's Vlan99
    # R1's other four addresses are not separate devices; the PCs and the VM are
    assert not {"10.10.1.1", "10.10.10.1", "10.10.20.1", "10.10.99.1"} & set(by_ip)
    assert sorted(by_ip) == sorted(["10.99.0.1", "10.10.99.2", "10.10.99.3", "10.10.1.41", "10.10.10.11",
                                    "10.10.10.12", "10.10.20.21", "10.10.20.22", "10.99.0.10"])
    assert by_ip["10.10.1.41"]["mac_vendor"] == "Private" and "mac_vendor" not in by_ip["10.99.0.10"]


def test_the_topology_upload_matches_the_contract():
    payload = topology_payload(lab_result(), "4f7c6a2e-0000-4000-8000-000000000001")
    payload["stats"]["seconds"] = 0.0                                            # timing varies
    assert [d["label"] for d in payload["devices"]] == ["R1", "SW1", "SW2"]
    assert payload["links"][0] == {"a": {"device": "R1", "port": "Gi0/1"}, "b": {"device": "SW1", "port": "Gi0/0"},
                                   "protocols": ["cdp", "lldp"]}
    pcd = next(h for h in payload["hosts"] if h["ip"] == "10.10.1.41")
    assert pcd["location"] == {"switch": "SW2", "port": "Gi0/3", "vlan": 1, "ambiguous": False}
    assert json.loads(json.dumps(payload)) == payload                             # plain JSON
    # Keep the contract file the server's test reads in step with what the agent sends.
    if not CONTRACT.exists() or json.loads(CONTRACT.read_text(encoding="utf-8")) != payload:
        CONTRACT.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")
        pytest.fail(f"{CONTRACT.name} was out of date and has been rewritten; run the tests again "
                    "(and `npm test` in workers/)")


# ── the loop ──
class FakeClient:
    def __init__(self):
        self.reports, self.ingests, self.topologies, self.failed, self.running = [], [], [], [], []
        self.policy_managed, self.policy_version = {}, None
        self.jobs_in_heartbeat, self.jobs = True, []

    def send_heartbeat(self, report=None):
        self.reports.append(report)
        return True

    def has_jobs(self):
        return bool(self.jobs)

    def take_jobs(self):
        jobs, self.jobs = self.jobs, []
        return jobs

    def ingest(self, scan_type, hosts, scan_id=None, network=None):
        self.ingests.append((scan_type, len(hosts), scan_id))
        return IngestResult(True, len(hosts), len(hosts), scan_id=scan_id or "auto-record")

    def send_topology(self, topology):
        self.topologies.append(topology)
        return True, "3 of 3 device(s) matched"

    def mark_scan_failed(self, scan_id, reason):
        self.failed.append((scan_id, reason))

    def mark_scan_running(self, scan_id):
        self.running.append(scan_id)


VM = {"ip": "10.99.0.20", "mac": "00:0c:29:aa:bb:cc", "hostname": "netvm"}


def make(tmp_path, now, whoami=lambda seed: VM, **kw):
    client = FakeClient()
    svc = NetworkAgentService(settings(**kw), client=client, policy_path=tmp_path / "policy.json",
                              state_path=tmp_path / "state.json", open_session=lab_session, clock=lambda: now[0],
                              whoami=whoami)
    return svc, client


def test_the_topology_upload_says_which_machine_it_runs_on(tmp_path):
    now, asked = [10_000.0], []

    def whoami(router):
        asked.append(router)
        return VM
    svc, client = make(tmp_path, now, whoami=whoami)
    svc.poll_once()
    assert client.topologies[-1]["self"] == VM
    assert asked == ["10.99.0.1"]                                                # toward the router that answered
    svc._heartbeat()
    assert "self" not in client.reports[-1]                                      # the heartbeat does not say it


def test_a_failed_lookup_only_leaves_self_out(tmp_path):
    now = [10_000.0]

    def broken(router):
        raise OSError("no route")
    svc, client = make(tmp_path, now, whoami=broken)
    svc.poll_once()
    assert "self" not in client.topologies[-1] and len(client.topologies[-1]["links"]) == 2


def test_it_crawls_on_time_and_uploads_both_parts(tmp_path):
    now = [10_000.0]
    svc, client = make(tmp_path, now)
    svc._heartbeat()
    report = client.reports[-1]
    assert report["kind"] == "network" and set(report["settings"]) == set(policy.NETWORK_FIELDS)
    assert report["capabilities"]["snmp_ready"] is True
    svc.poll_once()                                                              # never crawled: crawl now
    assert client.ingests == [("snmp", 9, None)]
    assert client.topologies[-1]["scan_id"] == "auto-record" and len(client.topologies[-1]["links"]) == 2
    now[0] += 600
    svc.poll_once()
    assert len(client.ingests) == 1                                              # not due for 15 minutes
    now[0] += 301
    svc.poll_once()
    assert len(client.ingests) == 2 and svc.history[-1].status == "completed"


def test_the_dashboard_job_and_settings(tmp_path):
    now = [10_000.0]
    svc, client = make(tmp_path, now, network_seeds=[])
    svc.poll_once()
    assert client.ingests == []                                                  # no seeds: nothing to do
    client.jobs = [{"scanId": "job-1", "scanType": "snmp"}]
    svc.poll_once()
    assert client.failed == [("job-1", "no seed devices are set (dashboard: Agents, this agent's settings)")]
    client.policy_managed, client.policy_version = {"network_seeds": ["10.99.0.1"], "network_depth": 1}, "0a1b2c3d"
    client.jobs = [{"scanId": "job-2", "scanType": "snmp"}, {"scanId": "job-3", "scanType": "active"}]
    svc.poll_once()
    assert svc.settings.network_seeds == ["10.99.0.1"] and svc.local_settings.network_seeds == []
    assert client.running == ["job-2"] and client.ingests[0] == ("snmp", 9, "job-2")
    assert [d["label"] for d in client.topologies[0]["devices"]] == ["R1", "SW1"]   # depth 1: SW2 is an address
    assert client.failed[-1] == ("job-3", "A network agent does not run active jobs")
    again = NetworkAgentService(settings(network_seeds=[]), client=FakeClient(), policy_path=tmp_path / "policy.json",
                                state_path=tmp_path / "state.json")
    assert again.settings.network_seeds == ["10.99.0.1"]                         # kept across a restart


def test_failures_are_reported_with_a_reason(tmp_path):
    now = [10_000.0]
    svc, client = make(tmp_path, now, network_seeds=["10.10.99.9"])
    client.jobs = [{"scanId": "job-1", "scanType": "snmp"}]
    svc.poll_once()
    assert client.failed == [("job-1", "no seed device answered: no answer from 10.10.99.9")]
    svc, client = make(tmp_path, now, network_poll=False)
    client.jobs = [{"scanId": "job-2", "scanType": "snmp"}]
    svc.poll_once()
    assert client.failed == [("job-2", "This network agent's Collector role is off")]
    now[0] += 100_000
    assert not svc._due()                                                        # never on time either
    no_creds = NetworkAgentService(settings(snmp_auth_key=""), client=FakeClient(), state_path=tmp_path / "s2.json")
    no_creds.client.jobs = [{"scanId": "job-4", "scanType": "snmp"}]
    no_creds.poll_once()
    assert no_creds.client.failed[0][1].startswith("SNMP credentials on the agent: the SNMPv3 authentication password")
    assert no_creds._report()["capabilities"]["snmp_ready"] is False


def test_netpoll_upload_talks_to_the_server_like_the_agent(tmp_path, capsys):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from eagleeye.cli import main

    calls = []

    class Server(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - http.server's name
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
            calls.append((self.path, self.headers["X-Agent-ID"], body))
            answers = {
                "/api/v1/scans/ingest": {"scan_id": "rec-1", "hosts_discovered": len(body.get("hosts", [])), "assets_upserted": 9},
                "/api/v1/network/topology": {"devices": 3, "devices_matched": 3, "links": 2, "located_on_ports": 1},
            }
            data = json.dumps(answers.get(self.path, {"ok": True, "policy": {"local_scans": False}, "scans": []})).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cfg = tmp_path / "netagent.json"
        cfg.write_text(json.dumps({"api_url": f"http://127.0.0.1:{server.server_port}/api/v1", "api_key": "test-key",
                                   "agent_id": "11111111-2222-4333-8444-555555555555"}))
        code = main(["netpoll", "--seed", "10.99.0.1", "--allow", "10.10.0.0/16", "--allow", "10.99.0.0/24",
                     "--replay", str(LAB), "--upload", "--config", str(cfg)])
    finally:
        server.shutdown()
    assert code == 0
    paths = [p for p, _a, _b in calls]
    assert paths == ["/api/v1/agents/11111111-2222-4333-8444-555555555555/heartbeat", "/api/v1/scans/ingest",
                     "/api/v1/network/topology"]
    heartbeat, ingest, topology = (b for _p, _a, b in calls)
    assert heartbeat["kind"] == "network" and heartbeat["settings"]["network_seeds"] == ["10.99.0.1"]
    assert ingest["scan_type"] == "snmp" and len(ingest["hosts"]) == 9 and "scan_id" not in ingest
    assert topology["scan_id"] == "rec-1" and len(topology["links"]) == 2
    assert "Upload: completed; 3 of 3 device(s) matched, 2 link(s), 1 device(s) on switch ports" in capsys.readouterr().out


def test_the_service_runs_the_network_agent_for_its_kind(tmp_path, monkeypatch):
    from eagleeye.netagent.service import NetworkAgentService
    from eagleeye.service import AgentService
    from eagleeye.servicehost import ServiceHost
    monkeypatch.setenv("EAGLEEYE_CONFIG", str(tmp_path / "config.json"))
    assert isinstance(ServiceHost._agent_service(settings()), NetworkAgentService)
    assert isinstance(ServiceHost._agent_service(settings(kind="host", inventory=False, sbom=False)), AgentService)


def test_settings_from_files_and_the_health_check(tmp_path):
    from eagleeye.config import env_value
    from eagleeye.netagent.health import check
    (tmp_path / "auth").write_text("EagleEyeAuth1\n")
    env = {"EAGLEEYE_SNMP_AUTH_KEY_FILE": str(tmp_path / "auth"), "EAGLEEYE_KIND": "network"}
    assert load_settings(tmp_path / "none.json", env=env).snmp_auth_key == "EagleEyeAuth1"
    assert env_value("EAGLEEYE_SNMP_AUTH_KEY", {"EAGLEEYE_SNMP_AUTH_KEY": "direct", **env}) == "direct"
    with pytest.raises(ConfigError, match="_FILE"):
        load_settings(tmp_path / "none.json", env={"EAGLEEYE_SNMP_AUTH_KEY_FILE": str(tmp_path / "missing")})

    now = [10_000.0]
    svc, client = make(tmp_path, now)
    assert check(svc.status_path, now=now[0])[0] is False                                           # nothing yet
    svc._heartbeat()
    assert check(svc.status_path, now=now[0] + 60) == (True, "ok")
    assert check(svc.status_path, now=now[0] + 200)[0] is False                                     # no heartbeat since
    client.send_heartbeat = lambda report=None: False
    svc._heartbeat()
    assert check(svc.status_path, now=now[0]) == (False, "the last heartbeat did not reach the server")


def test_config_init_sets_up_a_network_agent(tmp_path, monkeypatch):
    import base64
    import io

    from eagleeye import cli

    class NoKeychain:                           # never the real credential store in tests
        def available(self):
            return False

        def set(self, *_a):
            return False

        def get(self, *_a):
            return None

    asked = []

    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(cli, "Keychain", NoKeychain)
    monkeypatch.setattr("sys.stdin", Tty("eagleeye\n"))
    monkeypatch.setattr("getpass.getpass", lambda prompt: asked.append(prompt) or f"secret-{len(asked)}-pass")
    for var in ("EAGLEEYE_CONNECTION_CODE", "EAGLEEYE_CONFIG", "EAGLEEYE_KIND"):
        monkeypatch.delenv(var, raising=False)
    code = "EE1." + base64.urlsafe_b64encode(json.dumps({"u": "https://api.example/api/v1",
                                                          "i": "11111111-2222-4333-8444-555555555555", "k": "key"}).encode()).decode()
    cfg = tmp_path / "netagent.json"
    assert cli.main(["config", "init", "--config", str(cfg), "--connection-code", code, "--kind", "network",
                     "--network-seed", "10.99.0.1", "--network-range", "10.10.0.0/16", "--network-range", "10.99.0.0/24"]) == 0
    s = load_settings(cfg, env={})
    assert (s.kind, s.network_seeds, s.network_ranges, s.agent_id) == \
        ("network", ["10.99.0.1"], ["10.10.0.0/16", "10.99.0.0/24"], "11111111-2222-4333-8444-555555555555")
    assert (s.snmp_user, s.snmp_auth_key, s.snmp_priv_key) == ("eagleeye", "secret-1-pass", "secret-2-pass")
    assert [p.split(" for")[0] for p in asked] == ["SNMPv3 authentication password", "SNMPv3 privacy password"]
    assert not s.problems()


def test_run_with_a_config_keeps_its_state_next_to_that_config(tmp_path, monkeypatch):
    from eagleeye import cli
    from eagleeye.config import state_path
    from eagleeye.policy import policy_path
    monkeypatch.setenv("EAGLEEYE_CONFIG", str(tmp_path / "other.json"))   # restored after the test
    seen = {}

    class Stop(Exception):
        pass

    def fake_service(settings, state_path=None, policy_path=None, vendor=None):
        seen["paths"] = (state_path, policy_path)
        raise Stop
    monkeypatch.setattr("eagleeye.netagent.service.NetworkAgentService", fake_service)
    cfg = tmp_path / "netagent-staging.json"
    cfg.write_text(json.dumps({"api_url": "https://x/api/v1", "api_key": "k", "agent_id": "a", "kind": "network"}))
    with pytest.raises(Stop):
        cli.main(["run", "--config", str(cfg)])
    assert seen["paths"] == (tmp_path / "state-netagent-staging.json", tmp_path / "policy-netagent-staging.json")
    assert state_path() == tmp_path / "state-netagent-staging.json" and policy_path().parent == tmp_path
