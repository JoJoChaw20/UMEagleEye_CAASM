"""The agent as a system service (2.5.0): the host's lifecycle (not set up, running,
reload, a crash), its answers over the local channel, the machine secrets, and moving a
user's settings into the machine folder. No service is installed and nothing is written
outside tmp_path."""

from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime

import pytest

from eagleeye import ipc, machine, serviceinstall
from eagleeye.config import Settings, load_settings, save_settings
from eagleeye.servicehost import ServiceHost


@pytest.fixture
def machine_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(machine, "machine_dir", lambda: tmp_path / "machine")
    monkeypatch.setenv("EAGLEEYE_CONFIG", str(tmp_path / "unused.json"))   # restored after the test
    (tmp_path / "machine").mkdir()
    return tmp_path / "machine"


class FakeAgent:
    def __init__(self, settings, crash=False):
        self.settings, self.crash = settings, crash
        self.stopped = threading.Event()
        self.requests = []
        self.last_heartbeat_at, self.last_heartbeat_ok, self.current = datetime(2026, 11, 7, 12, 0), True, None
        self.history, self.managed, self.applied_policy_version, self.suite = [], {"passive": True}, "0a1b2c3d", None

    def run_forever(self):
        if self.crash:
            return                       # the agent thread ended without being asked to
        self.stopped.wait()

    def stop(self):
        self.stopped.set()

    def request_inventory(self):
        self.requests.append("inventory")

    def request_sbom(self):
        self.requests.append("sbom")

    def request_scan(self, subnet):
        self.requests.append(("scan", subnet))


def wait_for(cond, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def host_with(settings_box, made, addr, crash_first=False):
    def make(settings):
        agent = FakeAgent(settings, crash=crash_first and not made)
        made.append(agent)
        return agent
    return ServiceHost("t", make_service=make, load=lambda: settings_box[0], ipc_address=addr)


def test_waits_until_set_up_then_runs_and_answers_the_app(machine_dir):
    addr = ipc.address(f"test-{id(machine_dir)}")
    box, made = [Settings()], []                                       # no server details yet
    host = host_with(box, made, addr)
    worker = threading.Thread(target=host.run, daemon=True)
    worker.start()
    try:
        assert wait_for(lambda: host.state == "not_set_up")
        st = ipc.call({"cmd": "status"}, addr)
        assert st["state"] == "not_set_up" and "api_url is not set" in st["problems"]
        assert st["config_path"].endswith("config-t.json")
        box[0] = Settings(api_url="https://x/api/v1", api_key="k", agent_id="a")
        ipc.call({"cmd": "reload"}, addr)                              # an administrator saved the settings
        assert wait_for(lambda: host.state == "running")
        st = ipc.call({"cmd": "status"}, addr)
        assert st["managed"] == {"passive": True} and st["last_heartbeat_ok"] is True
        assert st["last_heartbeat_at"] == "2026-11-07T12:00:00"
        ipc.call({"cmd": "request", "what": "scan", "subnet": "192.168.0.0/24"}, addr)
        ipc.call({"cmd": "request", "what": "inventory"}, addr)
        assert made[-1].requests == [("scan", "192.168.0.0/24"), "inventory"]
        with pytest.raises(RuntimeError, match="unknown request"):
            ipc.call({"cmd": "request", "what": "format c:"}, addr)
        # a reload starts a new agent with the new settings
        box[0] = Settings(api_url="https://x/api/v1", api_key="k2", agent_id="a")
        ipc.call({"cmd": "reload"}, addr)
        assert wait_for(lambda: len(made) == 2 and host.state == "running")
        assert made[0].stopped.is_set() and made[1].settings.api_key == "k2"
    finally:
        host.stop()
        worker.join(5)
    assert host.state == "stopped" and made[1].stopped.is_set()


def test_an_agent_that_crashes_is_started_again(machine_dir, monkeypatch):
    monkeypatch.setattr("eagleeye.servicehost.RESTART_AFTER_FAILURE_SECONDS", 0.1)
    box, made = [Settings(api_url="https://x/api/v1", api_key="k", agent_id="a")], []
    host = host_with(box, made, ipc.address(f"test-crash-{id(machine_dir)}"), crash_first=True)
    worker = threading.Thread(target=host.run, daemon=True)
    worker.start()
    try:
        assert wait_for(lambda: len(made) == 2 and host.state == "running")
    finally:
        host.stop()
        worker.join(5)


def test_machine_secrets_keep_the_key_out_of_the_config(machine_dir):
    secrets = machine.MachineSecrets(machine_dir / "secrets.dat", restrict=False)
    settings = Settings(api_url="https://x/api/v1", api_key="super-secret", agent_id="a1")
    path = save_settings(settings, machine_dir / "config.json", keychain=secrets)
    assert "super-secret" not in path.read_text()
    assert b"super-secret" not in secrets.path.read_bytes() or sys.platform != "win32"   # DPAPI on Windows
    assert load_settings(path, env={}, keychain=secrets).api_key == "super-secret"
    assert secrets.set("a1/api_key", "") and secrets.get("a1/api_key") is None


class MemoryKeychain:
    def __init__(self, items=None):
        self.items = dict(items or {})

    def available(self):
        return True

    def get(self, name):
        return self.items.get(name)

    def set(self, name, value):
        self.items[name] = value
        return True


def test_a_users_settings_move_into_the_machine_folder_once(machine_dir, tmp_path, monkeypatch):
    user = tmp_path / "user" / "config-production.json"
    user.parent.mkdir()
    save_settings(Settings(api_url="https://x/api/v1", api_key="from-credman", agent_id="a1", passive=True),
                  user, keychain=MemoryKeychain())
    (user.with_name("state-production.json")).write_text('{"last_inventory": 1}')
    (user.with_name("policy-production.json")).write_text('{"version": "0a1b2c3d", "managed": {}}')
    user_keychain = MemoryKeychain({"a1/api_key": "from-credman"})
    monkeypatch.setattr(serviceinstall, "Keychain", lambda: user_keychain)
    machine_secrets = machine.MachineSecrets(machine_dir / "secrets.dat", restrict=False)
    monkeypatch.setattr(serviceinstall, "MachineSecrets", lambda: machine_secrets)
    monkeypatch.setattr(serviceinstall, "secure", lambda path, secret=False: None)

    note = serviceinstall.migrate_user_settings(user, "production")
    target = machine_dir / "config-production.json"
    assert note.startswith("moved") and "state" in note and "policy" in note
    assert json.loads(target.read_text())["passive"] is True and "from-credman" not in target.read_text()
    assert load_settings(target, env={}, keychain=machine_secrets).api_key == "from-credman"
    assert (machine_dir / "state-production.json").exists() and (machine_dir / "policy-production.json").exists()
    assert serviceinstall.migrate_user_settings(user, "production").startswith("kept")   # never twice
    assert serviceinstall.migrate_user_settings(tmp_path / "none.json").startswith("no settings")


def test_what_the_service_manager_runs():
    cmd = serviceinstall._command("production")
    assert cmd[-4:] == ["service", "scm" if sys.platform == "win32" else "run", "--instance", "production"]
    assert cmd[:3] == [sys.executable, "-m", "eagleeye"]                     # from source here
    assert serviceinstall.unit_name("") == "eagleeye-agent"
    assert serviceinstall.unit_name("production") == "eagleeye-agent-production"
    assert machine.service_name("production") == "EagleEyeAgent-production"


def test_the_service_waits_for_the_last_passive_upload(machine_dir):
    box, made, waited = [Settings(api_url="https://x/api/v1", api_key="k", agent_id="a")], [], []

    class Agent(FakeAgent):
        def wait_final_flush(self, timeout):
            waited.append(timeout)
    host = ServiceHost("t", make_service=lambda s: made.append(Agent(s)) or made[-1], load=lambda: box[0],
                       ipc_address=ipc.address(f"test-flush-{id(machine_dir)}"))
    worker = threading.Thread(target=host.run, daemon=True)
    worker.start()
    assert wait_for(lambda: host.state == "running")
    host.stop()
    worker.join(5)
    assert waited == [30] and made[0].stopped.is_set()
