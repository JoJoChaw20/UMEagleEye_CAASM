"""The agent app as a client of the agent service (gui/remote.py): what it shows from the
service's status, how it saves the service's settings (an elevated helper), and that
closing it leaves the service running. Nothing is installed and no prompt appears: the
service's answers and the elevated helper are faked; files stay under tmp_path."""

from __future__ import annotations

import json
import os
import sys

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from eagleeye import machine, serviceinstall  # noqa: E402
from eagleeye.config import Settings, load_settings, save_settings  # noqa: E402
from eagleeye.gui import app as gui_app  # noqa: E402
from eagleeye.gui import remote  # noqa: E402
from eagleeye.serviceinstall import SAVED_SECRET  # noqa: E402

STATUS = {
    "version": "2.5.0", "instance": "", "state": "running", "problems": [],
    "last_heartbeat_at": "2026-11-07T19:33:26", "last_heartbeat_ok": True, "current": None,
    "active_running": False, "inventory_running": False, "sbom_running": False, "local_scans_allowed": False,
    "managed": {"passive": True}, "applied_policy_version": "0a1b2c3d",
    "passive": {"listening_on": "Ethernet0 (192.168.36.60)", "capture": "Microsoft NDIS capture (built in)",
                "running": True, "problems": []},
    "history": [{"pipeline": "inventory", "trigger": "auto", "target": "this computer", "status": "completed",
                 "hosts": 1, "seconds": 4.2, "error": None, "finished_at": "2026-11-07T19:30:00"}],
}


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def machine_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(machine, "machine_dir", lambda: tmp_path / "machine")
    (tmp_path / "machine").mkdir()
    secrets = machine.MachineSecrets(tmp_path / "machine" / "secrets.dat", restrict=False)
    monkeypatch.setattr(serviceinstall, "MachineSecrets", lambda: secrets)
    monkeypatch.setattr(serviceinstall, "secure", lambda path, secret=False: None)
    monkeypatch.setenv("APPDATA", str(tmp_path / "user"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "user"))
    save_settings(Settings(api_url="https://x/api/v1", api_key="real-key", agent_id="a1", passive=False),
                  tmp_path / "machine" / "config.json", keychain=secrets)
    return tmp_path / "machine", secrets


class FakeIpc:
    def __init__(self, status=None):
        self.status, self.calls = status, []

    def __call__(self, request, addr=None, timeout=5.0):
        self.calls.append(request)
        if self.status is None:
            raise remote.ipc.ServiceUnavailable("the agent service is not running")
        return self.status if request.get("cmd") == "status" else {}


def test_the_store_knows_the_key_is_saved_but_not_what_it_is(machine_dir):
    store = remote.ServiceStore()
    assert store.settings.api_key == SAVED_SECRET and store.settings.api_url == "https://x/api/v1"
    assert store.settings.problems() == []                            # set up, as far as the app can tell
    assert "real-key" not in json.dumps(store.settings.__dict__)


def test_saving_goes_through_the_elevated_helper_and_keeps_the_key(machine_dir, monkeypatch):
    folder, secrets = machine_dir
    calls = []

    def helper(args):                          # what the UAC-elevated `eagleeye service apply` does
        calls.append(args)
        serviceinstall.apply_settings_file(serviceinstall.Path(args[args.index("--from-config") + 1]))
        return 0
    monkeypatch.setattr(remote, "run_elevated", helper)
    monkeypatch.setattr(remote.ipc, "call", FakeIpc(STATUS))
    store = remote.ServiceStore()
    store.settings.passive = True
    store.save()
    assert calls and calls[0][:2] == ["service", "apply"]
    saved = load_settings(folder / "config.json", env={}, keychain=secrets)
    assert saved.passive is True and saved.api_key == "real-key"     # the placeholder kept the key
    assert store.settings.passive is True and store.settings.api_key == SAVED_SECRET
    handover = serviceinstall.Path(calls[0][calls[0].index("--from-config") + 1])
    assert not handover.exists()                                      # the handover file is deleted
    # a new connection code (another agent) with its own key
    store.settings.agent_id, store.settings.api_key = "a2", "new-key"
    store.save()
    assert load_settings(folder / "config.json", env={}, keychain=secrets).api_key == "new-key"


def test_a_declined_prompt_saves_nothing(machine_dir, monkeypatch):
    monkeypatch.setattr(remote, "run_elevated", lambda args: None)
    store = remote.ServiceStore()
    store.settings.passive = True
    with pytest.raises(remote.SaveDeclined, match="declined"):
        store.save()
    folder, secrets = machine_dir
    assert load_settings(folder / "config.json", env={}, keychain=secrets).passive is False


def test_the_status_reads_like_the_in_app_agent():
    svc = remote.RemoteService(STATUS)
    assert svc.last_heartbeat_ok and svc.last_heartbeat_at.hour == 19 and not svc.local_scans_allowed
    assert svc.suite.listening_on.startswith("Ethernet0") and svc.suite.arp is not None
    assert svc.history[0].pipeline == "inventory" and svc.managed == {"passive": True}


def test_the_controller_follows_the_service(monkeypatch):
    fake = FakeIpc(dict(STATUS, state="not_set_up", problems=["api_url is not set"]))
    monkeypatch.setattr(remote.ipc, "call", fake)
    monkeypatch.setattr(remote.ServiceController, "_poll", lambda self: None)
    monkeypatch.setattr(remote.ServiceController, "_tail_log", lambda self: None)
    ctrl = remote.ServiceController()
    ctrl.refresh_now()
    assert (ctrl.state, ctrl.running) == ("not_set_up", False)
    assert "Setup page" in ctrl.start(Settings())                   # nothing to start before setup
    fake.status = STATUS
    ctrl.refresh_now()
    assert ctrl.running and ctrl.service.last_heartbeat_ok
    fake.status = None
    ctrl.refresh_now()
    assert (ctrl.state, ctrl.running) == ("unavailable", False)
    monkeypatch.setattr(remote, "run_elevated", lambda args: None)
    assert ctrl.stop() == "the administrator prompt was declined"


def test_the_window_in_service_mode(qapp, machine_dir, monkeypatch, tmp_path):
    monkeypatch.setattr(remote.ipc, "call", FakeIpc(STATUS))
    monkeypatch.setattr(remote.ServiceController, "_poll", lambda self: None)
    monkeypatch.setattr(remote.ServiceController, "_tail_log", lambda self: None)
    monkeypatch.setattr(gui_app.SettingsPage, "refresh_tools", lambda self: None)
    ctrl = remote.ServiceController()
    ctrl.refresh_now()
    win = gui_app.MainWindow(remote.ServiceStore(), tmp_path / "logs", ctrl)
    try:
        assert win.service_mode and win.settings_page.admin_btn.isHidden()
        win.refresh()
        assert win.state.text() == "Running" and "Heartbeat OK" in win.state_detail.text()
        assert win.admin.text().startswith("Agent service")
        assert win.settings_changed() is False                         # the service reloads by itself
        monkeypatch.setattr(remote, "run_elevated", lambda args: None)
        win.settings_page._save()
        assert "declined" in win.settings_page.save_result.text()
        stopped = []
        monkeypatch.setattr(ctrl, "stop", lambda: stopped.append(1))
        win._shutdown()                                                # closing the app
        assert stopped == [] and ctrl._stop.is_set()                   # the service keeps running
    finally:
        win._quitting = True
        win.close()


@pytest.mark.skipif(sys.platform != "win32", reason="the notice record lives in %APPDATA%")
def test_the_notice_is_recorded_per_user(machine_dir):
    assert remote.notice_read() == 0
    remote.record_notice(5)
    assert remote.notice_read() == 5
