"""Smoke tests for the desktop app, run without a display (Qt offscreen platform)."""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from eagleeye.config import Settings  # noqa: E402
from eagleeye.gui import app as gui_app  # noqa: E402
from eagleeye.schedule import Schedule  # noqa: E402
from eagleeye.gui.consent import ConsentDialog, needs_consent  # noqa: E402
from eagleeye.privacy import CONSENT_VERSION  # noqa: E402
from tests.test_keychain import FakeKeychain  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    monkeypatch.setenv("EAGLEEYE_CONFIG", str(tmp_path / "config.json"))
    kc = FakeKeychain()
    monkeypatch.setattr(gui_app, "Keychain", lambda: kc)
    monkeypatch.setattr(gui_app.DependenciesPage, "refresh", lambda self: None)   # no tool probing in tests
    store = gui_app.Store(tmp_path / "config.json")
    win = gui_app.MainWindow(store, tmp_path / "logs")
    yield win
    win.controller.stop()
    win._quitting = True
    win.close()


def test_the_notice_lists_what_is_collected_with_personal_data_off(qapp):
    s = Settings()
    assert needs_consent(s)
    dlg = ConsentDialog(s)
    on = {text[4:].strip() for text in dlg.items if text.startswith("On ")}
    assert "This computer's inventory" in on
    assert not any("personal data" in item for item in on) and not any("Passive" in item for item in on)
    dlg.apply()                                 # read: the settings stay as they are
    assert (s.inventory, s.inventory_user_software, s.inventory_admin_names, s.passive) == (True, False, False, False)
    assert (s.consent_version, bool(s.consent_at), needs_consent(s)) == (CONSENT_VERSION, True, False)


def test_main_window_builds_and_cannot_start_unconfigured(window, monkeypatch):
    window.refresh()
    assert window.toggle_btn.text() == "Start"
    assert "Not set up yet" in window.status_page.banner.text()
    assert window.controller.start(window.store.settings)          # returns the reason
    assert not window.controller.running


def test_settings_page_saves_secrets_to_the_keychain_only(window):
    page = window.settings_page
    page.api_url.setText("https://example.invalid/api/v1")
    page.agent_id.setText("00000000-0000-0000-0000-000000000001")
    page.api_key.setText("super-secret-key")
    window.controller.start = lambda settings: None                 # don't start a real agent
    page._save()
    text = (window.store.path).read_text()
    assert "super-secret-key" not in text
    assert window.store.keychain.items["00000000-0000-0000-0000-000000000001/api_key"] == "super-secret-key"
    assert page.api_key.text() == "" and "saved" in page.api_key.placeholderText()
    # leaving the field empty keeps the stored key
    page._save()
    assert window.store.settings.api_key == "super-secret-key"


def test_saving_new_server_details_starts_the_agent_once(window):
    page = window.settings_page
    started = []

    class FakeController:                     # the real one's `running` is a read-only property
        running = False
        service = None

        def start(self, settings):
            started.append(settings.agent_id)
            self.running = True
            return None

        def stop(self):
            self.running = False
    real = window.controller
    window.controller = FakeController()
    s = window.store.settings                 # the notice is always accepted before this page
    s.consent_version, s.consent_at = CONSENT_VERSION, "2026-10-13T00:00:00Z"
    page.api_url.setText("https://example.invalid/api/v1")
    page.agent_id.setText("00000000-0000-0000-0000-000000000002")
    page.api_key.setText("k")
    page._save()
    assert started == ["00000000-0000-0000-0000-000000000002"]
    assert "now running" in page.save_result.text()
    # Someone stops the agent on purpose, then changes another setting: it stays stopped.
    window.controller.running = False
    page._save()
    assert started == ["00000000-0000-0000-0000-000000000002"] and page.save_result.text() == "Saved."
    window.controller = real


def test_saving_incomplete_server_details_does_not_start(window):
    page = window.settings_page
    window.controller.start = lambda settings: pytest.fail("must not start without an API key")
    page.api_url.setText("https://example.invalid/api/v1")
    page.agent_id.setText("00000000-0000-0000-0000-000000000003")
    page._save()
    assert page.save_result.text().startswith("Saved, but:")


def test_connection_code_fills_the_server_fields(window):
    from tests.test_enrol import EXPECTED, FROM_DASHBOARD
    page = window.settings_page
    page.code.setText(FROM_DASHBOARD)
    page._use_code()
    assert (page.api_url.text(), page.agent_id.text(), page.api_key.text()) == EXPECTED
    assert page.code.text() == "" and "Test connection" in page.test_result.text()
    page.code.setText("not a code")
    page._use_code()
    assert page.test_result.property("tone") == "error" and page.api_url.text() == EXPECTED[0]   # fields kept


def test_schedules_page_is_hidden_while_schedules_are_off(window):
    names = [window.nav.item(i).text() for i in range(window.nav.count())]
    assert "Schedules" not in names and window.schedules_page is None
    window.show_page(window.settings_page)
    assert window.stack.currentWidget() is window.settings_page


@pytest.mark.skipif(not gui_app.SCHEDULES_ENABLED, reason="local schedules are switched off for now")
def test_schedules_page_adds_and_validates(window):
    page = window.schedules_page
    page._save([Schedule(subnet="192.168.50.0/24", mode="interval", hours=4)])
    assert window.store.settings.schedules[0]["subnet"] == "192.168.50.0/24"
    assert page.table.rowCount() == 1 and page.table.item(0, 1).text() == "Every 4 hours"
    subnets = [window.status_page.subnet.itemText(i) for i in range(window.status_page.subnet.count())]
    assert "192.168.50.0/24" in subnets


def test_app_icon_has_sizes(qapp):
    assert len(gui_app.app_icon().availableSizes()) >= 5


def test_quit_button_in_header_quits(window, monkeypatch):
    from PySide6.QtWidgets import QPushButton
    quits = []
    monkeypatch.setattr(gui_app.QApplication, "quit", staticmethod(lambda: quits.append(1)))
    button = next(b for b in window.findChildren(QPushButton) if b.text() == "Quit")
    button.click()
    assert quits == [1] and window._quitting


def test_the_app_only_connects_the_agent_and_shows_what_it_does(window):
    # 2.6: everything the agent does is set on the dashboard; the app has no controls for it
    page, status = window.settings_page, window.status_page
    for gone in ("engine", "scan_ports", "capture", "passive", "poll", "fingerbank"):
        assert not hasattr(page, gone), gone
    for gone in ("scan_btn", "inv_btn", "sbom_btn", "subnet"):
        assert not hasattr(status, gone), gone
    names = [window.nav.item(i).text() for i in range(window.nav.count())]
    assert "Connection" in names and "Tools" in names and "Settings" not in names and "Dependencies" not in names


def test_privacy_page_shows_the_dashboard_values_read_only(window, tmp_path):
    from eagleeye.policy import PolicyStore, policy_path
    privacy = window.privacy_page
    privacy.reload()
    assert privacy.values["inventory"].text() == "Yes, every 6 hours"            # this computer's, until the server answers
    assert privacy.values["passive"].text() == "No"
    store = PolicyStore(policy_path())
    assert store.path.parent == tmp_path                                       # beside the test config, not the real one
    store.save("0a1b2c3d", {"inventory": True, "inventory_interval": 3600, "inventory_user_software": True,
                            "sbom": False, "passive": True})
    privacy.reload()
    assert privacy.values["inventory"].text() == "Yes, every 1 hour"
    assert privacy.values["inventory_user_software"].text() == "Yes" and privacy.values["sbom"].text() == "No"
    assert privacy.values["passive"].text() == "Yes"
    from PySide6.QtWidgets import QCheckBox
    assert not privacy.findChildren(QCheckBox)                                 # nothing to change here
