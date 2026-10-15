"""Smoke tests for the desktop app, run without a display (Qt offscreen platform)."""

from __future__ import annotations

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


def test_consent_defaults_keep_personal_data_off(qapp):
    s = Settings()
    assert needs_consent(s)
    dlg = ConsentDialog(s)
    assert dlg.inventory.isChecked() and not dlg.user_software.isChecked() and not dlg.admin_names.isChecked()
    assert not dlg.passive.isChecked()
    dlg.inventory.setChecked(False)
    dlg.user_software.setChecked(True)          # ignored while inventory is off
    dlg.apply()
    assert (s.inventory, s.inventory_user_software, s.consent_version) == (False, False, CONSENT_VERSION)
    assert s.consent_at and not needs_consent(s)


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
    page.poll.setValue(page.poll.value() + 5)
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
    assert page.test_result.text().startswith("✖") and page.api_url.text() == EXPECTED[0]   # fields kept


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


def test_privacy_page_saves_choices(window):
    page = window.privacy_page
    page.inventory.setChecked(True)
    page.user_software.setChecked(True)
    page.interval.setValue(12)
    page._save()
    s = window.store.settings
    assert s.inventory_user_software and not s.inventory_admin_names and s.inventory_interval == 12 * 3600


def test_app_icon_has_sizes(qapp):
    assert len(gui_app.app_icon().availableSizes()) >= 5


def test_quit_button_in_header_quits(window, monkeypatch):
    from PySide6.QtWidgets import QPushButton
    quits = []
    monkeypatch.setattr(gui_app.QApplication, "quit", staticmethod(lambda: quits.append(1)))
    button = next(b for b in window.findChildren(QPushButton) if b.text() == "Quit")
    button.click()
    assert quits == [1] and window._quitting
