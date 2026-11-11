"""Main window, system tray, single-instance guard and start-up flow."""

from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from PySide6.QtCore import QLockFile, Qt, QTimer
from PySide6.QtGui import QAction, QCloseEvent, QIcon
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QMainWindow, QMenu, QMessageBox, QStackedWidget, QSystemTrayIcon,
    QVBoxLayout, QWidget,
)

from .. import VERSION, deps
from ..config import ConfigError, Settings, config_dir, default_config_path, instance_name, load_settings, save_settings
from ..keychain import Keychain
from ..service import SCHEDULES_ENABLED
from .consent import ConsentDialog, needs_consent
from .controller import AgentController, QtLogHandler, start_pump, stop_pump
from . import theme
from .pages import LogPage, PrivacyPage, SchedulesPage, SettingsPage, StatusPage, all_pages
from .widgets import PAGE_ROLE, ElidedLabel, LiveDot, RailNav, ThemeSwitch, button, refresh_icons

log = logging.getLogger("eagleeye.gui")
APP_NAME = "EagleEye Agent"
CREATE_NO_WINDOW = 0x08000000

RAIL_WIDTH = 240


def app_icon() -> QIcon:
    """The EagleEye emblem (assets/mark.png) at the sizes Windows asks for."""
    icon = QIcon()
    mark = theme.brand_pixmap("mark")
    for size in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(mark.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatio,
                                   Qt.TransformationMode.SmoothTransformation))
    return icon


class Store:
    """The settings being edited, and where they are saved."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.keychain = Keychain()
        self.load_error: Optional[str] = None
        try:
            self.settings = load_settings(path, keychain=self.keychain)
        except ConfigError as exc:
            self.load_error = str(exc)
            self.settings = Settings()

    def save(self) -> None:
        save_settings(self.settings, self.path, keychain=self.keychain)


class MainWindow(QMainWindow):
    def __init__(self, store: Store, log_dir: Path, controller: Any = None) -> None:
        super().__init__()
        start_pump()
        self.store = store
        # With the agent installed as a service (2.5.0) the app is its client (remote.py).
        self.controller = controller or AgentController()
        self.service_mode = bool(getattr(self.controller, "applies_settings_itself", False))
        inst = instance_name()
        self.setWindowTitle(f"{APP_NAME} {VERSION}" + (f" ({inst})" if inst else ""))
        self.setWindowIcon(app_icon())
        self.setMinimumSize(900, 600)
        # Never taller or wider than the screen: on a small display (a VM at 1024x768) the
        # bar with Save at the bottom of a settings page would sit under the taskbar.
        screen = QApplication.primaryScreen()
        free = screen.availableGeometry() if screen is not None else None
        width, height = 1120, 780
        if free is not None:
            width, height = min(width, free.width() - 40), min(height, free.height() - 40)
            self.setMinimumSize(min(900, width), min(600, height))
        self.resize(width, height)

        self.status_page = StatusPage(self)
        self.schedules_page = SchedulesPage(self) if SCHEDULES_ENABLED else None
        self.settings_page = SettingsPage(self)
        self.privacy_page = PrivacyPage(self)
        self.log_page = LogPage(self, log_dir)
        self.stack = QStackedWidget()
        # Two groups on the rail: what the agent does, and this computer's setup (the connection and
        # tools on one page since 2.6: each had one box left once the settings moved to the dashboard).
        doing: list[tuple[str, str, QWidget]] = [("Status", "activity", self.status_page)]
        if self.schedules_page is not None:
            doing.append(("Schedules", "calendar-clock", self.schedules_page))
        doing.append(("Log", "scroll-text", self.log_page))
        setup = [("Setup", "settings", self.settings_page), ("Privacy", "shield-check", self.privacy_page)]
        self.nav = RailNav()
        for group, pages in (("Agent", doing), ("This computer", setup)):
            self.nav.add_group(group)
            for name, icon_name, page in pages:
                self.nav.add_page(name, icon_name, self.stack.addWidget(page))
        self.nav.currentRowChanged.connect(self._nav_changed)

        # the navy rail: logo, navigation, this computer
        rail = QWidget()
        rail.setObjectName("rail")
        rail.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        rail.setFixedWidth(RAIL_WIDTH)
        rv = QVBoxLayout(rail)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(0)
        brand = QWidget()
        brand.setObjectName("railBrand")
        brand.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        brand.setFixedHeight(64)
        bh = QHBoxLayout(brand)
        bh.setContentsMargins(16, 0, 12, 0)
        logo = QLabel()
        logo.setAccessibleName("UMEagleEye")
        logo.setToolTip(f"UMEagleEye · {APP_NAME} {VERSION}")
        lockup = theme.brand_pixmap("lockup-on-dark")
        if not lockup.isNull():
            ratio = 2.0
            scaled = lockup.scaledToHeight(int(54 * ratio), Qt.TransformationMode.SmoothTransformation)
            scaled.setDevicePixelRatio(ratio)
            logo.setPixmap(scaled)
        bh.addWidget(logo)
        bh.addStretch(1)
        rv.addWidget(brand)
        rv.addSpacing(10)
        rv.addWidget(self.nav, 1)
        foot = QWidget()
        foot.setObjectName("railFoot")
        foot.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        fh = QHBoxLayout(foot)
        fh.setContentsMargins(14, 12, 14, 12)
        fh.setSpacing(10)
        host = socket.gethostname() or "This computer"
        tile = QLabel(host[:1].upper())
        tile.setObjectName("railTile")
        tile.setFixedSize(32, 32)
        tile.setAlignment(Qt.AlignmentFlag.AlignCenter)
        fh.addWidget(tile)
        who = QVBoxLayout()
        who.setSpacing(1)
        name = QLabel(host)
        name.setObjectName("railName")
        name.setToolTip("The computer this agent runs on")
        self.admin = QLabel()
        self.admin.setObjectName("railSub")
        who.addWidget(name)
        who.addWidget(self.admin)
        fh.addLayout(who, 1)
        rv.addWidget(foot)

        # header: state, theme, start/stop, quit
        top = QWidget()
        top.setObjectName("topbar")
        top.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        top.setFixedHeight(64)
        th = QHBoxLayout(top)
        th.setContentsMargins(20, 0, 16, 0)
        th.setSpacing(10)
        self.dot = LiveDot()
        self.state = QLabel()
        self.state.setObjectName("state")
        self.state_detail = ElidedLabel()
        self.state_detail.setObjectName("stateDetail")
        th.addWidget(self.dot)
        th.addWidget(self.state)
        th.addSpacing(2)
        th.addWidget(self.state_detail, 1)
        self.theme_switch = ThemeSwitch()
        th.addWidget(self.theme_switch)
        sep = QFrame()
        sep.setObjectName("vsep")
        sep.setFixedSize(1, 24)
        th.addSpacing(4)
        th.addWidget(sep)
        th.addSpacing(4)
        self.toggle_btn = button("Start", "primary", "play", self.toggle)
        self.toggle_btn.setMinimumWidth(92)
        th.addWidget(self.toggle_btn)
        quit_btn = button("Quit", "ghost", "power", self.quit)
        quit_btn.setToolTip("Stop the agent and close the app. Closing the window only hides it in the tray. "
                            "Open EagleEyeAgent.exe to start it again.")
        th.addWidget(quit_btn)

        workspace = QWidget()
        workspace.setObjectName("workspace")
        wv = QVBoxLayout(workspace)
        wv.setContentsMargins(0, 0, 0, 0)
        wv.setSpacing(0)
        wv.addWidget(top)
        wv.addWidget(self.stack, 1)

        root = QWidget()
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        h.addWidget(rail)
        h.addWidget(workspace, 1)
        self.setCentralWidget(root)
        self.nav.setCurrentRow(self.nav.row_for_page(0))
        mgr = theme.manager()
        if mgr is not None:
            mgr.changed.connect(lambda _name: self.restyle())

        self.controller.event.connect(self.status_page.on_event)
        self.controller.log_line.connect(self.log_page.append)
        self.log_handler: Optional[QtLogHandler] = QtLogHandler(self.controller)
        logging.getLogger().addHandler(self.log_handler)
        self.controller.running_changed.connect(lambda _: self.refresh())

        self.tray: Optional[QSystemTrayIcon] = None
        self._tray_hint_shown = False
        self._quitting = False
        if QSystemTrayIcon.isSystemTrayAvailable():
            self._make_tray()

        self._tick = 0
        timer = QTimer(self)
        timer.timeout.connect(self._on_timer)
        timer.start(1000)
        self.refresh()

    def show_page(self, page: QWidget) -> None:
        self.nav.setCurrentRow(self.nav.row_for_page(self.stack.indexOf(page)))

    def _nav_changed(self, row: int) -> None:
        item = self.nav.item(row) if row >= 0 else None
        index = item.data(PAGE_ROLE) if item is not None else None
        if index is not None:
            self.stack.setCurrentIndex(int(index))

    def restyle(self) -> None:
        """After a theme change: re-colour the icons and the colours set from code."""
        refresh_icons(self)
        self.theme_switch.restyle()
        for page in all_pages(self):
            restyle = getattr(page, "restyle", None)
            if restyle is not None:
                restyle()
        self.nav.viewport().update()
        self.refresh()

    # ── tray ──
    def _make_tray(self) -> None:
        self.tray = QSystemTrayIcon(app_icon(), self)
        menu = QMenu()
        menu.addAction("Open", self.show_window)
        self.tray_toggle = QAction("Start agent", self)
        self.tray_toggle.triggered.connect(self.toggle)
        menu.addAction(self.tray_toggle)
        self.tray_inventory = QAction("Collect inventory now", self)
        self.tray_inventory.triggered.connect(lambda: self.controller.service and self.controller.service.request_inventory())
        menu.addAction(self.tray_inventory)
        menu.addSeparator()
        menu.addAction("Quit", self.quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda reason: self.show_window() if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        self.tray.show()

    def show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt API
        if self._quitting or self.tray is None:
            self._shutdown()
            event.accept()
            return
        event.ignore()
        self.hide()
        if not self._tray_hint_shown and self.controller.running:
            self.tray.showMessage(APP_NAME, "The agent keeps running in the background. "
                                  + ("Closing this app never stops it." if self.service_mode
                                     else "Right-click the tray icon to quit."), app_icon(), 4000)
            self._tray_hint_shown = True

    def quit(self) -> None:
        svc = self.controller.service if self.controller.running else None
        if svc is not None and svc.active_running and not self.service_mode:
            answer = QMessageBox.question(self, APP_NAME, "A scan is still running. Quit anyway? The scan will be lost.")
            if answer != QMessageBox.StandardButton.Yes:
                return
        self._quitting = True
        self._shutdown()
        QApplication.quit()

    def _shutdown(self) -> None:
        # Detach logging from the widgets first: background threads keep logging
        # while Qt tears the window down.
        if self.log_handler is not None:
            logging.getLogger().removeHandler(self.log_handler)
            self.log_handler = None
        stop_pump()
        self.controller.detach()            # the in-app agent stops; a service keeps running
        if self.tray is not None:
            self.tray.hide()

    # ── agent ──
    def toggle(self) -> None:
        if self.controller.running:
            failed = self.controller.stop()
            if failed:
                QMessageBox.warning(self, APP_NAME, f"The agent was not stopped: {failed}.")
            else:
                log.info("Agent stopped from the app")
        else:
            self.start_agent()
        self.refresh()

    def save_store(self) -> Optional[str]:
        """Save the settings being edited; why they were not saved, or None. With the
        agent service, Windows asks for an administrator (remote.ServiceStore)."""
        try:
            self.store.save()
        except Exception as exc:  # noqa: BLE001 - shown on the page
            log.warning("Settings not saved: %s", exc)
            return str(exc) or "Not saved."
        return None

    def start_agent(self) -> None:
        s = self.store.settings
        if needs_consent(s):
            return
        reason = self.controller.start(s)
        if reason:
            # Said where it is fixed, not in a box: the Setup page, next to Test connection.
            self.show_page(self.settings_page)
            self.settings_page.show_problem(f"The agent cannot start yet: {reason}.")
            return
        log.info("EagleEye Agent v%s started (server %s, agent %s)", VERSION, s.api_url, s.agent_id)
        if s.passive and not deps.is_admin():
            log.info("Not running as Administrator: passive listening works only if the capture allows "
                     "non-admin capture (otherwise use Setup > Restart as Administrator)")

    def settings_changed(self, connection_changed: bool = False) -> bool:
        """Called after a page saved settings: restart the agent so they take effect.

        When the server details were just entered or changed and the agent is not running
        (first setup), start it, so Save is the last step. An agent someone stopped on
        purpose stays stopped when other settings change. Returns True if it started it.
        """
        self.privacy_page.reload()
        started = False
        if getattr(self.controller, "applies_settings_itself", False):
            self.refresh()                   # the service reloads them itself (eagleeye service apply)
            return False
        if self.controller.running:
            log.info("Settings changed; restarting the agent")
            self.controller.stop()
            self.start_agent()
        elif connection_changed and not self.store.settings.problems():
            self.start_agent()
            started = self.controller.running
        self.refresh()
        return started

    def refresh(self) -> None:
        running = self.controller.running
        # Start is the primary action only once it can work; until then Open Settings leads.
        role = "secondary" if running or self.store.settings.problems() else "primary"
        text = "Stop" if running else "Start"
        if self.toggle_btn.text() != text or self.toggle_btn.property("role") != role:
            self.toggle_btn.setText(text)
            self.toggle_btn.setToolTip("Stop the agent: it stops scanning and reporting; the app stays open (Quit closes it)"
                                       if running else "Start the agent: it connects to the dashboard and reports")
            self.toggle_btn.setProperty("role", role)
            self.toggle_btn.setProperty("iconName", "square" if running else "play")
            self.toggle_btn.style().unpolish(self.toggle_btn)
            self.toggle_btn.style().polish(self.toggle_btn)
            refresh_icons(self.toggle_btn.parentWidget())
        inst = instance_name()
        who = "Agent service" if self.service_mode else ("Administrator" if deps.is_admin() else "Standard user")
        self.admin.setText(who + f" · v{VERSION}" + (f" · {inst}" if inst else ""))
        self._refresh_state()
        if self.tray is not None:
            self.tray_toggle.setText("Stop agent" if running else "Start agent")
            self.tray_inventory.setEnabled(running and self.store.settings.inventory)
            self.tray.setToolTip(f"{APP_NAME}: {'running' if running else 'stopped'}")
        self.status_page.refresh()

    def _refresh_state(self) -> None:
        """The header's live dot and one line on what the agent is doing."""
        svc = self.controller.service if self.controller.running else None
        service_state = getattr(self.controller, "state", None) if self.service_mode else None
        if self.store.settings.problems() or service_state == "not_set_up":
            tone, state, detail = "off", "Not set up", "Paste the connection code on the Setup page"
        elif service_state == "unavailable":
            tone, state, detail = "down", "Stopped", "The agent service is not running (Start asks for an administrator)"
        elif svc is None:
            tone, state, detail = "down", "Stopped", "Press Start to connect to the server"
        elif svc.last_heartbeat_at is None:
            tone, state, detail = "warn", "Running", "Connecting to the server..."
        elif getattr(svc, "rejected", None):
            tone, state, detail = "down", "Not connected", "The dashboard no longer accepts this agent: paste a new connection code on the Setup page"
        elif svc.last_heartbeat_ok:
            tone, state, detail = "live", "Running", f"Heartbeat OK at {svc.last_heartbeat_at:%H:%M:%S}"
        else:
            tone, state, detail = "warn", "Running", f"Last heartbeat failed at {svc.last_heartbeat_at:%H:%M:%S} (see Log)"
        self.dot.set_tone(tone)
        self.state.setText(state)
        self.state_detail.setText(detail)

    def _on_timer(self) -> None:
        self._tick += 1
        self.status_page.refresh()
        self._refresh_state()
        if self._tick % 10 == 0:
            # The administrator changed this agent's settings: show them on the pages.
            from .pages import managed_now
            managed = managed_now(self)
            if managed != getattr(self, "_managed_shown", None):
                self._managed_shown = managed
                self.privacy_page.reload()
            if self.schedules_page is not None:
                self.schedules_page.refresh()
        if self.toggle_btn.text() != ("Stop" if self.controller.running else "Start"):
            self.refresh()

    # ── elevation ──
    def relaunch_elevated(self) -> None:
        if sys.platform != "win32":
            QMessageBox.information(self, APP_NAME, "Start the agent with sudo to give it root rights.")
            return
        import ctypes
        if getattr(sys, "frozen", False):
            exe, args = sys.executable, ""
        else:
            pythonw = Path(sys.executable).with_name("pythonw.exe")
            exe = str(pythonw if pythonw.is_file() else sys.executable)
            args = subprocess.list2cmdline(["-m", "eagleeye", "gui"])
        instance = QApplication.instance()
        guard: Optional[SingleInstance] = getattr(instance, "single_instance", None)
        if guard:
            guard.release()
        self.controller.stop()
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, os.getcwd(), 1)  # type: ignore[attr-defined]
        if rc <= 32:
            if guard:
                guard.acquire()
            QMessageBox.warning(self, APP_NAME, "Not restarted: the Administrator prompt was declined.")
            self.start_agent()
            return
        self._quitting = True
        self._shutdown()
        QApplication.quit()


class SingleInstance:
    """One app per user: a lock file, plus a local socket so a second launch can
    bring the running window forward."""

    def __init__(self, name: str) -> None:
        # One per config file (instance_name): a production agent started with
        # EAGLEEYE_CONFIG opens its own window instead of raising the staging one.
        inst = instance_name()
        suffix = f"-{inst}" if inst else ""
        config_dir().mkdir(parents=True, exist_ok=True)
        self.lock = QLockFile(str(config_dir() / f"agent-gui{suffix}.lock"))
        self.lock.setStaleLockTime(0)
        self.server_name = f"{name}{suffix}-{os.environ.get('USERNAME') or os.environ.get('USER') or 'user'}"
        self.server: Optional[QLocalServer] = None

    def acquire(self) -> bool:
        return self.lock.tryLock(200)

    def release(self) -> None:
        self.lock.unlock()
        if self.server is not None:
            self.server.close()
            self.server = None

    def listen(self, on_activate) -> None:  # type: ignore[no-untyped-def]
        QLocalServer.removeServer(self.server_name)
        self.server = QLocalServer()
        # The sign-in task starts the agent as Administrator; without this a copy you open
        # normally could not reach it to bring its window forward (Windows denies the pipe).
        self.server.setSocketOptions(QLocalServer.SocketOption.WorldAccessOption)
        self.server.newConnection.connect(lambda: (self.server and self.server.nextPendingConnection(), on_activate()))
        self.server.listen(self.server_name)

    def signal_running(self) -> bool:
        sock = QLocalSocket()
        sock.connectToServer(self.server_name)
        ok = sock.waitForConnected(500)
        sock.disconnectFromServer()
        return ok


TASK_NAME = "EagleEye Agent"      # the sign-in task the installer creates (packaging/installer.iss)


def start_via_task(guard: SingleInstance, wait_seconds: float = 10.0) -> bool:
    """Opening EagleEyeAgent.exe normally starts the agent through the installer's sign-in
    task, so it runs with the Administrator rights it needs (passive listening, the full
    inventory) without a UAC prompt, then brings its window up. True when that worked;
    False (start here instead) without the task, when it is disabled, or in a dev run."""
    if sys.platform != "win32" or not getattr(sys, "frozen", False) or deps.is_admin() or instance_name():
        return False
    try:
        if subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME], capture_output=True, timeout=10).returncode != 0:
            return False
        if subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], capture_output=True, timeout=10).returncode != 0:
            return False
    except (OSError, subprocess.SubprocessError):
        return False
    # The task's copy starts in the tray; once it listens, ask it to show its window.
    import time
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if guard.signal_running():
            return True
        time.sleep(0.5)
    return False


def _setup_logging(log_dir: Path) -> logging.Handler:
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fh = logging.handlers.RotatingFileHandler(log_dir / "agent.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    root.addHandler(fh)
    return fh


def _install_crash_diagnostics(log_dir: Path) -> None:
    """Leave a trace when the app dies: Python stacks of every thread on a native
    crash or abort (crash.log), and exceptions
    that escape a worker thread or a Qt slot (agent.log)."""
    import faulthandler
    import threading

    crash = open(log_dir / "crash.log", "a", encoding="utf-8")  # noqa: SIM115 - must stay open
    crash.write(f"\n=== {APP_NAME} {VERSION} started {__import__('datetime').datetime.now():%Y-%m-%d %H:%M:%S} ===\n"
                "(Windows also reports exceptions that were handled; an entry only matters if the app\n"
                " closed at that moment.)\n")
    crash.flush()
    faulthandler.enable(crash, all_threads=True)
    _install_crash_diagnostics.file = crash  # type: ignore[attr-defined]

    # No Qt message handler on purpose: Qt also reports from threads that are already
    # exiting (e.g. "QThreadStorage: entry destroyed before end of thread"), and a
    # Python handler called there aborts the whole process. Qt prints to stderr itself.

    def thread_hook(args: threading.ExceptHookArgs) -> None:
        log.error("Uncaught error in thread %s", args.thread.name if args.thread else "?",
                  exc_info=(args.exc_type, args.exc_value, args.exc_traceback))

    threading.excepthook = thread_hook
    sys.excepthook = lambda t, v, tb: log.error("Uncaught error", exc_info=(t, v, tb))


def _hide_child_consoles() -> None:
    """A windowed app that starts console programs (PowerShell, Nmap) would flash a
    console window for each. Start them without one."""
    if sys.platform != "win32":
        return
    original = subprocess.Popen

    class NoWindowPopen(original):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | CREATE_NO_WINDOW
            super().__init__(*args, **kwargs)

    subprocess.Popen = NoWindowPopen  # type: ignore[misc]


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="EagleEyeAgent")
    parser.add_argument("--minimized", action="store_true", help="start in the system tray")
    parser.add_argument("--no-task", action="store_true", help="start here, not through the sign-in task")
    args, _ = parser.parse_known_args(argv)

    for stream in ("stdout", "stderr"):          # windowed builds have no console
        if getattr(sys, stream) is None:
            setattr(sys, stream, open(os.devnull, "w", encoding="utf-8"))
    _hide_child_consoles()
    inst = instance_name()
    log_dir = config_dir() / (f"logs-{inst}" if inst else "logs")
    _setup_logging(log_dir)
    _install_crash_diagnostics(log_dir)

    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    theme.setup(app)
    app.setWindowIcon(app_icon())
    app.setQuitOnLastWindowClosed(False)

    guard = SingleInstance("EagleEyeAgent")
    # Already running (perhaps as Administrator from the sign-in task): show that window.
    if guard.signal_running():
        return 0
    from .remote import ServiceController, ServiceStore, notice_read, record_notice, service_installed
    service_mode = service_installed(inst)
    if not service_mode and not args.no_task and start_via_task(guard):
        return 0
    if not guard.acquire():
        if not guard.signal_running():
            which = f" ({inst})" if inst else ""
            QMessageBox.information(None, APP_NAME, f"EagleEye Agent{which} is already running. Look for its icon in the "
                                                    "system tray (it may be running as Administrator).")
        return 0
    app.single_instance = guard  # type: ignore[attr-defined]

    store: Any = ServiceStore(inst) if service_mode else Store(default_config_path())
    if store.load_error:
        QMessageBox.warning(None, APP_NAME, f"The settings file could not be read:\n{store.load_error}\n\n"
                                            "Starting with default settings; saving will replace that file.")

    # The notice is shown to each user once per version. With the service the settings are
    # the service's (an administrator's), so it is recorded per user instead.
    from ..privacy import CONSENT_VERSION
    unread = notice_read() < CONSENT_VERSION if service_mode else needs_consent(store.settings)
    if unread:
        dialog = ConsentDialog(store.settings)
        dialog.setWindowIcon(app_icon())
        if not dialog.exec():
            guard.release()
            return 0
        if service_mode:
            record_notice(CONSENT_VERSION)
        else:
            dialog.apply()
            store.save()
        log.info("Data-collection notice read (version %s)", CONSENT_VERSION)

    window = MainWindow(store, log_dir, ServiceController(inst) if service_mode else None)
    guard.listen(window.show_window)

    configured = not store.settings.problems()
    if configured and not service_mode:
        window.start_agent()
    else:
        window.show_page(window.settings_page)
    if not (args.minimized and configured and window.tray is not None):
        window.show()

    code = app.exec()
    guard.release()
    logging.shutdown()
    # Worker threads (a long Nmap run) must not keep the process alive after Quit.
    os._exit(code)
