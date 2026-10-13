"""Main window, system tray, single-instance guard and start-up flow."""

from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QLockFile, QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QAction, QBrush, QCloseEvent, QColor, QIcon, QPainter, QPainterPath, QPixmap
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QListWidget, QMainWindow, QMenu, QMessageBox, QPushButton, QStackedWidget,
    QSystemTrayIcon, QVBoxLayout, QWidget,
)

from .. import VERSION, deps
from ..config import ConfigError, Settings, config_dir, default_config_path, load_settings, save_settings
from ..keychain import Keychain
from ..service import SCHEDULES_ENABLED
from .consent import ConsentDialog, needs_consent
from .controller import AgentController, QtLogHandler, start_pump, stop_pump
from .pages import DependenciesPage, LogPage, PrivacyPage, SchedulesPage, SettingsPage, StatusPage

log = logging.getLogger("eagleeye.gui")
APP_NAME = "EagleEye Agent"
CREATE_NO_WINDOW = 0x08000000

STYLE = """
QLabel[role="hint"] { color: palette(placeholder-text); }
QLabel[role="error"] { color: #b42318; }
QLabel[role="banner"] { background: #fff4e5; color: #7a4100; border: 1px solid #f5c48a; border-radius: 6px; padding: 8px 10px; }
QLabel#state[state="running"] { color: #067647; font-weight: 600; }
QLabel#state[state="stopped"] { color: #b42318; font-weight: 600; }
QListWidget#nav { border: none; background: palette(window); font-size: 14px; }
QListWidget#nav::item { padding: 8px 14px; border-radius: 6px; margin: 1px 6px; }
QListWidget#nav::item:selected { background: palette(highlight); color: palette(highlighted-text); }
QGroupBox { font-weight: 600; }
QPushButton[role="primary"] { font-weight: 600; }
"""


def app_icon() -> QIcon:
    """The app icon, drawn in code so there are no image files to ship."""
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(size, size)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = float(size)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor("#1d4ed8")))
        p.drawRoundedRect(QRectF(0, 0, s, s), s * 0.22, s * 0.22)
        eye = QPainterPath()
        eye.moveTo(s * 0.10, s * 0.50)
        eye.quadTo(s * 0.50, s * 0.12, s * 0.90, s * 0.50)
        eye.quadTo(s * 0.50, s * 0.88, s * 0.10, s * 0.50)
        p.setBrush(QBrush(QColor("white")))
        p.drawPath(eye)
        p.setBrush(QBrush(QColor("#1d4ed8")))
        p.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.17, s * 0.17)
        p.setBrush(QBrush(QColor("white")))
        p.drawEllipse(QPointF(s * 0.56, s * 0.44), s * 0.05, s * 0.05)
        p.end()
        icon.addPixmap(pm)
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
    def __init__(self, store: Store, log_dir: Path) -> None:
        super().__init__()
        start_pump()
        self.store = store
        self.controller = AgentController()
        self.setWindowTitle(f"{APP_NAME} {VERSION}")
        self.setWindowIcon(app_icon())
        self.resize(980, 720)

        # header: state + start/stop
        self.state = QLabel()
        self.state.setObjectName("state")
        self.admin = QLabel()
        self.admin.setProperty("role", "hint")
        self.toggle_btn = QPushButton()
        self.toggle_btn.setProperty("role", "primary")
        self.toggle_btn.clicked.connect(self.toggle)
        header = QHBoxLayout()
        header.setContentsMargins(20, 12, 20, 4)
        title = QLabel(f"<b style='font-size:16px'>{APP_NAME}</b>")
        header.addWidget(title)
        header.addSpacing(16)
        header.addWidget(self.state)
        header.addStretch(1)
        header.addWidget(self.admin)
        header.addSpacing(12)
        header.addWidget(self.toggle_btn)
        quit_btn = QPushButton("Quit")
        quit_btn.setToolTip("Stop the agent and close the app (closing the window keeps it running in the tray)")
        quit_btn.clicked.connect(self.quit)
        header.addWidget(quit_btn)

        self.status_page = StatusPage(self)
        self.schedules_page = SchedulesPage(self) if SCHEDULES_ENABLED else None
        self.settings_page = SettingsPage(self)
        self.privacy_page = PrivacyPage(self)
        self.deps_page = DependenciesPage(self)
        self.log_page = LogPage(self, log_dir)
        pages = [("Status", self.status_page)]
        if self.schedules_page is not None:
            pages.append(("Schedules", self.schedules_page))
        pages += [("Settings", self.settings_page), ("Privacy", self.privacy_page),
                  ("Dependencies", self.deps_page), ("Log", self.log_page)]
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(170)
        self.stack = QStackedWidget()
        for name, page in pages:
            self.nav.addItem(name)
            self.stack.addWidget(page)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.addWidget(self.nav)
        body.addWidget(self.stack, 1)
        root = QWidget()
        v = QVBoxLayout(root)
        v.setContentsMargins(0, 0, 0, 0)
        v.addLayout(header)
        v.addLayout(body, 1)
        self.setCentralWidget(root)

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
        self.nav.setCurrentRow(self.stack.indexOf(page))

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
                                            "Right-click the tray icon to quit.", app_icon(), 4000)
            self._tray_hint_shown = True

    def quit(self) -> None:
        svc = self.controller.service if self.controller.running else None
        if svc is not None and svc.active_running:
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
        self.controller.stop()
        if self.tray is not None:
            self.tray.hide()

    # ── agent ──
    def toggle(self) -> None:
        if self.controller.running:
            self.controller.stop()
            log.info("Agent stopped from the app")
        else:
            self.start_agent()
        self.refresh()

    def start_agent(self) -> None:
        s = self.store.settings
        if needs_consent(s):
            return
        reason = self.controller.start(s)
        if reason:
            self.show_page(self.settings_page)
            QMessageBox.information(self, APP_NAME, f"The agent cannot start yet: {reason}.")
            return
        log.info("EagleEye Agent v%s started (server %s, agent %s)", VERSION, s.api_url, s.agent_id)
        if s.passive and not deps.is_admin():
            log.info("Not running as Administrator: passive listening works only if Npcap allows "
                     "non-admin capture (otherwise use Dependencies > Restart as Administrator)")

    def settings_changed(self, connection_changed: bool = False) -> bool:
        """Called after a page saved settings: restart the agent so they take effect.

        When the server details were just entered or changed and the agent is not running
        (first setup), start it, so Save is the last step. An agent someone stopped on
        purpose stays stopped when other settings change. Returns True if it started it.
        """
        self.status_page.reload_subnets()
        self.privacy_page.reload()
        started = False
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
        self.state.setText("● Running" if running else "● Stopped")
        self.state.setProperty("state", "running" if running else "stopped")
        self.state.style().unpolish(self.state)
        self.state.style().polish(self.state)
        self.toggle_btn.setText("Stop" if running else "Start")
        self.admin.setText("Administrator" if deps.is_admin() else "Standard user")
        if self.tray is not None:
            self.tray_toggle.setText("Stop agent" if running else "Start agent")
            self.tray_inventory.setEnabled(running and self.store.settings.inventory)
            self.tray.setToolTip(f"{APP_NAME}: {'running' if running else 'stopped'}")
        self.status_page.refresh()

    def _on_timer(self) -> None:
        self._tick += 1
        self.status_page.refresh()
        if self._tick % 10 == 0:
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
        config_dir().mkdir(parents=True, exist_ok=True)
        self.lock = QLockFile(str(config_dir() / "agent-gui.lock"))
        self.lock.setStaleLockTime(0)
        self.server_name = f"{name}-{os.environ.get('USERNAME') or os.environ.get('USER') or 'user'}"
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
        self.server.newConnection.connect(lambda: (self.server and self.server.nextPendingConnection(), on_activate()))
        self.server.listen(self.server_name)

    def signal_running(self) -> bool:
        sock = QLocalSocket()
        sock.connectToServer(self.server_name)
        ok = sock.waitForConnected(500)
        sock.disconnectFromServer()
        return ok


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
    args, _ = parser.parse_known_args(argv)

    for stream in ("stdout", "stderr"):          # windowed builds have no console
        if getattr(sys, stream) is None:
            setattr(sys, stream, open(os.devnull, "w", encoding="utf-8"))
    _hide_child_consoles()
    log_dir = config_dir() / "logs"
    _setup_logging(log_dir)
    _install_crash_diagnostics(log_dir)

    app = QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(app_icon())
    app.setStyleSheet(STYLE)
    app.setQuitOnLastWindowClosed(False)

    guard = SingleInstance("EagleEyeAgent")
    if not guard.acquire():
        if not guard.signal_running():
            QMessageBox.information(None, APP_NAME, "EagleEye Agent is already running. Look for its icon in the "
                                                    "system tray (it may be running as Administrator).")
        return 0
    app.single_instance = guard  # type: ignore[attr-defined]

    store = Store(default_config_path())
    if store.load_error:
        QMessageBox.warning(None, APP_NAME, f"The settings file could not be read:\n{store.load_error}\n\n"
                                            "Starting with default settings; saving will replace that file.")

    if needs_consent(store.settings):
        dialog = ConsentDialog(store.settings)
        dialog.setWindowIcon(app_icon())
        if not dialog.exec():
            guard.release()
            return 0
        dialog.apply()
        store.save()
        log.info("Data-collection notice accepted (version %s)", store.settings.consent_version)

    window = MainWindow(store, log_dir)
    guard.listen(window.show_window)

    configured = not store.settings.problems()
    if configured:
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
