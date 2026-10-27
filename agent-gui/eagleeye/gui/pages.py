"""The pages of the main window."""

from __future__ import annotations

import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from PySide6.QtCore import Qt, QTime, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
    QRadioButton, QScrollArea, QSpinBox, QTableWidget, QTableWidgetItem, QTextBrowser, QTimeEdit, QVBoxLayout,
    QWidget,
)

from .. import deps, installers
from ..api import AgentClient
from ..enrol import ConnectionCodeError, parse_connection_code
from ..netinfo import local_ip, local_network
from ..pipeline import EventKind, Pipeline, PipelineContext, PipelineEvent
from ..privacy import NOTICE_HTML
from ..schedule import Schedule
from ..stages import InventoryDryRunStage, LocalInventoryStage
from .controller import gui_call, run_in_thread

if TYPE_CHECKING:
    from .app import MainWindow

TRIGGERS = {"dashboard": "Dashboard", "schedule": "Schedule", "manual": "Scan now / button", "auto": "Automatic"}
TASKS = {"active": "Active scan", "passive": "Passive upload", "inventory": "Inventory", "sbom": "SBOM + CVE check"}


def _fmt(dt: Optional[datetime]) -> str:
    if dt is None:
        return "-"
    return dt.strftime("%H:%M:%S") if dt.date() == datetime.now().date() else dt.strftime("%d %b %H:%M")


def _hint(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setProperty("role", "hint")
    return label


def _page(*widgets: QWidget, stretch: bool = True) -> QScrollArea:
    """A scrollable column of sections."""
    body = QWidget()
    layout = QVBoxLayout(body)
    layout.setContentsMargins(20, 16, 20, 16)
    layout.setSpacing(14)
    for w in widgets:
        layout.addWidget(w)
    if stretch:
        layout.addStretch(1)
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QScrollArea.Shape.NoFrame)
    area.setWidget(body)
    return area


def _table(headers: list[str], stretch: Optional[int] = None) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    header = t.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    if stretch is None:
        header.setStretchLastSection(True)
    else:
        header.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)
    return t


# Larger networks are offered, but not first: Nmap needs hours for thousands of addresses.
DEFAULT_SCAN_MIN_PREFIX = 22


def scan_targets() -> list[str]:
    """Scan ranges to offer, the default first: the network this computer is on (as
    configured, e.g. a /22 office LAN) when it has at most 1024 addresses, else the /24
    around this computer followed by the whole network."""
    try:
        network = local_network()
        ip = network.get("local_ip") or local_ip()
        around = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        subnet = network.get("subnet") or around
        if ipaddress.ip_network(subnet).prefixlen >= DEFAULT_SCAN_MIN_PREFIX:
            return list(dict.fromkeys([subnet, around]))
        return [around, subnet]
    except ValueError:
        return ["192.168.1.0/24"]


def default_subnet() -> str:
    return scan_targets()[0]


# ── Status ────────────────────────────────────────────────────────────────
class StatusPage(QWidget):
    def __init__(self, win: "MainWindow") -> None:
        super().__init__()
        self.win = win

        self.banner = QLabel()
        self.banner.setWordWrap(True)
        self.banner.setProperty("role", "banner")

        conn = QGroupBox("Connection")
        form = QFormLayout(conn)
        self.server = QLabel()
        self.agent = QLabel()
        self.heartbeat = QLabel()
        for w in (self.server, self.agent):
            w.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.passive_on = QLabel()
        form.addRow("Server", self.server)
        form.addRow("Agent ID", self.agent)
        form.addRow("Last heartbeat", self.heartbeat)
        form.addRow("Passive listening", self.passive_on)

        activity = QGroupBox("Now")
        a = QVBoxLayout(activity)
        self.current = QLabel("Idle")
        self.stage = QLabel("")
        self.stage.setWordWrap(True)
        self.stage.setProperty("role", "hint")
        self.busy = QProgressBar()
        self.busy.setRange(0, 0)
        self.busy.setTextVisible(False)
        self.busy.setMaximumHeight(6)
        self.busy.hide()
        a.addWidget(self.current)
        a.addWidget(self.busy)
        a.addWidget(self.stage)

        actions = QGroupBox("Run now")
        g = QVBoxLayout(actions)
        row = QHBoxLayout()
        self.subnet = QComboBox()
        self.subnet.setEditable(True)
        self.subnet.setMinimumWidth(200)
        self.scan_btn = QPushButton("Scan now")
        self.scan_btn.clicked.connect(self._scan_now)
        row.addWidget(QLabel("Network"))
        row.addWidget(self.subnet, 1)
        row.addWidget(self.scan_btn)
        g.addLayout(row)
        row2 = QHBoxLayout()
        self.inv_btn = QPushButton("Collect inventory now")
        self.inv_btn.clicked.connect(self._inventory_now)
        row2.addWidget(self.inv_btn)
        self.sbom_btn = QPushButton("Build SBOM now")
        self.sbom_btn.clicked.connect(self._sbom_now)
        row2.addWidget(self.sbom_btn)
        row2.addStretch(1)
        g.addLayout(row2)
        g.addWidget(_hint("Scans started here are recorded in the dashboard like the ones started there. "
                          "The agent must be running."))

        recent = QGroupBox("Recent activity")
        r = QVBoxLayout(recent)
        self.table = _table(["Finished", "Task", "Started by", "Target", "Result", "Hosts", "Took"], stretch=3)
        self.table.setMinimumHeight(220)
        r.addWidget(self.table)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(_page(self.banner, conn, activity, actions, recent, stretch=False))
        self._history_len = -1
        self.reload_subnets()

    def reload_subnets(self) -> None:
        current = self.subnet.currentText()
        options = scan_targets() + [Schedule.from_dict(s).subnet for s in self.win.store.settings.schedules]
        self.subnet.clear()
        for opt in dict.fromkeys(o for o in options if o):
            self.subnet.addItem(opt)
        if current:
            self.subnet.setCurrentText(current)

    def _scan_now(self) -> None:
        target = self.subnet.currentText().strip()
        problems = Schedule(subnet=target).problems()
        if problems:
            QMessageBox.warning(self, "Scan now", problems[0])
            return
        svc = self.win.controller.service
        if svc is not None:
            svc.request_scan(target)
            self.stage.setText(f"Asking the server to record a scan of {target}...")

    def _inventory_now(self) -> None:
        svc = self.win.controller.service
        if svc is not None:
            svc.request_inventory()
            self.stage.setText("Collecting this computer's inventory...")

    def _sbom_now(self) -> None:
        svc = self.win.controller.service
        if svc is not None:
            if svc.sbom_running and svc.sbom_mode == "full":
                self.stage.setText("A full SBOM is already running; its result will appear when it finishes.")
            elif svc.sbom_running:
                self.stage.setText("Queued: a full SBOM starts when the current daily SBOM finishes.")
            else:
                self.stage.setText("Building this computer's full SBOM (this can take 10-30 minutes)...")
            svc.request_sbom()

    def on_event(self, event: PipelineEvent) -> None:
        if event.kind in (EventKind.STAGE_STARTED, EventKind.STAGE_PROGRESS):
            self.stage.setText(event.message)
        elif event.kind is EventKind.STAGE_FAILED:
            self.stage.setText(f"{event.stage} failed: {event.message}")
        elif event.kind is EventKind.PIPELINE_FINISHED:
            self.stage.setText(f"{TASKS.get(event.pipeline, event.pipeline)} finished: {event.message}")

    def refresh(self) -> None:
        s = self.win.store.settings
        ctrl = self.win.controller
        svc = ctrl.service if ctrl.running else None
        problems = [p for p in s.problems()]
        if problems:
            self.banner.setText("Not set up yet: open <b>Settings</b> and paste the connection code from the "
                                "dashboard's Agents page.")
            self.banner.show()
        elif not ctrl.running:
            self.banner.setText("The agent is stopped. Press <b>Start</b> to connect.")
            self.banner.show()
        else:
            self.banner.hide()

        self.server.setText(s.api_url or "-")
        self.agent.setText(s.agent_id or "-")
        if svc is None or svc.last_heartbeat_at is None:
            self.heartbeat.setText("-" if svc is None else "connecting...")
        else:
            state = "OK" if svc.last_heartbeat_ok else "failed (see Log)"
            self.heartbeat.setText(f"{state} at {_fmt(svc.last_heartbeat_at)}")
        suite = getattr(svc, "suite", None) if svc is not None else None
        if not s.passive:
            self.passive_on.setText("off (Settings > Passive listening)")
        elif suite is None or suite.arp is None:
            self.passive_on.setText("-" if svc is None else "not running (see Dependencies)")
        else:
            self.passive_on.setText(suite.listening_on)

        busy_bits = []
        if svc is not None:
            if svc.active_running:
                busy_bits.append(svc.current or "Scanning")
            if svc.inventory_running:
                busy_bits.append("Collecting inventory")
            if svc.sbom_running:
                busy_bits.append("Building SBOM")
        self.current.setText(" | ".join(busy_bits) if busy_bits else ("Idle" if svc else "Stopped"))
        self.busy.setVisible(bool(busy_bits))
        self.scan_btn.setEnabled(svc is not None and not svc.active_running)
        self.inv_btn.setEnabled(svc is not None and s.inventory and not svc.inventory_running)
        self.inv_btn.setToolTip("" if s.inventory else "Inventory is switched off on the Privacy page")
        # During a daily (quick) run it stays available: the full run it asks for starts after it.
        full_running = svc is not None and svc.sbom_running and svc.sbom_mode == "full"
        self.sbom_btn.setEnabled(svc is not None and s.sbom and not full_running)
        self.sbom_btn.setToolTip("SBOM is switched off on the Privacy page" if not s.sbom
                                 else "A full SBOM is already running; its result will appear when it finishes"
                                 if full_running else "")

        if svc is not None and len(svc.history) != self._history_len:
            self._history_len = len(svc.history)
            self._fill_history(list(svc.history))

    def _fill_history(self, rows: list[Any]) -> None:
        self.table.setRowCount(len(rows))
        for i, rec in enumerate(rows):
            result = {"ok": "OK", "failed": "Failed", "cancelled": "Cancelled"}.get(rec.status, rec.status)
            values = [
                _fmt(rec.finished_at), TASKS.get(rec.pipeline, rec.pipeline), TRIGGERS.get(rec.trigger, rec.trigger),
                rec.target, result, str(rec.hosts) if rec.pipeline not in ("inventory", "sbom") else "-", f"{rec.seconds:.0f}s",
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 4 and rec.error:
                    item.setToolTip(rec.error)
                self.table.setItem(i, col, item)


# ── Schedules ─────────────────────────────────────────────────────────────
class ScheduleDialog(QDialog):
    def __init__(self, schedule: Schedule, parent=None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(parent)
        self.setWindowTitle("Scan schedule")
        self.schedule = schedule
        self.subnet = QLineEdit(schedule.subnet or default_subnet())
        self.daily = QRadioButton("Every day at")
        self.interval = QRadioButton("Every")
        self.time = QTimeEdit(QTime.fromString(schedule.time, "HH:mm") if schedule.time else QTime(2, 0))
        self.time.setDisplayFormat("HH:mm")
        self.hours = QSpinBox()
        self.hours.setRange(1, 168)
        self.hours.setSuffix(" hours")
        self.hours.setValue(max(1, min(168, schedule.hours)))
        (self.daily if schedule.mode == "daily" else self.interval).setChecked(True)
        self.enabled = QCheckBox("Enabled")
        self.enabled.setChecked(schedule.enabled)

        form = QFormLayout()
        form.addRow("Network (IPv4 or CIDR)", self.subnet)
        d = QHBoxLayout()
        d.addWidget(self.daily)
        d.addWidget(self.time)
        d.addStretch(1)
        i = QHBoxLayout()
        i.addWidget(self.interval)
        i.addWidget(self.hours)
        i.addStretch(1)
        form.addRow("When", d)
        form.addRow("", i)
        form.addRow("", self.enabled)
        self.error = QLabel()
        self.error.setProperty("role", "error")
        self.error.setWordWrap(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(_hint("A missed run (computer off or agent stopped) runs once when the agent is next running."))
        layout.addWidget(self.error)
        layout.addWidget(buttons)

    def _save(self) -> None:
        s = Schedule(
            subnet=self.subnet.text().strip(),
            mode="daily" if self.daily.isChecked() else "interval",
            time=self.time.time().toString("HH:mm"),
            hours=self.hours.value(),
            enabled=self.enabled.isChecked(),
            id=self.schedule.id,
        )
        problems = s.problems()
        if problems:
            self.error.setText(problems[0])
            return
        self.schedule = s
        self.accept()


class SchedulesPage(QWidget):
    def __init__(self, win: "MainWindow") -> None:
        super().__init__()
        self.win = win
        box = QGroupBox("Scan schedules")
        v = QVBoxLayout(box)
        v.addWidget(_hint("Active scans this agent runs by itself. Administrators can still start scans from the "
                          "dashboard. Only one active scan runs at a time; a schedule that comes due during another "
                          "scan waits for it."))
        self.table = _table(["Network", "When", "Next run", "Status"])
        self.table.setMinimumHeight(240)
        self.table.doubleClicked.connect(lambda _: self._edit())
        v.addWidget(self.table)
        row = QHBoxLayout()
        for text, slot in (("Add...", self._add), ("Edit...", self._edit), ("Remove", self._remove)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            row.addWidget(b)
        row.addStretch(1)
        v.addLayout(row)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(_page(box))
        self.refresh()

    def _schedules(self) -> list[Schedule]:
        return [Schedule.from_dict(raw) for raw in self.win.store.settings.schedules]

    def _save(self, schedules: list[Schedule]) -> None:
        self.win.store.settings.schedules = [s.to_dict() for s in schedules]
        self.win.store.save()
        self.win.controller.apply_live(self.win.store.settings)
        self.win.status_page.reload_subnets()
        self.refresh()

    def _selected(self) -> Optional[int]:
        rows = self.table.selectionModel().selectedRows()
        return rows[0].row() if rows else None

    def _add(self) -> None:
        dlg = ScheduleDialog(Schedule(subnet=""), self)
        if dlg.exec():
            self._save(self._schedules() + [dlg.schedule])

    def _edit(self) -> None:
        idx = self._selected()
        if idx is None:
            return
        items = self._schedules()
        dlg = ScheduleDialog(items[idx], self)
        if dlg.exec():
            items[idx] = dlg.schedule
            self._save(items)

    def _remove(self) -> None:
        idx = self._selected()
        if idx is None:
            return
        items = self._schedules()
        if QMessageBox.question(self, "Remove schedule", f"Remove the schedule for {items[idx].subnet}?") \
                == QMessageBox.StandardButton.Yes:
            del items[idx]
            self._save(items)

    def refresh(self) -> None:
        svc = self.win.controller.service if self.win.controller.running else None
        upcoming = {s.id: nxt for s, nxt in svc.next_scheduled()} if svc else {}
        items = self._schedules()
        self.table.setRowCount(len(items))
        for i, s in enumerate(items):
            if not s.enabled:
                nxt = "-"
            elif svc is None:
                nxt = "when the agent runs"
            else:
                when = upcoming.get(s.id)
                nxt = _fmt(when) if when else "-"
            status = "Off" if not s.enabled else ("; ".join(s.problems()) or "On")
            for col, value in enumerate([s.subnet, s.describe(), nxt, status]):
                self.table.setItem(i, col, QTableWidgetItem(value))


# ── Settings ──────────────────────────────────────────────────────────────
class SettingsPage(QWidget):
    def __init__(self, win: "MainWindow") -> None:
        super().__init__()
        self.win = win
        s = win.store.settings

        conn = QGroupBox("Server")
        f = QFormLayout(conn)
        # One paste instead of three: the code from the dashboard's Agents page fills the
        # three fields below (nothing is saved until Save).
        code_row = QHBoxLayout()
        self.code = QLineEdit()
        self.code.setEchoMode(QLineEdit.EchoMode.Password)          # it contains the API key
        self.code.setPlaceholderText("paste the code from the dashboard (starts with EE1.)")
        self.code.returnPressed.connect(self._use_code)
        use_code = QPushButton("Use code")
        use_code.clicked.connect(self._use_code)
        code_row.addWidget(self.code, 1)
        code_row.addWidget(use_code)
        f.addRow("Connection code", code_row)
        f.addRow("", _hint("Or enter the three values yourself:"))
        self.api_url = QLineEdit(s.api_url)
        self.api_url.setPlaceholderText("https://.../api/v1")
        self.agent_id = QLineEdit(s.agent_id)
        self.api_key = QLineEdit()
        self.api_key.setEchoMode(QLineEdit.EchoMode.Password)
        f.addRow("API URL", self.api_url)
        f.addRow("Agent ID", self.agent_id)
        f.addRow("API key", self.api_key)
        self.key_hint = _hint("")
        f.addRow("", self.key_hint)
        row = QHBoxLayout()
        self.test_btn = QPushButton("Test connection")
        self.test_btn.clicked.connect(self._test)
        self.test_result = QLabel()
        self.test_result.setWordWrap(True)
        row.addWidget(self.test_btn)
        row.addWidget(self.test_result, 1)
        f.addRow("", row)

        timing = QGroupBox("Timing")
        t = QFormLayout(timing)
        self.poll = self._spin(5, 3600, s.poll_interval, " s")
        self.heartbeat = self._spin(5, 3600, s.heartbeat_interval, " s")
        t.addRow("Check for dashboard scans every", self.poll)
        t.addRow("Heartbeat every", self.heartbeat)

        passive = QGroupBox("Passive listening")
        p = QFormLayout(passive)
        self.passive = QCheckBox("Listen for ARP, mDNS, NetBIOS and DHCP announcements")
        self.passive.setChecked(s.passive)
        self.passive_iface = QLineEdit(s.passive_interface)
        self.passive_iface.setPlaceholderText("automatic")
        self.passive_interval = self._spin(10, 3600, s.passive_interval, " s")
        self.fingerbank = QLineEdit()
        self.fingerbank.setEchoMode(QLineEdit.EchoMode.Password)
        p.addRow(self.passive)
        p.addRow("Network interface", self.passive_iface)
        p.addRow("Upload what was heard every", self.passive_interval)
        p.addRow("Fingerbank API key (optional)", self.fingerbank)
        p.addRow(_hint("Needs Npcap and Administrator rights (see Dependencies)."))

        snmp = QGroupBox("SNMPv3 polling of network devices (optional)")
        n = QFormLayout(snmp)
        self.snmp_user = QLineEdit(s.snmp_user)
        self.snmp_auth = QLineEdit()
        self.snmp_auth.setEchoMode(QLineEdit.EchoMode.Password)
        self.snmp_priv = QLineEdit()
        self.snmp_priv.setEchoMode(QLineEdit.EchoMode.Password)
        self.snmp_auth_proto = QComboBox()
        self.snmp_auth_proto.addItems(["SHA", "SHA256", "SHA384", "SHA512", "SHA224", "MD5"])
        self.snmp_auth_proto.setCurrentText(s.snmp_auth_protocol)
        self.snmp_priv_proto = QComboBox()
        self.snmp_priv_proto.addItems(["AES", "AES192", "AES256", "3DES", "DES"])
        self.snmp_priv_proto.setCurrentText(s.snmp_priv_protocol)
        n.addRow("User", self.snmp_user)
        n.addRow("Auth key", self.snmp_auth)
        n.addRow("Auth protocol", self.snmp_auth_proto)
        n.addRow("Privacy key", self.snmp_priv)
        n.addRow("Privacy protocol", self.snmp_priv_proto)

        save_row = QWidget()
        sr = QHBoxLayout(save_row)
        sr.setContentsMargins(0, 0, 0, 0)
        self.save_btn = QPushButton("Save")
        self.save_btn.setProperty("role", "primary")
        self.save_btn.clicked.connect(self._save)
        self.save_result = QLabel()
        sr.addWidget(self.save_btn)
        sr.addWidget(self.save_result, 1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(_page(conn, timing, passive, snmp, save_row))
        self._secret_placeholders()

    @staticmethod
    def _spin(lo: int, hi: int, value: int, suffix: str) -> QSpinBox:
        sp = QSpinBox()
        sp.setRange(lo, hi)
        sp.setValue(max(lo, min(hi, value)))
        sp.setSuffix(suffix)
        sp.setMaximumWidth(140)
        return sp

    def _secret_placeholders(self) -> None:
        s = self.win.store.settings
        where = "the Windows Credential Manager" if sys.platform == "win32" else "the system keychain"
        where = where if self.win.store.keychain.available() else "the config file"
        for field, name in ((self.api_key, "api_key"), (self.fingerbank, "fingerbank_key"),
                            (self.snmp_auth, "snmp_auth_key"), (self.snmp_priv, "snmp_priv_key")):
            field.clear()
            field.setPlaceholderText("saved (leave empty to keep)" if getattr(s, name) else "")
        self.key_hint.setText(f"Shown once when the agent was registered. Secrets are kept in {where}.")

    def _secret(self, field: QLineEdit, current: str) -> str:
        return field.text().strip() or current

    def _use_code(self) -> None:
        try:
            url, agent_id, key = parse_connection_code(self.code.text())
        except ConnectionCodeError as exc:
            self.test_result.setText(f"✖ {exc}")
            return
        self.api_url.setText(url)
        self.agent_id.setText(agent_id)
        self.api_key.setText(key)
        self.code.clear()
        self.test_result.setText("Filled in from the code. Choose Test connection, then Save.")

    def _test(self) -> None:
        s = self.win.store.settings
        url, agent, key = self.api_url.text().strip(), self.agent_id.text().strip(), self._secret(self.api_key, s.api_key)
        if not (url and agent and key):
            self.test_result.setText("Enter the API URL, agent ID and API key first.")
            return
        self.test_btn.setEnabled(False)
        self.test_result.setText("Contacting the server...")

        def done(result: Any, error: Optional[BaseException]) -> None:
            self.test_btn.setEnabled(True)
            ok, text = result if result else (False, f"Error: {error}")
            self.test_result.setText(("✔ " if ok else "✖ ") + text)

        run_in_thread(lambda: AgentClient(url, key, agent).check_connection(), done)

    def _save(self) -> None:
        s = self.win.store.settings
        before = (s.api_url, s.agent_id, s.api_key)
        s.api_url = self.api_url.text().strip()
        s.agent_id = self.agent_id.text().strip()
        s.api_key = self._secret(self.api_key, s.api_key)
        s.poll_interval = self.poll.value()
        s.heartbeat_interval = self.heartbeat.value()
        s.passive = self.passive.isChecked()
        s.passive_interface = self.passive_iface.text().strip()
        s.passive_interval = self.passive_interval.value()
        s.fingerbank_key = self._secret(self.fingerbank, s.fingerbank_key)
        s.snmp_user = self.snmp_user.text().strip()
        s.snmp_auth_key = self._secret(self.snmp_auth, s.snmp_auth_key)
        s.snmp_priv_key = self._secret(self.snmp_priv, s.snmp_priv_key)
        s.snmp_auth_protocol = self.snmp_auth_proto.currentText()
        s.snmp_priv_protocol = self.snmp_priv_proto.currentText()
        self.win.store.save()
        self._secret_placeholders()
        problems = s.problems()
        started = self.win.settings_changed(connection_changed=(s.api_url, s.agent_id, s.api_key) != before)
        self.save_result.setText(
            "Saved, but: " + "; ".join(problems) if problems
            else "Saved. The agent is now running and connecting to the server." if started
            else "Saved.")

    def reload(self) -> None:
        s = self.win.store.settings
        self.passive.setChecked(s.passive)


# ── Privacy ───────────────────────────────────────────────────────────────
class PrivacyPage(QWidget):
    def __init__(self, win: "MainWindow") -> None:
        super().__init__()
        self.win = win

        notice = QGroupBox("Notice")
        nv = QVBoxLayout(notice)
        text = QTextBrowser()
        text.setHtml(NOTICE_HTML)
        text.setMinimumHeight(260)
        nv.addWidget(text)
        self.consent = _hint("")
        nv.addWidget(self.consent)

        inv = QGroupBox("This computer's inventory")
        f = QFormLayout(inv)
        self.inventory = QCheckBox("Collect this computer's inventory")
        self.user_software = QCheckBox("Include software installed only for individual users (personal data)")
        self.admin_names = QCheckBox("Include the names of administrator accounts (personal data)")
        self.interval = QSpinBox()
        self.interval.setRange(1, 168)
        self.interval.setSuffix(" hours")
        self.interval.setMaximumWidth(140)
        self.inventory.toggled.connect(self._enable)
        f.addRow(self.inventory)
        f.addRow(self.user_software)
        f.addRow(self.admin_names)
        f.addRow("Collect every", self.interval)
        row = QHBoxLayout()
        save = QPushButton("Save")
        save.setProperty("role", "primary")
        save.clicked.connect(self._save)
        self.preview_btn = QPushButton("Preview what would be sent...")
        self.preview_btn.clicked.connect(self._preview)
        self.result = QLabel()
        row.addWidget(save)
        row.addWidget(self.preview_btn)
        row.addWidget(self.result, 1)
        f.addRow(row)
        f.addRow(_hint("The preview collects the inventory on this computer and shows it. Nothing is sent."))

        sb = QGroupBox("Software packages (SBOM)")
        sf = QFormLayout(sb)
        self.sbom = QCheckBox("List this computer's software packages and check them for known vulnerabilities")
        self.sbom_extra = QPlainTextEdit()
        self.sbom_extra.setPlaceholderText("One folder per line, e.g. D:\\Apps")
        self.sbom_extra.setMaximumHeight(80)
        self.sbom_defaults = _hint("")
        self.sbom_binaries = QCheckBox("Include compiled programs (Go binaries, .exe/.dll, Linux kernel images): "
                                       "many more findings, mostly ones only the program's vendor can fix")
        self.sbom.toggled.connect(self.sbom_extra.setEnabled)
        self.sbom.toggled.connect(self.sbom_binaries.setEnabled)
        sf.addRow(self.sbom)
        sf.addRow(self.sbom_binaries)
        sf.addRow("Also scan", self.sbom_extra)
        sf.addRow(self.sbom_defaults)
        save_sbom = QPushButton("Save")
        save_sbom.setProperty("role", "primary")
        save_sbom.clicked.connect(self._save)
        sf.addRow(save_sbom)
        sf.addRow(_hint("Runs once a day and when an administrator asks from the dashboard. Uses Syft and Grype "
                        "(see Dependencies). Only package names, versions and licences are sent; no files."))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(_page(inv, sb, notice))
        self.reload()

    def _enable(self, on: bool) -> None:
        for w in (self.user_software, self.admin_names, self.interval):
            w.setEnabled(on)

    def reload(self) -> None:
        s = self.win.store.settings
        self.inventory.setChecked(s.inventory)
        self.user_software.setChecked(s.inventory_user_software)
        self.admin_names.setChecked(s.inventory_admin_names)
        self.interval.setValue(max(1, min(168, round(s.inventory_interval / 3600))))
        self._enable(s.inventory)
        self.sbom.setChecked(s.sbom)
        self.sbom_extra.setPlainText(s.sbom_extra_paths)
        self.sbom_extra.setEnabled(s.sbom)
        self.sbom_binaries.setChecked(s.sbom_include_binaries)
        self.sbom_binaries.setEnabled(s.sbom)
        from ..sbom import default_roots
        self.sbom_defaults.setText("Always scanned: " + ", ".join(default_roots()))
        try:
            accepted = datetime.fromisoformat(s.consent_at).strftime("%d %b %Y at %H:%M") if s.consent_at else ""
        except ValueError:
            accepted = s.consent_at
        self.consent.setText(f"Notice accepted on {accepted}." if accepted else "Notice not yet accepted.")

    def _save(self) -> None:
        s = self.win.store.settings
        s.inventory = self.inventory.isChecked()
        s.inventory_user_software = s.inventory and self.user_software.isChecked()
        s.inventory_admin_names = s.inventory and self.admin_names.isChecked()
        s.inventory_interval = self.interval.value() * 3600
        s.sbom = self.sbom.isChecked()
        s.sbom_include_binaries = self.sbom_binaries.isChecked()
        s.sbom_extra_paths = "\n".join(p for p in (line.strip() for line in self.sbom_extra.toPlainText().splitlines()) if p)
        self.win.store.save()
        self.result.setText("Saved.")
        self.win.settings_changed()

    def _preview(self) -> None:
        options = {"user_software": self.user_software.isChecked() and self.inventory.isChecked(),
                   "admin_names": self.admin_names.isChecked() and self.inventory.isChecked()}
        self.preview_btn.setEnabled(False)
        self.result.setText("Collecting (this takes up to a minute)...")

        def collect() -> dict[str, Any]:
            holder: dict[str, Any] = {}
            ctx = PipelineContext("inventory", scan_type="inventory")
            res = Pipeline("inventory", [LocalInventoryStage(options=options), InventoryDryRunStage(holder.update)]).run(ctx)
            if not res.ok:
                raise RuntimeError(res.error or res.status)
            return holder

        def done(result: Any, error: Optional[BaseException]) -> None:
            self.preview_btn.setEnabled(True)
            if error:
                self.result.setText(f"Preview failed: {error}")
                return
            self.result.setText("")
            JsonDialog("Inventory preview (not sent)", result, self).exec()

        run_in_thread(collect, done)


class JsonDialog(QDialog):
    def __init__(self, title: str, data: dict[str, Any], parent=None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 640)
        self.data = data
        view = QPlainTextEdit(json.dumps(data, indent=2))
        view.setReadOnly(True)
        view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        save = buttons.addButton("Save as...", QDialogButtonBox.ButtonRole.ActionRole)
        save.clicked.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        summary = _summarise(data)
        if summary:
            layout.addWidget(_hint(summary))
        layout.addWidget(view, 1)
        layout.addWidget(buttons)

    def _save(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save inventory", "inventory.json", "JSON (*.json)")
        if path:
            Path(path).write_text(json.dumps(self.data, indent=2), encoding="utf-8")


def _summarise(inv: dict[str, Any]) -> str:
    try:
        return (f"{len(inv.get('software', []))} application(s), "
                f"{len(inv['network']['interfaces'])} interface(s), {len(inv['network']['listening'])} listening port(s). "
                f"Per-user software: {'included' if inv['privacy']['user_software'] else 'not included'}; "
                f"admin names: {'included' if inv['privacy']['admin_names'] else 'not included'}.")
    except (KeyError, TypeError):
        return ""


# ── Dependencies ──────────────────────────────────────────────────────────
class DependenciesPage(QWidget):
    def __init__(self, win: "MainWindow") -> None:
        super().__init__()
        self.win = win
        box = QGroupBox("Tools and permissions")
        v = QVBoxLayout(box)
        self.table = _table(["Component", "Status", "Details"])
        self.table.setMinimumHeight(240)
        v.addWidget(self.table)
        row = QHBoxLayout()
        recheck = QPushButton("Re-check")
        recheck.clicked.connect(self.refresh)
        self.admin_btn = QPushButton("Restart as Administrator")
        self.admin_btn.clicked.connect(win.relaunch_elevated)
        row.addWidget(recheck)
        row.addWidget(self.admin_btn)
        row.addStretch(1)
        v.addLayout(row)

        get = QGroupBox("Get Nmap and Npcap")
        g = QVBoxLayout(get)
        g.addWidget(_hint(
            "These free tools are not included with the agent because their licences do not allow it. "
            "The buttons below download the official installer from nmap.org or npcap.com, check that it is "
            "signed by the Nmap project, and open it. You then go through the installer and accept its licence "
            "yourself. The Nmap installer can also install Npcap."))
        self.buttons: dict[str, QPushButton] = {}
        for key, tool in installers.TOOLS.items():
            r = QHBoxLayout()
            b = QPushButton(f"Download and install {tool.name}")
            b.clicked.connect(lambda _=False, k=key: self._install(k))
            self.buttons[key] = b
            lic = QLabel(f'{tool.purpose}. <a href="{tool.licence}">Licence</a>')
            lic.setOpenExternalLinks(True)
            lic.setWordWrap(True)
            r.addWidget(b)
            r.addWidget(lic, 1)
            g.addLayout(r)
        self.progress = QProgressBar()
        self.progress.hide()
        self.progress_text = QLabel()
        self.progress_text.setWordWrap(True)
        g.addWidget(self.progress)
        g.addWidget(self.progress_text)
        if sys.platform != "win32":
            for b in self.buttons.values():
                b.setEnabled(False)
            g.addWidget(_hint("On macOS and Linux, install them with your package manager (see the hints above)."))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(_page(box, get))
        self.refresh()

    def refresh(self) -> None:
        results = deps.check_all()
        self.table.setRowCount(len(results))
        for i, r in enumerate(results):
            status = "OK" if r.ok else ("Missing (required)" if r.required else "Not available")
            hint = r.hint if not r.ok and r.hint and r.name != "Administrator / root" else ""
            detail = r.detail + (f" ({r.version})" if r.version else "") + (f"\n{hint}" if hint else "")
            for col, value in enumerate([r.name, status, detail]):
                self.table.setItem(i, col, QTableWidgetItem(value))
        self.table.resizeRowsToContents()
        self.admin_btn.setVisible(not deps.is_admin())

    def _install(self, key: str) -> None:
        for b in self.buttons.values():
            b.setEnabled(False)
        self.progress.show()
        self.progress.setRange(0, 0)
        on_progress = self.on_progress        # looked up on the GUI thread (see controller.gui_call)

        def report(message: str, done: Optional[int], total: Optional[int]) -> None:   # worker thread
            gui_call(on_progress, message, done if done is not None else -1, total or 0)

        def finished(result: Any, error: Optional[BaseException]) -> None:
            for b in self.buttons.values():
                b.setEnabled(sys.platform == "win32")
            self.progress.hide()
            if error:
                self.progress_text.setText(f"✖ {error}")
            else:
                self.progress_text.setText(
                    f"The {result.tool.name} {result.version} installer is open. Finish it, then press Re-check.")

        run_in_thread(lambda: installers.fetch_and_launch(key, report), finished)

    def on_progress(self, message: str, done: int, total: int) -> None:
        self.progress_text.setText(message)
        if total > 0 and done >= 0:
            self.progress.setRange(0, 1000)
            self.progress.setValue(int(done * 1000 / total))
            self.progress_text.setText(f"{message}: {done / 2**20:.1f} of {total / 2**20:.1f} MB")
        else:
            self.progress.setRange(0, 0)


# ── Log ───────────────────────────────────────────────────────────────────
class LogPage(QWidget):
    def __init__(self, win: "MainWindow", log_dir: Path) -> None:
        super().__init__()
        self.log_dir = log_dir
        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(5000)
        self.view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        row = QHBoxLayout()
        open_btn = QPushButton("Open log folder")
        open_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.log_dir))))
        clear = QPushButton("Clear view")
        clear.clicked.connect(self.view.clear)
        row.addWidget(open_btn)
        row.addWidget(clear)
        row.addStretch(1)
        row.addWidget(_hint(f"Also written to {log_dir}"))
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.addWidget(self.view, 1)
        layout.addLayout(row)

    def append(self, level: int, line: str) -> None:
        self.view.appendPlainText(line)
