"""The pages of the main window."""

from __future__ import annotations

import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Optional

from PySide6.QtCore import Qt, QTime, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QRadioButton, QScrollArea, QSpinBox,
    QTableWidget, QTableWidgetItem, QTextBrowser, QTimeEdit, QVBoxLayout, QWidget,
)

from .. import deps, installers
from ..api import AgentClient
from ..enrol import ConnectionCodeError, parse_connection_code
from ..netinfo import local_ip, local_network
from ..pipeline import EventKind, Pipeline, PipelineContext, PipelineEvent
from ..privacy import NOTICE_HTML
from ..schedule import Schedule
from ..stages import InventoryDryRunStage, LocalInventoryStage
from . import theme
from .controller import gui_call, run_in_thread
from .widgets import FieldGrid, Notice, PageHeader, Panel, TraceLoader, button, divider, label, set_tone

if TYPE_CHECKING:
    from .app import MainWindow

TRIGGERS = {"dashboard": "Dashboard", "schedule": "Schedule", "manual": "Scan now / button", "auto": "Automatic",
            "new_device": "New device found"}
TASKS = {"active": "Active scan", "passive": "Passive upload", "inventory": "Inventory", "sbom": "SBOM + CVE check"}


def _fmt(dt: Optional[datetime]) -> str:
    if dt is None:
        return "-"
    return dt.strftime("%H:%M:%S") if dt.date() == datetime.now().date() else dt.strftime("%d %b %H:%M")


def _hint(text: str) -> QLabel:
    return label(text, "hint", wrap=True)


def _scroll(*widgets: QWidget) -> QScrollArea:
    """A scrollable column: the page header, then its panels."""
    body = QWidget()
    body.setObjectName("pageBody")
    layout = QVBoxLayout(body)
    layout.setContentsMargins(24, 22, 24, 24)
    layout.setSpacing(16)
    for i, w in enumerate(widgets):
        layout.addWidget(w)
        if i == 0 and isinstance(w, PageHeader):
            layout.addSpacing(4)
    layout.addStretch(1)
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setFrameShape(QScrollArea.Shape.NoFrame)
    area.setWidget(body)
    return area


def _root(page: QWidget, scroll: QWidget, footer: Optional[QWidget] = None) -> None:
    page.setObjectName("pageRoot")
    layout = QVBoxLayout(page)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(0)
    layout.addWidget(scroll, 1)
    if footer is not None:
        layout.addWidget(footer)


def _footer(*widgets: QWidget) -> QWidget:
    """The bar under a settings page that keeps Save in reach."""
    bar = QWidget()
    bar.setObjectName("footer")
    bar.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    h = QHBoxLayout(bar)
    h.setContentsMargins(24, 12, 24, 12)
    h.setSpacing(12)
    for w in widgets:
        h.addWidget(w, 1 if isinstance(w, QLabel) else 0)
    return bar


def _row(*widgets: QWidget, stretch_last: bool = False) -> QHBoxLayout:
    h = QHBoxLayout()
    h.setSpacing(10)
    for w in widgets:
        h.addWidget(w)
    if not stretch_last:
        h.addStretch(1)
    return h


NUMERIC = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter


def _table(headers: list[str], stretch: Optional[int] = None, numeric: Iterable[int] = ()) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels([h.upper() for h in headers])      # DESIGN Label: 11px uppercase
    t.setFont(theme.tabular(theme.font("body")))
    t.setProperty("numeric", list(numeric))
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(36)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setShowGrid(False)
    t.setFocusPolicy(Qt.FocusPolicy.TabFocus)
    t.setWordWrap(False)
    header = t.horizontalHeader()
    header.setFont(theme.font("label"))
    header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    header.setHighlightSections(False)
    header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    if stretch is None:
        header.setStretchLastSection(True)
    else:
        header.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)
    for col in numeric:
        head = t.horizontalHeaderItem(col)
        if head is not None:
            head.setTextAlignment(NUMERIC)
    return t


def fit_height(t: QTableWidget, minimum_rows: int = 0) -> None:
    """Size a table to its rows, so the page scrolls instead of the table."""
    rows = sum(t.rowHeight(r) for r in range(t.rowCount()))
    rows = max(rows, minimum_rows * t.verticalHeader().defaultSectionSize())
    t.setFixedHeight(t.horizontalHeader().sizeHint().height() + rows + 2)
    t.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)


def _item(text: str, tone: Optional[str] = None, mono: bool = False, tip: str = "",
          numeric: bool = False) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    if numeric:
        item.setTextAlignment(NUMERIC)
    pal = theme.current()
    if tone:
        item.setForeground(pal.q({"ok": "green", "warn": "amber", "error": "red", "muted": "text_muted"}[tone]))
    if mono:
        item.setFont(theme.font("mono"))
    if tip:
        item.setToolTip(tip)
    return item


def _indent(widget: QWidget, px: int = 26) -> QWidget:
    holder = QWidget()
    h = QHBoxLayout(holder)
    h.setContentsMargins(px, 0, 0, 0)
    h.addWidget(widget)
    return holder


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

        self.banner = Notice()

        # Now: what the agent is doing, and the buttons that make it do something
        now = Panel("Now")
        self.current = label("Idle", "lead")
        self.busy = TraceLoader()
        self.busy.hide()
        head = QHBoxLayout()
        head.setSpacing(12)
        head.addWidget(self.current)
        head.addWidget(self.busy, 0, Qt.AlignmentFlag.AlignVCenter)
        head.addStretch(1)
        now.add_layout(head)
        self.stage = _hint("")
        now.add(self.stage)
        now.add(divider())
        self.subnet = QComboBox()
        self.subnet.setEditable(True)
        self.subnet.setProperty("mono", True)
        self.subnet.setMinimumWidth(220)
        self.scan_btn = button("Scan now", "primary", "radar", self._scan_now)
        run = QHBoxLayout()
        run.setSpacing(10)
        run.addWidget(label("Network", "field"))
        run.addWidget(self.subnet, 1)
        run.addWidget(self.scan_btn)
        now.add_layout(run)
        self.inv_btn = button("Collect inventory now", None, "cpu", self._inventory_now)
        self.sbom_btn = button("Build SBOM now", None, "package", self._sbom_now)
        now.add_layout(_row(self.inv_btn, self.sbom_btn))
        now.add(_hint("Scans started here are recorded in the dashboard like the ones started there. "
                      "Your administrator can turn them off; the dashboard can still ask this agent to scan, "
                      "to collect this computer's inventory or to build its SBOM. The agent must be running."))

        conn = Panel("Connection")
        grid = FieldGrid(2)
        grid.setColumnStretch(1, 3)
        grid.setColumnStretch(3, 2)
        self.server = label("", "mono", wrap=True, selectable=True)
        self.agent = label("", "mono", wrap=True, selectable=True)
        self.heartbeat = label("", "value", wrap=True)
        self.passive_on = label("", "value", wrap=True)
        self.local_scans = label("", "value", wrap=True)
        grid.add("Server", self.server, 0)
        grid.add("Agent ID", self.agent, 0)
        grid.add("Last heartbeat", self.heartbeat, 1)
        grid.add("Passive listening", self.passive_on, 1)
        grid.add("Scans from here", self.local_scans, 1)
        conn.add_layout(grid)

        recent = Panel("Recent activity", flush=True)
        self.table = _table(["Finished", "Task", "Started by", "Target", "Result", "Hosts", "Took"], stretch=3,
                            numeric=(5, 6))
        self.empty = _hint("No runs yet. Scans, inventories and SBOMs are listed here as they finish.")
        self.empty.setContentsMargins(19, 4, 19, 19)
        recent.add(self.empty, self.table)
        self.table.hide()

        _root(self, _scroll(PageHeader("Status", "What this agent is doing now, how it reaches the dashboard and "
                                                 "what it finished recently."),
                            self.banner, now, conn, recent))
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
            self.stage.show()

    def _inventory_now(self) -> None:
        svc = self.win.controller.service
        if svc is not None:
            svc.request_inventory()
            self.stage.setText("Collecting this computer's inventory...")
            self.stage.show()

    def _sbom_now(self) -> None:
        # The button is unavailable while any SBOM runs (refresh), so this always starts one.
        svc = self.win.controller.service
        if svc is not None:
            self.stage.setText("Building this computer's full SBOM (this can take 10-30 minutes)...")
            self.stage.show()
            svc.request_sbom()

    def on_event(self, event: PipelineEvent) -> None:
        self.stage.show()
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
            self.banner.set_action("Open Settings", lambda: self.win.show_page(self.win.settings_page))
            self.banner.show()
        elif not ctrl.running:
            self.banner.setText("The agent is stopped. Press <b>Start</b> to connect.")
            self.banner.set_action("Start", self.win.toggle)
            self.banner.show()
        else:
            self.banner.hide()

        self.server.setText(s.api_url or "-")
        self.agent.setText(s.agent_id or "-")
        if svc is None or svc.last_heartbeat_at is None:
            self.heartbeat.setText("-" if svc is None else "connecting...")
            set_tone(self.heartbeat, None)
        else:
            state = "OK" if svc.last_heartbeat_ok else "failed (see Log)"
            self.heartbeat.setText(f"{state} at {_fmt(svc.last_heartbeat_at)}")
            set_tone(self.heartbeat, "ok" if svc.last_heartbeat_ok else "error")
        suite = getattr(svc, "suite", None) if svc is not None else None
        if not s.passive:
            self.passive_on.setText("off (Settings > Passive listening)")
            set_tone(self.passive_on, "muted")
        elif suite is None or suite.arp is None:
            self.passive_on.setText("-" if svc is None else "not running (see Dependencies)")
            set_tone(self.passive_on, None if svc is None else "warn")
        else:
            self.passive_on.setText(suite.listening_on)
            set_tone(self.passive_on, None)

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
        if svc is None:
            self.stage.setText("")
        elif not busy_bits and not self.stage.text():
            self.stage.setText("Waiting for the dashboard to ask for a scan, an inventory or an SBOM.")
        self.stage.setVisible(bool(self.stage.text()))
        local_ok = svc is None or svc.local_scans_allowed
        self.local_scans.setText("-" if svc is None else "allowed" if local_ok else
                                 "turned off by your administrator: scans are started from the dashboard")
        set_tone(self.local_scans, None if local_ok else "muted")
        self.scan_btn.setEnabled(svc is not None and local_ok and not svc.active_running)
        self.scan_btn.setToolTip("" if local_ok else "Your administrator has turned off scans started on this "
                                 "computer. Active scans are started from the EagleEye dashboard.")
        self.inv_btn.setEnabled(svc is not None and s.inventory and not svc.inventory_running)
        self.inv_btn.setToolTip("" if s.inventory else "Inventory is switched off on the Privacy page")
        # Unavailable during any SBOM run, like the dashboard's button and the other actions.
        sbom_busy = svc is not None and svc.sbom_running
        self.sbom_btn.setEnabled(svc is not None and s.sbom and not sbom_busy)
        self.sbom_btn.setToolTip("SBOM is switched off on the Privacy page" if not s.sbom
                                 else "An SBOM is being built; try again when it finishes" if sbom_busy else "")

        if svc is not None and len(svc.history) != self._history_len:
            self._history_len = len(svc.history)
            self._fill_history(list(svc.history))

    def restyle(self) -> None:
        self.banner.restyle()
        svc = self.win.controller.service if self.win.controller.running else None
        if svc is not None:
            self._fill_history(list(svc.history))

    def _fill_history(self, rows: list[Any]) -> None:
        self.table.setVisible(bool(rows))
        self.empty.setVisible(not rows)
        self.table.setRowCount(len(rows))
        for i, rec in enumerate(rows):
            result = {"ok": "OK", "failed": "Failed", "cancelled": "Cancelled"}.get(rec.status, rec.status)
            tone = {"ok": "ok", "failed": "error", "cancelled": "muted"}.get(rec.status)
            hosts = str(rec.hosts) if rec.pipeline not in ("inventory", "sbom") else "-"
            cells = [
                _item(_fmt(rec.finished_at)), _item(TASKS.get(rec.pipeline, rec.pipeline)),
                _item(TRIGGERS.get(rec.trigger, rec.trigger)), _item(rec.target, mono=True),
                _item(result, tone, tip=rec.error or ""), _item(hosts, numeric=True),
                _item(f"{rec.seconds:.0f}s", numeric=True),
            ]
            for col, item in enumerate(cells):
                self.table.setItem(i, col, item)
        fit_height(self.table)


# ── Schedules ─────────────────────────────────────────────────────────────
class ScheduleDialog(QDialog):
    def __init__(self, schedule: Schedule, parent=None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(parent)
        self.setWindowTitle("Scan schedule")
        self.schedule = schedule
        self.subnet = QLineEdit(schedule.subnet or default_subnet())
        self.subnet.setProperty("mono", True)
        self.daily = QRadioButton("Every day at")
        self.interval = QRadioButton("Every")
        self.time = QTimeEdit(QTime.fromString(schedule.time, "HH:mm") if schedule.time else QTime(2, 0))
        self.time.setDisplayFormat("HH:mm")
        self.hours = QSpinBox()
        self.hours.setRange(1, 168)
        self.hours.setSuffix(" hours")
        self.hours.setValue(max(1, min(168, schedule.hours)))
        theme.inset(self.hours)
        theme.inset(self.time)
        (self.daily if schedule.mode == "daily" else self.interval).setChecked(True)
        self.enabled = QCheckBox("Enabled")
        self.enabled.setChecked(schedule.enabled)

        grid = FieldGrid(1)
        grid.add("Network (IPv4 or CIDR)", self.subnet)
        d = QWidget()
        dl = QVBoxLayout(d)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.addLayout(_row(self.daily, self.time))
        dl.addLayout(_row(self.interval, self.hours))
        grid.add("When", d)
        grid.add("", self.enabled)
        self.error = QLabel()
        self.error.setProperty("role", "error")
        self.error.setWordWrap(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setProperty("role", "primary")
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)
        layout.addWidget(label("Scan schedule", "title"))
        layout.addLayout(grid)
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
        actions = [button("Add...", None, "plus", self._add), button("Edit...", None, "pencil", self._edit),
                   button("Remove", "danger", "trash-2", self._remove)]
        box = Panel("Scan schedules", actions, flush=True)
        self.table = _table(["Network", "When", "Next run", "Status"])
        self.empty = _hint("No schedules yet. Add one to scan a network on a timetable.")
        self.empty.setContentsMargins(19, 4, 19, 19)
        self.empty.hide()
        self.table.doubleClicked.connect(lambda _: self._edit())
        box.add(self.empty, self.table)
        _root(self, _scroll(PageHeader(
            "Schedules",
            "Active scans this agent runs by itself. Administrators can still start scans from the "
            "dashboard. Only one active scan runs at a time; a schedule that comes due during another "
            "scan waits for it. Schedules pause while your administrator has turned off scans started "
            "on this computer, and run again when they allow them."), box))
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
            problems = "; ".join(s.problems())
            status = "Off" if not s.enabled else (problems or "On")
            tone = "muted" if not s.enabled else "error" if problems else "ok"
            for col, item in enumerate([_item(s.subnet, mono=True), _item(s.describe()), _item(nxt), _item(status, tone)]):
                self.table.setItem(i, col, item)
        self.table.setVisible(bool(items))
        self.empty.setVisible(not items)
        fit_height(self.table)

    def restyle(self) -> None:
        self.refresh()


# ── Settings ──────────────────────────────────────────────────────────────
class SettingsPage(QWidget):
    def __init__(self, win: "MainWindow") -> None:
        super().__init__()
        self.win = win
        s = win.store.settings

        conn = Panel("Server")
        # One paste instead of three: the code from the dashboard's Agents page fills the
        # three fields below (nothing is saved until Save).
        self.code = QLineEdit()
        self.code.setEchoMode(QLineEdit.EchoMode.Password)          # it contains the API key
        self.code.setPlaceholderText("paste the code from the dashboard (starts with EE1.)")
        self.code.returnPressed.connect(self._use_code)
        use_code = button("Use code", None, "clipboard-paste", self._use_code)
        code_row = QWidget()
        cr = QHBoxLayout(code_row)
        cr.setContentsMargins(0, 0, 0, 0)
        cr.setSpacing(10)
        cr.addWidget(self.code, 1)
        cr.addWidget(use_code)
        top = FieldGrid(1)
        top.add("Connection code", code_row)
        conn.add_layout(top)
        conn.add(divider())
        conn.add(_hint("Or enter the three values yourself:"))
        self.api_url = QLineEdit(s.api_url)
        self.api_url.setPlaceholderText("https://.../api/v1")
        self.agent_id = QLineEdit(s.agent_id)
        self.agent_id.setProperty("mono", True)
        self.api_key = QLineEdit()
        self.api_key.setEchoMode(QLineEdit.EchoMode.Password)
        f = FieldGrid(1)
        f.add("API URL", self.api_url)
        f.add("Agent ID", self.agent_id)
        f.add("API key", self.api_key)
        self.key_hint = _hint("")
        f.add("", self.key_hint)
        self.test_btn = button("Test connection", None, "plug-zap", self._test)
        self.test_result = label("", wrap=True)
        test_row = QWidget()
        tr = QHBoxLayout(test_row)
        tr.setContentsMargins(0, 4, 0, 0)
        tr.setSpacing(12)
        tr.addWidget(self.test_btn)
        tr.addWidget(self.test_result, 1)
        f.add("", test_row)
        conn.add_layout(f)

        timing = Panel("Timing")
        t = FieldGrid(1)
        self.poll = self._spin(5, 3600, s.poll_interval, " s")
        self.heartbeat = self._spin(5, 3600, s.heartbeat_interval, " s")
        t.add("Check for dashboard scans every", _left(self.poll))
        t.add("Heartbeat every", _left(self.heartbeat))
        timing.add_layout(t)

        active = Panel("Active scanning")
        self.engine = QComboBox()
        for text, value in (("Nmap (built-in sweep when Nmap is missing)", "auto"),
                            ("EagleEye engine (no Nmap or Npcap needed)", "own"),
                            ("Both, and compare (writes a report on this computer)", "compare")):
            self.engine.addItem(text, value)
        self.engine.setCurrentIndex(max(0, self.engine.findData("auto" if s.scan_engine == "nmap" else s.scan_engine)))
        self.scan_ports = QComboBox()
        for text, value in (("Base: 13 server and remote-access ports", "base"),
                            ("Consumer: base + phones, TVs, printers, cameras (36)", "consumer"),
                            ("Wide: consumer + server, directory and industrial ports (90)", "wide")):
            self.scan_ports.addItem(text, value)
        self.scan_ports.setCurrentIndex(max(0, self.scan_ports.findData(s.scan_ports)))
        a = FieldGrid(1)
        a.add("Scan engine", self.engine)
        a.add("Ports (EagleEye engine)", self.scan_ports)
        active.add_layout(a)
        active.add(_hint("The EagleEye engine finds devices with ARP and names Windows machines from SMB "
                         "without logging in. Comparison reports go to the 'compare' folder next to the config file."))

        passive = Panel("Passive listening")
        self.passive = QCheckBox("Listen for ARP, mDNS, NetBIOS and DHCP announcements")
        self.passive.setChecked(s.passive)
        self.passive_iface = QLineEdit(s.passive_interface)
        self.passive_iface.setPlaceholderText("automatic")
        self.passive_interval = self._spin(10, 3600, s.passive_interval, " s")
        self.fingerbank = QLineEdit()
        self.fingerbank.setEchoMode(QLineEdit.EchoMode.Password)
        passive.add(self.passive)
        p = FieldGrid(1)
        p.add("Network interface", self.passive_iface)
        p.add("Upload what was heard every", _left(self.passive_interval))
        p.add("Fingerbank API key (optional)", self.fingerbank)
        passive.add_layout(p)
        passive.add(_hint("Needs Npcap and Administrator rights (see Dependencies)."))

        snmp = Panel("SNMPv3 polling of network devices (optional)")
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
        n = FieldGrid(2)
        n.add("User", self.snmp_user, 0)
        n.add("Auth key", self.snmp_auth, 0)
        n.add("Privacy key", self.snmp_priv, 0)
        n.add("", QWidget(), 1)
        n.add("Auth protocol", self.snmp_auth_proto, 1)
        n.add("Privacy protocol", self.snmp_priv_proto, 1)
        snmp.add_layout(n)

        self.save_btn = button("Save", "primary", "check", self._save)
        self.save_result = label("", wrap=True)
        _root(self, _scroll(PageHeader("Settings", "How this agent reaches the dashboard, how often it checks in, "
                                                   "and what it listens for on the network."),
                            conn, timing, active, passive, snmp),
              _footer(self.save_btn, self.save_result))
        self._secret_placeholders()

    @staticmethod
    def _spin(lo: int, hi: int, value: int, suffix: str) -> QSpinBox:
        sp = QSpinBox()
        sp.setRange(lo, hi)
        sp.setValue(max(lo, min(hi, value)))
        sp.setSuffix(suffix)
        sp.setMinimumWidth(120)
        sp.setMaximumWidth(140)
        theme.inset(sp)
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

    def show_problem(self, text: str) -> None:
        self._result(text, "error")

    def _result(self, text: str, tone: Optional[str]) -> None:
        self.test_result.setText(text)
        set_tone(self.test_result, tone)

    def _use_code(self) -> None:
        try:
            url, agent_id, key = parse_connection_code(self.code.text())
        except ConnectionCodeError as exc:
            self._result(str(exc), "error")
            return
        self.api_url.setText(url)
        self.agent_id.setText(agent_id)
        self.api_key.setText(key)
        self.code.clear()
        self._result("Filled in from the code. Choose Test connection, then Save.", None)

    def _test(self) -> None:
        s = self.win.store.settings
        url, agent, key = self.api_url.text().strip(), self.agent_id.text().strip(), self._secret(self.api_key, s.api_key)
        if not (url and agent and key):
            self._result("Enter the API URL, agent ID and API key first.", "error")
            return
        self.test_btn.setEnabled(False)
        self._result("Contacting the server...", "muted")

        def done(result: Any, error: Optional[BaseException]) -> None:
            self.test_btn.setEnabled(True)
            ok, text = result if result else (False, f"Error: {error}")
            self._result(text, "ok" if ok else "error")

        run_in_thread(lambda: AgentClient(url, key, agent).check_connection(), done)

    def _save(self) -> None:
        s = self.win.store.settings
        before = (s.api_url, s.agent_id, s.api_key)
        s.api_url = self.api_url.text().strip()
        s.agent_id = self.agent_id.text().strip()
        s.api_key = self._secret(self.api_key, s.api_key)
        s.poll_interval = self.poll.value()
        s.heartbeat_interval = self.heartbeat.value()
        s.scan_engine = self.engine.currentData()
        s.scan_ports = self.scan_ports.currentData()
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
        set_tone(self.save_result, "warn" if problems else "ok")

    def reload(self) -> None:
        s = self.win.store.settings
        self.passive.setChecked(s.passive)


def _left(widget: QWidget) -> QWidget:
    """A narrow control kept at its own width inside a stretching grid column."""
    holder = QWidget()
    h = QHBoxLayout(holder)
    h.setContentsMargins(0, 0, 0, 0)
    h.addWidget(widget)
    h.addStretch(1)
    return holder


# ── Privacy ───────────────────────────────────────────────────────────────
class PrivacyPage(QWidget):
    def __init__(self, win: "MainWindow") -> None:
        super().__init__()
        self.win = win

        notice = Panel("Notice")
        self.notice_text = QTextBrowser()
        self.notice_text.setOpenExternalLinks(True)
        self.notice_text.setMinimumHeight(280)
        notice.add(self.notice_text)
        self.consent = _hint("")
        notice.add(self.consent)

        inv = Panel("This computer's inventory")
        self.inventory = QCheckBox("Collect this computer's inventory")
        self.user_software = QCheckBox("Include software installed only for individual users (personal data)")
        self.admin_names = QCheckBox("Include the names of administrator accounts (personal data)")
        self.interval = QSpinBox()
        self.interval.setRange(1, 168)
        self.interval.setSuffix(" hours")
        self.interval.setMinimumWidth(120)
        self.interval.setMaximumWidth(140)
        theme.inset(self.interval)
        self.inventory.toggled.connect(self._enable)
        inv.add(self.inventory, _indent(self.user_software), _indent(self.admin_names))
        g = FieldGrid(1)
        g.add("Collect every", _left(self.interval))
        inv.add_layout(g)
        inv.add(divider())
        self.preview_btn = button("Preview what would be sent...", None, "eye", self._preview)
        self.preview_note = label("", "hint", wrap=True)
        row = QHBoxLayout()
        row.setSpacing(12)
        row.addWidget(self.preview_btn)
        row.addWidget(self.preview_note, 1)
        inv.add_layout(row)
        inv.add(_hint("Also collected when an administrator asks from the dashboard (Collect inventory). A "
                      "collection that fails, for example before the network is up after start-up, is tried "
                      "again a few minutes later. The preview collects the inventory on this computer and "
                      "shows it. Nothing is sent."))

        sb = Panel("Software packages (SBOM)")
        self.sbom = QCheckBox("List this computer's software packages and check them for known vulnerabilities")
        self.sbom_extra = QPlainTextEdit()
        self.sbom_extra.setProperty("mono", True)
        self.sbom_extra.setPlaceholderText("One folder per line, e.g. D:\\Apps")
        self.sbom_extra.setMaximumHeight(84)
        self.sbom_defaults = _hint("")
        self.sbom_binaries = QCheckBox("Include compiled programs (Go binaries, .exe/.dll, Linux kernel images)")
        binaries_hint = _hint("Many more findings, mostly ones only the program's vendor can fix.")
        self.sbom.toggled.connect(self.sbom_extra.setEnabled)
        self.sbom.toggled.connect(self.sbom_binaries.setEnabled)
        sb.add(self.sbom, _indent(self.sbom_binaries), _indent(binaries_hint, 52))
        g2 = FieldGrid(1)
        g2.add("Also scan", self.sbom_extra)
        g2.add("", self.sbom_defaults)
        sb.add_layout(g2)
        sb.add(_hint("Every day the agent lists again only the folders that changed; once a week, and whenever "
                     "you or an administrator ask (Build SBOM now, or Run SBOM scan on the dashboard), it lists "
                     "every folder. Uses Syft and Grype (see Dependencies). Only package names, versions and "
                     "licences are sent; no files or file paths."))

        save = button("Save", "primary", "check", self._save)
        self.result = label("", wrap=True)
        _root(self, _scroll(PageHeader("Privacy", "What this agent collects about this computer and sends to the "
                                                  "dashboard."),
                            inv, sb, notice),
              _footer(save, self.result))
        self.restyle()
        self.reload()

    def restyle(self) -> None:
        self.notice_text.document().setDefaultStyleSheet(theme.document_css(theme.current()))
        self.notice_text.setHtml(NOTICE_HTML)

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
        set_tone(self.result, "ok")
        self.win.settings_changed()

    def _preview(self) -> None:
        options = {"user_software": self.user_software.isChecked() and self.inventory.isChecked(),
                   "admin_names": self.admin_names.isChecked() and self.inventory.isChecked()}
        self.preview_btn.setEnabled(False)
        self.preview_note.setText("Collecting (this takes up to a minute)...")
        set_tone(self.preview_note, None)

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
                self.preview_note.setText(f"Preview failed: {error}")
                set_tone(self.preview_note, "error")
                return
            self.preview_note.setText("")
            JsonDialog("Inventory preview (not sent)", result, self).exec()

        run_in_thread(collect, done)


class JsonDialog(QDialog):
    def __init__(self, title: str, data: dict[str, Any], parent=None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(780, 660)
        self.data = data
        view = QPlainTextEdit(json.dumps(data, indent=2))
        view.setProperty("mono", True)
        view.setReadOnly(True)
        view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        save = buttons.addButton("Save as...", QDialogButtonBox.ButtonRole.ActionRole)
        save.clicked.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(12)
        layout.addWidget(label(title, "title"))
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
        recheck = button("Re-check", None, "refresh-cw", self.refresh)
        self.admin_btn = button("Restart as Administrator", None, "shield", win.relaunch_elevated)
        box = Panel("Tools and permissions", [recheck, self.admin_btn], flush=True)
        self.table = _table(["Component", "Status", "Details"])
        self.table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        box.add(self.table)

        get = Panel("Get Nmap and Npcap")
        get.add(_hint(
            "These free tools are not included with the agent because their licences do not allow it. "
            "The buttons below download the official installer from nmap.org or npcap.com, check that it is "
            "signed by the Nmap project, and open it. You then go through the installer and accept its licence "
            "yourself. The Nmap installer can also install Npcap."))
        self.buttons: dict[str, QPushButton] = {}
        for key, tool in installers.TOOLS.items():
            b = button(f"Download and install {tool.name}", None, "download")
            b.clicked.connect(lambda _=False, k=key: self._install(k))
            self.buttons[key] = b
            lic = QLabel(f'{tool.purpose}. <a href="{tool.licence}">Licence</a>')
            lic.setProperty("role", "hint")
            lic.setOpenExternalLinks(True)
            lic.setWordWrap(True)
            r = QHBoxLayout()
            r.setSpacing(12)
            r.addWidget(b)
            r.addWidget(lic, 1)
            get.add_layout(r)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.hide()
        self.progress_text = label("", wrap=True)
        get.add(self.progress, self.progress_text)
        if sys.platform != "win32":
            for b in self.buttons.values():
                b.setEnabled(False)
            get.add(_hint("On macOS and Linux, install them with your package manager (see the hints above)."))

        _root(self, _scroll(PageHeader("Dependencies", "The tools this agent uses for scans, passive listening and "
                                                       "SBOMs, and the rights it runs with."), box, get))
        self._results: list[Any] = []
        self.refresh()

    def refresh(self) -> None:
        self._results = deps.check_all()
        self._fill()
        self.admin_btn.setVisible(not deps.is_admin())

    def restyle(self) -> None:
        self._fill()

    def _fill(self) -> None:
        results = self._results
        self.table.setRowCount(len(results))
        for i, r in enumerate(results):
            status = "OK" if r.ok else ("Missing (required)" if r.required else "Not available")
            tone = "ok" if r.ok else ("error" if r.required else "warn")
            hint = r.hint if not r.ok and r.hint and r.name != "Administrator / root" else ""
            detail = r.detail + (f" ({r.version})" if r.version else "") + (f"\n{hint}" if hint else "")
            looks_like_path = ":\\" in r.detail or r.detail.startswith("/")
            cells = [_item(r.name), _item(status, tone), _item(detail, tip=detail, mono=looks_like_path)]
            for col, item in enumerate(cells):
                self.table.setItem(i, col, item)
        self.table.resizeRowsToContents()
        for row in range(self.table.rowCount()):
            self.table.setRowHeight(row, max(36, self.table.rowHeight(row) + 6))
        fit_height(self.table)

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
                self.progress_text.setText(str(error))
                set_tone(self.progress_text, "error")
            else:
                self.progress_text.setText(
                    f"The {result.tool.name} {result.version} installer is open. Finish it, then press Re-check.")
                set_tone(self.progress_text, None)

        run_in_thread(lambda: installers.fetch_and_launch(key, report), finished)

    def on_progress(self, message: str, done: int, total: int) -> None:
        self.progress_text.setText(message)
        set_tone(self.progress_text, None)
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
        self.view.setProperty("mono", True)
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(5000)
        self.view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.view.setPlaceholderText("Nothing logged yet in this session.")
        open_btn = button("Open log folder", None, "folder-open",
                          lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.log_dir))))
        clear = button("Clear view", "ghost", "eraser", self.view.clear)
        header = PageHeader("Log", "What the agent did in this session. Also written to", actions=[open_btn, clear])
        where = label(str(log_dir), "mono", selectable=True)
        header.layout().addWidget(where)
        self.setObjectName("pageRoot")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(18)
        layout.addWidget(header)
        layout.addWidget(self.view, 1)

    def append(self, level: int, line: str) -> None:
        self.view.appendPlainText(line)


def all_pages(win: "MainWindow") -> Iterable[QWidget]:
    return [w for w in (win.status_page, win.schedules_page, win.settings_page, win.privacy_page, win.deps_page,
                        win.log_page) if w is not None]
