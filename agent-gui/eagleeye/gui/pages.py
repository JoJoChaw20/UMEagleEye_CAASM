"""The pages of the main window."""

from __future__ import annotations

import ipaddress
import json
import sys
from dataclasses import fields as dataclass_fields
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Optional

from PySide6.QtCore import Qt, QTime, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QRadioButton, QScrollArea, QSpinBox,
    QTableWidget, QTableWidgetItem, QTextBrowser, QTimeEdit, QVBoxLayout, QWidget,
)

from .. import deps
from ..api import AgentClient
from ..config import Settings, with_credentials
from ..enrol import ConnectionCodeError, credentials_from_code
from ..netinfo import local_ip, local_network
from ..pipeline import EventKind, Pipeline, PipelineContext, PipelineEvent
from ..privacy import NOTICE_HTML
from ..schedule import Schedule
from ..stages import InventoryDryRunStage, LocalInventoryStage
from . import theme
from .controller import run_in_thread
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


# Pages stop growing at this width: forms and short text read badly across a maximised window.
PAGE_MAX_WIDTH = 980


def _scroll(*widgets: QWidget) -> QScrollArea:
    """A scrollable column: the page header, then its panels, at most PAGE_MAX_WIDTH wide."""
    body = QWidget()
    body.setObjectName("pageBody")
    outer = QHBoxLayout(body)
    outer.setContentsMargins(24, 22, 24, 24)
    outer.setSpacing(0)
    column = QWidget()
    column.setObjectName("pageBody")
    column.setMaximumWidth(PAGE_MAX_WIDTH)
    layout = QVBoxLayout(column)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(16)
    for i, w in enumerate(widgets):
        layout.addWidget(w)
        if i == 0 and isinstance(w, PageHeader):
            layout.addSpacing(4)
    layout.addStretch(1)
    outer.addWidget(column, 1)
    outer.addStretch(0)
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
    """What the agent is doing. Since 2.6 every job starts from the dashboard (New scan, Collect
    inventory, Run SBOM scan), so this page only shows; nothing here starts a job."""

    def __init__(self, win: "MainWindow") -> None:
        super().__init__()
        self.win = win

        self.banner = Notice()

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
        now.add(_hint("Scans, inventories and SBOMs are started from your organisation's EagleEye dashboard, "
                      "on a schedule or by an administrator. This window shows what the agent is doing."))

        conn = Panel("Connection")
        grid = FieldGrid(2)
        grid.setColumnStretch(1, 3)
        grid.setColumnStretch(3, 2)
        self.server = label("", "mono", wrap=True, selectable=True)
        self.agent = label("", "mono", wrap=True, selectable=True)
        self.heartbeat = label("", "value", wrap=True)
        self.passive_on = label("", "value", wrap=True)
        grid.add("Server", self.server, 0)
        grid.add("Agent ID", self.agent, 0)
        grid.add("Last heartbeat", self.heartbeat, 1)
        grid.add("Passive listening", self.passive_on, 1)
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
        rejected = getattr(svc, "rejected", None) if svc is not None else None
        if rejected:
            self.banner.setText(rejected)
            self.banner.set_action("Open Setup", lambda: self.win.show_page(self.win.settings_page))
            self.banner.show()
        elif s.problems():
            self.banner.setText("Not set up yet: open <b>Setup</b> and paste the code from your administrator "
                                "(the dashboard's Agents page).")
            self.banner.set_action("Open Setup", lambda: self.win.show_page(self.win.settings_page))
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
        passive = effective_settings(self.win).get("passive", s.passive)
        if not passive:
            self.passive_on.setText("off (set on the dashboard)")
            set_tone(self.passive_on, "muted")
        elif suite is None or suite.arp is None:
            self.passive_on.setText("-" if svc is None else "not running (see Log)")
            set_tone(self.passive_on, None if svc is None else "warn")
        else:
            capture = getattr(suite, "capture", "")
            self.passive_on.setText(f"{suite.listening_on}, {capture}" if capture else suite.listening_on)
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
def managed_now(win: "MainWindow") -> dict[str, Any]:
    """The settings the administrator set for this agent (policy.py): what the running
    agent applied, or else what it applied last time (kept on disk)."""
    svc = win.controller.service if win.controller.running else None
    if svc is not None:
        return dict(getattr(svc, "managed", {}) or {})
    from ..policy import PolicyStore, policy_path
    return PolicyStore(policy_path(), agent_id=win.store.settings.agent_id).load()[1]








class SettingsPage(QWidget):
    """Setup: how this agent reaches the dashboard, and the tools it uses on this computer (as the
    agent service finds them). Everything the agent does is set on the dashboard (2.6); the Privacy
    page shows it."""

    def __init__(self, win: "MainWindow") -> None:
        super().__init__()
        self.win = win
        s = win.store.settings

        conn = Panel("Connection")
        # One paste instead of three: the code from the dashboard (a connection code, or an install
        # code that registers this computer) fills the three fields below; nothing is saved until Save.
        self.code = QLineEdit()
        self.code.setEchoMode(QLineEdit.EchoMode.Password)          # it contains the API key
        self.code.setPlaceholderText("paste the code from your administrator (starts with EE1. or EE2.)")
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

        # What the agent uses besides itself: Syft and Grype for the SBOM (scanning and listening are
        # built in), and the rights it runs with. Asked of the service: it runs as SYSTEM/root and
        # does not see tools installed for one user only, which this window would.
        self.recheck_btn = button("Re-check", "ghost", "refresh-cw", self.refresh_tools)
        self.admin_btn = button("Restart as Administrator", None, "shield", win.relaunch_elevated)
        self.admin_btn.hide()
        tools = Panel("Tools on this computer", [self.recheck_btn, self.admin_btn])
        self.tools_grid = FieldGrid(1)
        tools.add_layout(self.tools_grid)
        self.tools_note = _hint("")
        tools.add(self.tools_note)
        self._tool_rows: dict[str, tuple[QLabel, QLabel, QLabel]] = {}

        self.save_btn = button("Save", "primary", "check", self._save)
        self.save_result = label("", wrap=True)
        _root(self, _scroll(PageHeader("Setup", "How this agent reaches your organisation's EagleEye dashboard, and the "
                                                "tools it uses here. What it does is set on the dashboard; the Privacy "
                                                "page shows it."),
                            conn, tools),
              _footer(self.save_btn, self.save_result))
        self._secret_placeholders()
        self.refresh_tools()

    # ── tools ──
    def refresh_tools(self) -> None:
        """Ask the agent service what it finds (in the background), or check here without one."""
        ctrl = self.win.controller
        ask_service = getattr(self.win, "service_mode", False) and hasattr(ctrl, "tools")
        self.recheck_btn.setEnabled(False)
        self.tools_note.setText("Checking...")
        set_tone(self.tools_note, "muted")

        def check() -> tuple[list[Any], str]:
            if ask_service:
                try:
                    return [deps.DepStatus(**t) for t in ctrl.tools()], "service"
                except Exception:  # noqa: BLE001 - the service is stopped or older: say so, check here
                    pass
            return deps.agent_tools(service=False), "app" if not ask_service else "app-fallback"

        def done(result: Any, error: Optional[BaseException]) -> None:
            self.recheck_btn.setEnabled(True)
            if error or not result:
                self.tools_note.setText(f"Could not check the tools: {error}")
                set_tone(self.tools_note, "error")
                return
            self._fill_tools(*result)

        run_in_thread(check, done)

    def _fill_tools(self, results: list[Any], source: str) -> None:
        for r in results:
            if r.name not in self._tool_rows:
                state, detail, fix = label("", "value"), label("", "mono", wrap=True, selectable=True), _hint("")
                cell = QWidget()
                v = QVBoxLayout(cell)
                v.setContentsMargins(0, 0, 0, 0)
                v.setSpacing(2)
                for w in (state, detail, fix):
                    v.addWidget(w)
                self.tools_grid.add(r.name, cell)
                self._tool_rows[r.name] = (state, detail, fix)
            state, detail, fix = self._tool_rows[r.name]
            if r.name not in ("Syft", "Grype"):                       # Runs as, Vulnerability database
                state.setText(r.detail[:1].upper() + r.detail[1:])
                set_tone(state, None if r.ok or r.name != "Runs as" else "warn")   # a sentence, not a status word
                detail.hide()
            else:
                state.setText(f"Found{f', version {r.version}' if r.version else ''}" if r.ok else "Not found")
                set_tone(state, "ok" if r.ok else "warn")
                detail.setText(r.detail if r.ok else "")
                detail.setVisible(r.ok)
            fix.setText(r.hint if not r.ok and r.name in ("Syft", "Grype") else "")
            fix.setVisible(bool(fix.text()))
        missing = [r.name for r in results if not r.ok and r.name in ("Syft", "Grype")]
        note = {
            "service": "As the agent service sees them. ",
            "app-fallback": "The agent service did not answer, so this is what this window finds; the service may not "
                            "see tools installed for your account only. ",
            "app": "",
        }[source]
        self.tools_note.setText(note + ("Without Syft and Grype the dashboard cannot list this computer's software "
                                        "packages or check them for vulnerabilities (SBOM)." if missing else
                                        "Scanning and passive listening are built in: nothing else to install."))
        set_tone(self.tools_note, None)
        self.admin_btn.setVisible(source == "app" and not deps.is_admin())


    def _secret_placeholders(self) -> None:
        s = self.win.store.settings
        where = "the Windows Credential Manager" if sys.platform == "win32" else "the system keychain"
        where = where if self.win.store.keychain.available() else "the config file"
        self.api_key.clear()
        self.api_key.setPlaceholderText("saved (leave empty to keep)" if s.api_key else "")
        self.key_hint.setText(f"Shown once when the agent was registered. Secrets are kept in {where}.")

    def _secret(self, field: QLineEdit, current: str) -> str:
        return field.text().strip() or current

    def show_problem(self, text: str) -> None:
        self._result(text, "error")

    def _result(self, text: str, tone: Optional[str]) -> None:
        self.test_result.setText(text)
        set_tone(self.test_result, tone)

    def _use_code(self) -> None:
        """A connection code (this agent), or an install code: it registers this computer as an
        agent of its own, unless it already has one with that server."""
        from ..serviceinstall import agent_name
        s = self.win.store.settings
        try:
            url, agent_id, key, new = credentials_from_code(self.code.text(), agent_name(), s.kind, s)
        except ConnectionCodeError as exc:
            self._result(str(exc), "error")
            return
        self.api_url.setText(url)
        self.agent_id.setText(agent_id)
        self.api_key.setText(key)
        self.code.clear()
        self._result(("Registered this computer as a new agent. " if new else "Filled in from the code. ")
                     + "Choose Test connection, then Save.", None)

    def _test(self) -> None:
        s = self.win.store.settings
        url, agent, key = self.api_url.text().strip(), self.agent_id.text().strip(), self._secret(self.api_key, s.api_key)
        from .remote import SAVED_SECRET
        if key == SAVED_SECRET:                 # the service keeps the key: its own heartbeat is the test
            svc = self.win.controller.service
            if svc is None or svc.last_heartbeat_at is None:
                self._result("The agent service is not connected yet (see the Status page and the Log).", "error")
            elif svc.last_heartbeat_ok:
                self._result(f"Connected: the agent service's heartbeat was accepted at {svc.last_heartbeat_at:%H:%M:%S}.", "ok")
            else:
                self._result(f"The agent service's last heartbeat failed at {svc.last_heartbeat_at:%H:%M:%S} (see the Log).", "error")
            return
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
        url, agent_id = self.api_url.text().strip(), self.agent_id.text().strip()
        # Connected as another agent (a new code): the settings start again from the defaults.
        fresh = with_credentials(s, url, agent_id, self._secret(self.api_key, s.api_key))
        for f in dataclass_fields(Settings):
            setattr(s, f.name, getattr(fresh, f.name))
        failed = self.win.save_store()
        if failed:
            self.save_result.setText(failed)
            set_tone(self.save_result, "error")
            return
        self._secret_placeholders()
        problems = s.problems()
        started = self.win.settings_changed(connection_changed=(s.api_url, s.agent_id, s.api_key) != before)
        self.save_result.setText(
            "Saved, but: " + "; ".join(problems) if problems
            else "Saved. The agent is now running and connecting to the server." if started
            else "Saved.")
        set_tone(self.save_result, "warn" if problems else "ok")


def _left(widget: QWidget) -> QWidget:
    """A narrow control kept at its own width inside a stretching grid column."""
    holder = QWidget()
    h = QHBoxLayout(holder)
    h.setContentsMargins(0, 0, 0, 0)
    h.addWidget(widget)
    h.addStretch(1)
    return holder


# ── Privacy ───────────────────────────────────────────────────────────────
def effective_settings(win: "MainWindow") -> dict[str, Any]:
    """What this agent does: the dashboard's values (a 2.6 server sends them all), else this
    computer's settings until the dashboard has answered."""
    s = win.store.settings
    managed = managed_now(win)
    keys = ("inventory", "inventory_interval", "sbom", "passive")
    return {k: managed.get(k, getattr(s, k)) for k in keys}


class PrivacyPage(QWidget):
    """What this agent collects and does, as set on the dashboard, read-only; the notice; and a
    preview of the inventory it would send."""

    def __init__(self, win: "MainWindow") -> None:
        super().__init__()
        self.win = win

        what = Panel("What this agent does")
        grid = FieldGrid(1)
        self.values: dict[str, QLabel] = {}
        for key, title in (("inventory", "Collects this computer's inventory"),
                           ("sbom", "Lists its software packages and checks them for vulnerabilities (SBOM)"),
                           ("passive", "Listens for the devices on its network")):
            value = label("", "value", wrap=True)
            grid.add(title, value)
            self.values[key] = value
        what.add_layout(grid)
        what.add(_hint("Set by your administrator on the EagleEye dashboard (Agents page). The inventory lists the "
                       "software installed for everyone and by each signed-in user, and only the number of administrator "
                       "accounts. For the SBOM only package names, versions and licences are sent; no files or file paths."))
        what.add(divider())
        self.preview_btn = button("Preview what would be sent...", None, "eye", self._preview)
        self.preview_note = label("", "hint", wrap=True)
        row = QHBoxLayout()
        row.setSpacing(12)
        row.addWidget(self.preview_btn)
        row.addWidget(self.preview_note, 1)
        what.add_layout(row)
        what.add(_hint("The preview collects this computer's inventory here and shows it. Nothing is sent."))

        notice = Panel("Notice")
        self.notice_text = QTextBrowser()
        self.notice_text.setOpenExternalLinks(True)
        self.notice_text.setMinimumHeight(280)
        notice.add(self.notice_text)
        self.consent = _hint("")
        notice.add(self.consent)

        _root(self, _scroll(PageHeader("Privacy", "What this agent collects about this computer and sends to the "
                                                  "dashboard."), what, notice))
        self.restyle()
        self.reload()

    def restyle(self) -> None:
        self.notice_text.document().setDefaultStyleSheet(theme.document_css(theme.current()))
        self.notice_text.setHtml(NOTICE_HTML)

    def reload(self) -> None:
        e = effective_settings(self.win)
        yes_no = lambda on: "Yes" if on else "No"          # noqa: E731
        hours = max(1, round(int(e["inventory_interval"]) / 3600))
        self.values["inventory"].setText(f"Yes, every {hours} hour{'s' if hours != 1 else ''}" if e["inventory"] else "No")
        for key in ("sbom", "passive"):
            self.values[key].setText(yes_no(e[key]))
        s = self.win.store.settings
        try:
            accepted = datetime.fromisoformat(s.consent_at).strftime("%d %b %Y at %H:%M") if s.consent_at else ""
        except ValueError:
            accepted = s.consent_at
        self.consent.setText(f"Notice read on {accepted}." if accepted else "Notice not yet read.")

    def _preview(self) -> None:
        options = self.win.store.settings.inventory_options
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
    return [w for w in (win.status_page, win.schedules_page, win.settings_page, win.privacy_page,
                        win.log_page) if w is not None]
