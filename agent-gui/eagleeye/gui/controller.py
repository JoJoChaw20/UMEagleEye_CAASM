"""Runs the agent service on background threads and relays what happens to the window.

Background threads never touch Qt. They put plain Python calls on a queue with
`gui_call`, and a timer on the GUI thread runs them. The relayed calls are plain
Python callbacks, not Qt signals: with PySide6 6.12 on Python 3.13, emitting
signals under load aborted the process from inside PySide6 (seen on Windows, in
the GUI thread, with no Python frame below the emit).
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Callable, Optional

from PySide6.QtCore import QTimer

from ..config import Settings, sbom_cache_path, state_path as instance_state_path
from ..pipeline import PipelineEvent
from ..service import AgentService, log_event

log = logging.getLogger("eagleeye.gui")


def state_path():  # type: ignore[no-untyped-def]
    return instance_state_path()


# ── calls from any thread, run on the GUI thread ──
_inbox: "queue.SimpleQueue[tuple[Callable[..., Any], tuple[Any, ...]]]" = queue.SimpleQueue()
_pump: Optional[QTimer] = None


def gui_call(fn: Callable[..., Any], *args: Any) -> None:
    """Run fn(*args) on the GUI thread soon. Safe from any thread; touches no Qt object."""
    _inbox.put((fn, args))


def _drain() -> None:
    for _ in range(500):                 # bounded, so a log flood cannot freeze the window
        try:
            fn, args = _inbox.get_nowait()
        except queue.Empty:
            return
        try:
            fn(*args)
        except Exception:  # noqa: BLE001 - one bad callback must not stop the pump
            logging.getLogger("eagleeye.gui").exception("GUI callback failed")


def start_pump() -> None:
    """Start delivering queued calls. Must be called on the GUI thread."""
    global _pump
    if _pump is None:
        _pump = QTimer()
        _pump.timeout.connect(_drain)
        _pump.start(50)


def stop_pump() -> None:
    global _pump
    if _pump is not None:
        _pump.stop()
        _pump = None


class Listeners:
    """A list of plain callbacks, called in order on the GUI thread."""

    def __init__(self) -> None:
        self._fns: list[Callable[..., Any]] = []

    def connect(self, fn: Callable[..., Any]) -> None:
        self._fns.append(fn)

    def emit(self, *args: Any) -> None:
        for fn in list(self._fns):
            fn(*args)


class QtLogHandler(logging.Handler):
    """Forwards log records to the GUI's log view (via the queue)."""

    def __init__(self, sink: "AgentController") -> None:
        super().__init__(logging.INFO)
        self._deliver = sink.log_line.emit
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            gui_call(self._deliver, record.levelno, self.format(record))
        except Exception:  # noqa: BLE001
            self.handleError(record)


class AgentController:
    """Owns the agent service. A plain Python object (not a QObject), so worker
    threads may read its attributes freely."""

    def __init__(self) -> None:
        self.event = Listeners()             # (PipelineEvent)
        self.log_line = Listeners()          # (level, formatted line)
        self.running_changed = Listeners()   # (running: bool)
        self.service: Optional[AgentService] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _on_event(self, event: PipelineEvent) -> None:      # worker threads
        log_event(event)
        gui_call(self.event.emit, event)

    def start(self, settings: Settings) -> Optional[str]:
        """Start the agent. Returns the reason it cannot start, or None."""
        if self.running:
            return None
        problems = settings.problems()
        if problems:
            return "; ".join(problems)
        self.service = AgentService(settings, on_event=self._on_event, state_path=state_path(),
                                    sbom_cache_path=sbom_cache_path())
        service = self.service

        def run() -> None:
            try:
                service.run_forever()
            except Exception as exc:  # noqa: BLE001
                log.error("The agent stopped unexpectedly: %s", exc, exc_info=True)
            finally:
                gui_call(self.running_changed.emit, False)

        self._thread = threading.Thread(target=run, daemon=True, name="agent")
        self._thread.start()
        self.running_changed.emit(True)
        return None

    def stop(self) -> None:
        if self.service is not None:
            self.service.stop()
        self._thread = None
        self.running_changed.emit(False)

    def apply_live(self, settings: Settings) -> None:
        """Hand settings that need no restart (schedules) to the running service."""
        if self.service is not None:
            self.service.settings.schedules = list(settings.schedules)


def run_in_thread(fn: Callable[[], Any], on_done: Callable[[Any, Optional[BaseException]], None]) -> None:
    """Run fn on a worker thread, then call on_done(result, error) on the GUI thread."""

    def work() -> None:
        try:
            result: Any = fn()
        except BaseException as exc:  # noqa: BLE001 - reported to the caller
            gui_call(on_done, None, exc)
        else:
            gui_call(on_done, result, None)

    threading.Thread(target=work, daemon=True).start()
