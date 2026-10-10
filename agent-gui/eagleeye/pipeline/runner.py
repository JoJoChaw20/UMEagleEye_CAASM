"""Runs stages in order over a shared context.

Rules (mirroring the old agent's "enrichment is best effort"):
  * a stage marked `optional` that fails is reported and the run continues;
  * any other failure stops the run and is returned as the failure reason;
  * cancellation is checked between stages.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .events import EventKind, PipelineEvent
from .record import HostRecord

EventHandler = Callable[[PipelineEvent], None]


class Cancelled(Exception):
    """Raised by a stage (or the runner) when the run was cancelled."""


class StageError(Exception):
    """A stage failed with a message that is safe to show to the user."""


@dataclass
class PipelineContext:
    pipeline: str
    scan_id: Optional[str] = None
    subnet: Optional[str] = None
    scan_type: str = "active"
    hosts: list[HostRecord] = field(default_factory=list)
    network: Optional[dict[str, Any]] = None
    summary: dict[str, Any] = field(default_factory=dict)
    cancelled: Callable[[], bool] = lambda: False
    _emit: EventHandler = field(default=lambda event: None, repr=False)
    _stage: str = field(default="", repr=False)

    def progress(self, message: str, current: Optional[int] = None, total: Optional[int] = None) -> None:
        self._emit(PipelineEvent(EventKind.STAGE_PROGRESS, self.pipeline, self._stage, message, current, total))


class Stage:
    name = "stage"
    label = "Stage"
    optional = False

    def should_run(self, ctx: PipelineContext) -> bool:
        return True

    def run(self, ctx: PipelineContext) -> None:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass
class StageResult:
    name: str
    status: str            # ok | skipped | failed
    seconds: float = 0.0
    error: Optional[str] = None


@dataclass
class PipelineResult:
    status: str            # ok | failed | cancelled
    stages: list[StageResult] = field(default_factory=list)
    error: Optional[str] = None
    hosts: int = 0
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class Pipeline:
    def __init__(self, name: str, stages: list[Stage], on_event: Optional[EventHandler] = None) -> None:
        self.name = name
        self.stages = stages
        self._on_event = on_event or (lambda event: None)

    def run(self, ctx: PipelineContext) -> PipelineResult:
        ctx._emit = self._on_event
        started = time.monotonic()
        results: list[StageResult] = []

        def finish(status: str, error: Optional[str] = None) -> PipelineResult:
            result = PipelineResult(status, results, error, len(ctx.hosts), time.monotonic() - started)
            self._on_event(PipelineEvent(EventKind.PIPELINE_FINISHED, self.name, None, error or status))
            return result

        self._on_event(PipelineEvent(EventKind.PIPELINE_STARTED, self.name))
        for stage in self.stages:
            if ctx.cancelled():
                return finish("cancelled")
            ctx._stage = stage.name

            if not stage.should_run(ctx):
                results.append(StageResult(stage.name, "skipped"))
                self._on_event(PipelineEvent(EventKind.STAGE_SKIPPED, self.name, stage.name, stage.label))
                continue

            self._on_event(PipelineEvent(EventKind.STAGE_STARTED, self.name, stage.name, stage.label))
            t0 = time.monotonic()
            try:
                stage.run(ctx)
            except Cancelled:
                return finish("cancelled")
            except Exception as exc:  # noqa: BLE001 - a stage may fail in any way
                reason = str(exc) or exc.__class__.__name__
                results.append(StageResult(stage.name, "failed", time.monotonic() - t0, reason))
                self._on_event(PipelineEvent(EventKind.STAGE_FAILED, self.name, stage.name, reason))
                if stage.optional:
                    continue
                return finish("failed", f"{stage.label} failed: {reason}")

            results.append(StageResult(stage.name, "ok", time.monotonic() - t0))
            self._on_event(PipelineEvent(
                EventKind.STAGE_FINISHED, self.name, stage.name, stage.label, len(ctx.hosts), None,
            ))

        return finish("ok")
