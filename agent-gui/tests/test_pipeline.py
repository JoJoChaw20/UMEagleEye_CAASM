from __future__ import annotations

from eagleeye.pipeline import EventKind, Pipeline, PipelineContext, Stage, StageError
from eagleeye.pipeline.runner import Cancelled


class Ok(Stage):
    def __init__(self, name, optional=False, run=None, runs=True):
        self.name, self.label, self.optional = name, name.title(), optional
        self._run, self._runs, self.ran = run, runs, False

    def should_run(self, ctx):
        return self._runs

    def run(self, ctx):
        self.ran = True
        if self._run:
            self._run(ctx)


def boom(ctx):
    raise StageError("kaboom")


def test_runs_in_order_and_reports_ok():
    order = []
    stages = [Ok("a", run=lambda c: order.append("a")), Ok("b", run=lambda c: order.append("b"))]
    result = Pipeline("t", stages).run(PipelineContext("t"))
    assert result.ok and order == ["a", "b"]
    assert [s.status for s in result.stages] == ["ok", "ok"]


def test_required_stage_failure_stops_the_run():
    after = Ok("after")
    result = Pipeline("t", [Ok("a"), Ok("bad", run=boom), after]).run(PipelineContext("t"))
    assert result.status == "failed"
    assert result.error == "Bad failed: kaboom"
    assert not after.ran


def test_optional_stage_failure_does_not_stop_the_run():
    after = Ok("after")
    result = Pipeline("t", [Ok("opt", optional=True, run=boom), after]).run(PipelineContext("t"))
    assert result.ok and after.ran
    assert result.stages[0].status == "failed" and result.stages[0].error == "kaboom"


def test_unexpected_exception_becomes_a_failure_with_its_message():
    def raise_value_error(ctx):
        raise ValueError("bad input")

    result = Pipeline("t", [Ok("x", run=raise_value_error)]).run(PipelineContext("t"))
    assert result.status == "failed" and "bad input" in result.error


def test_skipped_stage():
    skipped = Ok("skip", runs=False)
    result = Pipeline("t", [skipped, Ok("go")]).run(PipelineContext("t"))
    assert result.ok and not skipped.ran
    assert result.stages[0].status == "skipped"


def test_cancel_between_stages():
    flag = {"stop": False}
    second = Ok("second")
    first = Ok("first", run=lambda c: flag.update(stop=True))
    ctx = PipelineContext("t", cancelled=lambda: flag["stop"])
    result = Pipeline("t", [first, second]).run(ctx)
    assert result.status == "cancelled" and not second.ran


def test_stage_can_cancel_itself():
    def cancel(ctx):
        raise Cancelled()

    assert Pipeline("t", [Ok("x", run=cancel)]).run(PipelineContext("t")).status == "cancelled"


def test_events_cover_the_whole_run():
    events = []

    def progress(ctx):
        ctx.progress("halfway", 1, 2)

    Pipeline("t", [Ok("a", run=progress), Ok("b", optional=True, run=boom)], events.append).run(PipelineContext("t"))
    kinds = [e.kind for e in events]
    assert kinds == [
        EventKind.PIPELINE_STARTED,
        EventKind.STAGE_STARTED, EventKind.STAGE_PROGRESS, EventKind.STAGE_FINISHED,
        EventKind.STAGE_STARTED, EventKind.STAGE_FAILED,
        EventKind.PIPELINE_FINISHED,
    ]
    progress_event = events[2]
    assert (progress_event.stage, progress_event.message, progress_event.current, progress_event.total) == ("a", "halfway", 1, 2)
