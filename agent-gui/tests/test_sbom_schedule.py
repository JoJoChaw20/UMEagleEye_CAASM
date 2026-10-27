"""When SBOMs run (2.2.6): daily and weekly runs on their own times, Run now never moving
them, and what a request or a due run does while another SBOM is running."""

from __future__ import annotations

import threading
import time

import pytest

from eagleeye import sbom as sbom_tools
from test_service import SbomClient, service, wait_sbom

DAY = 86400


@pytest.fixture
def runs(monkeypatch):
    """SBOM runs that record whether they were full, and can be held running (gate) or
    made to fail (fail)."""
    from eagleeye.stages import sbom as sbom_stages
    state = {"modes": [], "gate": None, "fail": False}

    def build(self, ctx):
        state["modes"].append("full" if self.full else "quick")
        ctx.summary["sbom_full"] = self.full
        if state["gate"] is not None:
            state["gate"].wait(5)
        if state["fail"]:
            from eagleeye.pipeline.runner import StageError
            raise StageError("syft broke")
        ctx.summary.update(grype="grype", sbom={"specVersion": "1.6", "components": []}, sbom_scope=["/apps"])

    def check(self, ctx):
        ctx.summary["findings"] = []
    monkeypatch.setattr(sbom_stages.SbomBuildStage, "run", build)
    monkeypatch.setattr(sbom_stages.CveCheckStage, "run", check)
    monkeypatch.setattr(sbom_tools, "find_tool", lambda name: name)
    return state


def hold(runs):
    runs["gate"] = threading.Event()
    return runs["gate"]


def until(condition, timeout=5):
    deadline = time.time() + timeout
    while not condition() and time.time() < deadline:
        time.sleep(0.01)
    assert condition()


def test_the_first_daily_run_is_full_and_the_week_counts_from_it_then_daily_runs_are_quick(runs):
    client = SbomClient()
    svc = service(client)
    svc._next_sbom = 0
    svc.poll_once()
    wait_sbom(svc)
    assert runs["modes"] == ["full"] and client.sbom_modes == ["full"]
    assert svc.sbom_cache.last_full is not None and svc._next_sbom > time.time() + DAY - 60
    svc._next_sbom = 0
    svc.poll_once()
    wait_sbom(svc)
    assert runs["modes"] == ["full", "quick"] and client.sbom_modes[-1] == "quick"


def test_a_week_after_the_last_full_run_the_daily_run_is_full(runs):
    svc = service(SbomClient())
    svc.sbom_cache.last_full = time.time() - 7 * DAY - 1
    svc._next_sbom = 0
    svc.poll_once()
    wait_sbom(svc)
    assert runs["modes"] == ["full"]


def test_build_sbom_now_is_full_and_moves_neither_the_daily_nor_the_weekly_time(runs):
    svc = service(SbomClient())
    svc.sbom_cache.last_full = last_full = time.time() - DAY
    next_daily = svc._next_sbom
    svc.request_sbom()
    svc.poll_once()
    wait_sbom(svc)
    assert runs["modes"] == ["full"]
    assert svc._next_sbom == next_daily and svc.sbom_cache.last_full == last_full


def test_a_dashboard_job_is_full_and_does_not_move_the_daily_time(runs):
    client = SbomClient(pending=[{"scanId": "sb1", "scanType": "sbom", "subnet": "asset-id"}])
    svc = service(client)
    next_daily = svc._next_sbom
    svc.poll_once()
    wait_sbom(svc)
    assert client.sbom_starts == [("dashboard", "sb1")] and client.sbom_modes == ["full"]
    assert svc._next_sbom == next_daily


def test_build_sbom_now_during_a_daily_run_starts_a_full_run_after_it(runs):
    svc = service(SbomClient())
    svc.sbom_cache.last_full = time.time()                         # this week's full run is done
    gate = hold(runs)
    svc._next_sbom = 0
    svc.poll_once()
    until(lambda: runs["modes"] == ["quick"])
    svc.request_sbom()
    svc.poll_once()
    assert svc._sbom_wanted == "queued" and runs["modes"] == ["quick"]
    gate.set()
    wait_sbom(svc)
    runs["gate"] = None
    svc.poll_once()
    wait_sbom(svc)
    assert runs["modes"] == ["quick", "full"]


def test_build_sbom_now_during_a_full_run_is_answered_by_it(runs):
    svc = service(SbomClient())
    gate = hold(runs)
    svc.request_sbom()
    svc.poll_once()
    until(lambda: runs["modes"] == ["full"])
    svc.request_sbom()
    svc.poll_once()
    assert svc._sbom_wanted == "covered"
    gate.set()
    wait_sbom(svc)
    svc.poll_once()
    wait_sbom(svc)
    assert runs["modes"] == ["full"] and svc._sbom_wanted is None


def test_build_sbom_now_during_a_full_run_that_fails_still_runs(runs):
    svc = service(SbomClient())
    gate = hold(runs)
    runs["fail"] = True
    svc.request_sbom()
    svc.poll_once()
    until(lambda: runs["modes"] == ["full"])
    svc.request_sbom()
    svc.poll_once()
    gate.set()
    wait_sbom(svc)
    runs["gate"], runs["fail"] = None, False
    svc.poll_once()
    wait_sbom(svc)
    assert runs["modes"] == ["full", "full"]


def test_a_daily_run_due_during_a_full_run_is_answered_by_it_and_keeps_its_own_time(runs):
    svc = service(SbomClient())
    svc.sbom_cache.last_full = time.time()
    gate = hold(runs)
    svc.request_sbom()
    svc.poll_once()
    until(lambda: runs["modes"] == ["full"])
    due = time.time() - 5
    svc._next_sbom = due                                           # the daily run comes due meanwhile
    svc.poll_once()
    assert svc._sbom_due_waiting == due
    gate.set()
    wait_sbom(svc)
    svc.poll_once()
    wait_sbom(svc)
    assert runs["modes"] == ["full"] and svc._next_sbom == due + DAY


def test_a_weekly_run_due_during_a_full_run_counts_as_done_on_its_own_day(runs):
    svc = service(SbomClient())
    svc.sbom_cache.last_full = time.time() - 8 * DAY                # the weekly run is due
    gate = hold(runs)
    svc.request_sbom()
    svc.poll_once()
    until(lambda: runs["modes"] == ["full"])
    due = time.time() - 5
    svc._next_sbom = due
    svc.poll_once()
    gate.set()
    wait_sbom(svc)
    svc.poll_once()
    assert runs["modes"] == ["full"] and svc.sbom_cache.last_full == due


def test_a_daily_run_due_during_a_full_run_that_fails_runs_after_it(runs):
    svc = service(SbomClient())
    svc.sbom_cache.last_full = time.time()
    gate = hold(runs)
    runs["fail"] = True
    svc.request_sbom()
    svc.poll_once()
    until(lambda: runs["modes"] == ["full"])
    svc._next_sbom = time.time() - 5
    svc.poll_once()
    gate.set()
    wait_sbom(svc)
    runs["gate"], runs["fail"] = None, False
    svc.poll_once()
    wait_sbom(svc)
    assert runs["modes"] == ["full", "quick"] and svc._next_sbom > time.time() + DAY - 60


def test_a_failed_scheduled_full_run_leaves_the_week_due(runs):
    svc = service(SbomClient())
    runs["fail"] = True
    svc._next_sbom = 0
    svc.poll_once()
    wait_sbom(svc)
    assert runs["modes"] == ["full"] and svc.sbom_cache.last_full is None
