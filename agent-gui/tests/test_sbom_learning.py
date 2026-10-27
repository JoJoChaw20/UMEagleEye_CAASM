"""SBOM runs that learn and adapt (2.2.6): awake-time limits, folder fingerprints, the
per-folder cache (reuse, keep, learned limits), the weekly run's clock and upload retries."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from eagleeye import sbom
from eagleeye.pipeline import PipelineContext
from eagleeye.pipeline.runner import StageError
from eagleeye.stages import SbomBuildStage, SbomUploadStage

from test_sbom import doc, fake_syft, pkg


class Clock:
    """A clock the test moves by hand (seconds)."""

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def program_files(tmp_path, *names):
    pf = tmp_path / "Program Files"
    for name in names:
        (pf / name).mkdir(parents=True)
        (pf / name / "app.exe").write_bytes(name.encode())
    return pf


# ── time ──
def test_awake_time_leaves_out_a_long_gap_that_means_the_laptop_slept():
    real = Clock()
    awake = sbom.AwakeClock(real, gap=60)
    for t in (1, 2, 3):
        real.t = t
        awake()
    real.t = 3 + 27 * 60                   # 27 minutes of standby between two readings
    assert awake() == 3
    real.t += 1
    assert awake() == 4


def test_a_tool_past_its_limit_is_a_timeout_the_folder_can_learn_from():
    with pytest.raises(sbom.SbomTimeout, match="did not finish within"):
        sbom._run([sys.executable, "-c", "import time; time.sleep(30)"], 1)


# ── fingerprints ──
def test_the_fingerprint_changes_with_files_but_not_with_git_or_caches(tmp_path):
    app = tmp_path / "App"
    (app / "lib").mkdir(parents=True)
    (app / "lib" / "a.dll").write_bytes(b"x" * 10)
    first = sbom.fingerprint(str(app))
    assert first["files"] == 1 and first["bytes"] == 10 and first["errors"] == 0
    (app / ".git").mkdir()
    (app / ".git" / "index").write_bytes(b"y" * 99)
    assert sbom.fingerprint(str(app))["files"] == 1
    (app / "lib" / "b.dll").write_bytes(b"z")
    assert sbom.fingerprint(str(app)) != first


def test_an_office_update_check_is_not_a_change_and_its_updates_folder_is_not_listed(tmp_path):
    office = tmp_path / "Microsoft Office"
    (office / "root" / "Office16").mkdir(parents=True)
    (office / "root" / "Office16" / "word.dll").write_bytes(b"w")
    before = sbom.fingerprint(str(office))
    (office / "Updates" / "Download").mkdir(parents=True)          # the updater checked and downloaded
    (office / "Updates" / "Download" / "stream.cab").write_bytes(b"x" * 1000)
    assert sbom.fingerprint(str(office)) == before
    (office / "root" / "Office16" / "excel.dll").write_bytes(b"e")  # a real update
    assert sbom.fingerprint(str(office)) != before
    assert "./Updates/**" in sbom.excludes_for(str(office))
    assert "./Updates/**" not in sbom.excludes_for(str(tmp_path / "Git"))


# ── reuse and keep ──
def test_a_daily_run_lists_only_changed_folders_and_reuses_the_rest(tmp_path):
    pf = program_files(tmp_path, "A", "B")
    cache = sbom.FolderCache(tmp_path / "cache.json")
    run, calls = fake_syft({str(pf / "A"): doc(pkg("a", "1", "pkg:npm/a@1")), str(pf / "B"): doc(pkg("b", "1", "pkg:npm/b@1"))})
    full = sbom.build_sbom("syft", [str(pf)], run, containers={pf.resolve()}, cache=cache, full=True)
    assert [o.status for o in full.folders] == ["listed", "listed"] and len(calls) == 2

    (pf / "B" / "new.dll").write_bytes(b"new")                     # only B changed
    run2, calls2 = fake_syft({str(pf / "B"): doc(pkg("b", "2", "pkg:npm/b@2"))})
    cache2 = sbom.FolderCache(tmp_path / "cache.json")             # read back from disk
    daily = sbom.build_sbom("syft", [str(pf)], run2, containers={pf.resolve()}, cache=cache2, full=False)
    assert [c[2] for c in calls2] == [f"dir:{pf / 'B'}"]
    assert [(o.status, o.packages) for o in daily.folders] == [("unchanged", 1), ("listed", 1)]
    assert sorted(c["version"] for c in daily.document["components"]) == ["1", "2"]   # Grype sees A's too
    assert daily.document["metadata"]["tools"]                     # Syft's metadata survives reuse
    report = sbom.run_report(daily)
    assert (report["mode"], report["listed"], report["unchanged"]) == ("quick", 1, 1)


def test_a_full_run_lists_unchanged_folders_too(tmp_path):
    pf = program_files(tmp_path, "A")
    cache = sbom.FolderCache(None)
    run, calls = fake_syft([doc(pkg("a", "1", "pkg:npm/a@1")), doc(pkg("a", "1", "pkg:npm/a@1"))])
    sbom.build_sbom("syft", [str(pf)], run, containers={pf.resolve()}, cache=cache)
    sbom.build_sbom("syft", [str(pf)], run, containers={pf.resolve()}, cache=cache, full=True)
    assert len(calls) == 2


def test_a_folder_not_listed_keeps_its_last_packages_so_its_alerts_stay_open(tmp_path):
    pf = program_files(tmp_path, "A", "Office", "New")
    cache = sbom.FolderCache(tmp_path / "cache.json")
    run, _ = fake_syft({str(pf / "A"): doc(pkg("a", "1", "pkg:npm/a@1")),
                        str(pf / "Office"): doc(pkg("office-lib", "1", "pkg:nuget/office-lib@1")),
                        str(pf / "New"): sbom.SbomError("syft exited with code 1: access denied")})
    sbom.build_sbom("syft", [str(pf)], run, containers={pf.resolve()}, cache=cache)
    run2, _ = fake_syft({str(pf / "A"): doc(pkg("a", "1", "pkg:npm/a@1")),
                         str(pf / "Office"): sbom.SbomTimeout("syft did not finish within 10 minutes"),
                         str(pf / "New"): sbom.SbomError("syft exited with code 1: access denied")})
    again = sbom.build_sbom("syft", [str(pf)], run2, containers={pf.resolve()}, cache=cache)
    assert {c["name"] for c in again.document["components"]} == {"a", "office-lib"}
    assert {Path(o.path).name: o.status for o in again.folders} == {"A": "listed", "Office": "kept", "New": "missing"}
    report = sbom.run_report(again)
    assert [Path(k["folder"]).name for k in report["kept"]] == ["Office"] and report["kept"][0]["listed_at"]
    assert [Path(m["folder"]).name for m in report["missing"]] == ["New"]


def test_a_removed_folder_is_forgotten_so_its_alerts_can_close(tmp_path):
    pf = program_files(tmp_path, "A", "Gone")
    cache = sbom.FolderCache(None)
    run, _ = fake_syft({str(pf / "A"): doc(pkg("a", "1", "pkg:npm/a@1")), str(pf / "Gone"): doc(pkg("g", "1", "pkg:npm/g@1"))})
    sbom.build_sbom("syft", [str(pf)], run, containers={pf.resolve()}, cache=cache)
    (pf / "Gone" / "app.exe").unlink()
    (pf / "Gone").rmdir()                                          # uninstalled
    built = sbom.build_sbom("syft", [str(pf)], run, containers={pf.resolve()}, cache=cache, full=False)
    assert {c["name"] for c in built.document["components"]} == {"a"}
    assert list(cache.folders) == [str(pf / "A")]                 # and the cache forgets it


# ── learned limits ──
def test_a_timed_out_folder_gets_twice_the_time_and_runs_last_on_its_own(tmp_path):
    pf = program_files(tmp_path, "A", "B", "Office")
    cache = sbom.FolderCache(tmp_path / "cache.json")
    run, _ = fake_syft({str(pf / "A"): doc(), str(pf / "B"): doc(),
                        str(pf / "Office"): sbom.SbomTimeout("syft did not finish within 10 minutes")})
    sbom.build_sbom("syft", [str(pf)], run, containers={pf.resolve()}, cache=cache)
    office = str(pf / "Office")
    assert cache.folders[office]["limit"] == 2 * sbom.FOLDER_TIMEOUT and cache.folders[office]["timed_out"]

    order, limits = [], {}

    def record(cmd, timeout):
        name = Path(cmd[2][len("dir:"):]).name
        order.append(name)
        limits[name] = timeout
        out = next(a for a in cmd if a.startswith("cyclonedx-json=")).split("=", 1)[1]
        Path(out).write_text(json.dumps(doc()), encoding="utf-8")
        return 0
    sbom.build_sbom("syft", [str(pf)], record, containers={pf.resolve()}, cache=cache)
    assert order[-1] == "Office" and limits["Office"] == 2 * sbom.FOLDER_TIMEOUT
    assert not cache.folders[office].get("timed_out")              # listed: its time is learned again


def test_a_folder_learns_twice_its_listing_time_as_its_limit():
    unit = sbom.ScanUnit("x", "x", sbom.FOLDER_TIMEOUT)
    assert sbom.learned_limit(unit, 589) == 1178                   # Office: 589 s of a 600 s limit
    assert sbom.learned_limit(unit, 30) == sbom.FOLDER_TIMEOUT
    assert sbom.learned_limit(unit, 3000) == sbom.FOLDER_MAX_TIMEOUT
    assert sbom.raised_limit(unit, 50 * 60) == sbom.FOLDER_MAX_TIMEOUT


def test_when_the_whole_run_runs_out_of_time_the_rest_keep_their_packages_and_limits(tmp_path):
    pf = program_files(tmp_path, "A", "B")
    cache = sbom.FolderCache(None)
    run, _ = fake_syft({str(pf / n): doc(pkg(n, "1", f"pkg:npm/{n}@1")) for n in "AB"})
    sbom.build_sbom("syft", [str(pf)], run, containers={pf.resolve()}, cache=cache)
    limits = {p: e["limit"] for p, e in cache.folders.items()}

    clock = Clock()

    def slow_run(cmd, timeout):
        clock.t = sbom.SYFT_FULL_TIMEOUT + 1                       # the first folder used up the run's time
        return run(cmd, timeout)
    built = sbom.build_sbom("syft", [str(pf)], slow_run, containers={pf.resolve()}, cache=cache, clock=clock)
    assert sorted(o.status for o in built.folders) == ["kept", "listed"]
    assert {c["name"] for c in built.document["components"]} == {"A", "B"}
    kept = next(o for o in built.folders if o.status == "kept")
    assert "time limit for the whole SBOM" in kept.reason
    assert cache.folders[kept.path]["limit"] == limits[kept.path] and not cache.folders[kept.path].get("timed_out")


# ── the cache file ──
def test_the_cache_starts_over_for_another_setup_or_an_unreadable_file(tmp_path):
    path = tmp_path / "cache.json"
    cache = sbom.FolderCache(path)
    assert cache.use_setup({"syft": "1.44.0"}) is False            # nothing learned yet
    cache.folders["C:/A"] = {"components": []}
    cache.last_full = 100.0
    cache.save()
    again = sbom.FolderCache(path)
    assert again.use_setup({"syft": "1.44.0"}) is False and "C:/A" in again.folders
    assert again.use_setup({"syft": "1.45.0"}) is True and again.folders == {} and again.last_full is None
    path.write_text("{not json", encoding="utf-8")
    assert sbom.FolderCache(path).folders == {}
    assert not (tmp_path / "cache.json.tmp").exists()


def test_the_weekly_run_is_due_the_first_time_after_a_week_or_when_the_clock_went_back():
    cache = sbom.FolderCache(None)
    assert cache.weekly_due(1000.0)
    cache.last_full = 1000.0
    assert not cache.weekly_due(1000.0 + 6 * 86400)
    assert cache.weekly_due(1000.0 + 7 * 86400)
    assert cache.weekly_due(500.0)                                 # clock set back past the last run


def test_the_build_stage_lists_everything_when_nothing_is_learned_or_syft_changed(tmp_path, monkeypatch):
    monkeypatch.setattr(sbom, "scan_roots", lambda extra="": [str(tmp_path / "apps")])
    (tmp_path / "apps").mkdir()
    (tmp_path / "apps" / "x").write_text("x")
    cache = sbom.FolderCache(tmp_path / "c.json")
    run, calls = fake_syft([doc(pkg("a", "1", "pkg:npm/a@1"))] * 3)
    messages = []

    def stage_run(version):
        ctx = PipelineContext("sbom")
        ctx.progress = lambda m, *a: messages.append(m)
        SbomBuildStage(find_tool=lambda n: n, runner=run, cache=cache, full=False, tool_version=lambda p: version).run(ctx)
        return ctx
    assert stage_run("1.44.0").summary["sbom_full"] is True        # nothing learned yet: a full run
    assert stage_run("1.44.0").summary["sbom_full"] is False and len(calls) == 1   # unchanged: reused
    assert stage_run("1.45.0").summary["sbom_full"] is True and len(calls) == 2
    assert any("listing every folder again" in m for m in messages)


# ── upload ──
class UploadClient:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = 0
        self.run = None

    def send_sbom(self, scan_id, document, scope, run=None):
        self.calls += 1
        self.run = run
        return self.answers.pop(0)

    def send_cve_findings(self, scan_id, findings):
        return True, "alerts: 0 new"


def test_an_upload_right_after_waking_is_tried_again_until_the_network_is_back():
    client = UploadClient([(False, "could not reach the server: getaddrinfo failed"), (True, "5 package(s) stored")])
    waits = []
    ctx = PipelineContext("sbom", scan_id="s1")
    ctx.summary.update(sbom=doc(), sbom_run={"mode": "quick"})
    SbomUploadStage(client, sleep=waits.append).run(ctx)
    assert client.calls == 2 and len(waits) == 30 and client.run == {"mode": "quick"}


def test_an_upload_the_server_rejects_is_not_tried_again():
    client = UploadClient([(False, "server rejected the SBOM (HTTP 413)")])
    ctx = PipelineContext("sbom", scan_id="s1")
    ctx.summary.update(sbom=doc())
    with pytest.raises(StageError, match="413"):
        SbomUploadStage(client, sleep=lambda s: None).run(ctx)
    assert client.calls == 1
