from __future__ import annotations

import json
from pathlib import Path

import pytest

from eagleeye import sbom
from eagleeye.pipeline import Pipeline, PipelineContext
from eagleeye.pipeline.runner import StageError
from eagleeye.stages import CveCheckStage, SbomBuildStage, SbomDryRunStage

FIXTURES = Path(__file__).parent / "fixtures"
GRYPE = json.loads((FIXTURES / "grype_sample.json").read_text(encoding="utf-8"))


def doc(*components, os_component=None):
    comps = list(components) + ([os_component] if os_component else [])
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"tools": {"components": [{"name": "syft", "version": "1.44.0"}]},
            "component": {"type": "file", "name": "C:/x"}}, "components": comps}


def pkg(name, version, purl=None, **extra):
    c = {"type": "library", "name": name, "version": version,
         "properties": [{"name": "syft:location:0:path", "value": f"/secret/{name}"}], **extra}
    if purl:
        c["purl"] = purl
    return c


# ── Grype report → findings ──
def test_ghsa_matches_report_their_cve_so_epss_and_kev_can_match():
    findings = sbom.findings_from_grype(GRYPE)
    first = next(f for f in findings if f["advisory_id"] == "GHSA-x84v-xcm2-53pg")
    assert first["cve_id"] == "CVE-2018-18074"
    assert first["epss"] == pytest.approx(0.07443)
    assert first["cvss_base_score"] == 7.5
    assert first["package_name"] == "requests" and first["package_version"] == "2.19.0"
    assert first["fix_versions"] == ["2.20.0"]
    assert "CWE-522" in first["cwe_ids"]
    assert all(f["cve_id"].startswith("CVE-") for f in findings)


def test_a_cve_match_keeps_its_id_and_has_no_separate_advisory():
    report = {"matches": [{"vulnerability": {"id": "CVE-2024-0001", "severity": "Critical",
                                             "cvss": [{"metrics": {"baseScore": 9.8}}]},
                           "artifact": {"name": "openssl", "version": "3.0.1", "type": "deb"}}]}
    [f] = sbom.findings_from_grype(report)
    assert (f["cve_id"], f["advisory_id"], f["cvss_base_score"], f["epss"]) == ("CVE-2024-0001", None, 9.8, None)


def test_duplicate_matches_collapse_to_the_highest_score():
    m = {"vulnerability": {"id": "CVE-1", "cvss": [{"metrics": {"baseScore": 5.0}}]}, "artifact": {"name": "a", "version": "1"}}
    m2 = {"vulnerability": {"id": "CVE-1", "cvss": [{"metrics": {"baseScore": 8.0}}]}, "artifact": {"name": "a", "version": "1"}}
    [f] = sbom.findings_from_grype({"matches": [m, m2]})
    assert f["cvss_base_score"] == 8.0


# ── merging and slimming ──
def test_merge_drops_duplicates_and_folder_roots_but_keeps_the_os():
    osc = {"type": "operating-system", "name": "ubuntu", "version": "22.04"}
    a = doc(pkg("lodash", "4.17.15", "pkg:npm/lodash@4.17.15?package-id=1"), os_component=osc)
    b = doc(pkg("lodash", "4.17.15", "pkg:npm/lodash@4.17.15?package-id=2"), pkg("requests", "2.19.0", "pkg:pypi/requests@2.19.0"),
            {"type": "file", "name": "C:/y"})
    merged = sbom.merge_documents([a, b])
    names = [c["name"] for c in merged["components"]]
    assert names == ["lodash", "ubuntu", "requests"]
    assert "component" not in merged["metadata"]


def test_the_uploaded_document_has_no_file_paths():
    slim = sbom.slim_document(doc(pkg("requests", "2.19.0", "pkg:pypi/requests@2.19.0", cpe="cpe:2.3:a:python:requests:2.19.0")))
    [c] = slim["components"]
    assert c == {"type": "library", "name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0",
                 "cpe": "cpe:2.3:a:python:requests:2.19.0"}
    assert "/secret/" not in json.dumps(slim)


# ── folders ──
def test_scan_roots_skip_missing_duplicate_and_nested_folders(tmp_path, monkeypatch):
    apps = tmp_path / "Apps"
    (apps / "Tool").mkdir(parents=True)
    other = tmp_path / "Other"
    other.mkdir()
    monkeypatch.setattr(sbom, "default_roots", lambda: [str(apps)])
    extra = f"{apps / 'Tool'}\n{tmp_path / 'missing'}\n\"{other}\";{other}"
    assert sbom.scan_roots(extra) == [str(apps.resolve()), str(other.resolve())]


def test_an_extra_folder_containing_a_default_replaces_it(tmp_path, monkeypatch):
    inner = tmp_path / "a" / "b"
    inner.mkdir(parents=True)
    monkeypatch.setattr(sbom, "default_roots", lambda: [str(inner)])
    assert sbom.scan_roots(str(tmp_path / "a")) == [str((tmp_path / "a").resolve())]


def test_linux_root_scan_excludes_volatile_and_personal_folders(monkeypatch):
    monkeypatch.setattr(sbom.sys, "platform", "linux")
    patterns = sbom.excludes_for("/")
    assert "./proc/**" in patterns and "./home/**" in patterns
    assert "./home/**" not in sbom.excludes_for("/opt")


# ── running Syft ──
def fake_syft(results):
    """A runner that writes the document given for each folder (or raises its error).
    `results` maps folder -> document | Exception; a list is used in order."""
    calls = []
    queue = list(results) if isinstance(results, list) else None

    def run(cmd, timeout):
        calls.append(cmd)
        out = next(a for a in cmd if a.startswith("cyclonedx-json=")).split("=", 1)[1]
        folder = cmd[2][len("dir:"):]
        item = queue.pop(0) if queue is not None else results[folder]
        if isinstance(item, Exception):
            raise item
        Path(out).write_text(json.dumps(item), encoding="utf-8")
        return 0
    return run, calls


def test_build_merges_folders_and_reports_ones_that_failed():
    run, calls = fake_syft({"/one": doc(pkg("a", "1", "pkg:npm/a@1")), "/two": sbom.SbomError("syft exited with code 1: boom")})
    built = sbom.build_sbom("syft", ["/one", "/two"], run, containers=set())
    assert [c["name"] for c in built.document["components"]] == ["a"]
    assert built.scope == ["/one"] and "boom" in built.skipped[0]
    first = next(c for c in calls if c[2] == "dir:/one")
    assert first[:3] == ["syft", "scan", "dir:/one"] and "--exclude" in first
    assert first[first.index("--select-catalogers") + 1] == (
        "-go-module-binary-cataloger,-linux-kernel-cataloger,-pe-binary-package-cataloger")


def test_compiled_program_readers_can_be_switched_back_on():
    run, calls = fake_syft([doc(pkg("a", "1", "pkg:npm/a@1"))])
    sbom.build_sbom("syft", ["/one"], run, include_binaries=True, containers=set())
    assert "--select-catalogers" not in calls[0]


def test_build_fails_when_no_folder_could_be_scanned():
    run, _ = fake_syft([sbom.SbomError("nope")])
    with pytest.raises(sbom.SbomError, match="could not scan any folder"):
        sbom.build_sbom("syft", ["/one"], run, containers=set())


# ── the stages ──
def test_missing_tools_fail_before_scanning_with_install_hints():
    ctx = PipelineContext("sbom", scan_type="sbom")
    stage = SbomBuildStage(find_tool=lambda name: "syft" if name == "syft" else None)
    with pytest.raises(StageError, match="Grype not installed"):
        stage.run(ctx)


def test_dry_run_pipeline_builds_checks_and_hands_over_slim_documents(monkeypatch, tmp_path):
    monkeypatch.setattr(sbom, "default_roots", lambda: [str(tmp_path)])
    run, _ = fake_syft([doc(pkg("requests", "2.19.0", "pkg:pypi/requests@2.19.0"))])
    holder = {}
    stages = [SbomBuildStage(find_tool=lambda n: n, runner=run),
              CveCheckStage(runner=lambda cmd, timeout: json.dumps(GRYPE)), SbomDryRunStage(holder.update)]
    result = Pipeline("sbom", stages).run(PipelineContext("sbom", scan_type="sbom"))
    assert result.ok, result.error
    assert holder["scope"] == [str(tmp_path.resolve())]
    assert holder["sbom"]["components"][0]["name"] == "requests"
    assert {f["cve_id"] for f in holder["findings"]} >= {"CVE-2018-18074"}


def test_run_stops_the_tool_when_cancelled():
    import sys as _sys, time as _time
    started = _time.monotonic()
    with pytest.raises(sbom.SbomCancelled):
        sbom._run([_sys.executable, "-c", "import time; time.sleep(30)"], 60, cancelled=lambda: _time.monotonic() - started > 1)
    assert _time.monotonic() - started < 10


def test_run_reports_a_tools_error_line():
    import sys as _sys
    with pytest.raises(sbom.SbomError, match="boom"):
        sbom._run([_sys.executable, "-c", r"import sys; sys.stderr.write('first\nboom\n'); sys.exit(3)"], 60)



def test_program_folders_are_scanned_one_per_program_without_windows_own(tmp_path):
    pf = tmp_path / "Program Files"
    for name in ("Git", "JetBrains", "WindowsApps", "Windows Defender", "Microsoft Update Health Tools"):
        (pf / name).mkdir(parents=True)
    (pf / "readme.txt").write_text("x")
    extra = tmp_path / "Apps"
    extra.mkdir()
    units, left_out = sbom.scan_units([str(pf), str(extra)], containers={pf.resolve()})
    assert [Path(u.path).name for u in units] == ["Git", "JetBrains", "Apps"]
    assert {u.timeout for u in units[:2]} == {sbom.FOLDER_TIMEOUT} and units[2].timeout == sbom.SYFT_TIMEOUT
    assert all(u.root == str(pf) for u in units[:2]) and left_out == []


def test_one_slow_program_folder_costs_only_itself(tmp_path):
    pf = tmp_path / "Program Files"
    for name in ("A", "Slow", "Z"):
        (pf / name).mkdir(parents=True)
    run, calls = fake_syft({str(pf / "A"): doc(pkg("a", "1", "pkg:npm/a@1")),
                            str(pf / "Slow"): sbom.SbomError("syft did not finish within 5 minutes"),
                            str(pf / "Z"): doc(pkg("z", "1", "pkg:npm/z@1"))})
    built = sbom.build_sbom("syft", [str(pf)], run, containers={pf.resolve()})
    assert [c["name"] for c in built.document["components"]] == ["a", "z"]
    assert built.scope == [str(pf)]
    assert built.skipped == [f"{pf / 'Slow'}: syft did not finish within 5 minutes"]
    assert {c[2] for c in calls} == {f"dir:{pf / n}" for n in ("A", "Slow", "Z")}


def test_cancelling_stops_the_remaining_folders(tmp_path):
    pf = tmp_path / "Program Files"
    for name in ("A", "B", "C", "D"):
        (pf / name).mkdir(parents=True)
    run, calls = fake_syft({str(pf / n): doc() for n in "ABCD"})
    with pytest.raises(sbom.SbomCancelled):
        sbom.build_sbom("syft", [str(pf)], run, containers={pf.resolve()}, cancelled=lambda: len(calls) >= 1)
    assert len(calls) < 4
