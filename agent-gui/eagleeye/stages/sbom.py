"""SBOM pipeline: list this computer's packages (Syft), check them for CVEs (Grype),
upload both. See eagleeye/sbom.py for the folders and what is sent."""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

from .. import sbom
from ..api import TRY_AGAIN_LATER, AgentClient
from ..pipeline.runner import Cancelled, PipelineContext, Stage, StageError


class SbomBuildStage(Stage):
    name = "sbom"
    label = "List installed packages (Syft)"

    def __init__(self, extra_paths: str = "", find_tool: Callable[[str], Optional[str]] = sbom.find_tool,
                 runner: Optional[sbom.Runner] = None, include_binaries: bool = False,
                 cache: Optional[sbom.FolderCache] = None, full: bool = True,
                 tool_version: Callable[[str], Optional[str]] = sbom.tool_version) -> None:
        self.extra_paths = extra_paths
        self.include_binaries = include_binaries
        self.find_tool = find_tool
        self.runner = runner
        self.cache = cache
        self.full = full
        self.tool_version = tool_version

    def run(self, ctx: PipelineContext) -> None:
        # Both tools are checked first, so a missing Grype fails the run before a long scan.
        tools = {name: self.find_tool(name) for name in ("syft", "grype")}
        missing = [name for name, path in tools.items() if not path]
        if missing:
            raise StageError(" and ".join(n.capitalize() for n in missing) + " not installed on this computer. "
                             + " | ".join(sbom.install_hint(n) for n in missing))
        roots = sbom.scan_roots(self.extra_paths)
        runner = self.runner or (lambda cmd, timeout: sbom._run(cmd, timeout, ctx.cancelled))
        full = self.full
        if self.cache is not None:
            setup = {"syft": self.tool_version(tools["syft"]),  # type: ignore[arg-type]
                     "include_binaries": self.include_binaries, "excludes": list(sbom.COMMON_EXCLUDES)}
            if self.cache.use_setup(setup):
                ctx.progress("Syft or the SBOM settings changed since the last run: listing every folder again")
            if not self.cache.folders:
                full = True             # nothing learned yet: this run learns every folder
        ctx.summary["sbom_full"] = full
        try:
            built = sbom.build_sbom(tools["syft"], roots, runner, ctx.progress,  # type: ignore[arg-type]
                                    include_binaries=self.include_binaries, cancelled=ctx.cancelled,
                                    cache=self.cache, full=full)
        except sbom.SbomCancelled as exc:
            raise Cancelled(str(exc)) from exc
        except sbom.SbomError as exc:
            raise StageError(str(exc)) from exc
        ctx.summary.update(grype=tools["grype"], sbom=built.document, sbom_scope=built.scope,
                           sbom_run=sbom.run_report(built))
        report = ctx.summary["sbom_run"]
        older = len(report["kept"]) + len(report["missing"])
        ctx.progress(f"{len(built.document['components'])} package(s) from {report['folders']} folder(s): "
                     f"{report['listed']} listed, {report['unchanged']} unchanged"
                     + (f", {older} not listed this time" if older else "")
                     + f" ({'full' if full else 'daily'} run, {sbom._duration(built.seconds)})")


class CveCheckStage(Stage):
    name = "grype"
    label = "Check packages for known vulnerabilities (Grype)"

    def __init__(self, runner: Optional[Callable[[list[str], int], str]] = None) -> None:
        self.runner = runner

    def run(self, ctx: PipelineContext) -> None:
        ctx.progress("Checking packages against Grype's vulnerability database "
                     "(the first run downloads it, which takes a few minutes)")
        try:
            report = sbom.run_grype(ctx.summary["grype"], ctx.summary["sbom"], self.runner, ctx.cancelled)
        except sbom.SbomCancelled as exc:
            raise Cancelled(str(exc)) from exc
        except (sbom.SbomError, ValueError, OSError) as exc:
            raise StageError(f"Grype failed: {exc}") from exc
        findings = sbom.findings_from_grype(report)
        ctx.summary["findings"] = findings
        ctx.progress(f"{len(findings)} vulnerability finding(s)")


class SbomUploadStage(Stage):
    name = "upload"
    label = "Upload SBOM and vulnerabilities"
    # A run that ends just after the laptop wakes finds no network yet (26 Oct: "getaddrinfo
    # failed" for a while after standby). Wait and try again instead of losing the run.
    RETRY_DELAYS: tuple[float, ...] = (30.0, 60.0, 120.0)

    def __init__(self, client: AgentClient, sleep: Callable[[float], None] = time.sleep) -> None:
        self.client = client
        self.sleep = sleep

    def _send(self, ctx: PipelineContext, send: Callable[[], tuple[bool, str]]) -> str:
        delays = list(self.RETRY_DELAYS)
        while True:
            ok, detail = send()
            if ok:
                return detail
            if not detail.startswith(TRY_AGAIN_LATER) or not delays:
                raise StageError(detail)
            delay = delays.pop(0)
            ctx.progress(f"{detail}; trying again in {int(delay)} s")
            waited = 0.0
            while waited < delay:            # stays cancellable while it waits
                if ctx.cancelled():
                    raise Cancelled("the scan was cancelled")
                self.sleep(1.0)
                waited += 1.0

    def run(self, ctx: PipelineContext) -> None:
        scan_id = ctx.scan_id
        if not scan_id:
            raise StageError("no scan record to upload to")
        document = sbom.slim_document(ctx.summary["sbom"])
        self._send(ctx, lambda: self.client.send_sbom(scan_id, document, ctx.summary.get("sbom_scope") or [],
                                                      ctx.summary.get("sbom_run")))
        ctx.progress(self._send(ctx, lambda: self.client.send_cve_findings(scan_id, ctx.summary.get("findings") or [])))


class SbomDryRunStage(Stage):
    """Keeps the documents instead of uploading them (CLI --dry-run)."""
    name = "upload"
    label = "Prepare SBOM (dry run)"

    def __init__(self, sink: Optional[Callable[[dict[str, Any]], None]] = None) -> None:
        self.sink = sink

    def run(self, ctx: PipelineContext) -> None:
        if self.sink:
            self.sink({"sbom": sbom.slim_document(ctx.summary["sbom"]), "scope": ctx.summary.get("sbom_scope") or [],
                       "findings": ctx.summary.get("findings") or []})
