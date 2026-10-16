"""SBOM pipeline: list this computer's packages (Syft), check them for CVEs (Grype),
upload both. See eagleeye/sbom.py for the folders and what is sent."""

from __future__ import annotations

from typing import Any, Callable, Optional

from .. import sbom
from ..api import AgentClient
from ..pipeline.runner import Cancelled, PipelineContext, Stage, StageError


class SbomBuildStage(Stage):
    name = "sbom"
    label = "List installed packages (Syft)"

    def __init__(self, extra_paths: str = "", find_tool: Callable[[str], Optional[str]] = sbom.find_tool,
                 runner: Optional[sbom.Runner] = None, include_binaries: bool = False) -> None:
        self.extra_paths = extra_paths
        self.include_binaries = include_binaries
        self.find_tool = find_tool
        self.runner = runner

    def run(self, ctx: PipelineContext) -> None:
        # Both tools are checked first, so a missing Grype fails the run before a long scan.
        tools = {name: self.find_tool(name) for name in ("syft", "grype")}
        missing = [name for name, path in tools.items() if not path]
        if missing:
            raise StageError(" and ".join(n.capitalize() for n in missing) + " not installed on this computer. "
                             + " | ".join(sbom.install_hint(n) for n in missing))
        roots = sbom.scan_roots(self.extra_paths)
        runner = self.runner or (lambda cmd, timeout: sbom._run(cmd, timeout, ctx.cancelled))
        try:
            built = sbom.build_sbom(tools["syft"], roots, runner, ctx.progress,  # type: ignore[arg-type]
                                    include_binaries=self.include_binaries, cancelled=ctx.cancelled)
        except sbom.SbomCancelled as exc:
            raise Cancelled(str(exc)) from exc
        except sbom.SbomError as exc:
            raise StageError(str(exc)) from exc
        ctx.summary.update(grype=tools["grype"], sbom=built.document, sbom_scope=built.scope)
        for reason in built.skipped:
            ctx.progress(f"Skipped {reason}")
        ctx.progress(f"{len(built.document['components'])} package(s) in {len(built.scope)} folder(s)")


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

    def __init__(self, client: AgentClient) -> None:
        self.client = client

    def run(self, ctx: PipelineContext) -> None:
        scan_id = ctx.scan_id
        if not scan_id:
            raise StageError("no scan record to upload to")
        ok, detail = self.client.send_sbom(scan_id, sbom.slim_document(ctx.summary["sbom"]), ctx.summary.get("sbom_scope") or [])
        if not ok:
            raise StageError(detail)
        ok, detail = self.client.send_cve_findings(scan_id, ctx.summary.get("findings") or [])
        if not ok:
            raise StageError(detail)
        ctx.progress(detail)


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
