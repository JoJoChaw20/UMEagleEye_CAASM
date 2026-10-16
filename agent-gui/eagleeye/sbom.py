"""Software bill of materials (SBOM) of this computer, checked for known CVEs.

Syft lists the packages in a few folders (one run per folder), the results are merged
into one CycloneDX document, and Grype checks that document against its vulnerability
database. Neither tool ships with the agent; both are free downloads from Anchore
(see deps.py for where the agent looks for them).

Which folders: on Linux the whole system except volatile and personal areas (so the
OS packages are found); on Windows and macOS the places programs install to. An
administrator can add folders in the agent's settings. The dashboard cannot choose
a folder: the agent only ever scans what is configured on this computer.

Only package facts leave the computer (name, version, package URL, CPE, licences):
the uploaded SBOM drops Syft's per-file details such as the paths where each package
was found.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

SYFT_TIMEOUT = 45 * 60          # seconds, all folders together (walking Program Files takes minutes)
FOLDER_TIMEOUT = 10 * 60        # seconds for one program's folder (see scan_units)
SYFT_PARALLEL = 2               # Syft runs at once (each already uses every CPU core)
GRYPE_TIMEOUT = 20 * 60         # includes its first vulnerability-database download
CREATE_NO_WINDOW = 0x08000000

# Syft readers left out unless "include compiled programs" is on. On a test PC they made
# 90% of the findings and none a person could act on: Go standard-library CVEs flagged by
# the Go version a program was built with (Docker Desktop: only a Docker update fixes them),
# WSL's Linux kernel image (Microsoft's backported fixes are invisible to version matching),
# and Windows .exe/.dll version info (rarely matches a CVE). Turning them off does not make
# Syft faster: the time goes on walking the folders.
COMPILED_PROGRAM_CATALOGERS = ("go-module-binary-cataloger", "linux-kernel-cataloger", "pe-binary-package-cataloger")

# Windows' own folders, the same on every Windows 10/11 PC: Windows components and caches
# (Defender, the Store's app packages, the search index, installer caches), not third-party
# packages Syft could match to a CVE, and partly unreadable even for administrators.
# Compared case-insensitively against the folders directly inside Program Files,
# Program Files (x86) and ProgramData.
WINDOWS_OWNED = frozenset(name.lower() for name in (
    "WindowsApps", "ModifiableWindowsApps", "Windows Defender", "Windows Defender Advanced Threat Protection",
    "Windows Security", "Windows Mail", "Windows Media Player", "Windows NT", "Windows Photo Viewer",
    "Windows Sidebar", "Windows Portable Devices", "Microsoft Update Health Tools", "Uninstall Information",
    "Internet Explorer", "WindowsPowerShell",
    # ProgramData
    "Microsoft", "Package Cache", "Packages", "regid.1991-06.com.microsoft", "ssh", "USOPrivate", "USOShared",
))

# Syft exclude patterns are relative to the scanned folder.
COMMON_EXCLUDES = ("**/.git/**", "**/__pycache__/**", "**/.cache/**")
LINUX_EXCLUDES = (
    "./proc/**", "./sys/**", "./dev/**", "./run/**", "./tmp/**", "./var/tmp/**", "./var/cache/**",
    "./var/log/**", "./var/lib/docker/**", "./var/lib/containerd/**", "./snap/**", "./mnt/**",
    "./media/**", "./lost+found/**",
    # Personal folders: not scanned by default (an administrator can add one).
    "./home/**", "./root/**",
)


class SbomError(RuntimeError):
    """A failure with a message that is safe to show in the dashboard."""


class SbomCancelled(Exception):
    """The run was cancelled (dashboard Cancel, or the agent is stopping); the tool was stopped."""


# ── tools ──
def _tool_candidates(name: str) -> list[str]:
    exe = f"{name}.exe" if sys.platform == "win32" else name
    found = shutil.which(name)
    paths = [found] if found else []
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:   # winget's command aliases (not on PATH for every process)
            paths.append(str(Path(local) / "Microsoft" / "WinGet" / "Links" / exe))
        for var in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(var)
            if base:
                paths.append(str(Path(base) / name / exe))
    else:
        paths += [f"/usr/local/bin/{name}", f"/opt/homebrew/bin/{name}", f"/usr/bin/{name}"]
    from .config import config_dir
    paths.append(str(config_dir() / "tools" / exe))    # placed there by hand
    return paths


def find_tool(name: str) -> Optional[str]:
    """Path to the syft or grype executable, or None."""
    for path in _tool_candidates(name):
        if path and Path(path).is_file():
            return path
    return None


def tool_version(path: str) -> Optional[str]:
    try:
        out = subprocess.run([path, "version"], capture_output=True, text=True, timeout=20,
                             creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0).stdout
    except Exception:  # noqa: BLE001
        return None
    for line in out.splitlines():
        if line.lower().startswith("version:"):
            return line.split(":", 1)[1].strip()
    return None


INSTALL_HINTS = {
    "syft": {
        "win32": "winget install Anchore.Syft   (or download from https://github.com/anchore/syft/releases)",
        "linux": "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin",
        "darwin": "brew install syft",
    },
    "grype": {
        "win32": "winget install Anchore.Grype   (or download from https://github.com/anchore/grype/releases)",
        "linux": "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin",
        "darwin": "brew install grype",
    },
}


def install_hint(name: str) -> str:
    table = INSTALL_HINTS[name]
    return table.get(sys.platform if sys.platform in table else "linux", "")


# ── folders ──
def default_roots() -> list[str]:
    if sys.platform == "win32":
        roots = [os.environ.get(v) for v in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData")]
        appdata, local = os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA")
        if appdata:     # npm's global packages of the account the agent runs as
            roots.append(str(Path(appdata) / "npm" / "node_modules"))
        if local:       # Python installed "for me only"
            roots.append(str(Path(local) / "Programs" / "Python"))
        return [r for r in roots if r]
    if sys.platform == "darwin":
        return ["/Applications", "/usr/local", "/opt/homebrew"]
    return ["/"]


def parse_extra_paths(text: str) -> list[str]:
    """Extra folders from the settings: one per line (or separated by ';')."""
    out: list[str] = []
    for line in (text or "").replace(";", "\n").splitlines():
        line = line.strip().strip('"')
        if line:
            out.append(line)
    return out


def scan_roots(extra: str = "") -> list[str]:
    """Existing folders to scan, defaults first, without duplicates or folders inside
    another one already listed."""
    seen: list[Path] = []
    for raw in default_roots() + parse_extra_paths(extra):
        try:
            p = Path(os.path.expandvars(raw)).resolve()
        except OSError:
            continue
        if not p.is_dir():
            continue
        if any(p == s or s in p.parents for s in seen):
            continue
        seen = [s for s in seen if p not in s.parents] + [p]
    return [str(p) for p in seen]


def _is_link(path: Path) -> bool:
    """Symbolic links and Windows junctions (e.g. ProgramData's "Application Data", which
    points back at ProgramData itself): never followed."""
    try:
        return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())
    except OSError:
        return True


def _program_containers() -> set[Path]:
    """Folders whose subfolders are each one program: Program Files, (x86), ProgramData."""
    if sys.platform != "win32":
        return set()
    out = set()
    for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        value = os.environ.get(var)
        if value:
            try:
                out.add(Path(value).resolve())
            except OSError:
                pass
    return out


@dataclass(frozen=True)
class ScanUnit:
    path: str           # what Syft scans
    root: str           # the configured folder it belongs to (reported as scope)
    timeout: int        # its own time limit, in seconds


def scan_units(roots: list[str], containers: Optional[set[Path]] = None) -> tuple[list[ScanUnit], list[str]]:
    """What Syft runs on. Program Files, Program Files (x86) and ProgramData are split into
    their subfolders (one per program), each with its own time limit, so one huge or
    unreadable folder costs only itself instead of the whole SBOM; Windows' own folders and
    links are left out. Other folders (Linux '/', which must stay whole so Syft finds the
    distro, macOS, and the extra folders an administrator adds) are scanned whole.
    Returns the units and what was left out."""
    containers = _program_containers() if containers is None else containers
    units: list[ScanUnit] = []
    left_out: list[str] = []
    for root in roots:
        rp = Path(root)
        if rp.resolve() not in containers:
            units.append(ScanUnit(root, root, SYFT_TIMEOUT))
            continue
        try:
            children = sorted((c for c in rp.iterdir() if c.is_dir()), key=lambda c: c.name.lower())
        except OSError as exc:
            left_out.append(f"{root}: cannot be listed ({exc.strerror or exc})")
            continue
        for child in children:
            if child.name.lower() in WINDOWS_OWNED or _is_link(child):
                continue
            units.append(ScanUnit(str(child), root, FOLDER_TIMEOUT))
    return units, left_out


def excludes_for(root: str) -> list[str]:
    patterns = list(COMMON_EXCLUDES)
    if sys.platform not in ("win32", "darwin") and Path(root) == Path("/"):
        patterns += LINUX_EXCLUDES
    return patterns


# ── running the tools ──
Runner = Callable[[list[str], int], int]     # (command, timeout) -> exit code


def _run(command: list[str], timeout: int, cancelled: Callable[[], bool] = lambda: False) -> int:
    """Run a tool, stopping it when `cancelled()` turns true (checked every second) or
    when it runs past `timeout` seconds."""
    flags = CREATE_NO_WINDOW if sys.platform == "win32" else 0
    name = Path(command[0]).stem
    with tempfile.TemporaryFile() as err:     # a file, not a pipe: a chatty tool can never block on it
        proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=err, creationflags=flags)
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    proc.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    if cancelled():
                        raise SbomCancelled(f"{name} stopped: the scan was cancelled") from None
                    if time.monotonic() >= deadline:
                        raise SbomError(f"{name} did not finish within {timeout // 60} minutes") from None
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        if proc.returncode != 0:
            err.seek(0)
            detail = err.read().decode("utf-8", errors="replace").strip().splitlines()
            raise SbomError(f"{name} exited with code {proc.returncode}: {(detail[-1] if detail else '')[:300]}")
    return proc.returncode


@dataclass
class SbomRun:
    document: dict[str, Any]        # merged CycloneDX, as Syft wrote it (for Grype)
    scope: list[str]                # folders scanned
    skipped: list[str]              # folders Syft failed on, with the reason


def build_sbom(syft: str, roots: list[str], runner: Runner = _run,
               progress: Callable[[str], None] = lambda m: None, include_binaries: bool = False,
               cancelled: Callable[[], bool] = lambda: False,
               containers: Optional[set[Path]] = None) -> SbomRun:
    """Run Syft on each scan unit (SYFT_PARALLEL at a time, each within its own limit and
    all within SYFT_TIMEOUT) and merge the documents."""
    if not roots:
        raise SbomError("None of the folders to scan exist on this computer")
    units, skipped = scan_units(roots, containers)
    if not units:
        raise SbomError("No folder to scan. " + "; ".join(skipped)[:500])
    deadline = time.monotonic() + SYFT_TIMEOUT
    parts: dict[int, dict[str, Any]] = {}
    failed: dict[int, str] = {}
    done = [0]

    with tempfile.TemporaryDirectory(prefix="eagleeye-sbom-") as tmp:
        def scan(i: int, unit: ScanUnit) -> None:
            if cancelled():
                raise SbomCancelled("the scan was cancelled")
            limit = int(min(unit.timeout, deadline - time.monotonic()))
            if limit <= 0:
                failed[i] = "not scanned, the time limit for the whole SBOM was reached"
                return
            out = Path(tmp) / f"part{i}.json"
            cmd = [syft, "scan", f"dir:{unit.path}", "-o", f"cyclonedx-json={out}", "-q"]
            for pattern in excludes_for(unit.path):
                cmd += ["--exclude", pattern]
            if not include_binaries:
                cmd += ["--select-catalogers", ",".join(f"-{name}" for name in COMPILED_PROGRAM_CATALOGERS)]
            try:
                runner(cmd, limit)
                parts[i] = json.loads(out.read_text(encoding="utf-8", errors="replace"))
            except (SbomError, OSError, ValueError) as exc:
                failed[i] = str(exc)
            done[0] += 1
            progress(f"Listed {unit.path} ({done[0]}/{len(units)})")

        progress(f"Listing packages in {len(units)} folder(s), {SYFT_PARALLEL} at a time")
        with ThreadPoolExecutor(max_workers=SYFT_PARALLEL, thread_name_prefix="syft") as pool:
            futures = [pool.submit(scan, i, unit) for i, unit in enumerate(units)]
            try:
                for f in futures:
                    f.result()
            except SbomCancelled:
                for f in futures:
                    f.cancel()
                raise

    skipped += [f"{units[i].path}: {reason}" for i, reason in sorted(failed.items())]
    if not parts:
        raise SbomError("Syft could not scan any folder. " + "; ".join(skipped)[:500])
    scanned_roots = {units[i].root for i in parts}
    return SbomRun(merge_documents([parts[i] for i in sorted(parts)]), [r for r in roots if r in scanned_roots], skipped)


def _component_key(comp: dict[str, Any]) -> tuple[str, ...]:
    if comp.get("purl"):
        return ("purl", str(comp["purl"]).split("?")[0])
    return ("nv", str(comp.get("type")), str(comp.get("name")), str(comp.get("version")))


def merge_documents(docs: list[dict[str, Any]]) -> dict[str, Any]:
    """One CycloneDX document holding every distinct package of the parts. The
    operating-system component (which Grype uses to pick the distro's data) is kept;
    the per-folder 'file' root components and dependency graphs are dropped."""
    first = docs[0]
    components: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for doc in docs:
        for comp in doc.get("components") or []:
            if not isinstance(comp, dict) or comp.get("type") == "file":
                continue
            key = _component_key(comp)
            if key in seen:
                continue
            seen.add(key)
            components.append(comp)
    meta = dict(first.get("metadata") or {})
    meta.pop("component", None)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": first.get("specVersion", "1.6"),
        "version": 1,
        "metadata": meta,
        "components": components,
    }


def slim_document(doc: dict[str, Any]) -> dict[str, Any]:
    """What is uploaded: package facts only, no file paths or other Syft properties."""
    keep = ("type", "name", "version", "purl", "cpe", "licenses", "publisher", "group")
    meta = doc.get("metadata") or {}
    return {
        "bomFormat": "CycloneDX",
        "specVersion": doc.get("specVersion", "1.6"),
        "version": 1,
        "metadata": {k: meta[k] for k in ("timestamp", "tools") if k in meta},
        "components": [{k: c[k] for k in keep if c.get(k)} for c in doc.get("components") or []],
    }


def run_grype(grype: str, doc: dict[str, Any], runner: Optional[Callable[[list[str], int], str]] = None,
              cancelled: Callable[[], bool] = lambda: False) -> dict[str, Any]:
    """Grype's JSON report for the SBOM document."""
    with tempfile.TemporaryDirectory(prefix="eagleeye-grype-") as tmp:
        sbom_path = Path(tmp) / "sbom.json"
        out_path = Path(tmp) / "grype.json"
        sbom_path.write_text(json.dumps(doc), encoding="utf-8")
        cmd = [grype, f"sbom:{sbom_path}", "-o", f"json={out_path}", "-q"]
        if runner:
            return json.loads(runner(cmd, GRYPE_TIMEOUT))
        _run(cmd, GRYPE_TIMEOUT, cancelled)
        return json.loads(out_path.read_text(encoding="utf-8", errors="replace"))


# ── Grype report → findings for /sboms/ingest-cve ──
def _best_cvss(*vulns: dict[str, Any]) -> float:
    best = 0.0
    for v in vulns:
        for entry in v.get("cvss") or []:
            try:
                best = max(best, float((entry.get("metrics") or {}).get("baseScore") or 0))
            except (TypeError, ValueError):
                pass
    return best


def findings_from_grype(report: dict[str, Any]) -> list[dict[str, Any]]:
    """One finding per (CVE, package). Grype often matches a GitHub advisory (GHSA-...)
    whose CVE is in relatedVulnerabilities; the CVE is used so EPSS and CISA KEV can
    match it, and the advisory ID is kept alongside."""
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for match in report.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        related = match.get("relatedVulnerabilities") or []
        art = match.get("artifact") or {}
        vid = str(vuln.get("id") or "")
        if not vid or not art.get("name"):
            continue
        cve = vid if vid.startswith("CVE-") else next(
            (str(r.get("id")) for r in related if str(r.get("id") or "").startswith("CVE-")), vid)
        epss = next((e.get("epss") for e in vuln.get("epss") or [] if e.get("cve") == cve), None)
        cwes = sorted({str(c.get("cwe")) for c in vuln.get("cwes") or [] if c.get("cwe")})
        description = vuln.get("description") or next((r.get("description") for r in related if r.get("description")), "")
        finding = {
            "cve_id": cve,
            "advisory_id": vid if vid != cve else None,
            "severity": vuln.get("severity") or "Unknown",
            "description": (description or "")[:500],
            "cvss_base_score": _best_cvss(vuln, *related),
            "epss": float(epss) if isinstance(epss, (int, float)) else None,
            "package_name": str(art.get("name"))[:255],
            "package_version": str(art.get("version") or "")[:100],
            "package_type": str(art.get("type") or "")[:40] or None,
            "fix_versions": [str(v) for v in (vuln.get("fix") or {}).get("versions") or []][:10],
            "cwe_ids": cwes[:10],
        }
        key = (finding["cve_id"], finding["package_name"], finding["package_version"])
        if key not in by_key or finding["cvss_base_score"] > by_key[key]["cvss_base_score"]:
            by_key[key] = finding
    return list(by_key.values())
