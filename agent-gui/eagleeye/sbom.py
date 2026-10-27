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

Learning and adapting (2.2.6). A full run (the first one, the weekly one, and every
Run now) lists every folder and remembers, per folder, its packages, a fingerprint
(files, size, newest change), how long Syft took and the time limit it needs. A daily
run fingerprints every folder (seconds) and lists only those that changed; the others
reuse their remembered packages. Grype always checks the whole list, so a new CVE in an
unchanged folder is still found. A folder that could not be listed (timed out, failed,
or the run's time ran out) keeps its last known packages instead of dropping them,
which closed 436 alerts by mistake on 26 Oct. Measured on a test PC: 30 of 94 folders
held packages and took 80% of Syft's time; fingerprinting all 107,044 files took 12 s.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

log = logging.getLogger("eagleeye.sbom")

# Every limit counts only the time this computer is awake (AwakeClock).
SYFT_TIMEOUT = 45 * 60          # seconds, all folders together in a daily run
SYFT_FULL_TIMEOUT = 90 * 60     # ... in a full run, which lists every folder
FOLDER_TIMEOUT = 10 * 60        # seconds for one program's folder until its own time is learned
FOLDER_MAX_TIMEOUT = 60 * 60    # the most a learned (or doubled after a timeout) limit grows to
SYFT_PARALLEL = 2               # Syft runs at once (each already uses every CPU core)
GRYPE_TIMEOUT = 20 * 60         # includes its first vulnerability-database download
SLEEP_GAP = 60                  # seconds between two clock readings that mean the computer slept
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

# Folders inside a program's folder that only its updater writes to (update checks and
# downloads), holding no installed packages. Left out of the listing and the fingerprint,
# so an update check alone does not count as a change. Measured on a test PC: Office's
# Updates folder held 0 of its 392 packages, and its updater rewrote it on a day Office
# was already up to date, which would re-list Office (9 min) in every daily run.
UPDATER_FOLDERS = {"microsoft office": ("Updates",)}


def updater_folders(path: str) -> tuple[str, ...]:
    """The updater-only subfolders of a program folder (keyed by the folder's name)."""
    return UPDATER_FOLDERS.get(Path(path).name.lower(), ())
LINUX_EXCLUDES = (
    "./proc/**", "./sys/**", "./dev/**", "./run/**", "./tmp/**", "./var/tmp/**", "./var/cache/**",
    "./var/log/**", "./var/lib/docker/**", "./var/lib/containerd/**", "./snap/**", "./mnt/**",
    "./media/**", "./lost+found/**",
    # Personal folders: not scanned by default (an administrator can add one).
    "./home/**", "./root/**",
)


class SbomError(RuntimeError):
    """A failure with a message that is safe to show in the dashboard."""


class SbomTimeout(SbomError):
    """A tool ran past its own time limit (the folder may need a longer one)."""


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
    timeout: int        # its own time limit, in seconds, until a better one is learned
    # False for Linux '/': too big and too volatile (/proc) to fingerprint, so always listed.
    reusable: bool = True


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
            units.append(ScanUnit(root, root, SYFT_TIMEOUT, reusable=not (sys.platform != "win32" and rp == Path("/"))))
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
    patterns = list(COMMON_EXCLUDES) + [f"./{name}/**" for name in updater_folders(root)]
    if sys.platform not in ("win32", "darwin") and Path(root) == Path("/"):
        patterns += LINUX_EXCLUDES
    return patterns


# ── time ──
class AwakeClock:
    """Seconds this computer has been awake since the clock was made.

    time.monotonic() keeps counting through sleep and Modern Standby, so a limit measured
    with it ran out while the laptop slept (26 Oct: 27 of the SBOM's 45 minutes went by
    in standby, and 66 folders were never listed). The clock is read at least every
    second while a tool runs (_run polls, build_sbom keeps a ticker), so a longer gap
    between two readings is sleep and is not counted. Safe to read from several threads."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, gap: float = SLEEP_GAP) -> None:
        self._clock, self._gap = clock, gap
        self._lock = threading.Lock()
        self._last = clock()
        self._awake = 0.0

    def __call__(self) -> float:
        with self._lock:
            now = self._clock()
            step, self._last = now - self._last, now
            if 0 < step < self._gap:
                self._awake += step
            return self._awake


# ── running the tools ──
Runner = Callable[[list[str], int], int]     # (command, timeout) -> exit code


def _run(command: list[str], timeout: int, cancelled: Callable[[], bool] = lambda: False) -> int:
    """Run a tool, stopping it when `cancelled()` turns true (checked every second) or
    when it has run for `timeout` seconds of awake time."""
    flags = CREATE_NO_WINDOW if sys.platform == "win32" else 0
    name = Path(command[0]).stem
    with tempfile.TemporaryFile() as err:     # a file, not a pipe: a chatty tool can never block on it
        proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=err, creationflags=flags)
        awake = AwakeClock()
        try:
            while True:
                try:
                    proc.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    if cancelled():
                        raise SbomCancelled(f"{name} stopped: the scan was cancelled") from None
                    if awake() >= timeout:
                        raise SbomTimeout(f"{name} did not finish within {timeout // 60} minutes") from None
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        if proc.returncode != 0:
            err.seek(0)
            detail = err.read().decode("utf-8", errors="replace").strip().splitlines()
            raise SbomError(f"{name} exited with code {proc.returncode}: {(detail[-1] if detail else '')[:300]}")
    return proc.returncode


@contextmanager
def _ticking(clock: Callable[[], float], every: float = 1.0) -> Iterator[None]:
    """Read `clock` every second while the block runs, so a stretch of sleep shows up as
    one long gap even between two tools."""
    stop = threading.Event()

    def tick() -> None:
        while not stop.wait(every):
            clock()
    threading.Thread(target=tick, daemon=True, name="sbom-clock").start()
    try:
        yield
    finally:
        stop.set()


def _duration(seconds: float) -> str:
    minutes, secs = divmod(int(round(seconds)), 60)
    return f"{minutes} min {secs} s" if minutes else f"{secs} s"


def _date(ts: Optional[float]) -> str:
    return datetime.fromtimestamp(ts).strftime("%d %b %Y %H:%M") if ts else "an unknown date"


# ── what earlier runs learned ──
CACHE_FORMAT = 1
WEEK_SECONDS = 7 * 86400
_FINGERPRINT_SKIP = frozenset((".git", "__pycache__", ".cache"))     # what COMMON_EXCLUDES leaves out


def fingerprint(path: str) -> dict[str, int]:
    """A cheap answer to "did anything in this folder change": its files, their total size,
    the newest change to a file or folder (adding or removing a file changes its folder),
    and how many entries could not be read. Links, junctions, what Syft leaves out
    (.git, caches) and the program's updater-only folders are not counted."""
    skip = {os.path.normcase(os.path.join(path, name)) for name in updater_folders(path)}
    files = size = newest = errors = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            newest = max(newest, int(os.stat(current).st_mtime))
            with os.scandir(current) as it:
                entries = list(it)
        except OSError:
            errors += 1
            continue
        for entry in entries:
            try:
                if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in _FINGERPRINT_SKIP and os.path.normcase(entry.path) not in skip:
                        stack.append(entry.path)
                    continue
                st = entry.stat(follow_symlinks=False)
            except OSError:
                errors += 1
                continue
            files += 1
            size += st.st_size
            newest = max(newest, int(st.st_mtime))
    return {"files": files, "bytes": size, "newest": newest, "errors": errors}


class FolderCache:
    """What the SBOM runs learned per folder, kept on disk between runs (one file per
    agent instance, next to its settings): the packages Syft listed (its components, file
    paths included; they never leave the computer), the folder's fingerprint when they
    were listed, how long Syft took and the time limit the folder needs; plus when the
    last weekly full run finished.

    Learned under one setup only. Another Syft version (it may find other packages), the
    compiled-programs switch or other excludes make it start over, and so does a file it
    cannot read; the next run then lists everything. Saved to a temporary file that
    replaces the old one, so a crash never leaves half a cache."""

    def __init__(self, path: Optional[Path]) -> None:
        self.path = path
        self.setup: dict[str, Any] = {}
        self.folders: dict[str, dict[str, Any]] = {}
        self.last_full: Optional[float] = None
        if path is None or not path.is_file():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("format") == CACHE_FORMAT:
                self.setup = dict(data.get("setup") or {})
                self.folders = dict(data.get("folders") or {})
                self.last_full = data.get("last_full")
        except (OSError, ValueError, AttributeError, TypeError) as exc:
            log.warning("SBOM folder cache %s could not be read (%s); every folder is listed again", path, exc)
            self.setup, self.folders, self.last_full = {}, {}, None

    def use_setup(self, setup: dict[str, Any]) -> bool:
        """Forget what was learned under another setup. True when something was forgotten."""
        if self.setup == setup:
            return False
        forgot = bool(self.folders or self.last_full)
        self.setup, self.folders, self.last_full = dict(setup), {}, None
        return forgot

    def weekly_due(self, now: float) -> bool:
        """A weekly full run is due: there never was one, a week has passed, or the clock
        was set back to before the last one (which would otherwise never come due)."""
        last = self.last_full
        return last is None or now < last or now - last >= WEEK_SECONDS

    def limit(self, unit: ScanUnit) -> int:
        return int((self.folders.get(unit.path) or {}).get("limit") or unit.timeout)

    def save(self) -> None:
        if self.path is None:
            return
        data = {"format": CACHE_FORMAT, "setup": self.setup, "last_full": self.last_full, "folders": self.folders}
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("SBOM folder cache %s could not be saved: %s", self.path, exc)


def _ceiling(unit: ScanUnit) -> int:
    return max(FOLDER_MAX_TIMEOUT, unit.timeout)


def learned_limit(unit: ScanUnit, seconds: float) -> int:
    """A folder's limit after Syft listed it in `seconds`: twice that, never below the
    default, so a busier day still fits (Office took 589 s of a 600 s limit)."""
    return int(min(max(unit.timeout, 2 * seconds), _ceiling(unit)))


def raised_limit(unit: ScanUnit, limit: int) -> int:
    """A folder's limit after it timed out at `limit`: twice as long next time."""
    return int(min(2 * limit, _ceiling(unit)))


# ── building the SBOM ──
@dataclass
class FolderOutcome:
    path: str
    status: str                         # listed | unchanged | kept | missing
    packages: int = 0
    seconds: float = 0.0                # Syft's awake time (listed only)
    reason: str = ""                    # why it was not listed this run (kept, missing)
    listed_at: Optional[float] = None   # when its packages were listed


@dataclass
class SbomRun:
    document: dict[str, Any]        # merged CycloneDX, as Syft wrote it (for Grype)
    scope: list[str]                # configured folders that have packages in this SBOM
    skipped: list[str]              # folders not listed this run, with the reason
    folders: list[FolderOutcome] = field(default_factory=list)
    full: bool = True
    seconds: float = 0.0            # awake time spent listing


def build_sbom(syft: str, roots: list[str], runner: Runner = _run,
               progress: Callable[[str], None] = lambda m: None, include_binaries: bool = False,
               cancelled: Callable[[], bool] = lambda: False,
               containers: Optional[set[Path]] = None,
               cache: Optional[FolderCache] = None, full: bool = True,
               clock: Optional[Callable[[], float]] = None,
               now: Callable[[], float] = time.time) -> SbomRun:
    """List the packages of every scan unit and merge them into one document.

    A full run lists every folder. A daily run (full=False) lists only the folders whose
    fingerprint changed since they were last listed and reuses the packages of the rest.
    Each folder gets the limit it learned, all of them together SYFT_TIMEOUT (daily) or
    SYFT_FULL_TIMEOUT (full) of awake time. The longest-known folders start first,
    SYFT_PARALLEL at a time; folders that timed out last time run after the others, alone,
    with every CPU core. A folder that is not listed keeps the packages of its last listing,
    so its CVE alerts stay open; one never listed has none. `cache` learns and is saved."""
    if not roots:
        raise SbomError("None of the folders to scan exist on this computer")
    units, left_out = scan_units(roots, containers)
    if not units:
        raise SbomError("No folder to scan. " + "; ".join(left_out)[:500])
    cache = cache if cache is not None else FolderCache(None)
    budget = SYFT_FULL_TIMEOUT if full else SYFT_TIMEOUT
    awake = clock or AwakeClock()
    outcomes: dict[int, FolderOutcome] = {}
    docs: dict[int, dict[str, Any]] = {}
    failures: dict[int, str] = {}

    todo: list[tuple[int, ScanUnit, Optional[dict[str, int]]]] = []
    for i, unit in enumerate(units):
        if cancelled():
            raise SbomCancelled("the scan was cancelled")
        entry = cache.folders.get(unit.path) or {}
        fp = fingerprint(unit.path) if unit.reusable else None
        if not full and fp is not None and entry.get("components") is not None and entry.get("fingerprint") == fp:
            outcomes[i] = FolderOutcome(unit.path, "unchanged", len(entry["components"]), listed_at=entry.get("listed_at"))
        else:
            todo.append((i, unit, fp))
    timed_out = [t for t in todo if (cache.folders.get(t[1].path) or {}).get("timed_out")]
    first = sorted((t for t in todo if t not in timed_out),
                   key=lambda t: -float((cache.folders.get(t[1].path) or {}).get("seconds") or 0))
    done = [0]
    lock = threading.Lock()

    def finish_one(message: str) -> None:
        with lock:
            done[0] += 1
            progress(f"{message} ({done[0]}/{len(todo)})")

    try:
        with tempfile.TemporaryDirectory(prefix="eagleeye-sbom-") as tmp, _ticking(awake):
            def scan(i: int, unit: ScanUnit, fp: Optional[dict[str, int]]) -> None:
                if cancelled():
                    raise SbomCancelled("the scan was cancelled")
                folder_limit = cache.limit(unit)
                limit = int(min(folder_limit, budget - awake()))
                if limit <= 0:
                    failures[i] = "not listed: the time limit for the whole SBOM was reached"
                    finish_one(f"Not listed {unit.path}")
                    return
                out = Path(tmp) / f"part{i}.json"
                cmd = [syft, "scan", f"dir:{unit.path}", "-o", f"cyclonedx-json={out}", "-q"]
                for pattern in excludes_for(unit.path):
                    cmd += ["--exclude", pattern]
                if not include_binaries:
                    cmd += ["--select-catalogers", ",".join(f"-{name}" for name in COMPILED_PROGRAM_CATALOGERS)]
                started = awake()
                try:
                    runner(cmd, limit)
                    doc = json.loads(out.read_text(encoding="utf-8", errors="replace"))
                except SbomTimeout as exc:
                    failures[i] = str(exc)
                    entry = cache.folders.setdefault(unit.path, {})
                    if limit >= folder_limit:      # its own limit, not the run's time running out
                        entry.update(limit=raised_limit(unit, folder_limit), timed_out=True)
                    entry.update(failed_at=now(), failure=str(exc)[:300])
                    finish_one(f"Not listed {unit.path}: {exc}")
                    return
                except (SbomError, OSError, ValueError) as exc:
                    failures[i] = str(exc)
                    cache.folders.setdefault(unit.path, {}).update(failed_at=now(), failure=str(exc)[:300])
                    finish_one(f"Not listed {unit.path}: {exc}")
                    return
                seconds = awake() - started
                comps = [c for c in doc.get("components") or [] if isinstance(c, dict) and c.get("type") != "file"]
                docs[i] = doc
                cache.folders[unit.path] = {"components": comps, "fingerprint": fp, "listed_at": now(),
                                            "seconds": round(seconds, 1), "limit": learned_limit(unit, seconds)}
                outcomes[i] = FolderOutcome(unit.path, "listed", len(comps), round(seconds, 1), listed_at=now())
                finish_one(f"Listed {unit.path}: {len(comps)} package(s) in {_duration(seconds)}")

            reused = len(units) - len(todo)
            progress(f"Listing packages in {len(todo)} of {len(units)} folder(s), {SYFT_PARALLEL} at a time"
                     + ("" if full else f"; {reused} unchanged since their last listing"))
            with ThreadPoolExecutor(max_workers=SYFT_PARALLEL, thread_name_prefix="syft") as pool:
                futures = [pool.submit(scan, *t) for t in first]
                try:
                    for f in futures:
                        f.result()
                except SbomCancelled:
                    for f in futures:
                        f.cancel()
                    raise
            for t in timed_out:        # timed out last time: alone, with what time is left
                scan(*t)
    finally:
        # Folders that are gone (uninstalled, or an extra folder taken out of the settings)
        # are forgotten; what was learned about the rest stays, even when cancelled.
        current = {u.path for u in units}
        for path in [p for p in cache.folders if p not in current]:
            del cache.folders[path]
        cache.save()

    for i, reason in failures.items():
        entry = cache.folders.get(units[i].path) or {}
        if entry.get("components") is not None:
            outcomes[i] = FolderOutcome(units[i].path, "kept", len(entry["components"]), reason=reason,
                                        listed_at=entry.get("listed_at"))
            progress(f"Kept {units[i].path} as listed on {_date(entry.get('listed_at'))} ({reason})")
        else:
            outcomes[i] = FolderOutcome(units[i].path, "missing", reason=reason)
            progress(f"Skipped {units[i].path}: {reason} (never listed, so no packages from it)")

    parts: list[dict[str, Any]] = []
    for i in range(len(units)):
        o = outcomes[i]
        if o.status == "listed":
            parts.append(docs[i])
        elif o.status in ("unchanged", "kept"):
            parts.append({"components": cache.folders[o.path]["components"]})
    skipped = left_out + [f"{o.path}: {o.reason}" for i, o in sorted(outcomes.items()) if o.status in ("kept", "missing")]
    if not parts:
        raise SbomError("Syft could not scan any folder. " + "; ".join(skipped)[:500])
    roots_with_packages = {units[i].root for i, o in outcomes.items() if o.status != "missing"}
    return SbomRun(merge_documents(parts), [r for r in roots if r in roots_with_packages], skipped,
                   [outcomes[i] for i in range(len(units))], full, round(awake(), 1))


def run_report(run: SbomRun) -> dict[str, Any]:
    """What the dashboard is told about how the SBOM was built (no package paths): the
    kind of run, its awake time, and the folders whose packages are older than this run
    (kept from their last listing) or absent (never listed)."""
    count = lambda status: sum(1 for o in run.folders if o.status == status)  # noqa: E731
    return {
        "mode": "full" if run.full else "quick",
        "seconds": int(run.seconds),
        "folders": len(run.folders),
        "listed": count("listed"),
        "unchanged": count("unchanged"),
        "kept": [{"folder": o.path, "listed_at": datetime.fromtimestamp(o.listed_at).isoformat(timespec="seconds")
                  if o.listed_at else None, "reason": o.reason[:200]}
                 for o in run.folders if o.status == "kept"][:50],
        "missing": [{"folder": o.path, "reason": o.reason[:200]} for o in run.folders if o.status == "missing"][:50],
    }


def _component_key(comp: dict[str, Any]) -> tuple[str, ...]:
    if comp.get("purl"):
        return ("purl", str(comp["purl"]).split("?")[0])
    return ("nv", str(comp.get("type")), str(comp.get("name")), str(comp.get("version")))


def merge_documents(docs: list[dict[str, Any]]) -> dict[str, Any]:
    """One CycloneDX document holding every distinct package of the parts. The
    operating-system component (which Grype uses to pick the distro's data) is kept;
    the per-folder 'file' root components and dependency graphs are dropped. Packages
    reused from the folder cache come without Syft's metadata, so it is taken from the
    first part that has it."""
    first = next((d for d in docs if d.get("metadata")), docs[0])
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
