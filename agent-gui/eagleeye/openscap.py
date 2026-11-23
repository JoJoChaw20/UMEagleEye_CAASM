"""OpenSCAP on Linux (optional, the dashboard's "OpenSCAP" setting): the CIS Level 1 profile of the SCAP
Security Guide, run at most weekly, its results sent with the inventory (inventory.openscap). Shown on
the asset page beside the security baseline, never instead of it: Windows has no OpenSCAP, and the
baseline must judge both systems alike (workers/src/lib/baseline.ts).

Content must match the exact OS version. Distributions lag (Ubuntu 24.04's own package covers up to
22.04), so an administrator can also put a ComplianceAsCode release's ssg-<os><version>-ds.xml in the
agent's scap-content folder; without content for this version the result says so instead of running
another version's rules, which would mark nearly all of them "not applicable" and look like a result.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Optional

from .machine import machine_dir

log = logging.getLogger("eagleeye.openscap")

SYSTEM_CONTENT = Path("/usr/share/xml/scap/ssg/content")
RERUN_AFTER = 7 * 86400
TIMEOUT = 3600
MAX_FAILED = 300
RESULTS = ("pass", "fail", "error", "unknown", "notapplicable", "notchecked", "notselected", "informational", "fixed")
_SEVERITY = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
_PREFIX = "xccdf_org.ssgproject.content_rule_"
# SCAP Security Guide's names for distributions whose os-release ID differs
_SSG_ID = {"centos": "cs", "rocky": "rl", "sles": "sle", "sled": "sle"}


def content_dir() -> Path:
    """Where an administrator may put content the distribution does not ship."""
    return machine_dir() / "scap-content"


def content_names(os_release: dict[str, str]) -> list[str]:
    """The SCAP Security Guide datastream names for this exact OS version, most specific first."""
    os_id = (os_release.get("ID") or "").lower()
    version = os_release.get("VERSION_ID") or ""
    if not os_id or not version:
        return []
    ssg = _SSG_ID.get(os_id, os_id)
    major = version.split(".")[0]
    names = [f"ssg-{ssg}{version.replace('.', '')}-ds.xml"]
    if os_id not in ("ubuntu",):                       # Ubuntu content is per release (2404), others per major (rhel9)
        names.append(f"ssg-{ssg}{major}-ds.xml")
    return list(dict.fromkeys(names))


def find_content(os_release: dict[str, str], dirs: Optional[list[Path]] = None) -> Optional[Path]:
    for d in dirs if dirs is not None else [content_dir(), SYSTEM_CONTENT]:
        for name in content_names(os_release):
            if (d / name).is_file():
                return d / name
    return None


def choose_profile(profiles_text: str, role: Optional[str]) -> Optional[tuple[str, str]]:
    """The CIS Level 1 profile for this machine's role, from `oscap info --profiles` (id:title lines)."""
    profiles = [tuple(ln.split(":", 1)) for ln in profiles_text.splitlines() if ln.startswith("xccdf_") and ":" in ln]
    server = re.compile(r"cis.*(level1_server|server_l1)$")
    workstation = re.compile(r"cis.*(level1_workstation|workstation_l1)$")
    order = [workstation, server] if role == "workstation" else [server, workstation]
    for rx in order:
        for pid, title in profiles:
            if rx.search(pid):
                return pid, title.strip()
    return None


def parse_results(path: Path, max_failed: int = MAX_FAILED) -> dict[str, Any]:
    """Counts per result and the failed rules (title, severity) from an XCCDF results file. Streamed:
    the file holds the whole benchmark (about 20 MB)."""
    rules: dict[str, tuple[str, str]] = {}
    results: list[tuple[str, str]] = []
    profile_titles: dict[str, str] = {}
    meta: dict[str, Any] = {}
    local = lambda tag: tag.rsplit("}", 1)[-1]                                    # noqa: E731
    child_text = lambda el, name: next((c.text or "" for c in el if local(c.tag) == name), "")  # noqa: E731
    for _, el in ET.iterparse(path, events=("end",)):
        tag = local(el.tag)
        if tag == "Rule":
            rules[el.get("id", "")] = (child_text(el, "title").strip(), el.get("severity", "unknown"))
            el.clear()
        elif tag == "Profile":
            profile_titles[el.get("id", "")] = child_text(el, "title").strip()
            el.clear()
        elif tag == "rule-result":
            results.append((el.get("idref", ""), child_text(el, "result").strip()))
            el.clear()
        elif tag == "TestResult":
            meta = {"content_version": el.get("version"), "started": el.get("start-time"), "finished": el.get("end-time"),
                    "profile_id": next((c.get("idref") for c in el if local(c.tag) == "profile"), None),
                    "scanner": el.get("test-system")}
            el.clear()
        elif tag in ("Value", "Group"):
            el.clear()
    counts = {r: 0 for r in RESULTS}
    failed = []
    for idref, result in results:
        counts[result] = counts.get(result, 0) + 1
        if result in ("fail", "error"):
            title, severity = rules.get(idref, ("", "unknown"))
            failed.append({"id": idref.removeprefix(_PREFIX), "title": title[:200] or idref, "severity": severity,
                           **({"result": "error"} if result == "error" else {})})
    failed.sort(key=lambda f: (_SEVERITY.get(f["severity"], 3), f["title"]))
    return {**meta, "profile_title": profile_titles.get(meta.get("profile_id") or "", None),
            "counts": counts, "failed": failed[:max_failed], "failed_total": len(failed)}


class OpenScap:
    """Run at most weekly; between runs every inventory carries the last result."""

    def __init__(self, state_dir: Optional[Path] = None, run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                 which: Callable[[str], Optional[str]] = shutil.which, clock: Callable[[], float] = time.time,
                 is_root: Optional[bool] = None) -> None:
        self.dir = state_dir or machine_dir() / "openscap"
        self.run = run
        self.which = which
        self.clock = clock
        self.is_root = (hasattr(os, "geteuid") and os.geteuid() == 0) if is_root is None else is_root

    @property
    def state_path(self) -> Path:
        return self.dir / "last.json"

    def _last(self) -> dict[str, Any]:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def result(self, os_release: dict[str, str], role: Optional[str], content_dirs: Optional[list[Path]] = None) -> dict[str, Any]:
        """What to send with this inventory: the last result, after running again when it is due."""
        name = os_release.get("PRETTY_NAME") or os_release.get("ID") or "this system"
        if not self.is_root:
            return {"status": "unavailable", "reason": "OpenSCAP needs the agent to run as root (its service does)"}
        oscap = self.which("oscap")
        if not oscap:
            return {"status": "unavailable", "reason": "OpenSCAP is not installed (apt install openscap-scanner, or dnf install openscap-scanner)"}
        content = find_content(os_release, content_dirs)
        if content is None:
            wanted = " or ".join(content_names(os_release)) or "content for this system"
            return {"status": "unavailable", "reason": f"No SCAP Security Guide content for {name}: put {wanted} "
                    f"(from a ComplianceAsCode release) in {content_dir()}, or install the distribution's ssg / scap-security-guide package"}
        prof = self.run([oscap, "info", "--profiles", str(content)], capture_output=True, text=True, timeout=120)
        chosen = choose_profile(prof.stdout or "", role) if prof.returncode == 0 else None
        if chosen is None:
            return {"status": "unavailable", "reason": f"{content.name} has no CIS Level 1 profile"}
        profile_id, profile_title = chosen
        last = self._last()
        mtime = content.stat().st_mtime
        if (last.get("status") == "ok" and last.get("content_path") == str(content) and last.get("content_mtime") == mtime
                and last.get("profile_id") == profile_id and self.clock() - float(last.get("ran_at") or 0) < RERUN_AFTER):
            return last
        return self._run(oscap, content, mtime, profile_id, profile_title)

    def _run(self, oscap: str, content: Path, mtime: float, profile_id: str, profile_title: str) -> dict[str, Any]:
        self.dir.mkdir(parents=True, exist_ok=True)
        results = self.dir / "results.xml"
        started = self.clock()
        log.info("OpenSCAP: %s with %s (this can take several minutes)", profile_title, content.name)
        try:
            r = self.run([oscap, "xccdf", "eval", "--profile", profile_id, "--results", str(results), str(content)],
                         capture_output=True, text=True, timeout=TIMEOUT)
            if r.returncode not in (0, 2):              # 2: some rules failed; anything else is an error
                raise RuntimeError((r.stderr or r.stdout or f"exit {r.returncode}").strip().splitlines()[-1][:300])
            out = {"status": "ok", **parse_results(results), "profile_id": profile_id, "profile_title": profile_title,
                   "content": content.name, "content_path": str(content), "content_mtime": mtime,
                   "ran_at": started, "duration_s": round(self.clock() - started, 1)}
        except Exception as exc:  # noqa: BLE001 - reported with the inventory; the agent carries on
            log.warning("OpenSCAP failed: %s", exc)
            out = {"status": "error", "reason": str(exc)[:300], "ran_at": started, "content": content.name, "profile_id": profile_id}
        finally:
            results.unlink(missing_ok=True)             # the summary is kept; the 20 MB file is not
        self.state_path.write_text(json.dumps(out), encoding="utf-8")
        if out["status"] == "ok":
            log.info("OpenSCAP: %d pass, %d fail, %d not applicable in %.0f s",
                     out["counts"]["pass"], out["counts"]["fail"], out["counts"]["notapplicable"], out["duration_s"])
        return out
