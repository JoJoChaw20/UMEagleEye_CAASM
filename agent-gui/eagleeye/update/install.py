"""Installing an update the dashboard asked for (an `update` job): download, check, install.

  1. Download the package through the agent's own authenticated route (GET /agents/<id>/package),
     into the machine folder only SYSTEM/root and administrators can change.
  2. Check it: the manifest's signature, kind and build (package.check_manifest), then the file's
     size and SHA-256 against the signed ones.
  3. Install it:
     * Windows: the installer, silently, as a detached process (it stops this service, replaces the
       program and starts the service again; the key and settings in %ProgramData% are kept).
     * Linux: unpack into a new /opt/eagleeye-agent-<build> with its own venv from the bundled
       wheels, then a separate transient systemd unit switches the service to it and restarts it.
       If the new build has not checked in within ROLLBACK_AFTER, the service goes back to the old
       folder. The previous folder is kept; older ones are removed.

What happened is kept in STATE: the new agent marks it healthy after its first heartbeat, and the
job fails with the reason when the install failed or was rolled back (report_outcome).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .. import BUILD
from ..machine import machine_dir, secure
from .package import Refused, check_manifest, install_kind, install_root

log = logging.getLogger("eagleeye.update")

ROLLBACK_AFTER = 300
WINDOWS_GIVE_UP = 15 * 60                       # an installer that never brought the new build up (they take 1-4 minutes)


def state_path() -> Path:
    return machine_dir() / "update-state.json"


def read_state() -> dict[str, Any]:
    try:
        data = json.loads(state_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(state: dict[str, Any]) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    tmp.replace(path)


def file_digest(path: Path) -> tuple[int, str]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


def check_file(path: Path, info: dict[str, Any]) -> None:
    size, digest = file_digest(path)
    if size != info["size"]:
        raise Refused(f"the download is {size} bytes, the signed package is {info['size']}")
    if digest != info["sha256"]:
        raise Refused("the download's SHA-256 does not match the signed package")


# ── Windows ─────────────────────────────────────────────────────────────────
DETACHED_PROCESS, CREATE_NEW_PROCESS_GROUP, CREATE_BREAKAWAY_FROM_JOB = 0x8, 0x200, 0x01000000


def launch_windows_installer(setup: Path, log_file: Path) -> None:  # pragma: no cover - needs Windows
    # FORCECLOSEAPPLICATIONS: a silent Setup that cannot close a program answers its own question
    # with Abort; this makes it end the program instead.
    args = [str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/FORCECLOSEAPPLICATIONS", f"/LOG={log_file}"]
    base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    try:                    # out of the service's job object, so stopping the service leaves it running
        subprocess.Popen(args, creationflags=base | CREATE_BREAKAWAY_FROM_JOB, close_fds=True)
    except OSError:
        subprocess.Popen(args, creationflags=base, close_fds=True)


# ── Linux ───────────────────────────────────────────────────────────────────
def linux_target(build: str) -> Path:
    return Path("/opt") / f"eagleeye-agent-{build.replace('+', '-')}"


def unpack(archive: Path, target: Path) -> None:
    """The package's single top folder becomes `target` (data filter: no links out, no devices)."""
    work = target.with_name(target.name + ".unpacking")
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(work, filter="data")
    tops = [p for p in work.iterdir() if p.is_dir()]
    if len(tops) != 1:
        shutil.rmtree(work, ignore_errors=True)
        raise Refused("the package does not hold one agent folder")
    shutil.rmtree(target, ignore_errors=True)
    tops[0].rename(target)
    shutil.rmtree(work, ignore_errors=True)


def clean_env(env: Optional[dict[str, str]] = None) -> dict[str, str]:
    """This agent's environment without what points Python at its own packages: the new build's
    venv, pip and version check must see only the new build."""
    env = dict(os.environ if env is None else env)
    for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "VIRTUAL_ENV", "PIP_FIND_LINKS",
                 "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_TARGET", "PIP_PREFIX"):
        env.pop(name, None)
    return env


def prepare_linux(archive: Path, build: str,
                  run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> Path:  # pragma: no cover - needs Linux
    current = install_root()
    target = linux_target(build)
    if current is not None and target.resolve() == current.resolve():
        raise Refused("this build is already the installed folder")
    unpack(archive, target)
    python = getattr(sys, "_base_executable", None) or sys.executable
    venv_py = target / ".venv" / "bin" / "python"
    steps = [[python, "-m", "venv", str(target / ".venv")]]
    wheels = target / "wheels"
    pip = [str(venv_py), "-m", "pip", "install", "--disable-pip-version-check", "--quiet"]
    steps.append(pip + (["--no-index", "--find-links", str(wheels)] if wheels.is_dir() else []) + [str(target)])
    steps.append([str(venv_py), "-m", "eagleeye", "version"])
    env = clean_env()
    for step in steps:
        r = run(step, capture_output=True, text=True, timeout=900, env=env, cwd="/")   # not the unpacked tree
        if r.returncode != 0:
            raise Refused(f"preparing the new build failed at '{' '.join(step[-2:])}': {(r.stdout + r.stderr).strip()[-300:]}")
    if build not in r.stdout:
        raise Refused(f"the new build reports {r.stdout.strip()[:80]!r}, not {build}")
    return target


def launch_switch(target: Path, previous: Optional[Path], build: str) -> None:  # pragma: no cover - needs systemd
    """The switch runs as its own transient unit: restarting the agent's service does not stop it."""
    cmd = ["systemd-run", "--collect", f"--unit=eagleeye-update-{int(time.time())}",
           str(target / ".venv" / "bin" / "python"), "-m", "eagleeye", "update", "switch",
           "--to", str(target), "--build", build] + (["--from", str(previous)] if previous else [])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise Refused(f"could not start the switch: {(r.stdout + r.stderr).strip()[-300:]}")


def _service_install(root: Path) -> None:  # pragma: no cover - needs systemd
    from ..serviceinstall import unit_name
    subprocess.run([str(root / ".venv" / "bin" / "python"), "-m", "eagleeye", "service", "install", "--no-start"],
                   check=True, capture_output=True, text=True, timeout=120, env=clean_env(), cwd="/")
    subprocess.run(["systemctl", "restart", unit_name()], check=True, capture_output=True, text=True, timeout=120)


def switch(target: Path, previous: Optional[Path], build: str,
           service_install: Callable[[Path], None] = _service_install,
           sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.time,
           rollback_after: float = ROLLBACK_AFTER) -> str:
    """Point the service at `target` and restart it; go back to `previous` if the new build does not
    check in (mark its state healthy) within `rollback_after`. Returns 'healthy' or 'rolled_back'."""
    state = read_state()
    state.update(state="switching", switched_at=clock())
    write_state(state)
    try:
        service_install(target)
    except Exception as exc:  # noqa: BLE001
        log.error("Switching the service to %s failed: %s", target, exc)
    deadline = clock() + rollback_after
    while clock() < deadline:
        now = read_state()
        if now.get("build") == build and now.get("state") == "healthy":
            _tidy(target, previous)
            return "healthy"
        sleep(5)
    now = read_state()
    now.update(state="rolled_back", error=f"build {build} did not check in within {int(rollback_after // 60)} minutes; "
               "the previous build was restored")
    write_state(now)
    if previous is not None:
        try:
            service_install(previous)
        except Exception as exc:  # noqa: BLE001
            log.error("Restoring %s failed: %s", previous, exc)
    return "rolled_back"


def _tidy(keep: Path, previous: Optional[Path]) -> None:
    """Remove older install folders, keeping the new one and the one before it."""
    for p in Path("/opt").glob("eagleeye-agent-*"):
        if p.is_dir() and p.resolve() not in {keep.resolve(), (previous or keep).resolve()} and not p.name.endswith(".unpacking"):
            shutil.rmtree(p, ignore_errors=True)


# ── the job ─────────────────────────────────────────────────────────────────
def run_update(client: Any, job_id: str, manifest: Any) -> None:
    """Carry out an update job. A refusal fails the job with its reason; a started install is
    finished by the next agent (report_outcome)."""
    kind = install_kind()
    try:
        info = check_manifest(manifest, BUILD, kind)
        folder = machine_dir() / "updates"
        folder.mkdir(parents=True, exist_ok=True)
        secure(folder)
        for old in folder.iterdir():
            if old.is_file():
                old.unlink(missing_ok=True)
        path = folder / info["file"]
        client.download_package(info["kind"], path, info["size"])
        check_file(path, info)
        state = {"job": job_id, "build": info["build"], "from": BUILD, "state": "installing", "at": time.time()}
        if kind == "windows":
            setup_log = folder / f"install-{int(time.time())}.log"
            state["log"] = str(setup_log)
            write_state(state)
            log.info("Update %s: package checked, starting the installer", info["build"])
            launch_windows_installer(path, setup_log)
        else:
            previous = install_root()
            target = prepare_linux(path, info["build"])
            state.update(previous=str(previous) if previous else None, target=str(target))
            write_state(state)
            log.info("Update %s: prepared in %s, switching the service", info["build"], target)
            launch_switch(target, previous, info["build"])
    except Refused as exc:
        log.warning("Update refused: %s", exc)
        client.mark_scan_failed(job_id, f"Update not installed: {exc}")
    except Exception as exc:  # noqa: BLE001 - any failure: the job says so, the agent keeps running
        log.error("Update failed: %s", exc, exc_info=True)
        client.mark_scan_failed(job_id, f"Update failed: {str(exc)[:300]}")


def update_pending() -> bool:
    """An update whose outcome has not been reported yet."""
    state = read_state()
    return bool(state) and not state.get("reported")


def setup_gave_up(log_text: Optional[str]) -> Optional[str]:
    """Why a finished Windows Setup did not install, from its log; None while it runs or when it
    installed."""
    if not log_text or "Log closed." not in log_text or "Installation process succeeded" in log_text:
        return None
    if "could not be shut down" in log_text or "unable to automatically close" in log_text:
        return "the installer could not close the running agent and cancelled; the previous build is still running"
    if "Rolling back changes" in log_text:
        return "the installer cancelled and rolled back; the previous build is still running"
    return None


def report_outcome(client: Any, clock: Callable[[], float] = time.time) -> Optional[str]:
    """After a successful heartbeat: settle an update in progress. Returns what was done."""
    state = read_state()
    if not state or state.get("reported"):
        return None
    job = state.get("job")
    if state.get("build") == BUILD and state.get("state") in ("installing", "switching"):
        state.update(state="healthy", reported=True)
        write_state(state)
        return "healthy"
    if state.get("state") == "installing" and state.get("log") and state.get("build") != BUILD:
        try:
            text = Path(state["log"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = None
        reason = setup_gave_up(text)
        if reason:
            state.update(state="failed", error=reason)
    failed = state.get("state") in ("rolled_back", "failed") or (
        state.get("state") == "installing" and clock() - float(state.get("at") or 0) > WINDOWS_GIVE_UP)
    if failed and job and state.get("build") != BUILD:
        reason = state.get("error") or "the installer did not bring the new build up; the previous build is still running"
        client.mark_scan_failed(job, f"Update failed: {reason}")
        state.update(reported=True)
        write_state(state)
        return "failed"
    return None
