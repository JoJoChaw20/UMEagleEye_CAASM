"""Installing the agent as a system service (2.5.0): `eagleeye service install|uninstall|
start|stop|status|run|scm`. The Windows installer runs `install` and `uninstall`.

install (as an administrator):
  1. creates the machine folder (machine.py) and restricts it;
  2. moves this user's settings there once, with the secrets from their Credential
     Manager into the machine secrets file (nothing to enter again after an upgrade);
  3. registers the service (Windows: delayed automatic start as LocalSystem, restarted
     after a failure; Linux: a systemd unit) and starts it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from .config import ConfigError, default_config_path, load_settings, save_settings
from .keychain import Keychain
from .machine import (DESCRIPTION, DISPLAY_NAME, MachineSecrets, machine_config_path, machine_dir, machine_log_dir,
                      secure, service_name)

# Stands for a secret the service keeps: the agent app cannot read it (only SYSTEM and
# administrators can), so its settings carry this instead, and `apply` keeps the secret.
SAVED_SECRET = "•saved in the service•"

# Files beside a config that belong to the same agent (config.py, policy.py, sbom.py).
COMPANIONS = ("state", "policy", "sbom-cache")


def _command(instance: str) -> list[str]:
    """How the service manager starts the agent."""
    tail = ["service", "scm" if sys.platform == "win32" else "run"] + (["--instance", instance] if instance else [])
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable)
        cli = exe.with_name("eagleeye.exe") if sys.platform == "win32" else exe
        return [str(cli)] + tail
    return [sys.executable, "-m", "eagleeye"] + tail


def _source_root() -> Optional[str]:
    """The folder holding the eagleeye package when run from source (for PYTHONPATH)."""
    return None if getattr(sys, "frozen", False) else str(Path(__file__).resolve().parent.parent)


def unit_name(instance: str = "") -> str:
    """The systemd unit: eagleeye-agent, or eagleeye-agent-<instance>."""
    return f"eagleeye-agent-{instance}" if instance else "eagleeye-agent"


def _quote(arg: str) -> str:
    return f'"{arg}"' if (" " in arg or not arg) else arg


def migrate_user_settings(source: Optional[Path], instance: str = "") -> str:
    """Copy this user's settings (and their secrets) into the machine folder, once."""
    target = machine_config_path(instance)
    if target.exists():
        return f"kept the existing {target}"
    src = source or default_config_path()
    if not src.exists():
        return "no settings to move yet (set the agent up from its app)"
    try:
        settings = load_settings(src, env={}, keychain=Keychain())
    except ConfigError as exc:
        return f"could not read {src}: {exc}"
    save_settings(settings, target, keychain=MachineSecrets())
    secure(target)
    moved = []
    stem = src.stem[len("config"):]                     # "" or "-production"
    for name in COMPANIONS:
        companion = src.with_name(f"{name}{stem}.json")
        if companion.exists():
            dest = target.with_name(f"{name}{'-' + instance if instance else ''}.json")
            shutil.copy2(companion, dest)
            moved.append(name)
    return f"moved {src} to {target}" + (f" (with {', '.join(moved)})" if moved else "")


def _run(args: list[str], check: bool = False) -> subprocess.CompletedProcess:
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:3])} failed: {(r.stdout + r.stderr).strip()}")
    return r


def install(instance: str = "", source: Optional[Path] = None, start: bool = True) -> list[str]:
    done = []
    base = machine_dir()
    base.mkdir(parents=True, exist_ok=True)
    secure(base)
    machine_log_dir(instance).mkdir(parents=True, exist_ok=True)
    done.append(migrate_user_settings(source, instance))
    name = service_name(instance)
    command = " ".join(_quote(a) for a in _command(instance))
    if sys.platform == "win32":
        if _run(["sc.exe", "query", name]).returncode == 0:
            _run(["sc.exe", "config", name, "binPath=", command, "start=", "delayed-auto"], check=True)
            done.append(f"updated the service {name}")
        else:
            _run(["sc.exe", "create", name, "binPath=", command, "start=", "delayed-auto", "obj=", "LocalSystem",
                  "DisplayName=", DISPLAY_NAME + (f" ({instance})" if instance else "")], check=True)
            done.append(f"created the service {name}")
        _run(["sc.exe", "description", name, DESCRIPTION])
        # Started again 1 minute after a failure (twice), then after 5 minutes; reset daily.
        _run(["sc.exe", "failure", name, "reset=", "86400", "actions=", "restart/60000/restart/60000/restart/300000"])
        _run(["sc.exe", "failureflag", name, "1"])
        # Up to 60 s at shutdown, for the last passive upload (default is 20 s).
        _run(["reg", "add", rf"HKLM\SYSTEM\CurrentControlSet\Services\{name}", "/v", "PreshutdownTimeout",
              "/t", "REG_DWORD", "/d", "60000", "/f"])
        root = _source_root()
        if root:                                     # a run from source: the service finds the package
            _run(["reg", "add", rf"HKLM\SYSTEM\CurrentControlSet\Services\{name}", "/v", "Environment",
                  "/t", "REG_MULTI_SZ", "/d", f"PYTHONPATH={root}", "/f"], check=True)
        if start:
            r = _run(["sc.exe", "start", name])
            done.append("started it" if r.returncode == 0 else f"could not start it: {(r.stdout + r.stderr).strip()[-200:]}")
    else:
        legacy = Path("/etc/systemd/system/eagleeye.service")    # the hand-installed unit before 2.5.0
        if not instance and legacy.exists():
            _run(["systemctl", "disable", "--now", "eagleeye"])
            done.append(f"stopped and disabled the old eagleeye.service (its file {legacy} is kept)")
        unit = Path(f"/etc/systemd/system/{unit_name(instance)}.service")
        root = _source_root()
        unit.write_text("\n".join([
            "[Unit]", f"Description={DISPLAY_NAME}" + (f" ({instance})" if instance else ""),
            "After=network-online.target", "Wants=network-online.target", "",
            "[Service]", f"ExecStart={' '.join(_quote(a) for a in _command(instance))}",
            *( [f"Environment=PYTHONPATH={root}"] if root else []),
            "Restart=on-failure", "RestartSec=60", "TimeoutStopSec=60", "",
            "[Install]", "WantedBy=multi-user.target", "",
        ]))
        _run(["systemctl", "daemon-reload"], check=True)
        _run(["systemctl", "enable", "--now" if start else "--quiet", unit.stem], check=True)
        done.append(f"installed {unit}" + (" and started it" if start else ""))
    return done


def uninstall(instance: str = "", purge: bool = False) -> list[str]:
    done = []
    name = service_name(instance)
    if sys.platform == "win32":
        _run(["sc.exe", "stop", name])
        for _ in range(60):                         # the final passive upload may take a moment
            q = _run(["sc.exe", "query", name])
            if q.returncode != 0 or "STOPPED" in q.stdout:
                break
            time.sleep(1)
        r = _run(["sc.exe", "delete", name])
        done.append(f"removed the service {name}" if r.returncode == 0 else f"no service {name}")
    else:
        unit = unit_name(instance)
        _run(["systemctl", "disable", "--now", unit])
        path = Path(f"/etc/systemd/system/{unit}.service")
        if path.exists():
            path.unlink()
            _run(["systemctl", "daemon-reload"])
        done.append(f"removed {unit}")
    if purge and machine_dir().exists():
        shutil.rmtree(machine_dir(), ignore_errors=True)
        done.append(f"deleted {machine_dir()}")
    return done


def control(action: str, instance: str = "") -> str:
    name = service_name(instance)
    if sys.platform == "win32":
        r = _run(["sc.exe", action, name])
    else:
        r = _run(["systemctl", action, unit_name(instance)])
    return (r.stdout + r.stderr).strip() or "ok"


def is_admin() -> bool:
    from .deps import is_admin as admin
    return bool(admin())


def environment_note() -> str:
    return "" if os.environ.get("EAGLEEYE_CONFIG") is None else \
        "Note: EAGLEEYE_CONFIG is set; the service uses its own settings in the machine folder."


def apply_settings_file(path: Path, instance: str = "") -> str:
    """`eagleeye service apply` (as an administrator): settings the app saved -> the
    service's settings and secrets; a secret left as SAVED_SECRET or empty is kept."""
    from . import ipc
    from .keychain import SECRET_FIELDS
    from .machine import unprotect
    from .config import Settings
    raw = path.read_bytes()
    if sys.platform == "win32":
        raw = unprotect(raw)
    data = json.loads(raw.decode("utf-8"))
    store = MachineSecrets()
    target = machine_config_path(instance)
    try:
        current = load_settings(target, env={}, keychain=store) if target.exists() else Settings()
    except ConfigError:
        current = Settings()
    settings = Settings()
    for key, value in data.items():
        if hasattr(settings, key):
            setattr(settings, key, value)
    for name in SECRET_FIELDS:
        value = getattr(settings, name)
        if not value or value == SAVED_SECRET:
            setattr(settings, name, getattr(current, name) if current.agent_id == settings.agent_id else "")
    save_settings(settings, target, keychain=store)
    secure(target)
    try:
        ipc.call({"cmd": "reload"}, ipc.address(instance), timeout=3)
    except Exception:  # noqa: BLE001 - the service picks the settings up when it starts
        pass
    return f"saved {target}"
