"""The agent installed as a system service (2.5.0): its machine-wide folder and secrets.

The service runs as SYSTEM (Windows) or root (Linux), not as a signed-in user, so it
keeps its settings in a machine folder instead of the user's profile, and its secrets
(the API key...) where only SYSTEM/root and administrators can read them:

  * Windows: %ProgramData%\\EagleEye. config.json, state, logs: SYSTEM and Administrators
    full control, Users read (the agent app shows status and settings without
    elevation). secrets.dat: DPAPI (machine scope) and SYSTEM + Administrators only.
  * Linux: /var/lib/eagleeye, secrets.json mode 600 (root).

MachineSecrets has the Keychain interface (get, set, available), so load_settings and
save_settings use it unchanged.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("eagleeye.machine")

SERVICE_NAME = "EagleEyeAgent"
DISPLAY_NAME = "EagleEye Agent"
DESCRIPTION = ("Reports this computer to your organisation's EagleEye dashboard and runs the network "
               "discovery it asks for.")

# Well-known SIDs (locale independent: "Administrators" is "Administradores" elsewhere).
SID_SYSTEM, SID_ADMINS, SID_USERS = "*S-1-5-18", "*S-1-5-32-544", "*S-1-5-32-545"


def machine_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("ProgramData") or r"C:\ProgramData") / "EagleEye"
    if sys.platform == "darwin":
        return Path("/Library/Application Support/EagleEye")
    return Path("/var/lib/eagleeye")


def service_name(instance: str = "") -> str:
    return f"{SERVICE_NAME}-{instance}" if instance else SERVICE_NAME


def machine_config_path(instance: str = "") -> Path:
    return machine_dir() / (f"config-{instance}.json" if instance else "config.json")


def machine_log_dir(instance: str = "") -> Path:
    return machine_dir() / (f"logs-{instance}" if instance else "logs")


def secure(path: Path, secret: bool = False) -> None:
    """Restrict a machine folder or file: SYSTEM/root and administrators may change it;
    Users may read it unless it is `secret`. Best effort: a failure is logged."""
    try:
        if sys.platform == "win32":
            grants = [f"{SID_SYSTEM}:(OI)(CI)F", f"{SID_ADMINS}:(OI)(CI)F"] if path.is_dir() else \
                [f"{SID_SYSTEM}:F", f"{SID_ADMINS}:F"]
            if not secret:
                grants.append(f"{SID_USERS}:(OI)(CI)RX" if path.is_dir() else f"{SID_USERS}:RX")
            args = ["icacls", str(path), "/inheritance:r"]
            for grant in grants:
                args += ["/grant:r", grant]
            r = subprocess.run(args, capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                log.warning("Could not restrict %s: %s", path, (r.stdout + r.stderr).strip()[:300])
        else:
            path.chmod(0o600 if secret else (0o755 if path.is_dir() else 0o644))
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("Could not restrict %s: %s", path, exc)


# ── Windows DPAPI (machine scope) ─────────────────────────────────────────────

if sys.platform == "win32":  # pragma: no cover - Windows only
    import ctypes
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    CRYPTPROTECT_UI_FORBIDDEN, CRYPTPROTECT_LOCAL_MACHINE = 0x1, 0x4
    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    for _fn in (_crypt32.CryptProtectData, _crypt32.CryptUnprotectData):
        _fn.argtypes = [ctypes.POINTER(DATA_BLOB), wt.LPCWSTR, ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
                        ctypes.c_void_p, wt.DWORD, ctypes.POINTER(DATA_BLOB)]
        _fn.restype = wt.BOOL
    _crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(DATA_BLOB),
                                            ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(DATA_BLOB)]
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    def _blob(data: bytes) -> tuple[DATA_BLOB, Any]:
        buf = ctypes.create_string_buffer(data, len(data))
        return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def protect(data: bytes, machine: bool = True) -> bytes:
        src, _keep = _blob(data)
        out = DATA_BLOB()
        flags = CRYPTPROTECT_UI_FORBIDDEN | (CRYPTPROTECT_LOCAL_MACHINE if machine else 0)
        if not _crypt32.CryptProtectData(ctypes.byref(src), "EagleEye", None, None, None, flags, ctypes.byref(out)):
            raise OSError(f"CryptProtectData failed ({ctypes.get_last_error()})")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(out.pbData)

    def unprotect(data: bytes) -> bytes:
        src, _keep = _blob(data)
        out = DATA_BLOB()
        if not _crypt32.CryptUnprotectData(ctypes.byref(src), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN,
                                           ctypes.byref(out)):
            raise OSError(f"CryptUnprotectData failed ({ctypes.get_last_error()})")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(out.pbData)


class MachineSecrets:
    """The service's secrets, in one file next to its config (Keychain interface)."""

    def __init__(self, path: Optional[Path] = None, restrict: bool = True) -> None:
        self.path = path or machine_dir() / ("secrets.dat" if sys.platform == "win32" else "secrets.json")
        self.restrict = restrict                # False in tests: they run as a normal user

    def available(self) -> bool:
        return True

    def _read(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        try:
            raw = self.path.read_bytes()
            if sys.platform == "win32":
                raw = unprotect(raw)
            data = json.loads(raw.decode("utf-8"))
            return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
        except (OSError, ValueError) as exc:
            log.warning("Could not read the agent's secrets (%s): %s", self.path, exc)
            return {}

    def get(self, name: str) -> Optional[str]:
        return self._read().get(name)

    def set(self, name: str, value: str) -> bool:
        data = self._read()
        if value:
            data[name] = value
        else:
            data.pop(name, None)
        raw = json.dumps(data).encode("utf-8")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_bytes(protect(raw) if sys.platform == "win32" else raw)
            if sys.platform != "win32":
                tmp.chmod(0o600)
            tmp.replace(self.path)
            if sys.platform == "win32" and self.restrict:
                secure(self.path, secret=True)
            return True
        except OSError as exc:
            log.warning("Could not store %s: %s", name, exc)
            return False
