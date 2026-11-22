"""The programs running on this computer, as file hashes, for matching against the malware hashes
the organisation's threat intelligence lists (ThreatFox's payload hashes, an analyst's event).

Each round lists the running processes' executables and hashes the ones not hashed before, or
changed since (size or modification time): SHA-256, SHA-1 and MD5 in one read, as feeds list any of
the three. A program is hashed once while it stays the same, so a round costs a process listing
and a few new files. Only a match leaves the computer (the hash and the program's file name);
what runs here is never sent.

  * Windows: EnumProcesses + QueryFullProcessImageNameW (the service runs as SYSTEM: every process).
  * Linux: /proc/<pid>/exe, read through the link, so a program that deleted its own file after
    starting is still hashed (root sees every process).
  * macOS: ps -axo pid=,comm= (the full path of each executable).

A file larger than MAX_FILE is skipped (installers and IDEs, not payloads), and a round hashes at
most MAX_NEW files: a computer that has just started has the rest hashed over the next rounds.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

log = logging.getLogger("eagleeye.sightings")

MAX_FILE = 100 * 1024 * 1024
MAX_NEW = 50
CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Program:
    path: str                       # where it runs from (for the cache; never sent)
    read_from: str                  # what to open: the path, or /proc/<pid>/exe on Linux

    @property
    def name(self) -> str:
        return re.split(r"[\\/]", self.path.replace(" (deleted)", ""))[-1] or self.path


@dataclass(frozen=True)
class Hashes:
    sha256: str
    sha1: str
    md5: str

    def all(self) -> tuple[str, str, str]:
        return (self.sha256, self.sha1, self.md5)


def hash_file(path: str, max_size: int = MAX_FILE) -> Optional[Hashes]:
    """The three hashes of a file in one read, or None (unreadable, gone, or too large)."""
    try:
        with open(path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            if size > max_size:
                return None
            s256, s1, m5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()  # noqa: S324 - matching feeds' MD5s, not security
            while chunk := fh.read(CHUNK):
                s256.update(chunk)
                s1.update(chunk)
                m5.update(chunk)
    except OSError:
        return None
    return Hashes(s256.hexdigest(), s1.hexdigest(), m5.hexdigest())


def _stat_key(path: str) -> Optional[tuple[int, int]]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_size, st.st_mtime_ns)


class ProgramHasher:
    """Hashes of the running programs, each file hashed once while it stays the same."""

    def __init__(self, list_programs: Callable[[], Iterable[Program]],
                 hasher: Callable[[str], Optional[Hashes]] = hash_file,
                 stat: Callable[[str], Optional[tuple[int, int]]] = _stat_key,
                 max_new: int = MAX_NEW) -> None:
        self._list = list_programs
        self._hash = hasher
        self._stat = stat
        self._max_new = max_new
        self._cache: dict[str, tuple[Optional[tuple[int, int]], Optional[Hashes]]] = {}
        self.hashed = 0                 # files hashed since the agent started

    def round(self) -> list[tuple[Program, Hashes]]:
        """The running programs with their hashes (the ones known so far)."""
        out: list[tuple[Program, Hashes]] = []
        new = 0
        running: set[str] = set()
        for prog in self._list():
            if prog.path in running:
                continue
            running.add(prog.path)
            key = self._stat(prog.read_from)
            cached = self._cache.get(prog.path)
            if cached is None or (key is not None and cached[0] != key):
                if new >= self._max_new:
                    continue            # the next round
                new += 1
                hashes = self._hash(prog.read_from)
                self.hashed += hashes is not None
                cached = (key, hashes)
                self._cache[prog.path] = cached
            if cached[1] is not None:
                out.append((prog, cached[1]))
        # programs no longer running are forgotten (their file may be replaced before the next run)
        for path in [p for p in self._cache if p not in running]:
            del self._cache[path]
        return out


# ── this system ──────────────────────────────────────────────────────────────
def linux_programs(proc: str = "/proc") -> list[Program]:
    out: list[Program] = []
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return out
    for pid in pids:
        link = os.path.join(proc, pid, "exe")
        try:
            target = os.readlink(link)
        except OSError:
            continue                    # a kernel thread, or another user's (not root)
        out.append(Program(target, link))
    return out


def parse_ps(text: str) -> list[Program]:
    """`ps -axo pid=,comm=` on macOS: the full path of each executable."""
    out: list[Program] = []
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[1].startswith("/"):
            out.append(Program(parts[1], parts[1]))
    return out


def macos_programs() -> list[Program]:  # pragma: no cover - runs ps
    try:
        res = subprocess.run(["ps", "-axo", "pid=,comm="], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_ps(res.stdout)


def windows_programs() -> list[Program]:  # pragma: no cover - needs Windows
    import ctypes
    from ctypes import wintypes as wt
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    count = 4096
    while True:
        pids = (wt.DWORD * count)()
        needed = wt.DWORD()
        if not psapi.EnumProcesses(pids, ctypes.sizeof(pids), ctypes.byref(needed)):
            return []
        if needed.value < ctypes.sizeof(pids):
            break
        count *= 2
    out: list[Program] = []
    buf = ctypes.create_unicode_buffer(1024)
    for pid in pids[: needed.value // ctypes.sizeof(wt.DWORD)]:
        if not pid:
            continue
        handle = kernel32.OpenProcess(0x1000, False, pid)       # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            continue
        try:
            size = wt.DWORD(len(buf))
            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)) and buf.value:
                out.append(Program(buf.value, buf.value))
        finally:
            kernel32.CloseHandle(handle)
    return out


def running_programs() -> list[Program]:  # pragma: no cover - reads the live system
    try:
        if sys.platform == "win32":
            return windows_programs()
        if sys.platform == "darwin":
            return macos_programs()
        if sys.platform.startswith("linux"):
            return linux_programs()
    except Exception as exc:  # noqa: BLE001 - one bad listing must not stop sightings
        log.debug("Could not list the running programs: %s", exc)
    return []
