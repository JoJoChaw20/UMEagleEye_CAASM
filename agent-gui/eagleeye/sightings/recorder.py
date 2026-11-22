"""Matches waiting to be uploaded, counted: one entry per (listed value seen, how it was seen).

A first contact is uploaded within a minute; repeats are counted here and go with the next
upload (every 5 minutes while there are any). The same DNS answer can be heard more than
once (Windows' capture sees a packet at several network layers): a repeat within
DUPLICATE_SECONDS is the same lookup. What a failed upload held is put back.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

DUPLICATE_SECONDS = 2.0
MAX_ENTRIES = 1000                  # far more than any real computer; a flood keeps the first ones


@dataclass
class Entry:
    value: str
    type: str                       # domain | ip | hash
    via: str                        # dns | connection | process (a running program's file hash)
    count: int
    first: float
    last: float
    process: Optional[str] = None
    port: Optional[int] = None

    def payload(self) -> dict[str, Any]:
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds")  # noqa: E731
        out: dict[str, Any] = {"value": self.value, "type": self.type, "via": self.via, "count": self.count,
                               "first_seen": iso(self.first), "last_seen": iso(self.last)}
        if self.process:
            out["process"] = self.process
        if self.port:
            out["port"] = self.port
        return out


class HitRecorder:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str, str], Entry] = {}
        self._fresh = False                 # a value not uploaded before is waiting
        self._sent: set[tuple[str, str, str]] = set()   # uploaded since the agent started
        self.total = 0                      # contacts recorded since the agent started

    def record(self, value: str, type_: str, via: str, process: Optional[str] = None,
               port: Optional[int] = None) -> None:
        now = self._clock()
        key = (value, type_, via)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                if len(self._entries) >= MAX_ENTRIES:
                    return
                self._entries[key] = Entry(value, type_, via, 1, now, now, process, port)
                self._fresh = self._fresh or key not in self._sent
                self.total += 1
                return
            if via == "dns" and now - entry.last < DUPLICATE_SECONDS:
                return
            entry.count += 1
            entry.last = now
            entry.process = process or entry.process
            entry.port = port or entry.port
            self.total += 1

    def pending(self) -> int:
        with self._lock:
            return len(self._entries)

    def fresh(self) -> bool:
        with self._lock:
            return self._fresh

    def take(self) -> list[Entry]:
        with self._lock:
            out = list(self._entries.values())
            self._entries.clear()
            self._fresh = False
            return out

    def sent(self, entries: list[Entry]) -> None:
        """An upload worked: these are no longer new (their repeats wait for the 5-minute upload)."""
        with self._lock:
            self._sent.update((e.value, e.type, e.via) for e in entries)

    def restore(self, entries: list[Entry]) -> None:
        """Put back what a failed upload held, merged with what was recorded meanwhile."""
        with self._lock:
            self._fresh = self._fresh or any((e.value, e.type, e.via) not in self._sent for e in entries)
            for e in entries:
                key = (e.value, e.type, e.via)
                cur = self._entries.get(key)
                if cur is None:
                    if len(self._entries) < MAX_ENTRIES:
                        self._entries[key] = e
                    continue
                cur.count += e.count
                cur.first = min(cur.first, e.first)
                cur.last = max(cur.last, e.last)
                cur.process = cur.process or e.process
                cur.port = cur.port or e.port
