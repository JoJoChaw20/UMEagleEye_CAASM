"""Local scan schedules.

A schedule scans one subnet either every day at a local time ("daily") or every N
hours ("interval"). The agent asks the server for a scan record when a schedule is
due, so scheduled scans appear in the dashboard like dashboard-triggered ones.

When a run was missed (the machine was off), it runs once at the next check, not
once per missed slot. A schedule seen for the first time starts counting from then,
so adding one never triggers an immediate scan.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

_TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
MIN_HOURS, MAX_HOURS = 1, 168


@dataclass
class Schedule:
    subnet: str
    mode: str = "daily"          # daily | interval
    time: str = "02:00"          # daily: local HH:MM
    hours: int = 24              # interval: every N hours
    enabled: bool = True
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Schedule":
        known = {k: raw[k] for k in ("subnet", "mode", "time", "hours", "enabled", "id") if k in raw}
        known.setdefault("subnet", "")
        try:
            known["hours"] = int(known.get("hours", 24))
        except (TypeError, ValueError):
            known["hours"] = 0
        known["enabled"] = bool(known.get("enabled", True))
        return cls(**known)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def problems(self) -> list[str]:
        from .stages.scan_nmap import validate_target
        out: list[str] = []
        try:
            validate_target(self.subnet)
        except ValueError as exc:
            out.append(str(exc))
        if self.mode == "daily":
            if not _TIME.match(self.time or ""):
                out.append("time must be HH:MM (24-hour)")
        elif self.mode == "interval":
            if not MIN_HOURS <= self.hours <= MAX_HOURS:
                out.append(f"hours must be between {MIN_HOURS} and {MAX_HOURS}")
        else:
            out.append("mode must be 'daily' or 'interval'")
        return out

    def describe(self) -> str:
        if self.mode == "daily":
            return f"Every day at {self.time}"
        return "Every hour" if self.hours == 1 else f"Every {self.hours} hours"

    def last_slot(self, now: datetime) -> Optional[datetime]:
        """Daily only: the most recent scheduled moment at or before `now`."""
        if self.mode != "daily" or not _TIME.match(self.time or ""):
            return None
        hh, mm = (int(x) for x in self.time.split(":"))
        slot = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        return slot if slot <= now else slot - timedelta(days=1)

    def is_due(self, last_run: datetime, now: datetime) -> bool:
        if not self.enabled or self.problems():
            return False
        if self.mode == "daily":
            slot = self.last_slot(now)
            return slot is not None and last_run < slot
        return now - last_run >= timedelta(hours=self.hours)

    def next_run(self, last_run: datetime, now: datetime) -> Optional[datetime]:
        """When it will next run (for display); `now` if it is overdue."""
        if not self.enabled or self.problems():
            return None
        if self.is_due(last_run, now):
            return now
        if self.mode == "daily":
            slot = self.last_slot(now)
            return slot + timedelta(days=1) if slot else None
        return last_run + timedelta(hours=self.hours)


class ScheduleState:
    """When each schedule last ran, kept in a small JSON file next to the config so
    restarting the agent does not repeat or skip runs."""

    def __init__(self, path: Optional[Path]) -> None:
        self.path = path
        self.last_runs: dict[str, datetime] = {}
        self._load()

    def _load(self) -> None:
        if not self.path or not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.last_runs = {k: datetime.fromisoformat(v) for k, v in data.get("schedules", {}).items()}
        except (OSError, ValueError, AttributeError):
            self.last_runs = {}

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = {"schedules": {k: v.isoformat(timespec="seconds") for k, v in self.last_runs.items()}}
            self.path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass

    def last_run(self, schedule_id: str, now: datetime) -> datetime:
        """Last run, starting the clock now for a schedule seen for the first time."""
        if schedule_id not in self.last_runs:
            self.last_runs[schedule_id] = now
            self.save()
        return self.last_runs[schedule_id]

    def mark(self, schedule_id: str, when: datetime) -> None:
        self.last_runs[schedule_id] = when
        self.save()

    def forget_except(self, ids: set[str]) -> None:
        stale = set(self.last_runs) - ids
        if stale:
            for key in stale:
                del self.last_runs[key]
            self.save()
