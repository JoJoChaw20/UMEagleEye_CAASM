"""The organisation's bad domains, IPs and malware file hashes, as this agent keeps them, and how
it keeps them up to date.

Two parts come from the server (workers/src/routes/sightings.ts):
  * feeds: ~130,000 values (ThreatFox, URLhaus, Feodo Tracker), paged by a cursor. Hashes come with
    list rules 4; an older server sends none, and an older agent skips them. The agent asks for what
    changed since its last page every FEEDS_EVERY; once a week it fetches the whole list
    again into a fresh copy and swaps it in, which drops what the server removed.
  * events: the published threat-intel events of its organisation, small, fetched whole
    every EVENTS_EVERY so an analyst's new event reaches the computers quickly.

Kept in memory as sets (~10 MB) and on disk (gzip JSON next to the config), so matching
works from the start, before the first sync. A list saved by another agent (this computer
connected before as another agent, perhaps of another organisation) is not used.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

log = logging.getLogger("eagleeye.sightings")

FEEDS_EVERY = 6 * 3600
FULL_EVERY = 7 * 86400
EVENTS_EVERY = 30 * 60
RETRY_AFTER = 15 * 60
MAX_PAGES = 200                     # 400,000 values: far above today's ~90,000
FILE_VERSION = 1
HEX = re.compile(r"[0-9a-f]+")


def normal_ip(value: str) -> Optional[str]:
    try:
        return ipaddress.ip_address(value.strip().strip("[]")).compressed
    except ValueError:
        return None


def normal_name(value: str) -> str:
    return value.strip().lower().rstrip(".")


class IndicatorList:
    """What to match: domains (a name matches when it or a parent domain is listed) and IPs."""

    def __init__(self) -> None:
        self.domains: set[str] = set()
        self.ips: set[str] = set()
        self.hashes: set[str] = set()           # malware file hashes (lowercase hex: MD5, SHA-1, SHA-256)
        self.event_domains: set[str] = set()
        self.event_ips: set[str] = set()
        self.event_hashes: set[str] = set()
        self.cursor: Optional[str] = None
        self.full_at = 0.0
        self.feeds_at = 0.0
        self.events_at = 0.0
        # The server's list rules (which indicators go on the list): when its number changes, the
        # whole list is fetched again (a delta would keep values the new rules leave out).
        self.rules: Optional[int] = None
        # The sync swaps whole sets in (one assignment each), so matching on the capture
        # thread never sees one half-filled.

    def __len__(self) -> int:
        return (len(self.domains) + len(self.ips) + len(self.hashes)
                + len(self.event_domains) + len(self.event_ips) + len(self.event_hashes))

    def has_hashes(self) -> bool:
        return bool(self.hashes or self.event_hashes)

    def match_hash(self, value: str) -> Optional[str]:
        h = value.lower()
        return h if h in self.hashes or h in self.event_hashes else None

    def match_domain(self, name: str) -> Optional[str]:
        """The listed domain `name` falls under (itself or a parent with two labels or more), or None."""
        labels = normal_name(name).split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self.domains or candidate in self.event_domains:
                return candidate
        return None

    def match_ip(self, value: str) -> Optional[str]:
        ip = normal_ip(value)
        return ip if ip is not None and (ip in self.ips or ip in self.event_ips) else None

    # ── filling it ──
    @staticmethod
    def split(items: Iterable[Any]) -> tuple[set[str], set[str]]:
        """Server items ({k: 'd'|'i', v}) as (domains, ips); anything else is skipped."""
        domains: set[str] = set()
        ips: set[str] = set()
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("v"), str):
                continue
            if item.get("k") == "d":
                name = normal_name(item["v"])
                if "." in name:
                    domains.add(name)
            elif item.get("k") == "i":
                ip = normal_ip(item["v"])
                if ip:
                    ips.add(ip)
        return domains, ips

    @staticmethod
    def hashes_of(items: Iterable[Any]) -> set[str]:
        """Server items {k: 'h', v} (list rules 4+) as lowercase hex hashes of 32, 40 or 64 digits."""
        out: set[str] = set()
        for item in items:
            if isinstance(item, dict) and item.get("k") == "h" and isinstance(item.get("v"), str):
                h = item["v"].strip().lower()
                if len(h) in (32, 40, 64) and HEX.fullmatch(h):
                    out.add(h)
        return out

    # ── on disk ──
    def save(self, path: Optional[Path], agent_id: str) -> None:
        if path is None:
            return
        data = {
            "version": FILE_VERSION, "agent_id": agent_id, "cursor": self.cursor, "rules": self.rules,
            "full_at": self.full_at, "feeds_at": self.feeds_at, "events_at": self.events_at,
            "domains": sorted(self.domains), "ips": sorted(self.ips), "hashes": sorted(self.hashes),
            "event_domains": sorted(self.event_domains), "event_ips": sorted(self.event_ips),
            "event_hashes": sorted(self.event_hashes),
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(gzip.compress(json.dumps(data).encode("utf-8")))
            tmp.replace(path)
        except OSError as exc:
            log.warning("Could not save the threat list to %s: %s", path, exc)

    @classmethod
    def load(cls, path: Optional[Path], agent_id: str) -> "IndicatorList":
        out = cls()
        if path is None or not path.exists():
            return out
        try:
            data = json.loads(gzip.decompress(path.read_bytes()).decode("utf-8"))
        except (OSError, ValueError, EOFError) as exc:
            log.warning("Could not read the saved threat list (%s); fetching it again", exc)
            return out
        if not isinstance(data, dict) or data.get("version") != FILE_VERSION or data.get("agent_id") != agent_id:
            return out
        out.domains = {normal_name(d) for d in data.get("domains") or [] if isinstance(d, str)}
        out.ips = {ip for ip in (normal_ip(v) for v in data.get("ips") or [] if isinstance(v, str)) if ip}
        out.event_domains = {normal_name(d) for d in data.get("event_domains") or [] if isinstance(d, str)}
        out.event_ips = {ip for ip in (normal_ip(v) for v in data.get("event_ips") or [] if isinstance(v, str)) if ip}
        # saved as hex strings: read back through the same check as the server's items
        out.hashes = IndicatorList.hashes_of({"k": "h", "v": v} for v in data.get("hashes") or [])
        out.event_hashes = IndicatorList.hashes_of({"k": "h", "v": v} for v in data.get("event_hashes") or [])
        out.cursor = data.get("cursor") if isinstance(data.get("cursor"), str) else None
        out.rules = data.get("rules") if isinstance(data.get("rules"), int) else None
        for key in ("full_at", "feeds_at", "events_at"):
            value = data.get(key)
            setattr(out, key, float(value) if isinstance(value, (int, float)) else 0.0)
        return out


# fetch(part, after) -> {"items": [...], "next": str|None, "done": bool} (feeds)
#                     | {"items": [...], "truncated": bool} (events); raises on failure
Fetch = Callable[[str, Optional[str]], dict[str, Any]]


class ListSync:
    """Keeps an IndicatorList current. sync() does what is due and returns what it did."""

    def __init__(self, lst: IndicatorList, fetch: Fetch, path: Optional[Path], agent_id: str,
                 clock: Callable[[], float] = time.time) -> None:
        self.list = lst
        self._fetch = fetch
        self._path = path
        self._agent_id = agent_id
        self._clock = clock
        self.retry_at = 0.0
        self.last_error: Optional[str] = None

    def due(self) -> bool:
        now = self._clock()
        if now < self.retry_at:
            return False
        lst = self.list
        return (now - lst.events_at >= EVENTS_EVERY or now - lst.feeds_at >= FEEDS_EVERY
                or now - lst.full_at >= FULL_EVERY)

    def sync(self) -> list[str]:
        """Fetch what is due: the events part, then the feeds (whole when a week has passed).
        A failure keeps the list as it was and tries again after RETRY_AFTER."""
        now = self._clock()
        lst = self.list
        done: list[str] = []
        new_rules: Optional[int] = None
        try:
            full = now - lst.full_at >= FULL_EVERY
            if now - lst.events_at >= EVENTS_EVERY:
                answer = self._fetch("events", None)
                items = answer.get("items") or []
                domains, ips = IndicatorList.split(items)
                hashes = IndicatorList.hashes_of(items)
                lst.event_domains, lst.event_ips, lst.event_hashes = domains, ips, hashes
                lst.events_at = now
                done.append(f"events: {len(domains) + len(ips) + len(hashes)} value(s)")
                if answer.get("truncated"):
                    log.warning("The organisation's threat-intel events list more values than the agent takes; "
                                "only the first ones are matched")
                rules = answer.get("rules")
                if isinstance(rules, int) and rules != lst.rules:
                    if lst.rules is not None or lst.full_at:    # a list kept under other rules (or none said)
                        log.info("The server's threat list rules changed (%s -> %s); fetching the whole list", lst.rules, rules)
                        full = True
                    new_rules = rules       # kept only once the list was fetched under them
            if full:
                domains, ips, hashes, cursor, pages = self._pages(None, set(), set(), set())
                lst.domains, lst.ips, lst.hashes, lst.cursor = domains, ips, hashes, cursor
                lst.full_at = lst.feeds_at = now
                done.append(f"feeds in full: {len(domains) + len(ips) + len(hashes)} value(s) in {pages} page(s)")
            elif now - lst.feeds_at >= FEEDS_EVERY:
                before = len(lst.domains) + len(lst.ips) + len(lst.hashes)
                domains, ips, hashes, cursor, pages = self._pages(lst.cursor, set(lst.domains), set(lst.ips), set(lst.hashes))
                lst.domains, lst.ips, lst.hashes, lst.cursor = domains, ips, hashes, cursor
                lst.feeds_at = now
                done.append(f"feeds since the last sync: {len(domains) + len(ips) + len(hashes) - before} new value(s) "
                            f"in {pages} page(s)")
            if new_rules is not None:
                lst.rules = new_rules
        except Exception as exc:  # noqa: BLE001 - any failure: keep the list, try later
            if new_rules is not None:
                lst.events_at = 0.0         # ask again, so the new rules still force the whole list
            self.retry_at = now + RETRY_AFTER
            self.last_error = str(exc)
            log.warning("Threat list sync failed (%s); trying again in %d min", exc, RETRY_AFTER // 60)
            return done
        self.last_error = None
        if done:
            lst.save(self._path, self._agent_id)
        return done

    def _pages(self, cursor: Optional[str], domains: set[str], ips: set[str],
               hashes: set[str]) -> tuple[set[str], set[str], set[str], Optional[str], int]:
        pages = 0
        while pages < MAX_PAGES:
            answer = self._fetch("feeds", cursor)
            pages += 1
            items = answer.get("items") or []
            more_domains, more_ips = IndicatorList.split(items)
            domains |= more_domains
            ips |= more_ips
            hashes |= IndicatorList.hashes_of(items)
            nxt = answer.get("next")
            if isinstance(nxt, str):
                cursor = nxt
            if answer.get("done", True) or not isinstance(nxt, str):
                break
        return domains, ips, hashes, cursor, pages
