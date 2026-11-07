"""Hardware vendor of a MAC address, looked up offline.

scapy ships Wireshark's manufacturer list (scapy.libs.manuf, about 50,000 prefixes), so
most real MACs get their vendor without asking an online service. The server used to look
every vendor up on api.macvendors.com, whose rate limit (about one request a second) left
most devices without one; it now takes the vendor sent here. The list holds only whole
3-byte prefixes and is as old as the scapy release, so for a real MAC it cannot name (an
IEEE MA-M/MA-S sub-block, a newer prefix) None is sent and the server asks online.

The agent also ships the IEEE registry itself (data/ieee_oui.tsv.gz, rebuilt with
packaging/update_ieee_oui.py), so it no longer needs scapy for this. Order: the IEEE
28/36-bit sub-blocks first (the most specific answer, which scapy's list lacks), then
scapy's list where scapy is installed (so vendors already stored keep their spelling),
then the IEEE 24-bit list.

A private (randomised) MAC has no vendor: its first byte has the "locally administered"
bit set (second hex digit 2, 6, A or E), so whatever its prefix matches means nothing.
"""

from __future__ import annotations

import gzip
import logging
import threading
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("eagleeye.vendor")

IEEE_FILE = Path(__file__).resolve().parent / "data" / "ieee_oui.tsv.gz"

_lock = threading.Lock()
_db: Any = None
_loaded = False
_ieee: Optional[dict[str, str]] = None


def _ieee_table() -> dict[str, str]:
    global _ieee
    with _lock:
        if _ieee is None:
            try:
                with gzip.open(IEEE_FILE, "rt", encoding="utf-8") as f:
                    _ieee = dict(line.rstrip("\n").split("\t", 1) for line in f if "\t" in line)
            except OSError as exc:
                log.debug("IEEE vendor list unavailable: %s", exc)
                _ieee = {}
        return _ieee


def ieee_vendor(norm: str, sub_blocks_only: bool = False) -> Optional[str]:
    """Longest-prefix match in the IEEE registry: 36-bit, then 28-bit, then 24-bit."""
    digits = norm.replace(":", "").upper()
    table = _ieee_table()
    for n in ((9, 7) if sub_blocks_only else (9, 7, 6)):
        name = table.get(digits[:n])
        if name:
            return name
    return None


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """'7C-61-30-38-96-02' -> '7c:61:30:38:96:02'; None for anything that is not a MAC."""
    if not mac:
        return None
    hexdigits = "".join(ch for ch in str(mac).lower() if ch in "0123456789abcdef")
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2)) if len(hexdigits) == 12 else None


def is_private_mac(mac: Optional[str]) -> bool:
    """True for a locally administered (randomised / virtual) MAC."""
    norm = normalize_mac(mac)
    return norm is not None and bool(int(norm[:2], 16) & 0x02)


def _manufdb() -> Any:
    global _db, _loaded
    with _lock:
        if not _loaded:
            _loaded = True
            try:
                from scapy.all import conf  # type: ignore
                _db = conf.manufdb
            except Exception as exc:  # noqa: BLE001 - no scapy: the server falls back
                log.debug("MAC vendor database unavailable: %s", exc)
                _db = None
        return _db


def mac_vendor(mac: Optional[str]) -> Optional[str]:
    """'Apple, Inc.' for 7c:61:30:..., None for a private, multicast or unknown MAC."""
    norm = normalize_mac(mac)
    if norm is None or int(norm[:2], 16) & 0x03:          # private or multicast
        return None
    specific = ieee_vendor(norm, sub_blocks_only=True)
    if specific:
        return specific
    db = _manufdb()
    if db is not None:
        try:
            _short, long_name = db.lookup(norm)
        except Exception:  # noqa: BLE001
            long_name = None
        name = str(long_name or "").strip()
        if name and normalize_mac(name) is None:           # unknown prefixes echo the MAC
            return name
    return ieee_vendor(norm)
