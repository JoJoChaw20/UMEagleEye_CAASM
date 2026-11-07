"""Rebuild eagleeye/data/ieee_oui.tsv.gz from the IEEE registration authority's public lists.

    python packaging/update_ieee_oui.py

Downloads the MA-L (24-bit), MA-M (28-bit) and MA-S (36-bit) registries and writes one
line per assignment: the prefix in upper-case hex (6, 7 or 9 digits), a tab, the
organisation name. vendor.py looks MACs up in it, longest prefix first. Run it before a
release so new prefixes are known; the agent never downloads it itself.
"""

from __future__ import annotations

import csv
import gzip
import io
import sys
import urllib.request
from pathlib import Path

SOURCES = (
    ("MA-L", "https://standards-oui.ieee.org/oui/oui.csv", 6),
    ("MA-M", "https://standards-oui.ieee.org/oui28/mam.csv", 7),
    ("MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv", 9),
)
OUT = Path(__file__).resolve().parents[1] / "eagleeye" / "data" / "ieee_oui.tsv.gz"


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (EagleEye agent build)"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse(text: str, digits: int) -> dict[str, str]:
    """Registry CSV (columns Registry, Assignment, Organization Name, ...) -> prefix -> name."""
    out: dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(text)):
        prefix = "".join(ch for ch in (row.get("Assignment") or "").upper() if ch in "0123456789ABCDEF")
        name = " ".join((row.get("Organization Name") or "").split())
        if len(prefix) == digits and name and name.lower() != "private":
            out[prefix] = name
    return out


def main() -> int:
    entries: dict[str, str] = {}
    for label, url, digits in SOURCES:
        found = parse(fetch(url), digits)
        if len(found) < (1000 if digits == 6 else 100):
            print(f"{label}: only {len(found)} entries from {url}; not writing a partial list", file=sys.stderr)
            return 1
        print(f"{label}: {len(found)} entries")
        entries.update(found)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{p}\t{n}\n" for p, n in sorted(entries.items()))
    with gzip.open(OUT, "wt", encoding="utf-8", newline="\n") as f:
        f.write(body)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB, {len(entries)} prefixes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
