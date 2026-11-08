"""Score a crawl against a lab's ground truth.

devices CSV: ip, mac, name, device, os, services, vlan, switch, port, notes (one row per address;
    switch/port = where it is plugged in, empty when it is not behind a switch)
links CSV:   a_device, a_port, b_device, b_port, seen_by, notes (seen_by 'none' = a cable no
    CDP/LLDP can see, e.g. to a host without LLDP)
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Optional

from .collect import base_name, short_port
from .crawl import CrawlResult


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as f:
        return [{k.strip(): (v or "").strip() for k, v in row.items()} for row in csv.DictReader(f)]


def _same_device(a: str, b: str) -> bool:
    return bool(a) and base_name(a).lower() == base_name(b).lower()


def _same_port(a: str, b: str) -> bool:
    return short_port(a).lower() == short_port(b).lower()


def score(result: CrawlResult, devices: list[dict[str, str]],
          links: Optional[list[dict[str, str]]] = None) -> dict[str, Any]:
    hosts = {h["ip"]: h for h in result.hosts if h["ip"]}
    owner = {ip: d for d in result.devices for ip in d.own_ips}
    rows: list[dict[str, Any]] = []
    out: dict[str, Any] = {"addresses": 0, "found": 0, "mac_right": 0, "mac_checked": 0,
                           "names_right": 0, "names_checked": 0,
                           "located_right": 0, "located_wrong": 0, "not_located": 0, "rows": rows}
    for t in devices:
        ip, mac = t.get("ip", ""), t.get("mac", "").upper()
        h, dev = hosts.get(ip), owner.get(ip)
        row: dict[str, Any] = {"ip": ip, "name": t.get("name", ""), "found": bool(h or dev)}
        out["addresses"] += 1
        out["found"] += row["found"]
        got_mac = (h or {}).get("mac")
        if mac and got_mac:
            out["mac_checked"] += 1
            out["mac_right"] += got_mac == mac
            row["mac"] = "right" if got_mac == mac else f"wrong ({got_mac})"
        if dev is not None and t.get("name"):           # a polled device: is its name right?
            out["names_checked"] += 1
            out["names_right"] += _same_device(dev.label, t["name"])
        switch, port = t.get("switch", ""), t.get("port", "")
        if switch and port:
            if dev is not None:                         # a network device: a link must say where it is
                ok = any(_link_has(l, switch, port, dev.label) for l in result.links)
                row["location"] = "right (link)" if ok else "no link found"
                out["located_right" if ok else "not_located"] += 1
            else:
                loc = (h or {}).get("location")
                if not loc:
                    row["location"] = "not located"
                    out["not_located"] += 1
                elif _same_device(loc["switch"], switch) and _same_port(loc["port"], port):
                    row["location"] = "right" + (" (ambiguous)" if loc.get("ambiguous") else "")
                    out["located_right"] += 1
                else:
                    row["location"] = f"wrong ({loc['switch']} {loc['port']})"
                    out["located_wrong"] += 1
        rows.append(row)

    if links is not None:
        found, expected, missed, invisible = 0, 0, [], []
        for t in links:
            ends = (t.get("a_device", ""), t.get("a_port", ""), t.get("b_device", ""), t.get("b_port", ""))
            hit = any(_link_matches(l, *ends) for l in result.links)
            if t.get("seen_by", "").lower() == "none":
                invisible.append({"link": " - ".join(ends), "found": hit})
                continue
            expected += 1
            found += hit
            if not hit:
                missed.append(" ".join(ends[:2]) + " - " + " ".join(ends[2:]))
        extra = [l for l in result.links if not any(_link_matches(l, t.get("a_device", ""), t.get("a_port", ""),
                                                                  t.get("b_device", ""), t.get("b_port", ""))
                                                    for t in links)]
        out["links"] = {"expected": expected, "found": found, "missed": missed, "not_visible": invisible,
                        "extra": [f"{l['a']['device']} {l['a']['port']} - {l['b']['device']} {l['b']['port']}" for l in extra]}
    return out


def _end_is(end: dict, device: str, port: str) -> bool:
    return _same_device(end["device"], device) and _same_port(end["port"], port)


def _link_matches(link: dict, a_dev: str, a_port: str, b_dev: str, b_port: str) -> bool:
    a, b = link["a"], link["b"]
    return ((_end_is(a, a_dev, a_port) and _end_is(b, b_dev, b_port))
            or (_end_is(a, b_dev, b_port) and _end_is(b, a_dev, a_port)))


def _link_has(link: dict, switch: str, port: str, device: str) -> bool:
    a, b = link["a"], link["b"]
    return ((_end_is(a, switch, port) and _same_device(b["device"], device))
            or (_end_is(b, switch, port) and _same_device(a["device"], device)))
