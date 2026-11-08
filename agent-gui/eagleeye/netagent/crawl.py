"""Follow CDP/LLDP neighbours from the seed devices, then put the answers together.

The crawl only polls addresses inside the allowed ranges, at most `depth` hops from a seed. A
device reached again by another of its addresses (CDP often names a router by the address of
the port that faces you) is recognised by its own address list and polled once.

The analysis:
- links: one per cable, from both ends' CDP/LLDP (port names made the same: Gi0/1; LLDP a router sends
  from a subinterface, Gi0/1.10, counts for its cable port Gi0/1);
- hosts: every IP -> MAC from the routers' ARP tables, marked when it is one of the polled
  devices;
- locations: the switch port a MAC is plugged into. Trunks and ports with a CDP/LLDP neighbour
  carry many devices' MACs, so only edge ports locate a device; when a MAC is on edge ports of
  two switches (an unmanaged switch in between), the port with the fewest MACs wins and the
  location is marked ambiguous.
"""

from __future__ import annotations

import ipaddress
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from .collect import Device, base_name, cable_port, poll_device, short_port
from .snmp import SnmpError

Network = ipaddress.IPv4Network


def parse_ranges(ranges: Iterable[str]) -> list[Network]:
    return [ipaddress.ip_network(r.strip(), strict=False) for r in ranges if r.strip()]  # type: ignore[misc]


def in_ranges(ip: str, ranges: list[Network]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in r for r in ranges)


@dataclass
class CrawlResult:
    devices: list[Device] = field(default_factory=list)
    unreachable: list[dict] = field(default_factory=list)   # {address, error, via}
    skipped: list[dict] = field(default_factory=list)       # neighbours not polled: {name, address, reason, via}
    links: list[dict] = field(default_factory=list)
    hosts: list[dict] = field(default_factory=list)
    networks: list[dict] = field(default_factory=list)
    seconds: float = 0.0
    requests: int = 0
    bytes_received: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "devices": [d.to_dict() for d in self.devices], "unreachable": self.unreachable,
            "skipped": self.skipped, "links": self.links, "hosts": self.hosts, "networks": self.networks,
            "seconds": self.seconds, "requests": self.requests, "bytes_received": self.bytes_received,
        }


def crawl(seeds: list[str], open_session: Callable[[str], Any], allowed: list[Network], depth: int = 3,
          workers: int = 8, max_devices: int = 500,
          progress: Optional[Callable[[str], None]] = None) -> CrawlResult:
    """Poll the seeds, then their neighbours inside `allowed`, up to `depth` hops away."""
    started = time.monotonic()
    result = CrawlResult()
    tried: set[str] = set()
    known_ips: set[str] = set()
    known_names: set[str] = set()
    say = progress or (lambda _m: None)

    def poll(item: tuple[str, str]) -> tuple[str, str, Any]:
        address, via = item
        try:
            with open_session(address) as session:
                return address, via, poll_device(session, address)
        except SnmpError as exc:
            return address, via, exc

    level = [(s, "seed") for s in seeds]
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for hop in range(depth + 1):
            todo = []
            for address, via in level:
                if address in tried or address in known_ips:
                    continue
                tried.add(address)
                todo.append((address, via))
            if not todo:
                break
            room = max_devices - len(result.devices)
            for address, via in todo[room:]:
                result.skipped.append({"name": "", "address": address, "via": via,
                                       "reason": f"more than {max_devices} devices"})
            todo = todo[:max(0, room)]
            next_level: list[tuple[str, str]] = []
            for address, via, outcome in pool.map(poll, todo):
                if isinstance(outcome, Exception):
                    result.unreachable.append({"address": address, "error": str(outcome), "via": via})
                    say(f"{address}: {outcome}")
                    continue
                dev: Device = outcome
                if dev.own_ips & known_ips:                 # the same device by another address
                    continue
                dev.found_via, dev.depth = via, hop
                result.devices.append(dev)
                known_ips.update(dev.own_ips)
                known_names.add(dev.label.lower())
                say(f"{dev.label} ({address}): {len(dev.interfaces)} interfaces, {len(dev.arp)} ARP, "
                    f"{len(dev.fdb)} MAC, {len(dev.neighbors)} neighbours, {dev.seconds}s")
                for n in dev.neighbors:
                    via_text = f"{n.protocol.upper()} from {dev.label} {short_port(n.local_port)}"
                    who = base_name(n.name) or n.address or "?"
                    if n.address and n.address in known_ips or who.lower() in known_names:
                        continue
                    if not n.address:
                        reason = "its CDP/LLDP gives no management address"
                    elif not in_ranges(n.address, allowed):
                        reason = "outside the allowed ranges"
                    elif hop >= depth:
                        reason = f"more than {depth} hops from a seed"
                    else:
                        next_level.append((n.address, via_text))
                        continue
                    result.skipped.append({"name": n.name, "address": n.address, "reason": reason, "via": via_text})
            level = next_level
    # a neighbour skipped from one side may have been polled from another
    result.skipped = _dedupe_skipped([s for s in result.skipped
                                      if s["address"] not in known_ips and base_name(s["name"]).lower() not in known_names])
    analyse(result)
    result.seconds = round(time.monotonic() - started, 2)
    result.requests = sum(d.requests for d in result.devices)
    result.bytes_received = sum(d.bytes_received for d in result.devices)
    return result


def _dedupe_skipped(skipped: list[dict]) -> list[dict]:
    seen, out = set(), []
    for s in skipped:
        key = (base_name(s["name"]).lower(), s["address"])
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


def analyse(result: CrawlResult) -> None:
    devices = result.devices
    owner_by_ip = {ip: d.label for d in devices for ip in d.own_ips}
    owner_by_mac = {mac: d.label for d in devices for mac in d.own_macs}
    owner_by_name = {d.label.lower(): d.label for d in devices}

    # ── links ──
    links: dict[tuple, dict] = {}
    uplinks: dict[str, set[int]] = defaultdict(set)
    for d in devices:
        for n in d.neighbors:
            remote = (owner_by_ip.get(n.address or "") or owner_by_name.get(base_name(n.name).lower())
                      or base_name(n.name) or n.address or "?")
            a, b = (d.label, cable_port(n.local_port)), (remote, cable_port(n.port))
            key = tuple(sorted([a, b]))
            link = links.setdefault(key, {
                "a": {"device": key[0][0], "port": key[0][1]}, "b": {"device": key[1][0], "port": key[1][1]},
                "protocols": set(), "seen_from": set(),
            })
            link["protocols"].add(n.protocol)
            link["seen_from"].add(d.label)
            if n.local_if is not None:
                uplinks[d.label].add(n.local_if)
        for iface in d.interfaces.values():
            if iface.trunk:
                uplinks[d.label].add(iface.index)
    polled = set(owner_by_name.values())
    result.links = [
        {**l, "protocols": sorted(l["protocols"]), "seen_from": sorted(l["seen_from"]),
         "both_polled": l["a"]["device"] in polled and l["b"]["device"] in polled}
        for _k, l in sorted(links.items())
    ]

    # ── hosts from ARP ──
    hosts: dict[str, dict] = {}
    for d in devices:
        for e in d.arp:
            iface = d.interfaces.get(e["if_index"])
            h = hosts.setdefault(e["ip"], {
                "ip": e["ip"], "mac": e["mac"], "device": owner_by_ip.get(e["ip"]) or owner_by_mac.get(e["mac"]),
                "seen_by": [], "interface": iface.name if iface else "", "vlan": iface.vlan if iface else None,
                "location": None,
            })
            if d.label not in h["seen_by"]:
                h["seen_by"].append(d.label)
            if h["mac"] != e["mac"]:
                h.setdefault("other_macs", []).append(e["mac"])

    # ── locations from the MAC tables (edge ports only) ──
    per_port = Counter((d.label, f["if_index"]) for d in devices for f in d.fdb if f["if_index"] is not None)
    candidates: dict[str, list[dict]] = defaultdict(list)
    for d in devices:
        for f in d.fdb:
            if f["if_index"] is None or f["mac"] in owner_by_mac or f["if_index"] in uplinks[d.label]:
                continue
            candidates[f["mac"]].append({"switch": d.label, "port": short_port(d.port_name(f["if_index"])),
                                         "vlan": f["vlan"], "macs_on_port": per_port[(d.label, f["if_index"])]})
    by_mac = {h["mac"]: h for h in hosts.values()}
    for mac, cands in candidates.items():
        best = min(cands, key=lambda c: (c["macs_on_port"], c["switch"]))
        location = {**best, "ambiguous": len({(c["switch"], c["port"]) for c in cands}) > 1}
        if mac in by_mac:
            by_mac[mac]["location"] = location
            if by_mac[mac]["vlan"] is None:
                by_mac[mac]["vlan"] = best["vlan"]
        else:                                   # heard on a switch, never in an ARP table
            hosts[mac] = {"ip": None, "mac": mac, "device": None, "seen_by": [best["switch"]],
                          "interface": "", "vlan": best["vlan"], "location": location}
    result.hosts = sorted(hosts.values(), key=lambda h: (h["ip"] is None, _ip_key(h["ip"]), h["mac"]))

    # ── networks the devices are on ──
    nets: dict[str, dict] = {}
    for d in devices:
        for a in d.addresses:
            if a["network"] and not a["network"].endswith("/32"):
                iface = d.interfaces.get(a["if_index"])
                nets.setdefault(a["network"], {"network": a["network"], "addresses": [], "vlan": iface.vlan if iface else None})
                nets[a["network"]]["addresses"].append({"device": d.label, "ip": a["ip"],
                                                       "interface": iface.name if iface else ""})
    result.networks = sorted(nets.values(), key=lambda n: ipaddress.ip_network(n["network"]))


def _ip_key(ip: Optional[str]) -> int:
    try:
        return int(ipaddress.ip_address(ip)) if ip else 0
    except ValueError:
        return 0
