"""A crawl as the server takes it, in two uploads (workers/src/routes):

1. POST /scans/ingest, scan_type "snmp": one host per address, like any scan, so the
   devices become assets through the same identity rules as every other agent's. Each
   polled router or switch is ONE host (the address it was polled at, named by its sysName,
   with its SNMP facts); its other addresses go in the topology, not here, so a router with
   five interfaces is not five devices.
2. POST /network/topology: the polled devices' details, the cables between them and where
   each device is plugged in, matched to those assets by the server.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .crawl import CrawlResult

VendorLookup = Callable[[Optional[str]], Optional[str]]


def _device_mac(dev: Any) -> Optional[str]:
    """The MAC of the interface that has the address the device was polled at."""
    for a in dev.addresses:
        if a["ip"] == dev.address:
            iface = dev.interfaces.get(a["if_index"])
            if iface and iface.mac:
                return iface.mac
    return None


def ingest_hosts(result: CrawlResult, vendor: Optional[VendorLookup] = None) -> list[dict[str, Any]]:
    hosts: list[dict[str, Any]] = []
    for d in result.devices:
        os_name = " ".join(p for p in (d.os, d.version) if p)
        host: dict[str, Any] = {
            "ip": d.address, "mac": _device_mac(d), "hostname": d.label,
            "snmp_sysname": d.name or d.label, "snmp_sysdescr": d.descr[:2000] or None,
            "snmp_sysobjectid": d.object_id or None,
            "snmp_interfaces": [i.name for i in sorted(d.interfaces.values(), key=lambda i: i.index) if i.name][:500],
        }
        if os_name:
            host["os"] = {"name": os_name, **({"vendor": d.vendor} if d.vendor else {})}
        hosts.append(host)
    for h in result.hosts:
        if not h["ip"] or h["device"]:             # MAC only, or a polled device's own address
            continue
        host = {"ip": h["ip"], "mac": h["mac"]}
        name = vendor(h["mac"]) if vendor else None
        if name:
            host["mac_vendor"] = name[:255]
        hosts.append(host)
    return hosts


def _device(d: Any) -> dict[str, Any]:
    full = d.to_dict()
    keep = ("address", "name", "label", "object_id", "vendor", "os", "version", "uptime_seconds", "found_via",
            "bridge_mac", "interfaces", "addresses", "vlans")
    out = {k: full[k] for k in keep}
    out["descr"] = d.descr[:2000]
    out["notes"] = [n[:500] for n in d.notes][:50]
    out["errors"] = [e[:500] for e in d.errors][:50]
    out["interfaces"] = [{**i, "name": i["name"][:64], "alias": i["alias"][:255]} for i in out["interfaces"]][:2000]
    return out


def topology_payload(result: CrawlResult, scan_id: Optional[str] = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "devices": [_device(d) for d in result.devices],
        "links": [{"a": l["a"], "b": l["b"], "protocols": l["protocols"]} for l in result.links],
        "hosts": [{"ip": h["ip"], "mac": h["mac"], "vlan": h["vlan"], "interface": h["interface"][:64],
                   "seen_by": h["seen_by"][:20], "device": h["device"],
                   "location": None if not h["location"] else {
                       k: h["location"][k] for k in ("switch", "port", "vlan", "ambiguous")}}
                  for h in result.hosts],
        "stats": {"seconds": result.seconds, "requests": result.requests, "bytes_received": result.bytes_received,
                  "unreachable": [{"address": u["address"], "error": u["error"][:300]} for u in result.unreachable][:500],
                  "skipped": len(result.skipped)},
    }
    if scan_id:
        payload["scan_id"] = scan_id
    return payload
