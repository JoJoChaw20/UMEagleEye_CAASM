"""The own engine as a pipeline stage, the side-by-side comparison with the Nmap stage, and
the choice between them (Settings.scan_engine):

    auto, nmap   the Nmap stage as before (Nmap, or the built-in sweep without it)
    own          the own engine (engine/)
    compare      both, one after the other on the same target; the own engine's hosts are
                 the result, and a report of where the two agree is written locally
"""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ..engine import run_own_scan
from ..pipeline.record import HostRecord
from ..pipeline.runner import PipelineContext, Stage
from .scan_nmap import NmapScanStage, fill_own_host, validate_target

log = logging.getLogger("eagleeye.scan")

ENGINES = ("auto", "nmap", "own", "compare")
OWN_MAX_HOSTS = 4096     # the own engine ARPs/pings every address: a /20 at most


class OwnScanStage(Stage):
    name = "scan"
    label = "Discover and fingerprint hosts"

    def __init__(self, subnet: str, tier: str = "base") -> None:
        self.subnet = subnet
        self.tier = tier

    def run(self, ctx: PipelineContext) -> None:
        target = validate_target(self.subnet, max_hosts=OWN_MAX_HOSTS)
        ctx.progress(f"Scanning {target} with the own engine ({self.tier} ports)")
        hosts, stats = run_own_scan(target, self.tier, ctx.progress, ctx.cancelled)
        fill_own_host(hosts)
        ctx.hosts = hosts
        ctx.summary["scanner"] = "own"
        ctx.summary["engine"] = stats.as_dict()
        ctx.progress(f"{len(hosts)} host(s) up", len(hosts), None)


# ── comparison ──────────────────────────────────────────────────────────────

def _norm_service(name: str) -> str:
    """Treat the two engines' names for the same thing as equal (Nmap says http for a TLS
    port it identified; IANA says https)."""
    n = (name or "").lower().replace("ssl/", "")
    return {"https": "http", "http-alt": "http", "http-proxy": "http", "pcsync-https": "http",
            "https-alt": "http", "mongod": "mongodb", "epmap": "msrpc"}.get(n, n)


def compare_hosts(own: list[HostRecord], ref: list[HostRecord]) -> dict[str, Any]:
    """Where the own engine and the reference agree: hosts, MACs, open ports, names."""
    a = {h.ip: h for h in own}
    b = {h.ip: h for h in ref}
    both = sorted(set(a) & set(b), key=lambda ip: tuple(int(x) for x in ip.split(".")))
    per_host = []
    port_same = port_union = mac_same = mac_both = 0
    for ip in both:
        pa = {p["port"]: p for p in a[ip].ports}
        pb = {p["port"]: p for p in b[ip].ports}
        port_same += len(set(pa) & set(pb))
        port_union += len(set(pa) | set(pb))
        if a[ip].mac and b[ip].mac:
            mac_both += 1
            mac_same += a[ip].mac.upper() == b[ip].mac.upper()
        per_host.append({
            "ip": ip,
            "mac": {"own": a[ip].mac, "ref": b[ip].mac},
            "hostname": {"own": a[ip].hostname, "ref": b[ip].hostname},
            "ports_only_own": sorted(set(pa) - set(pb)),
            "ports_only_ref": sorted(set(pb) - set(pa)),
            "ports_both": sorted(set(pa) & set(pb)),
            "services": {str(port): {"own": [pa[port].get("service"), pa[port].get("product"), pa[port].get("version")],
                                     "ref": [pb[port].get("service"), pb[port].get("product"), pb[port].get("version")],
                                     "same_service": _norm_service(pa[port].get("service", "")) == _norm_service(pb[port].get("service", ""))}
                         for port in sorted(set(pa) & set(pb))},
            "os": {"own": a[ip].os, "ref": b[ip].os},
        })
    return {
        "hosts": {"own": len(a), "ref": len(b), "both": len(both),
                  "only_own": sorted(set(a) - set(b)), "only_ref": sorted(set(b) - set(a))},
        "ports": {"both": port_same, "union": port_union,
                  "agreement": round(port_same / port_union, 3) if port_union else 1.0},
        "macs": {"compared": mac_both, "same": mac_same,
                 "own_only": sum(1 for ip in both if a[ip].mac and not b[ip].mac),
                 "ref_only": sum(1 for ip in both if b[ip].mac and not a[ip].mac)},
        "per_host": per_host,
    }


# ── scoring against a ground-truth list (the lab's lab-devices.csv) ─────────

def parse_truth_services(text: str) -> list[dict[str, Any]]:
    """'22 OpenSSH 10.2p1; 139/445 Samba 4.23.6; udp161 net-snmp 5.9.4' -> one entry per port."""
    out = []
    for part in (text or "").split(";"):
        words = part.split()
        if not words or not re.match(r"^(udp)?\d+(/\d+)*$", words[0]):
            continue
        protocol = "udp" if words[0].startswith("udp") else "tcp"
        rest = words[1:]
        version = rest.pop() if rest and re.match(r"^\d+(\.\w+)+$", rest[-1]) else ""
        for port in words[0].removeprefix("udp").split("/"):
            out.append({"port": int(port), "protocol": protocol, "product": " ".join(rest), "version": version})
    return out


def load_truth(path: Path) -> dict[str, dict[str, Any]]:
    """ip -> {mac, name, os, services} from a CSV with columns ip, mac, name, device, os, services."""
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    truth = {}
    for row in rows:
        row = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
        if row.get("ip"):
            truth[row["ip"]] = {"mac": row.get("mac", ""), "name": row.get("name", ""), "os": row.get("os", ""),
                                "services": parse_truth_services(row.get("services", ""))}
    return truth


# A ground-truth list names a service the way people do ("RDP"); an engine names the
# product ("Microsoft Terminal Services") or the service ("ms-wbt-server"). Equal for both.
PRODUCT_SYNONYMS = {"rdp": ("terminal services", "rdp", "ms-wbt-server"),
                    "smb": ("smb", "samba", "microsoft-ds", "netbios-ssn"),
                    "rpc": ("rpc", "msrpc", "epmap")}


def product_matches(truth_product: str, got: dict[str, Any]) -> bool:
    first = truth_product.split()[0].lower()
    text = f"{got.get('product') or ''} {got.get('service') or ''}".lower()
    return any(alias in text for alias in PRODUCT_SYNONYMS.get(first, (first,)))


def _known(value: str) -> bool:
    return bool(value) and value != "?"


def score_against_truth(hosts: list[HostRecord], truth: dict[str, dict[str, Any]], target: str) -> dict[str, Any]:
    """How much of the truth one engine got right, for the truth devices inside `target`."""
    net = ipaddress.ip_network(target, strict=False)
    found = {h.ip: h for h in hosts}
    c = {"devices": 0, "found": 0, "mac_checked": 0, "mac_right": 0, "name_checked": 0, "name_right": 0,
         "ports": 0, "ports_found": 0, "product_checked": 0, "product_right": 0, "version_checked": 0, "version_right": 0}
    missing, wrong = [], []
    for ip, t in truth.items():
        if ipaddress.ip_address(ip) not in net:
            continue
        c["devices"] += 1
        h = found.get(ip)
        if h is None:
            missing.append(ip)
            continue
        c["found"] += 1
        if _known(t["mac"]) and h.mac:
            c["mac_checked"] += 1
            c["mac_right"] += h.mac.replace("-", ":").upper() == t["mac"].replace("-", ":").upper()
        if _known(t["name"]):
            c["name_checked"] += 1
            if (h.hostname or "").lower().split(".")[0] == t["name"].lower().split(" ")[0].split(".")[0]:
                c["name_right"] += 1
            else:
                wrong.append({"ip": ip, "field": "name", "truth": t["name"], "got": h.hostname})
        ports = {(p["port"], p.get("protocol", "tcp")): p for p in h.ports}
        for svc in t["services"]:
            c["ports"] += 1
            got = ports.get((svc["port"], svc["protocol"]))
            if not got:
                continue
            c["ports_found"] += 1
            if svc["product"]:
                c["product_checked"] += 1
                if product_matches(svc["product"], got):
                    c["product_right"] += 1
                else:
                    wrong.append({"ip": ip, "port": svc["port"], "field": "product", "truth": svc["product"], "got": got.get("product")})
            if svc["version"]:
                c["version_checked"] += 1
                if (got.get("version") or "").split()[0:1] == [svc["version"]]:
                    c["version_right"] += 1
                else:
                    wrong.append({"ip": ip, "port": svc["port"], "field": "version", "truth": svc["version"], "got": got.get("version")})
    return {**c, "missing": missing, "wrong": wrong}


def report_dir() -> Path:
    """Next to this agent's settings: the user's config folder, or the service's machine
    folder (not the SYSTEM account's profile)."""
    from ..config import default_config_path
    return default_config_path().parent / "compare"


class CompareScanStage(Stage):
    name = "scan"
    label = "Discover hosts with both engines and compare"

    def __init__(self, subnet: str, tier: str = "base", out_dir: Optional[Path] = None,
                 truth: Optional[Path] = None) -> None:
        self.subnet = subnet
        self.tier = tier
        self.out_dir = out_dir
        self.truth = truth

    def run(self, ctx: PipelineContext) -> None:
        own_ctx = PipelineContext(ctx.pipeline, subnet=self.subnet, cancelled=ctx.cancelled, _emit=ctx._emit, _stage=ctx._stage)
        OwnScanStage(self.subnet, self.tier).run(own_ctx)
        ref_ctx = PipelineContext(ctx.pipeline, subnet=self.subnet, cancelled=ctx.cancelled, _emit=ctx._emit, _stage=ctx._stage)
        started = time.monotonic()
        NmapScanStage(self.subnet).run(ref_ctx)
        ref_seconds = round(time.monotonic() - started, 2)
        report = {
            "when": datetime.now().isoformat(timespec="seconds"),
            "target": self.subnet,
            "own": own_ctx.summary.get("engine"),
            "ref": {"scanner": ref_ctx.summary.get("scanner"), "seconds": ref_seconds},
            **compare_hosts(own_ctx.hosts, ref_ctx.hosts),
        }
        if self.truth:
            truth = load_truth(self.truth)
            report["truth"] = {"file": str(self.truth),
                               "own": score_against_truth(own_ctx.hosts, truth, self.subnet),
                               "ref": score_against_truth(ref_ctx.hosts, truth, self.subnet)}
        out_dir = self.out_dir or report_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"compare-{datetime.now():%Y%m%d-%H%M%S}.json"
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        ctx.hosts = own_ctx.hosts
        ctx.summary.update(own_ctx.summary)
        ctx.summary["compare"] = {"report": str(path), "hosts": report["hosts"], "ports": report["ports"],
                                  "ref_scanner": report["ref"]["scanner"], "ref_seconds": ref_seconds,
                                  "truth": {k: {n: v for n, v in report["truth"][k].items() if n not in ("missing", "wrong")}
                                            for k in ("own", "ref")} if "truth" in report else None}
        log.info("Engine comparison written to %s", path)


def active_scan_stage(subnet: str, settings: Any, truth: Optional[Path] = None) -> Stage:
    """The scan stage Settings.scan_engine asks for (`truth`: a ground-truth CSV for compare).
    The agent's own engine unless the command line asks for Nmap (2.6: nmap and compare are
    evaluation tools, `eagleeye scan --engine nmap|compare`)."""
    engine = getattr(settings, "scan_engine", "auto") or "auto"
    tier = getattr(settings, "scan_ports", "base") or "base"
    if engine == "nmap":
        return NmapScanStage(subnet)
    if engine == "compare":
        return CompareScanStage(subnet, tier, truth=truth)
    return OwnScanStage(subnet, tier)
