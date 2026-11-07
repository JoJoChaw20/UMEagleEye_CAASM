"""The own engine as a pipeline stage, the side-by-side comparison with the Nmap stage, and
the choice between them (Settings.scan_engine):

    auto, nmap   the Nmap stage as before (Nmap, or the built-in sweep without it)
    own          the own engine (engine/)
    compare      both, one after the other on the same target; the own engine's hosts are
                 the result, and a report of where the two agree is written locally
"""

from __future__ import annotations

import json
import logging
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


def report_dir() -> Path:
    from ..config import config_dir
    return config_dir() / "compare"


class CompareScanStage(Stage):
    name = "scan"
    label = "Discover hosts with both engines and compare"

    def __init__(self, subnet: str, tier: str = "base", out_dir: Optional[Path] = None) -> None:
        self.subnet = subnet
        self.tier = tier
        self.out_dir = out_dir

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
        out_dir = self.out_dir or report_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"compare-{datetime.now():%Y%m%d-%H%M%S}.json"
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        ctx.hosts = own_ctx.hosts
        ctx.summary.update(own_ctx.summary)
        ctx.summary["compare"] = {"report": str(path), "hosts": report["hosts"], "ports": report["ports"],
                                  "ref_scanner": report["ref"]["scanner"], "ref_seconds": ref_seconds}
        log.info("Engine comparison written to %s", path)


def active_scan_stage(subnet: str, settings: Any) -> Stage:
    """The scan stage Settings.scan_engine asks for."""
    engine = getattr(settings, "scan_engine", "auto") or "auto"
    tier = getattr(settings, "scan_ports", "base") or "base"
    if engine == "own":
        return OwnScanStage(subnet, tier)
    if engine == "compare":
        return CompareScanStage(subnet, tier)
    return NmapScanStage(subnet)
