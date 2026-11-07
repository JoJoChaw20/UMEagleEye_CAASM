"""`eagleeye listen --compare`: Npcap/libpcap and the built-in capture listen at the same
time, then what each one's sniffers learned is put side by side, with the CPU each
capture used. The check that the built-in capture can replace Npcap on a real network.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any, Callable, Optional

from .sniffers import PassiveSuite

NPCAP_THREADS = ("arp-sniffer", "mdns-sniffer", "dhcp-sniffer", "ssdp-sniffer")
BUILT_IN_THREADS = ("ndis-capture", "capture-hub")


def thread_cpu_seconds(names: tuple[str, ...]) -> Optional[float]:
    """CPU time used so far by this process's live threads with these names."""
    ids = [t.native_id for t in threading.enumerate() if t.name in names and t.native_id]
    try:
        if sys.platform == "win32":
            import ctypes
            import ctypes.wintypes as wt
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.OpenThread.restype = wt.HANDLE
            total = 0
            for tid in ids:
                h = k32.OpenThread(0x0800, False, tid)            # THREAD_QUERY_LIMITED_INFORMATION
                if not h:
                    continue
                times = [wt.FILETIME() for _ in range(4)]
                if k32.GetThreadTimes(h, *(ctypes.byref(t) for t in times)):
                    total += sum((t.dwHighDateTime << 32) | t.dwLowDateTime for t in times[2:])
                k32.CloseHandle(h)
            return total / 1e7
        tick = os.sysconf("SC_CLK_TCK")
        total = 0
        for tid in ids:
            with open(f"/proc/self/task/{tid}/stat", encoding="ascii") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            total += int(fields[11]) + int(fields[12])           # utime, stime
        return total / tick
    except (OSError, ValueError, AttributeError):
        return None


def learned(suite: PassiveSuite) -> dict[str, Any]:
    """What a suite's sniffers know: hosts (ip -> mac), names, and the MACs with DHCP
    or SSDP details."""
    hosts = {h.ip: (h.mac or "").lower() for h in suite.arp.drain()} if suite.arp else {}
    names: dict[str, str] = {}
    if suite.mdns:
        for ip in hosts:
            name = suite.mdns.get_hostname(ip)
            if name:
                names[ip] = name
    macs = set(hosts.values())
    dhcp = sorted(m for m in macs if suite.dhcp and suite.dhcp.get_info_by_mac(m))
    ssdp = sorted(m for m in macs if suite.ssdp and suite.ssdp.get_mac_info(m))
    return {"hosts": hosts, "names": names, "dhcp": dhcp, "ssdp": ssdp}


def side_by_side(a: dict[str, Any], b: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Per kind: how many each found, how many both, and what only one found."""
    out: dict[str, dict[str, Any]] = {}
    for kind in ("hosts", "names", "dhcp", "ssdp"):
        ka = set(a[kind].items()) if isinstance(a[kind], dict) else set(a[kind])
        kb = set(b[kind].items()) if isinstance(b[kind], dict) else set(b[kind])
        out[kind] = {"npcap": len(ka), "built_in": len(kb), "both": len(ka & kb),
                     "only_npcap": sorted(map(str, ka - kb)), "only_built_in": sorted(map(str, kb - ka))}
    return out


def run(interface: Optional[str], seconds: int, fingerbank_key: Optional[str] = None,
        progress: Callable[[str], None] = print) -> dict[str, Any]:
    npcap = PassiveSuite(interface, fingerbank_key, backend="npcap")
    built_in = PassiveSuite(interface, fingerbank_key, backend="native")
    report: dict[str, Any] = {"seconds": seconds, "capture": None, "problems": []}
    started = [s for s in (npcap, built_in) if s.start()]
    if len(started) < 2:
        report["problems"] = npcap.problems() + built_in.problems() or ["a capture could not start"]
        for suite in started:
            suite.stop()
        return report
    report["capture"] = built_in.capture
    cpu0 = (thread_cpu_seconds(NPCAP_THREADS), thread_cpu_seconds(BUILT_IN_THREADS))
    t0 = time.monotonic()
    progress(f"Listening with Npcap and {built_in.capture} for {seconds}s ...")
    time.sleep(seconds)
    cpu1 = (thread_cpu_seconds(NPCAP_THREADS), thread_cpu_seconds(BUILT_IN_THREADS))
    elapsed = time.monotonic() - t0
    hub = built_in.hub
    report.update({
        "listening_on": built_in.listening_on,
        "adapter_index": built_in.chooser.index,
        "cpu_seconds": {"npcap": _diff(cpu0[0], cpu1[0]), "built_in": _diff(cpu0[1], cpu1[1])},
        "frames": {"built_in_from_adapter": hub.frames if hub else 0,
                   "built_in_to_sniffers": hub.dispatched if hub else 0,
                   "per_second": round((hub.frames if hub else 0) / elapsed, 1)},
        "ndis_indexes": {f"{m}/{lo}": n for (m, lo), n in getattr(hub.source, "seen", {}).most_common(8)} if hub else {},
        "compare": side_by_side(learned(npcap), learned(built_in)),
        "problems": npcap.problems() + built_in.problems(),
    })
    npcap.stop()
    built_in.stop()
    return report


def _diff(a: Optional[float], b: Optional[float]) -> Optional[float]:
    return round(b - a, 2) if a is not None and b is not None else None
