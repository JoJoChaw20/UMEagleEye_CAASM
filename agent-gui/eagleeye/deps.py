"""Finds the external tools the agent uses and reports what is missing.

Nmap and Npcap are not shipped with the agent (their licences restrict
redistribution). This module only detects them and says where to get them; the
installer/GUI will fetch them from the official sources.
"""

from __future__ import annotations

import ctypes.util
import importlib.util
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class DepStatus:
    name: str
    ok: bool
    required: bool
    detail: str
    hint: str = ""
    version: Optional[str] = None


def is_admin() -> bool:
    """True when running as Administrator (Windows) or root (Linux/macOS)."""
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


def _nmap_candidates() -> list[str]:
    found = shutil.which("nmap")
    paths = [found] if found else []
    if sys.platform == "win32":
        for var in ("ProgramFiles(x86)", "ProgramFiles"):
            base = os.environ.get(var)
            if base:
                paths.append(str(Path(base) / "Nmap" / "nmap.exe"))
    else:
        paths += ["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap", "/usr/bin/nmap"]
    return paths


def find_nmap() -> Optional[str]:
    """Path to a working nmap executable, or None."""
    for path in _nmap_candidates():
        if path and Path(path).is_file():
            return path
    return None


def nmap_version(path: str) -> Optional[str]:
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10).stdout
    except Exception:  # noqa: BLE001
        return None
    m = re.search(r"Nmap version ([\d.]+\w*)", out)
    return m.group(1) if m else None


def _packet_capture_library() -> tuple[bool, str]:
    if sys.platform == "win32":
        root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        for candidate in (root / "Npcap" / "wpcap.dll", root / "wpcap.dll"):
            if candidate.is_file():
                return True, str(candidate)
        return False, "Npcap not found"
    lib = ctypes.util.find_library("pcap")
    return (True, lib) if lib else (False, "libpcap not found")


_HINTS = {
    "nmap": {
        "win32": "Install Nmap from https://nmap.org/download.html#windows",
        "darwin": "brew install nmap",
        "linux": "sudo apt install nmap   (or: sudo dnf install nmap)",
    },
    "pcap": {
        "win32": "Install Npcap from https://npcap.com/#download (tick 'WinPcap API-compatible mode')",
        "darwin": "libpcap ships with macOS; install Xcode command line tools if missing",
        "linux": "sudo apt install libpcap0.8   (or: sudo dnf install libpcap)",
    },
}


def _hint(key: str) -> str:
    table = _HINTS[key]
    return table.get(sys.platform if sys.platform in table else "linux", "")


def _module(name: str, pip_name: str, required: bool, why: str) -> DepStatus:
    ok = importlib.util.find_spec(name) is not None
    return DepStatus(
        name=f"python: {pip_name}", ok=ok, required=required,
        detail="installed" if ok else f"missing ({why})",
        hint="" if ok else f"pip install {pip_name}",
    )


def check_all() -> list[DepStatus]:
    results: list[DepStatus] = []

    nmap_path = find_nmap()
    if nmap_path:
        ver = nmap_version(nmap_path)
        results.append(DepStatus("Nmap", True, False, nmap_path, version=ver))
    else:
        results.append(DepStatus(
            "Nmap", False, False,
            "not found - scans fall back to the built-in sweep (no service, version or OS detail)",
            _hint("nmap"),
        ))

    pcap_ok, pcap_detail = _packet_capture_library()
    results.append(DepStatus(
        "Packet capture (Npcap/libpcap)", pcap_ok, False,
        pcap_detail if pcap_ok else f"{pcap_detail} - passive sniffing unavailable", "" if pcap_ok else _hint("pcap"),
    ))

    results.append(_module("requests", "requests", True, "cannot reach the server"))
    results.append(_module("nmap", "python-nmap", False, "needed to drive Nmap"))
    results.append(_module("scapy", "scapy", False, "needed for passive sniffing"))
    results.append(_module("pysnmp", "pysnmp", False, "needed for SNMPv3 polling"))

    admin = is_admin()
    results.append(DepStatus(
        "Administrator / root", admin, False,
        "yes" if admin else "no - passive sniffing needs it, and Nmap falls back to a connect scan",
        "" if admin else ("Run the terminal as Administrator" if sys.platform == "win32" else "Run with sudo"),
    ))
    return results
