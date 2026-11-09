"""Finds the external tools the agent uses and reports what is missing.

Syft and Grype (the SBOM tools) are not shipped with the agent; this module detects them and
says where to put them (agent_tools: the window's Setup page). Nmap and Npcap are only
evaluation tools of the command line since 2.6 (`eagleeye deps` still lists them).
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
        # A packaged agent cannot pip-install; what it leaves out is left out on purpose.
        hint="" if ok or getattr(sys, "frozen", False) else f"pip install {pip_name}",
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
        pcap_detail if pcap_ok else f"{pcap_detail} - passive listening uses the built-in capture",
        "" if pcap_ok else _hint("pcap"),
    ))

    from . import sbom
    for tool in ("syft", "grype"):
        path = sbom.find_tool(tool)
        results.append(DepStatus(
            tool.capitalize(), bool(path), False,
            path if path else "not found - this computer's SBOM and CVE check are unavailable",
            "" if path else sbom.install_hint(tool), version=sbom.tool_version(path) if path else None,
        ))

    results.append(_module("scapy", "scapy", False, "needed for passive listening with Npcap/libpcap "
                                                       "(the built-in capture does not use it)"))

    admin = is_admin()
    results.append(DepStatus(
        "Administrator / root", admin, False,
        "yes" if admin else "no - passive listening and some security checks need it",
        "" if admin else ("Run the terminal as Administrator" if sys.platform == "win32" else "Run with sudo"),
    ))
    return results


def agent_tools(service: bool) -> list[DepStatus]:
    """What the agent itself uses, for its window's Setup page: Syft and Grype (the SBOM; scanning and
    listening are built in) and the rights it runs with. `service`: checked inside the agent service,
    so what it finds is what the daily SBOM will use (the window, running as the signed-in user, may
    see tools the service cannot)."""
    from . import sbom
    results: list[DepStatus] = []
    for tool in ("syft", "grype"):
        path = sbom.find_tool(tool)
        results.append(DepStatus(
            tool.capitalize(), bool(path), False,
            path if path else "not found: no SBOM or CVE check of this computer",
            "" if path else sbom.install_hint(tool), version=sbom.tool_version(path) if path else None,
        ))
    if service:
        downloaded, where = sbom.grype_db_summary()
        results.append(DepStatus("Vulnerability database", downloaded, False, where))
    admin = is_admin()
    if service:
        account = "LocalSystem" if sys.platform == "win32" else "root"
        results.append(DepStatus("Runs as", True, False, f"the agent service ({account}): the rights listening and "
                                                         "the security checks need"))
    else:
        results.append(DepStatus("Runs as", admin, False, "an administrator" if admin else
                                 "the signed-in user: passive listening and some security checks need administrator rights",
                                 "" if admin else "Restart as Administrator"))
    return results
