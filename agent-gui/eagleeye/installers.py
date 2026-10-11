"""Fetches the Nmap and Npcap installers from their official sites (Windows).

The agent does not ship either tool (their licences restrict redistribution).
Instead, when the person asks for it, this module:
  1. reads the official download page and picks the newest installer link;
  2. downloads it over HTTPS from that site only;
  3. checks its Authenticode signature: valid, and signed by Nmap Software LLC;
  4. starts it with the normal Windows elevation prompt.
The person then goes through the official installer and accepts its licence
themselves. Nothing is installed silently.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from . import VERSION, httpclient

TRUSTED_PUBLISHERS = ("Nmap Software LLC", "Insecure.Com LLC")
MAX_BYTES = 200 * 1024 * 1024
CREATE_NO_WINDOW = 0x08000000


class InstallError(RuntimeError):
    """A step failed; the message is safe to show to the person."""


@dataclass(frozen=True)
class Tool:
    key: str
    name: str
    page: str
    host: str
    pattern: str            # group 1: file name, group 2: version
    licence: str
    purpose: str


TOOLS = {
    "nmap": Tool(
        "nmap", "Nmap", "https://nmap.org/download.html", "nmap.org",
        r"(?:https:)?(?://nmap\.org)?/?dist/(nmap-(\d+(?:\.\d+)+)-setup\.exe)",
        "https://nmap.org/npsl/",
        "Service, version and OS detection during active scans",
    ),
    "npcap": Tool(
        "npcap", "Npcap", "https://npcap.com/", "npcap.com",
        r"(?:https:)?(?://npcap\.com)?/?dist/(npcap-(\d+(?:\.\d+)+)\.exe)",
        "https://npcap.com/oem/",
        "Packet capture for passive sniffing (tick 'WinPcap API-compatible mode')",
    ),
}


@dataclass(frozen=True)
class Installer:
    tool: Tool
    url: str
    version: str


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


def find_latest(tool: Tool, page_html: str) -> Installer:
    """The newest installer linked from the download page."""
    found = {(m.group(1), m.group(2)) for m in re.finditer(tool.pattern, page_html)}
    if not found:
        raise InstallError(f"could not find the {tool.name} installer on {tool.page}; download it from there manually")
    filename, version = max(found, key=lambda f: _version_key(f[1]))
    return Installer(tool, f"https://{tool.host}/dist/{filename}", version)


def _session() -> httpclient.Session:
    s = httpclient.Session()
    s.headers["User-Agent"] = f"EagleEye-Agent/{VERSION}"
    return s


def latest_installer(tool: Tool, session: Optional[httpclient.Session] = None) -> Installer:
    session = session or _session()
    try:
        resp = session.get(tool.page, timeout=20)
        resp.raise_for_status()
    except httpclient.RequestException as exc:
        raise InstallError(f"could not open {tool.page}: {exc}") from None
    return find_latest(tool, resp.text)


def download(
    installer: Installer,
    dest_dir: Optional[Path] = None,
    progress: Callable[[int, Optional[int]], None] = lambda done, total: None,
    cancelled: Callable[[], bool] = lambda: False,
    session: Optional[httpclient.Session] = None,
) -> Path:
    """Download to a new private temporary folder. Only HTTPS from the tool's own site."""
    parsed = urlparse(installer.url)
    if parsed.scheme != "https" or parsed.hostname != installer.tool.host:
        raise InstallError(f"refusing to download from {installer.url}")
    folder = dest_dir or Path(tempfile.mkdtemp(prefix="eagleeye-"))
    target = folder / Path(parsed.path).name
    session = session or _session()
    try:
        with session.get(installer.url, stream=True, timeout=60) as resp:
            resp.raise_for_status()
            final = urlparse(resp.url)
            if final.scheme != "https" or final.hostname != installer.tool.host:
                raise InstallError(f"the download was redirected to {resp.url}; stopped")
            total = int(resp.headers.get("Content-Length") or 0) or None
            if total and total > MAX_BYTES:
                raise InstallError("the installer is unexpectedly large; stopped")
            done = 0
            with open(target, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=256 * 1024):
                    if cancelled():
                        raise InstallError("download cancelled")
                    fh.write(chunk)
                    done += len(chunk)
                    if done > MAX_BYTES:
                        raise InstallError("the installer is unexpectedly large; stopped")
                    progress(done, total)
    except httpclient.RequestException as exc:
        target.unlink(missing_ok=True)
        raise InstallError(f"download failed: {exc}") from None
    except InstallError:
        target.unlink(missing_ok=True)
        raise
    return target


_SIGNATURE_SCRIPT = (
    "$s = Get-AuthenticodeSignature -LiteralPath $env:EAGLEEYE_VERIFY_PATH; "
    "@{status = $s.Status.ToString(); subject = $s.SignerCertificate.Subject} | ConvertTo-Json -Compress"
)


def publisher_of(subject: str) -> Optional[str]:
    """The O= (organisation) field of a certificate subject."""
    m = re.search(r"(?:^|,\s*)O=(\"[^\"]+\"|[^,]+)", subject or "")
    return m.group(1).strip('"').strip() if m else None


def verify_signature(path: Path) -> str:
    """Raise InstallError unless the file carries a valid signature from a trusted
    publisher. Returns the publisher name."""
    if sys.platform != "win32":
        raise InstallError("signature checks are only implemented on Windows")
    env = {**os.environ, "EAGLEEYE_VERIFY_PATH": str(path)}
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _SIGNATURE_SCRIPT],
            capture_output=True, text=True, timeout=60, env=env, creationflags=CREATE_NO_WINDOW,
        )
        info = json.loads(proc.stdout.strip() or "{}")
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise InstallError(f"could not check the installer's signature: {exc}") from None
    status, publisher = info.get("status"), publisher_of(info.get("subject") or "")
    if status != "Valid":
        raise InstallError(f"the installer's signature is not valid ({status or 'unsigned'}); it was not started")
    if publisher not in TRUSTED_PUBLISHERS:
        raise InstallError(f"the installer is signed by {publisher!r}, not by the Nmap project; it was not started")
    return publisher


def launch(path: Path) -> None:
    """Start the installer with the Windows elevation prompt. Returns once started."""
    if sys.platform != "win32":
        raise InstallError("automatic installation is only available on Windows")
    import ctypes
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", str(path), None, str(path.parent), 1)  # type: ignore[attr-defined]
    if rc <= 32:
        raise InstallError("the installer was not started (the elevation prompt was declined or failed)")


def fetch_and_launch(
    key: str,
    progress: Callable[[str, Optional[int], Optional[int]], None] = lambda msg, done, total: None,
    cancelled: Callable[[], bool] = lambda: False,
) -> Installer:
    """The whole flow for one tool. Raises InstallError with a readable reason."""
    tool = TOOLS[key]
    progress(f"Looking up the latest {tool.name} on {tool.host}", None, None)
    installer = latest_installer(tool)
    progress(f"Downloading {tool.name} {installer.version}", 0, None)
    path = download(installer, progress=lambda d, t: progress(f"Downloading {tool.name} {installer.version}", d, t),
                    cancelled=cancelled)
    progress("Checking the installer's digital signature", None, None)
    publisher = verify_signature(path)
    progress(f"Signed by {publisher}. Starting the installer", None, None)
    launch(path)
    return installer
