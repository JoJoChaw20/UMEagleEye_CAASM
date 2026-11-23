"""What makes an update package acceptable. Pure functions (no network, no installing).

A package comes with a manifest the build machine signed (packaging/sign_package.py):

    {"format": 1, "kind": "windows" | "source", "file": ..., "build": ..., "sha256": ..., "size": ...,
     "key": <key id>, "signature": <base64 Ed25519 signature of signed_message(...)>}

The agent installs it only when the signature is made with one of keys.PUBLIC_KEYS, the file's size
and SHA-256 are the ones signed, the kind is this computer's, and the build is newer than its own
(no downgrade, so an old signed package cannot be replayed).
"""

from __future__ import annotations

import base64
import re
import sys
from pathlib import Path
from typing import Any, Optional

from . import ed25519
from .keys import PUBLIC_KEYS

FORMAT = 1
MAX_SIZE = 200 * 1024 * 1024
KINDS = ("windows", "source")
# 0.1.0+20261123T041200Z.ab12cd3: the version, the UTC build time, the commit
BUILD_RE = re.compile(r"^\d+\.\d+\.\d+\+(\d{8}T\d{6}Z)(?:\.[0-9a-f]{4,40})?$")


class Refused(Exception):
    """The package must not be installed; the message says why (shown on the dashboard)."""


def signed_message(kind: str, file: str, build: str, sha256: str, size: int) -> bytes:
    return "\n".join(["UMEagleEye agent package v1", f"kind={kind}", f"file={file}", f"build={build}",
                      f"sha256={sha256}", f"size={size}"]).encode("utf-8")


def build_time(build: Optional[str]) -> Optional[str]:
    """The sortable UTC time inside a build stamp, or None (a development copy, or junk)."""
    m = BUILD_RE.match(build or "")
    return m.group(1) if m else None


def check_manifest(manifest: Any, own_build: Optional[str], own_kind: Optional[str]) -> dict[str, Any]:
    """The manifest's fields when it may be installed here; raises Refused otherwise."""
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise Refused("the package manifest is missing or in an unknown format")
    kind, file, build = manifest.get("kind"), manifest.get("file"), manifest.get("build")
    sha, size, key, sig = manifest.get("sha256"), manifest.get("size"), manifest.get("key"), manifest.get("signature")
    if kind not in KINDS or not isinstance(file, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", file):
        raise Refused("the package manifest names an unknown kind or file")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise Refused("the package manifest has no valid SHA-256")
    if not isinstance(size, int) or not 0 < size <= MAX_SIZE:
        raise Refused("the package manifest has no valid size")
    if build_time(build) is None:
        raise Refused(f"the package build {build!r} is not a release build")
    public = PUBLIC_KEYS.get(key) if isinstance(key, str) else None
    if public is None:
        raise Refused("the package is signed with a key this agent does not trust")
    try:
        raw_sig = base64.b64decode(sig, validate=True) if isinstance(sig, str) else b""
    except ValueError:
        raw_sig = b""
    if not ed25519.verify(base64.b64decode(public), signed_message(kind, file, build, sha, size), raw_sig):
        raise Refused("the package signature is not valid")
    if kind != own_kind:
        raise Refused(f"the package is for {kind} installs, this agent is a {own_kind or 'development'} install")
    mine = build_time(own_build)
    if mine is not None and build_time(build) <= mine:          # type: ignore[operator]
        raise Refused(f"the package build {build} is not newer than this agent's ({own_build})")
    return {"kind": kind, "file": file, "build": build, "sha256": sha, "size": size}


def install_kind() -> Optional[str]:
    """How this copy of the agent was installed, so which package updates it: the Windows installer,
    the Linux source package (in /opt/eagleeye-agent-*), or neither (a development copy, macOS, the
    network agent's container): those are updated by hand."""
    if sys.platform == "win32":
        return "windows" if getattr(sys, "frozen", False) else None
    if sys.platform.startswith("linux") and not getattr(sys, "frozen", False):
        return "source" if install_root() is not None else None
    return None


def install_root(prefix: Optional[str] = None) -> Optional[Path]:
    """The Linux install folder, /opt/eagleeye-agent-<...>, whose .venv runs this agent; else None."""
    venv = Path(prefix or sys.prefix)
    root = venv.parent
    if venv.name == ".venv" and root.parent == Path("/opt") and root.name.startswith("eagleeye-agent-"):
        return root
    return None
