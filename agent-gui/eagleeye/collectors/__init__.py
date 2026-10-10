"""Endpoint inventory of the machine the agent runs on.

`collect_inventory()` returns one normalised, versioned document (schema 1) with
identity, hardware, OS, patches, security posture, network interfaces, listening
services and installed software. Windows is implemented; Linux and macOS raise
UnsupportedPlatform until their collectors are written.
"""

from __future__ import annotations

import sys
from typing import Any


class UnsupportedPlatform(RuntimeError):
    pass


class CollectorError(RuntimeError):
    pass


def collect_inventory(user_software: bool = False, admin_names: bool = False) -> dict[str, Any]:
    """user_software / admin_names opt in to per-user installs and local administrator
    account names, which are personal data and are left out by default."""
    if sys.platform == "win32":
        from .windows import collect
        return collect(user_software=user_software, admin_names=admin_names)
    raise UnsupportedPlatform(f"endpoint inventory is not available on {sys.platform} yet (Windows only for now)")
