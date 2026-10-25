"""Platform default hostnames that say nothing about which device it is.

The same list as the server's (workers/src/lib/hostnames.ts): a name like "Android"
ranks below any specific name, here when the agent picks one name per host from what
the sniffers heard, and on the server when it decides whether a stored name may be
replaced. An Oppo phone announces itself over mDNS as "Android" while its DHCP request
says "OPPO-A31"; the second is the one worth keeping.
"""

from __future__ import annotations

import re
from typing import Optional

_GENERIC_NAME_PATTERNS = [re.compile(p) for p in (
    r"^android(-\d{1,2})?$",                                           # Android's mDNS default; -2 after a name clash
    r"^android-[0-9a-f]{6,}$",                                           # android-83f59958ba7e18a1
    r"^localhost(\.localdomain)?$",
    r"^(iphone|ipad|macbook(-pro|-air)?)(-\d{1,2})?$",                   # Apple defaults; -2 after a name clash
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",   # UUID-style
)]


def is_generic_hostname(name: Optional[str]) -> bool:
    """True for a platform default such as "Android" or "android-83f59958ba7e18a1"."""
    if not isinstance(name, str):
        return False
    value = name.strip().lower()
    if value.endswith(".local"):
        value = value[:-len(".local")]
    return bool(value) and any(p.match(value) for p in _GENERIC_NAME_PATTERNS)
