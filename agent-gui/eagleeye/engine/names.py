"""One ranking for a host's name, whatever produced the candidates.

Candidates come best source first (later: SMB/NTLM computer name, NetBIOS, then what passive
listening heard; now: reverse DNS). A platform default such as "Android" or "iPhone"
(hostnames.is_generic_hostname) ranks below any specific name, and Docker-internal names
are dropped, the same rules the Nmap stage and the passive enrichment apply.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Iterable, Optional

from ..hostnames import is_generic_hostname


def usable(name: Optional[str]) -> Optional[str]:
    name = (name or "").strip().rstrip(".")
    if not name or "docker.internal" in name or name.startswith("docker"):
        return None
    return name


def pick_name(candidates: Iterable[tuple[Optional[str], str]]) -> tuple[Optional[str], Optional[str]]:
    """(name, source): the first specific name, else the first default one, else (None, None)."""
    usable_ones = [(n, src) for raw, src in candidates if (n := usable(raw))]
    for name, src in usable_ones:
        if not is_generic_hostname(name):
            return name, src
    return usable_ones[0] if usable_ones else (None, None)


def _reverse(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None


def reverse_dns(ips: Iterable[str], workers: int = 32, budget: float = 8.0) -> dict[str, str]:
    """ip -> name from reverse DNS, asked once per address. The whole batch gets `budget`
    seconds: a resolver that hangs on one address must not stall the scan."""
    ips = list(ips)
    if not ips:
        return {}
    pool = ThreadPoolExecutor(max_workers=min(workers, len(ips)), thread_name_prefix="rdns")
    futures = {pool.submit(_reverse, ip): ip for ip in ips}
    done, _pending = wait(futures, timeout=budget)
    pool.shutdown(wait=False, cancel_futures=True)
    return {futures[f]: n for f in done if (n := usable(f.result()))}
