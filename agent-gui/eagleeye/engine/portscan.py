"""TCP connect scan: open (it accepted), closed (it refused), filtered (no answer).

A connect scan needs no admin rights and no capture driver. Each open port is closed again
with a reset (SO_LINGER 0) so thousands of scans leave no TIME_WAIT sockets behind. Work is
spread port-by-port across hosts, at most PER_HOST connections are open to one device at
a time (a busy home router drops what arrives in a burst), and the total in flight is capped. A port that timed out on a host that is
known to be up is tried once more, waiting longer: Wi-Fi drops the odd packet and a busy
router can be slow to accept, and neither must hide an open port.
"""

from __future__ import annotations

import errno
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, Optional

from ..pipeline.runner import Cancelled

OPEN, CLOSED, FILTERED = "open", "closed", "filtered"
RETRY_MIN_TIMEOUT = 2.0
PER_HOST = 4              # connections in flight to one device at a time (Nmap limits this too)
_REFUSED = {errno.ECONNREFUSED, 10061, 111, 61}

Connect = Callable[[str, int, float], str]
Progress = Callable[[str, Optional[int], Optional[int]], None]


def connect_state(ip: str, port: int, timeout: float) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        return OPEN
    except ConnectionRefusedError:
        return CLOSED
    except OSError as exc:
        return CLOSED if exc.errno in _REFUSED or getattr(exc, "winerror", None) in _REFUSED else FILTERED
    finally:
        s.close()


def scan(
    hosts: Iterable[str],
    ports: Iterable[int],
    timeout: float = 1.0,
    workers: int = 128,
    known_up: Iterable[str] = (),
    per_host: int = PER_HOST,
    connect: Connect = connect_state,
    progress: Progress = lambda *a: None,
    cancelled: Callable[[], bool] = lambda: False,
) -> tuple[dict[str, dict[int, str]], int]:
    """({ip: {port: state}}, connections attempted)."""
    hosts, ports = list(hosts), list(ports)
    results: dict[str, dict[int, str]] = {ip: {} for ip in hosts}
    attempts = 0
    gates = {ip: threading.BoundedSemaphore(per_host) for ip in hosts}

    def gated(ip: str, port: int, wait: float) -> str:
        with gates[ip]:
            return connect(ip, port, wait)

    def run(tasks: list[tuple[str, int]], label: str, wait: float) -> None:
        nonlocal attempts
        if not tasks:
            return
        done = 0
        with ThreadPoolExecutor(max_workers=min(workers, len(tasks)), thread_name_prefix="tcp") as pool:
            futures = {pool.submit(gated, ip, port, wait): (ip, port) for ip, port in tasks}
            for fut in as_completed(futures):
                if cancelled():
                    pool.shutdown(wait=False, cancel_futures=True)
                    raise Cancelled()
                ip, port = futures[fut]
                results[ip][port] = fut.result()
                attempts += 1
                done += 1
                if done % 64 == 0 or done == len(tasks):
                    progress(f"{label}: {done}/{len(tasks)} connections", done, len(tasks))

    run([(ip, port) for port in ports for ip in hosts], "Port scan", timeout)
    up = set(known_up) | {ip for ip, states in results.items() if any(s != FILTERED for s in states.values())}
    retry = [(ip, port) for port in ports for ip in hosts if ip in up and results[ip].get(port) == FILTERED]
    # The second try waits longer: a busy home router can take over a second to accept.
    run(retry, "Retrying unanswered ports", max(RETRY_MIN_TIMEOUT, timeout * 2.5))
    return results, attempts
