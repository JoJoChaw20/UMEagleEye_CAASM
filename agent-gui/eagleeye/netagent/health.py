"""A container's health check for the network agent:

    python -m eagleeye.netagent.health      exit 0 = healthy, 1 = not

Healthy: the agent wrote its status (service.py) within the last three heartbeats and the
last heartbeat reached the server. A crawl that found nothing is not a health problem (the
dashboard shows it); a dead loop or a server it cannot reach is.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

from ..config import state_path


def check(path: Optional[Path] = None, now: Optional[float] = None) -> tuple[bool, str]:
    path = path or state_path().with_name("netagent-status.json")
    try:
        status = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return False, f"no status yet ({exc})"
    age = (now if now is not None else time.time()) - float(status.get("heartbeat_at") or 0)
    limit = 3 * float(status.get("heartbeat_interval") or 30) + 30
    if age > limit:
        return False, f"no heartbeat for {age:.0f}s"
    if not status.get("heartbeat_ok"):
        return False, "the last heartbeat did not reach the server"
    return True, "ok"


def main() -> int:
    ok, why = check()
    print(why)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
