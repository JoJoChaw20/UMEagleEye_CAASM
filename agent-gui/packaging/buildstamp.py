"""The build stamp of an agent build: 0.1.0+<UTC time>.<commit> (eagleeye/__init__.py BUILD).

    python packaging/buildstamp.py write     # writes eagleeye/_build.py, prints the stamp
    python packaging/buildstamp.py remove    # removes it again (a source tree reports "dev")

The version stays 0.1.0 until the official release; the stamp is what tells two builds apart, and
what the dashboard compares with the newest published package (eagleeye/update).
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eagleeye import VERSION  # noqa: E402

TARGET = ROOT / "eagleeye" / "_build.py"


def stamp() -> str:
    when = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        commit = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, timeout=20).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        commit = ""
    return f"{VERSION}+{when}" + (f".{commit}" if commit else "")


def module_text(build: str) -> str:
    return f'"""Written by packaging/buildstamp.py for this build."""\n\nBUILD = "{build}"\n'


def main(argv: list[str]) -> int:
    if argv[:1] == ["remove"]:
        TARGET.unlink(missing_ok=True)
        return 0
    if argv[:1] == ["write"]:
        build = stamp()
        TARGET.write_text(module_text(build), encoding="utf-8")
        print(build)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
