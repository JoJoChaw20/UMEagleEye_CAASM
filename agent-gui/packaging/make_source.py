"""The agent's source package for Linux, macOS (packaging/macos/install-macos.sh) and the network agent: dist/eagleeye-agent-<version>.tar.gz.

Everything a Linux computer needs to run the agent as a service, and to build the network agent's
Docker image (packaging/network-agent), without the tests or the Windows packaging. Published next
to the Windows installer (AGENT_SETUP_GUIDE.md, "Publishing a new version"); the dashboard offers
the newest upload of each.

    python packaging/make_source.py            # from agent-gui/
"""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eagleeye import VERSION  # noqa: E402

INCLUDE = [
    "eagleeye", "pyproject.toml", "README.md", ".dockerignore",
    "packaging/network-agent", "packaging/eagleeye.service", "packaging/macos", "packaging/THIRD-PARTY-NOTICES.txt",
]
SKIP_PARTS = {"__pycache__", ".pytest_cache"}


def wanted(path: Path) -> bool:
    return not (SKIP_PARTS & set(path.parts)) and path.suffix not in (".pyc", ".pyo")


def main() -> int:
    name = f"eagleeye-agent-{VERSION}"
    out = ROOT / "dist" / f"{name}.tar.gz"
    out.parent.mkdir(exist_ok=True)

    def reset(info: tarfile.TarInfo) -> tarfile.TarInfo:     # no build machine's user names in it
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        # Built on Windows the files come out writable by everyone (0666); unpacked as root for a
        # root service, any local user could then change the code it runs. Owner-writable only.
        info.mode = 0o755 if info.isdir() or info.name.endswith(".sh") else 0o644
        return info

    count = 0
    with tarfile.open(out, "w:gz") as tar:
        for item in INCLUDE:
            src = ROOT / item
            files = [src] if src.is_file() else sorted(p for p in src.rglob("*") if p.is_file())
            for f in files:
                rel = f.relative_to(ROOT)
                if wanted(rel):
                    tar.add(f, arcname=f"{name}/{rel.as_posix()}", filter=reset)
                    count += 1
    print(f"{out} ({count} files, {out.stat().st_size / 2**20:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
