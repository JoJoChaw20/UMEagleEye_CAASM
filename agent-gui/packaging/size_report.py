"""Size of a built agent folder, for keeping the agent small (run by build.ps1).

    python packaging/size_report.py dist/EagleEyeAgent

Prints the total, the biggest parts, and what should not be there (scapy unless built
with EAGLEEYE_WITH_SCAPY=1; the Qt parts the spec leaves out).
Baseline 2026-11-07: 84 MB without scapy and the unused Qt parts (was 127-134 MB);
PySide6 is most of it. The GUI uses about 35 MB of private memory when idle.
"""

from __future__ import annotations

import sys
from pathlib import Path

WATCH = ("opengl32sw.dll", "Qt6Pdf.dll", "Qt6Quick.dll", "Qt6Qml.dll", "Qt6VirtualKeyboard.dll")


def size(path: Path) -> int:
    return path.stat().st_size if path.is_file() else sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def main(folder: str) -> int:
    root = Path(folder)
    if not root.is_dir():
        print(f"{root} is not a folder")
        return 1
    mb = lambda n: f"{n / 1_048_576:7.1f} MB"  # noqa: E731
    print(f"Total {mb(size(root))}  ({root})")
    internal = root / "_internal"
    parts = sorted(((size(p), p.name) for p in internal.iterdir()), reverse=True) if internal.is_dir() else []
    for n, name in parts[:8]:
        print(f"  {mb(n)}  {name}")
    for exe in sorted(root.glob("*.exe")):
        print(f"  {mb(exe.stat().st_size)}  {exe.name} (Python code is inside)")
    found = [str(p.relative_to(root)) for p in root.rglob("*") if any(w.lower() in p.name.lower() for w in WATCH)]
    found += [f"scapy (inside {exe.name})" for exe in root.glob("*.exe") if b"scapy.layers" in exe.read_bytes()]
    if found:
        print("  Included on purpose? " + ", ".join(found[:6]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "dist/EagleEyeAgent"))
