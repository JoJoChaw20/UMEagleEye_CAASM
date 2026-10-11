"""Writes build/eagleeye.ico from the icon the app draws in code."""

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtCore import QSize  # noqa: E402
from PySide6.QtGui import QGuiApplication  # noqa: E402

app = QGuiApplication([])
from eagleeye.gui.app import app_icon  # noqa: E402

target = Path(sys.argv[1])
target.parent.mkdir(parents=True, exist_ok=True)
if not app_icon().pixmap(QSize(256, 256)).save(str(target), "ICO"):
    raise SystemExit(f"could not write {target}")
print(f"icon written to {target}")
