"""First-run notice. The agent does not start until it is acknowledged. What the agent
collects is set by the organisation's administrator (agent settings on the dashboard,
2.4.0); the notice lists what it collects until they set something."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QTextBrowser, QVBoxLayout

from ..config import Settings
from ..privacy import CONSENT_VERSION, NOTICE_HTML, NOTICE_TITLE
from . import theme
from .widgets import Panel, Trace, label


class ConsentDialog(QDialog):
    def __init__(self, settings: Settings, parent=None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle(f"EagleEye Agent: {NOTICE_TITLE.lower()}")
        self.resize(680, 760)

        text = QTextBrowser()
        text.setOpenExternalLinks(True)
        text.document().setDefaultStyleSheet(theme.document_css(theme.current()))
        text.setHtml(NOTICE_HTML)

        box = Panel("What it collects now")
        self.items = summary(settings)
        for item in self.items:
            box.add(label(item, "value", wrap=True))
        box.add(label("Your organisation's administrator can change these from the EagleEye dashboard.", "hint",
                      wrap=True))

        buttons = QDialogButtonBox()
        accept = buttons.addButton("OK, continue", QDialogButtonBox.ButtonRole.AcceptRole)
        accept.setProperty("role", "primary")
        quit_btn = buttons.addButton("Quit", QDialogButtonBox.ButtonRole.RejectRole)
        quit_btn.setProperty("role", "ghost")
        accept.setDefault(True)
        accept.setFocus()
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        mark = QLabel()
        pm = theme.brand_pixmap("mark")
        if not pm.isNull():
            scaled = pm.scaledToHeight(88, Qt.TransformationMode.SmoothTransformation)
            scaled.setDevicePixelRatio(2.0)
            mark.setPixmap(scaled)
        head = QHBoxLayout()
        head.setSpacing(12)
        head.addWidget(mark)
        head.addWidget(label(NOTICE_TITLE, "display"))
        head.addWidget(Trace(44, "ground"), 0, Qt.AlignmentFlag.AlignVCenter)
        head.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)
        layout.addLayout(head)
        layout.addWidget(label("The agent starts once you have read what it collects.", "description", wrap=True))
        layout.addWidget(text, 1)
        layout.addWidget(box)
        note = label("By continuing you confirm you have read this notice.", "hint", wrap=True)
        layout.addWidget(note)
        layout.addWidget(buttons)

    def apply(self) -> None:
        """Record that the notice was read (the settings themselves are unchanged)."""
        s = self.settings
        s.consent_version = CONSENT_VERSION
        s.consent_at = datetime.now().astimezone().isoformat(timespec="seconds")


def summary(settings: Settings) -> list[str]:
    """One line per kind of collection, on or off, as the agent would run now."""
    def mark(on: bool) -> str:
        return "On " if on else "Off"
    return [
        f"{mark(settings.inventory)}  This computer's inventory, with the software each user installed",
        f"{mark(settings.sbom)}  Software packages and their known vulnerabilities (SBOM)",
        f"{mark(settings.passive)}  Passive listening for device announcements",
    ]


def needs_consent(settings: Settings) -> bool:
    return settings.consent_version < CONSENT_VERSION
