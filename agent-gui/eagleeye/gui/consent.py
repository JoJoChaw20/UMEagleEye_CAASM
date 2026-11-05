"""First-run notice and choices. The agent does not start until it is accepted."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QTextBrowser, QVBoxLayout

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

        box = Panel("Your choices")
        self.inventory = QCheckBox("Collect this computer's inventory")
        self.inventory.setChecked(settings.inventory)
        self.user_software = QCheckBox("Include software installed only for individual users (personal data)")
        self.user_software.setChecked(settings.inventory_user_software)
        self.admin_names = QCheckBox("Include the names of administrator accounts (personal data)")
        self.admin_names.setChecked(settings.inventory_admin_names)
        self.passive = QCheckBox("Listen passively for device announcements (needs Administrator)")
        self.passive.setChecked(settings.passive)
        self.inventory.toggled.connect(self.user_software.setEnabled)
        self.inventory.toggled.connect(self.admin_names.setEnabled)
        self.user_software.setEnabled(settings.inventory)
        self.admin_names.setEnabled(settings.inventory)

        box.add(label("You can change them later on the Privacy page.", "hint"))
        for w in (self.inventory, self.user_software, self.admin_names, self.passive):
            box.add(w)
        for w in (self.user_software, self.admin_names):
            w.setContentsMargins(26, 0, 0, 0)

        buttons = QDialogButtonBox()
        accept = buttons.addButton("Accept and continue", QDialogButtonBox.ButtonRole.AcceptRole)
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
        layout.addWidget(label("The agent does not start until you accept. Read what it collects, then choose.",
                               "description", wrap=True))
        layout.addWidget(text, 1)
        layout.addWidget(box)
        note = label("By continuing you confirm you have read this notice.", "hint", wrap=True)
        layout.addWidget(note)
        layout.addWidget(buttons)

    def apply(self) -> None:
        """Write the choices and the consent record into the settings."""
        s = self.settings
        s.inventory = self.inventory.isChecked()
        s.inventory_user_software = s.inventory and self.user_software.isChecked()
        s.inventory_admin_names = s.inventory and self.admin_names.isChecked()
        s.passive = self.passive.isChecked()
        s.consent_version = CONSENT_VERSION
        s.consent_at = datetime.now().astimezone().isoformat(timespec="seconds")


def needs_consent(settings: Settings) -> bool:
    return settings.consent_version < CONSENT_VERSION
