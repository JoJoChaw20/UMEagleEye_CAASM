"""First-run notice and choices. The agent does not start until it is accepted."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QGroupBox, QLabel, QTextBrowser, QVBoxLayout,
)

from ..config import Settings
from ..privacy import CONSENT_VERSION, NOTICE_HTML, NOTICE_TITLE


class ConsentDialog(QDialog):
    def __init__(self, settings: Settings, parent=None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle(f"EagleEye Agent: {NOTICE_TITLE.lower()}")
        self.resize(640, 680)

        text = QTextBrowser()
        text.setOpenExternalLinks(True)
        text.setHtml(NOTICE_HTML)

        box = QGroupBox("Your choices (you can change them later on the Privacy page)")
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

        inner = QVBoxLayout(box)
        for w in (self.inventory, self.user_software, self.admin_names, self.passive):
            inner.addWidget(w)
        for w in (self.user_software, self.admin_names):
            w.setStyleSheet("margin-left: 20px")

        buttons = QDialogButtonBox()
        accept = buttons.addButton("Accept and continue", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton("Quit", QDialogButtonBox.ButtonRole.RejectRole)
        accept.setDefault(True)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(text, 1)
        layout.addWidget(box)
        note = QLabel("By continuing you confirm you have read this notice.")
        note.setWordWrap(True)
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
