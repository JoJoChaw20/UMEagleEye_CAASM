"""Secrets in the operating system's credential store.

Windows Credential Manager, macOS Keychain, or the Secret Service on Linux, through
the `keyring` package. When a config file was saved this way it carries
`"secrets_in_keychain": true` and its secret fields are blank; `load_settings` then
reads them from here. Without `keyring` (or without a usable backend, e.g. a Linux
server with no Secret Service) secrets stay in the config file as before.
"""

from __future__ import annotations

import logging
from typing import Optional

log = logging.getLogger("eagleeye.keychain")

SERVICE = "EagleEye Agent"
SECRET_FIELDS = ("api_key", "fingerbank_key", "snmp_auth_key", "snmp_priv_key")


class Keychain:
    """Thin wrapper over `keyring`; every method fails soft and reports availability."""

    def __init__(self, service: str = SERVICE) -> None:
        self.service = service

    @staticmethod
    def _keyring():  # type: ignore[no-untyped-def]
        try:
            import keyring
            from keyring.backends import fail
        except ImportError:
            return None
        if isinstance(keyring.get_keyring(), fail.Keyring):
            return None
        return keyring

    def available(self) -> bool:
        return self._keyring() is not None

    def get(self, name: str) -> Optional[str]:
        kr = self._keyring()
        if kr is None:
            return None
        try:
            return kr.get_password(self.service, name)
        except Exception as exc:  # noqa: BLE001 - backend errors vary by platform
            log.warning("Could not read %s from the credential store: %s", name, exc)
            return None

    def set(self, name: str, value: str) -> bool:
        """Store `value`, or remove the entry when it is empty. False if not stored."""
        kr = self._keyring()
        if kr is None:
            return False
        try:
            if value:
                kr.set_password(self.service, name, value)
            elif kr.get_password(self.service, name) is not None:
                kr.delete_password(self.service, name)
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not store %s in the credential store: %s", name, exc)
            return False
