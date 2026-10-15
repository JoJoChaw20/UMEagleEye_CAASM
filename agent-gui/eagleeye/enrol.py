"""One-paste connection code from the dashboard's Agents page.

The code carries the three values the agent needs (API URL, agent ID, API key), so a
user pastes one string instead of three. Format: "EE1." + base64url(JSON {u, i, k}),
made by frontend/src/utils/connectionCode.js; a new format gets a new prefix.
"""

from __future__ import annotations

import base64
import binascii
import json
import re

PREFIX = "EE1."
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class ConnectionCodeError(ValueError):
    """A code that cannot be used; the message says what to do."""


def parse_connection_code(text: str) -> tuple[str, str, str]:
    """(api_url, agent_id, api_key) from a connection code. Spaces, line breaks and
    surrounding quotes from copying it out of a chat or an email are ignored."""
    raw = "".join((text or "").split()).strip("\"'")
    if not raw:
        raise ConnectionCodeError("Paste the connection code from the dashboard's Agents page first.")
    if not raw.startswith(PREFIX):
        raise ConnectionCodeError("This is not an EagleEye connection code: it starts with EE1. "
                                  "Copy it again from the dashboard's Agents page.")
    body = raw[len(PREFIX):]
    try:
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise ConnectionCodeError("The connection code is incomplete or damaged. Copy the whole code again.") from None
    if not isinstance(data, dict):
        raise ConnectionCodeError("The connection code is incomplete or damaged. Copy the whole code again.")
    url, agent_id, key = (str(data.get(k) or "").strip() for k in ("u", "i", "k"))
    if not url.lower().startswith(("https://", "http://")) or not _UUID.match(agent_id) or not key:
        raise ConnectionCodeError("The connection code is incomplete or damaged. Copy the whole code again.")
    return url.rstrip("/"), agent_id.lower(), key
