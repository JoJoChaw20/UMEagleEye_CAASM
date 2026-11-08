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


# ── Install codes ("EE2."): one code for many computers ──
# Made on the dashboard's Agents page (Install codes) for Intune, GPO, scripts or containers:
# base64url(JSON {u: API URL, t: token}). Each computer exchanges it once, at
# POST /enrolment/enrol, for an agent of its own (workers/src/routes/enrolment.ts).
INSTALL_PREFIX = "EE2."
_TOKEN = re.compile(r"^[0-9a-f]{64}$")


def is_install_code(text: str) -> bool:
    return "".join((text or "").split()).strip("\"'").startswith(INSTALL_PREFIX)


def parse_install_code(text: str) -> tuple[str, str]:
    """(api_url, token) from an install code."""
    raw = "".join((text or "").split()).strip("\"'")
    body = raw[len(INSTALL_PREFIX):] if raw.startswith(INSTALL_PREFIX) else ""
    try:
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        data = None
    url, token = (str((data or {}).get(k) or "").strip() for k in ("u", "t")) if isinstance(data, dict) else ("", "")
    if not url.lower().startswith(("https://", "http://")) or not _TOKEN.match(token):
        raise ConnectionCodeError("The install code is incomplete or damaged. Copy the whole code again.")
    return url.rstrip("/"), token


def exchange_install_code(code: str, name: str, kind: str = "host", session: object = None) -> tuple[str, str, str]:
    """Register this computer with an install code: (api_url, agent_id, api_key) of its new agent."""
    from . import httpclient
    url, token = parse_install_code(code)
    http = session or httpclient.Session(follow_redirects=False)
    try:
        resp = http.post(f"{url}/enrolment/enrol", timeout=30, json={"token": token, "name": name[:255], "kind": kind})
    except httpclient.RequestException as exc:
        raise ConnectionCodeError(f"Could not reach the EagleEye server to register: {exc}") from None
    try:
        body = resp.json()
    except ValueError:
        body = {}
    if not resp.ok:
        detail = body.get("detail") if isinstance(body, dict) else None
        raise ConnectionCodeError(detail or f"The server refused the install code (HTTP {resp.status_code}).")
    agent_id, key = str(body.get("agent_id") or ""), str(body.get("api_key") or "")
    if not _UUID.match(agent_id) or not key:
        raise ConnectionCodeError("The server's answer had no agent ID and key.")
    return url, agent_id.lower(), key


def credentials_from_code(code: str, name: str, kind: str = "host", existing: object = None,
                          session: object = None) -> tuple[str, str, str, bool]:
    """(api_url, agent_id, api_key, registered_now) from a connection code (one agent) or an
    install code. With an install code, credentials this computer already has for the same
    server are kept: a reinstall or a restarted container never makes a second agent."""
    if not is_install_code(code):
        return (*parse_connection_code(code), False)
    url, _token = parse_install_code(code)
    have = existing if existing is not None else None
    if have is not None and getattr(have, "api_url", "").rstrip("/") == url and getattr(have, "agent_id", "") \
            and getattr(have, "api_key", ""):
        return url, have.agent_id, have.api_key, False
    return (*exchange_install_code(code, name, kind, session), True)
