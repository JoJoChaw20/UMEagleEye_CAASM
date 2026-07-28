"""
UMEagleEye - Telegram Push Notification Service.
Broadcasts alerts to all linked users + the admin TELEGRAM_CHAT_ID fallback.
Uses TelegramFormatter for MarkdownV2 + inline buttons on every push.
"""

import logging
import httpx
from datetime import datetime, timezone
from typing import List, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"


def get_all_linked_chat_ids(roles: Optional[List[str]] = None) -> List[str]:
    """
    Retrieve telegram_chat_ids from linked users, optionally filtered by role.
    Always includes settings.TELEGRAM_CHAT_ID (admin).
    """
    chat_ids = set()
    if settings.TELEGRAM_CHAT_ID:
        chat_ids.add(str(settings.TELEGRAM_CHAT_ID))
    try:
        from sqlalchemy import create_engine, select
        from sqlalchemy.orm import Session
        from app.db.models import User
        engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
        with Session(engine) as session:
            stmt = select(User.telegram_chat_id).where(User.telegram_chat_id.isnot(None))
            if roles:
                stmt = stmt.where(User.role.in_(roles))
            
            for chat_id in session.execute(stmt).scalars().all():
                if chat_id:
                    chat_ids.add(str(chat_id))
    except Exception as e:
        logger.error(f"Error fetching linked Telegram chat IDs: {e}")
    return list(chat_ids)


def _api_url(method: str) -> str:
    return TELEGRAM_API.format(token=settings.TELEGRAM_BOT_TOKEN, method=method)


def _send_to_chat(
    chat_id: str,
    text: str,
    parse_mode: str = "MarkdownV2",
    reply_markup: Optional[dict] = None,
) -> bool:
    """Send a single message (with optional inline keyboard) to one chat ID."""
    if not settings.TELEGRAM_BOT_TOKEN:
        return False
    payload: dict = {"chat_id": chat_id, "text": text, "parse_mode": parse_mode}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        resp = httpx.post(_api_url("sendMessage"), json=payload, timeout=10)
        if resp.status_code == 200:
            return True
        logger.error(f"Telegram API error {resp.status_code} for {chat_id}: {resp.text}")
        return False
    except Exception as e:
        logger.error(f"Failed to send Telegram message to {chat_id}: {e}")
        return False


def send_telegram_message(
    text: str,
    chat_id: Optional[str] = None,
    parse_mode: str = "MarkdownV2",
    reply_markup: Optional[dict] = None,
) -> bool:
    target = chat_id or settings.TELEGRAM_CHAT_ID
    if not settings.TELEGRAM_BOT_TOKEN or not target:
        logger.warning("Telegram not configured — skipping notification.")
        return False
    return _send_to_chat(target, text, parse_mode, reply_markup)


def broadcast_telegram_message(
    text: str,
    parse_mode: str = "MarkdownV2",
    reply_markup: Optional[dict] = None,
    allowed_roles: Optional[List[str]] = None,
) -> int:
    """Broadcast to linked users (filtered by role) + admin. Returns success count."""
    if not settings.TELEGRAM_BOT_TOKEN:
        logger.warning("Telegram not configured — skipping broadcast.")
        return 0
    chat_ids = get_all_linked_chat_ids(roles=allowed_roles)
    if not chat_ids:
        logger.warning("No Telegram chat IDs found for this broadcast.")
        return 0
    success = sum(_send_to_chat(cid, text, parse_mode, reply_markup) for cid in chat_ids)
    logger.info(f"Telegram broadcast to {allowed_roles or 'all'}: {success}/{len(chat_ids)} sent.")
    return success


def _markup_to_dict(markup) -> Optional[dict]:
    """Convert PTB InlineKeyboardMarkup to plain dict for httpx."""
    if markup is None:
        return None
    try:
        return markup.to_dict()
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════
# Alert formatters — all use TelegramFormatter + buttons
# ═══════════════════════════════════════════════════════════

SEVERITY_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def notify_drift_event(
    asset_ip: str,
    asset_hostname: str,
    event_type: str,
    severity: str,
    changed_attribute: str,
    previous_value: str,
    new_value: str,
    event_id: str = "unknown",
    evidence: dict = None,
) -> bool:
    """FR-05-03: Push drift alert with Acknowledge button to all linked users."""
    from app.services.telegram_formatter import format_drift_alert
    text, markup = format_drift_alert(
        asset_ip=asset_ip,
        asset_hostname=asset_hostname,
        event_type=event_type,
        severity=severity,
        changed_attribute=changed_attribute,
        previous_value=previous_value,
        new_value=new_value,
        event_id=event_id,
        evidence=evidence,
        role=None,
    )
    # Only broadcast to technical staff
    technical_roles = ["superadmin", "tenant_superadmin", "tenant_admin"]
    return broadcast_telegram_message(
        text, 
        reply_markup=_markup_to_dict(markup),
        allowed_roles=technical_roles
    ) > 0


def notify_pdpa_violation(
    asset_ip: str,
    asset_hostname: str,
    control_lost: str,
    details: str,
) -> bool:
    """PDPA Compliance Drift — Critical notification to all linked users."""
    import re
    def esc(t): return re.sub(r"([_*\[\]()~`>#+=|{}.!\-\\])", r"\\\1", str(t))
    ts = datetime.now(timezone.utc).strftime("%Y\\-%m\\-%d %H:%M UTC")
    text = (
        f"🔴 *PDPA COMPLIANCE VIOLATION — CRITICAL*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🖥️ *Asset:* `{esc(asset_ip)}` \\({esc(asset_hostname or 'Unknown')}\\)\n"
        f"❌ *Control Lost:* {esc(control_lost)}\n"
        f"📋 *Details:* {esc(details[:200])}\n"
        f"🕐 *Time:* {ts}\n\n"
        f"⚠️ *Action Required:* Restore control immediately\\.\n"
        f"_Reply /advisories for AI remediation steps_"
    )
    # Broadcast to technical staff + MSSP
    technical_roles = ["superadmin", "tenant_superadmin", "tenant_admin"]
    return broadcast_telegram_message(text, allowed_roles=technical_roles) > 0


def notify_new_advisory(
    event_type: str,
    severity: str,
    summary: str,
    asset_ip: str = "Unknown",
    advisory_id: str = "unknown",
) -> bool:
    """Notify technical users when a new AI advisory is generated (FR-05-02)."""
    from app.services.telegram_formatter import format_advisory_message
    text, markup = format_advisory_message(
        advisory_id=advisory_id,
        event_type=event_type,
        severity=severity,
        summary=summary,
        recommended_action="Use /advisories to view full remediation steps.",
        asset_ip=asset_ip,
        role=None,
    )
    # Default to technical roles only (business_owner excluded for detailed advisories)
    technical_roles = ["superadmin", "tenant_superadmin", "tenant_admin"]
    return broadcast_telegram_message(
        text, 
        reply_markup=_markup_to_dict(markup),
        allowed_roles=technical_roles
    ) > 0


def notify_critical_escalation(
    advisory_id: str,
    event_type: str,
    asset_ip: str,
    hours_open: float,
) -> bool:
    """Escalation: Critical advisory open >4 hours — with Acknowledge button."""
    from app.services.telegram_formatter import format_escalation_alert
    text, markup = format_escalation_alert(
        advisory_id=advisory_id,
        event_type=event_type,
        asset_ip=asset_ip,
        hours_open=hours_open,
        role=None,
    )
    # Escalate only to technical roles
    technical_roles = ["superadmin", "tenant_superadmin", "tenant_admin"]
    return broadcast_telegram_message(
        text, 
        reply_markup=_markup_to_dict(markup),
        allowed_roles=technical_roles
    ) > 0
