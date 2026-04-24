"""
UMEagleEye - SLA monitoring Celery tasks (FR-06-03).
Escalates Critical alerts open > 4 hours via Telegram notification.
"""

import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, select, and_
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.db.models import Advisory, Event, Asset
from app.db.enums import AdvisoryStatus, Severity

logger = logging.getLogger(__name__)


def get_sync_session() -> Session:
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


async def send_telegram_alert(message: str):
    """Send an escalation alert via Telegram bot."""
    if not settings.TELEGRAM_BOT_TOKEN:
        logger.warning("Telegram bot token not configured")
        return

    import httpx
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"

    # Send to all recent chat IDs (in production, store authorized chat IDs)
    try:
        async with httpx.AsyncClient() as client:
            # Get updates to find chat IDs
            updates_resp = await client.get(
                f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/getUpdates",
                params={"limit": 10},
            )
            updates = updates_resp.json().get("result", [])

            chat_ids = set()
            for update in updates:
                chat = update.get("message", {}).get("chat", {})
                if chat.get("id"):
                    chat_ids.add(chat["id"])

            for chat_id in chat_ids:
                await client.post(url, json={
                    "chat_id": chat_id,
                    "text": message,
                    "parse_mode": "Markdown",
                })

            logger.info(f"Telegram alert sent to {len(chat_ids)} chats")
    except Exception as e:
        logger.error(f"Telegram alert error: {e}")


@celery_app.task(name="app.tasks.sla_tasks.check_sla_breaches")
def check_sla_breaches():
    """Check for Critical alerts breaching 4-hour SLA (FR-06-03).

    If a Critical advisory remains Open for > 4 hours,
    trigger a secondary escalation notification via Telegram.
    """
    session = get_sync_session()

    try:
        threshold = datetime.now(timezone.utc) - timedelta(hours=4)

        # Find Critical/Open advisories older than 4 hours
        breached = session.execute(
            select(Advisory).join(Event).where(
                and_(
                    Advisory.status == AdvisoryStatus.OPEN,
                    Event.severity == Severity.CRITICAL,
                    Advisory.created_at < threshold,
                )
            )
        ).scalars().all()

        if not breached:
            return {"sla_breaches": 0}

        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            for advisory in breached:
                event = session.execute(
                    select(Event).where(Event.event_id == advisory.event_id)
                ).scalar_one_or_none()

                asset = None
                if event:
                    asset = session.execute(
                        select(Asset).where(Asset.asset_id == event.asset_id)
                    ).scalar_one_or_none()

                hours_open = (datetime.now(timezone.utc) - advisory.created_at).total_seconds() / 3600

                message = (
                    f"🚨 *SLA BREACH - CRITICAL ALERT*\n\n"
                    f"Advisory has been OPEN for {hours_open:.1f} hours (SLA: 4h)\n\n"
                    f"*Summary:* {advisory.summary[:200]}\n"
                    f"*Asset:* {asset.hostname or asset.ip_address if asset else 'Unknown'}\n"
                    f"*Event Type:* {event.event_type.value if event else 'Unknown'}\n"
                    f"*Created:* {advisory.created_at.strftime('%Y-%m-%d %H:%M UTC')}\n\n"
                    f"⚠️ Immediate action required!"
                )

                loop.run_until_complete(send_telegram_alert(message))

        finally:
            loop.close()

        logger.warning(f"SLA breaches detected: {len(breached)} critical advisories")
        return {"sla_breaches": len(breached)}

    finally:
        session.close()
