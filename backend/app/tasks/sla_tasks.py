"""
UMEagleEye - SLA monitoring Celery tasks (FR-06-03).
Escalates Critical alerts open >4 hours via Telegram notification.
"""

import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, select, and_
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.db.models import Advisory, Event, Asset
from app.db.enums import AdvisoryStatus, Severity
from app.services.telegram_notifier import notify_critical_escalation

logger = logging.getLogger(__name__)


def get_sync_session() -> Session:
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


@celery_app.task(name="app.tasks.sla_tasks.check_sla_breaches")
def check_sla_breaches():
    """Check for Critical alerts breaching 4-hour SLA (FR-06-03).

    If a Critical advisory remains Open for >4 hours,
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
            logger.info("SLA check: no breaches found.")
            return {"sla_breaches": 0}

        count = 0
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

            notify_critical_escalation(
                advisory_id=str(advisory.advisory_id),
                event_type=event.event_type.value if event else "unknown",
                asset_ip=str(asset.ip_address) if asset else "Unknown",
                hours_open=hours_open,
            )
            count += 1

        logger.warning(f"SLA breaches detected: {count} critical advisories escalated via Telegram")
        return {"sla_breaches": count}

    finally:
        session.close()
