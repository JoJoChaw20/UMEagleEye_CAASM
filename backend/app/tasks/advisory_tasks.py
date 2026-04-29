"""
UMEagleEye - AI advisory generation Celery tasks (FR-05-02).
"""

import asyncio
import logging
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.advisory import AdvisoryService
from app.db.models import Event, Asset, Advisory
from app.db.enums import AdvisoryStatus

logger = logging.getLogger(__name__)


def get_sync_session() -> Session:
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


@celery_app.task(name="app.tasks.advisory_tasks.generate_advisory", bind=True)
def generate_advisory(self, event_id: str):
    """Generate AI advisory for a specific event via Gemini RAG pipeline."""
    session = get_sync_session()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        event = session.execute(
            select(Event).where(Event.event_id == event_id)
        ).scalar_one_or_none()

        if not event:
            return {"error": f"Event {event_id} not found"}

        asset = session.execute(
            select(Asset).where(Asset.asset_id == event.asset_id)
        ).scalar_one_or_none()

        event_data = {
            "event_type": event.event_type.value,
            "severity": event.severity.value,
            "details": event.details,
            "composite_risk_score": float(event.composite_risk_score) if event.composite_risk_score else None,
        }

        asset_data = {
            "device_type": asset.device_type.value if asset else "unknown",
            "criticality_score": asset.criticality_score if asset else 5,
            "is_internet_facing": asset.is_internet_facing if asset else False,
            "hostname": asset.hostname if asset else "unknown",
        }

        # Generate advisory with RAG context
        result = loop.run_until_complete(
            AdvisoryService.generate_advisory(event_data, asset_data, db=session)
        )

        advisory = Advisory(
            event_id=event_id,
            summary=result["summary"],
            recommended_action=result["recommended_action"],
            status=AdvisoryStatus.OPEN,
        )
        session.add(advisory)
        session.commit()

        logger.info(f"Advisory generated for event {event_id}")
        return {
            "advisory_id": str(advisory.advisory_id),
            "summary": result["summary"][:200],
        }

    except Exception as e:
        session.rollback()
        logger.error(f"Advisory generation error: {e}")
        raise
    finally:
        session.close()
        loop.close()


@celery_app.task(name="app.tasks.advisory_tasks.generate_batch_advisories")
def generate_batch_advisories():
    """Generate advisories for all high/critical events without existing advisories."""
    session = get_sync_session()
    try:
        # Find events without advisories
        events = session.execute(
            select(Event).where(
                Event.severity.in_(["high", "critical"]),
                ~Event.event_id.in_(
                    select(Advisory.event_id)
                ),
            ).order_by(Event.timestamp.desc()).limit(20)
        ).scalars().all()

        count = 0
        for event in events:
            generate_advisory.delay(str(event.event_id))
            count += 1

        return {"queued_advisories": count}

    finally:
        session.close()
