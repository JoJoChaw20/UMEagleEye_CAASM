"""
UMEagleEye - Drift detection Celery tasks (FR-03-02).
"""

import logging
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.drift import DriftService
from app.db.models import Asset, Event

logger = logging.getLogger(__name__)


def get_sync_session() -> Session:
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


@celery_app.task(name="app.tasks.drift_tasks.run_drift_audit")
def run_drift_audit():
    """Compare all baselined assets against current state and generate drift events."""
    session = get_sync_session()
    try:
        # Get all assets that have a baseline set
        result = session.execute(
            select(Asset).where(Asset.baseline_state.isnot(None))
        )
        assets = result.scalars().all()

        total_drifts = 0
        for asset in assets:
            baseline = asset.baseline_state
            current_state = asset.os_info or {}

            drift_events = DriftService.compute_drift(
                baseline=baseline,
                current_state=current_state,
                asset_id=str(asset.asset_id),
            )

            # Persist drift events
            for drift in drift_events:
                event = Event(
                    asset_id=asset.asset_id,
                    event_type=drift["event_type"],
                    severity=drift["severity"],
                    details=drift["details"],
                )
                session.add(event)
                total_drifts += 1

        session.commit()
        logger.info(f"Drift audit complete: {total_drifts} events across {len(assets)} baselined assets")
        return {"total_drifts": total_drifts, "assets_audited": len(assets)}

    except Exception as e:
        session.rollback()
        logger.error(f"Drift audit error: {e}")
        raise
    finally:
        session.close()
