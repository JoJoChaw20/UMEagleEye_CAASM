"""
UMEagleEye - Asset Relationship Inference Celery Tasks.
Runs after discovery scans to auto-infer asset relationships.
"""

import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.relationship import RelationshipService

logger = logging.getLogger(__name__)


def get_sync_session() -> Session:
    """Create a synchronous DB session for Celery workers."""
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


@celery_app.task(name="app.tasks.relationship_tasks.infer_asset_relationships", bind=True)
def infer_asset_relationships(self):
    """Run relationship inference across all discovered assets.
    
    Called after discovery scans or manually via API.
    Infers same_subnet, connects_to, and exposes_service relationships
    from open port profiles and IP address analysis.
    """
    logger.info("Starting asset relationship inference")
    session = get_sync_session()
    try:
        result = RelationshipService.infer_relationships(session)
        logger.info(
            f"Relationship inference complete: "
            f"{result['new_relationships']} new relationships, "
            f"{result['total_relationships']} total"
        )
        return result
    except Exception as e:
        session.rollback()
        logger.error(f"Relationship inference error: {e}")
        raise
    finally:
        session.close()
