"""
UMEagleEye - CTI ingestion Celery tasks (FR-04-01).
Scheduled OTX + ThreatFox feed polling with deduplication.
"""

import asyncio
import logging
from datetime import datetime, timezone
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.threat_intel import ThreatIntelService
from app.db.models import CTIIndicator, Asset, Event
from app.db.enums import EventType

logger = logging.getLogger(__name__)


def get_sync_session() -> Session:
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


@celery_app.task(name="app.tasks.cti_tasks.ingest_mycert_feeds")
def ingest_mycert_feeds():
    """Ingest threat intel from AlienVault OTX and abuse.ch ThreatFox."""
    logger.info("Starting CTI ingestion pipeline")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        # Fetch from both sources
        otx_indicators = loop.run_until_complete(
            ThreatIntelService.fetch_otx_pulses(days=7, limit=50)
        )
        threatfox_indicators = loop.run_until_complete(
            ThreatIntelService.fetch_abusech_threatfox(days=7)
        )

        all_indicators = otx_indicators + threatfox_indicators
        logger.info(f"Total indicators fetched: {len(all_indicators)}")

        if not all_indicators:
            return {"status": "no_data", "total": 0}

        session = get_sync_session()
        try:
            new_count = 0
            updated_count = 0
            match_count = 0

            for ind in all_indicators:
                value = ind.get("value", "").strip()
                if not value:
                    continue

                # Deduplication check
                existing = session.execute(
                    select(CTIIndicator).where(CTIIndicator.value == value)
                ).scalar_one_or_none()

                if existing:
                    existing.last_seen = datetime.now(timezone.utc)
                    if ind.get("confidence_score"):
                        existing.confidence_score = ind["confidence_score"]
                    updated_count += 1
                else:
                    cti = CTIIndicator(
                        source=ind.get("source", "Unknown"),
                        indicator_type=ind["indicator_type"],
                        value=value,
                        confidence_score=ind.get("confidence_score", 0.5),
                        attack_tactic=ind.get("attack_tactic", ""),
                        attack_technique=ind.get("attack_technique", ""),
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                    )
                    session.add(cti)
                    new_count += 1

                # Cross-reference against internal assets (FR-04-02)
                if ind["indicator_type"].value == "ip":
                    search_ip = value
                    # Strip port for IPv4 or bracketed IPv6 to prevent INET cast errors
                    if search_ip.count(":") == 1:
                        search_ip = search_ip.split(":")[0]
                    elif "]" in search_ip:
                        search_ip = search_ip.split("]")[0].lstrip("[")

                    asset = session.execute(
                        select(Asset).where(
                            Asset.ip_address == search_ip
                        )
                    ).scalar_one_or_none()

                    if asset:
                        triage_score = ThreatIntelService.compute_triage_score(
                            indicator_confidence=ind.get("confidence_score", 0.5),
                            matched_asset_criticality=asset.criticality_score,
                            is_internet_facing=asset.is_internet_facing,
                            indicator_type="ip",
                        )
                        severity = ThreatIntelService.classify_triage_severity(triage_score)

                        event = Event(
                            asset_id=asset.asset_id,
                            event_type=EventType.CTI_MATCH,
                            severity=severity,
                            composite_risk_score=triage_score,
                            details={
                                "indicator_value": value,
                                "indicator_source": ind.get("source", ""),
                                "attack_tactic": ind.get("attack_tactic", ""),
                                "attack_technique": ind.get("attack_technique", ""),
                                "triage_score": triage_score,
                            },
                        )
                        session.add(event)
                        match_count += 1
                        logger.warning(
                            f"CTI MATCH: {value} -> asset {asset.asset_id} "
                            f"(score: {triage_score}, severity: {severity.value})"
                        )

            session.commit()
            result = {
                "status": "complete",
                "new_indicators": new_count,
                "updated_indicators": updated_count,
                "asset_matches": match_count,
                "total_processed": len(all_indicators),
            }
            logger.info(f"CTI ingestion complete: {result}")
            return result

        finally:
            session.close()
    finally:
        loop.close()
