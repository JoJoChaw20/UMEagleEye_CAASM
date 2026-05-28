"""
UMEagleEye - CTI API routes for threat indicators and MITRE ATT&CK matrix.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.dependencies import get_db, get_current_user
from app.db.models import CTIIndicator, User
from app.schemas.models import CTIIndicatorResponse, CTIListResponse

router = APIRouter(prefix="/cti", tags=["Threat Intelligence"])


@router.get("/indicators", response_model=CTIListResponse)
async def list_indicators(
    source: Optional[str] = None,
    indicator_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List CTI indicators with optional filtering."""
    query = select(CTIIndicator)

    if source:
        query = query.where(CTIIndicator.source.ilike(f"%{source}%"))
    if indicator_type:
        query = query.where(CTIIndicator.indicator_type == indicator_type)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    query = query.order_by(CTIIndicator.last_seen.desc()).limit(limit)
    result = await db.execute(query)
    indicators = result.scalars().all()

    return CTIListResponse(
        items=[CTIIndicatorResponse.model_validate(i) for i in indicators],
        total=total,
    )


@router.get("/matrix")
async def get_attack_matrix(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get MITRE ATT&CK matrix data from stored indicators."""
    from app.services.threat_intel import ThreatIntelService

    result = await db.execute(select(CTIIndicator).limit(1000))
    indicators = result.scalars().all()

    indicator_dicts = [
        {
            "attack_tactic": i.attack_tactic,
            "attack_technique": i.attack_technique,
            "source": i.source,
        }
        for i in indicators
    ]

    matrix = ThreatIntelService.get_attack_matrix_data(indicator_dicts)
    return {"matrix": matrix, "total_indicators": len(indicators)}


@router.post("/ingest")
async def trigger_cti_ingestion(
    current_user: User = Depends(get_current_user),
):
    """Manually trigger CTI feed ingestion."""
    from app.tasks.cti_tasks import ingest_mycert_feeds
    task = ingest_mycert_feeds.delay()
    return {"task_id": task.id, "status": "QUEUED"}


@router.get("/lookup")
async def lookup_indicator(
    value: str = Query(..., description="IP, domain, URL, or hash to look up"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Look up a specific IOC value in the threat intelligence database.

    Returns the indicator record if found, plus a cross-reference
    against internal assets for immediate triage context.
    """
    from app.db.models import Asset

    # Find the indicator
    result = await db.execute(
        select(CTIIndicator).where(CTIIndicator.value == value.strip())
    )
    indicator = result.scalar_one_or_none()

    # Cross-reference against assets (IP only)
    matched_asset = None
    try:
        asset_result = await db.execute(
            select(Asset).where(Asset.ip_address == value.strip()).limit(1)
        )
        asset = asset_result.scalar_one_or_none()
        if asset:
            matched_asset = {
                "asset_id": str(asset.asset_id),
                "hostname": asset.hostname,
                "ip_address": str(asset.ip_address),
                "criticality_score": asset.criticality_score,
                "is_internet_facing": asset.is_internet_facing,
            }
    except Exception:
        pass  # Non-IP lookups will fail the INET cast — expected

    if indicator:
        return {
            "found": True,
            "indicator": {
                "indicator_id": str(indicator.indicator_id),
                "source": indicator.source,
                "indicator_type": indicator.indicator_type.value,
                "value": indicator.value,
                "confidence_score": float(indicator.confidence_score) if indicator.confidence_score else None,
                "attack_tactic": indicator.attack_tactic,
                "attack_technique": indicator.attack_technique,
                "first_seen": indicator.first_seen.isoformat(),
                "last_seen": indicator.last_seen.isoformat(),
            },
            "matched_internal_asset": matched_asset,
        }

    return {
        "found": False,
        "value": value,
        "matched_internal_asset": matched_asset,
    }


@router.get("/stats")
async def get_cti_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get CTI statistics summary."""
    total = (await db.execute(select(func.count(CTIIndicator.indicator_id)))).scalar()

    # Count by source
    sources = (await db.execute(
        select(CTIIndicator.source, func.count(CTIIndicator.indicator_id))
        .group_by(CTIIndicator.source)
    )).all()

    # Count by type
    types = (await db.execute(
        select(CTIIndicator.indicator_type, func.count(CTIIndicator.indicator_id))
        .group_by(CTIIndicator.indicator_type)
    )).all()

    return {
        "total_indicators": total,
        "by_source": {s: c for s, c in sources},
        "by_type": {t.value if hasattr(t, 'value') else t: c for t, c in types},
    }
