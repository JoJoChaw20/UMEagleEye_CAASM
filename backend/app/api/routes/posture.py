"""
UMEagleEye - Posture metrics and executive reporting API routes.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.dependencies import get_db, get_current_user
from app.db.models import PostureMetrics, User
from app.schemas.models import PostureMetricsResponse, PostureHistoryResponse

router = APIRouter(prefix="/posture", tags=["Posture"])


from sqlalchemy import func
from app.db.models import Asset, Event
from app.db.enums import Severity

@router.get("/current", response_model=PostureMetricsResponse)
async def get_current_posture(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the live current posture score snapshot."""
    total_assets = (await db.execute(select(func.count()).select_from(Asset))).scalar()
    total_critical_assets = (await db.execute(select(func.count()).select_from(Asset).where(Asset.criticality_score >= 8))).scalar()
    
    open_critical_events = (await db.execute(
        select(func.count()).select_from(Event).where(Event.severity.in_([Severity.HIGH, Severity.CRITICAL]))
    )).scalar()

    score = 100
    score -= (open_critical_events * 5)
    score -= (total_critical_assets * 2)
    score = max(0, min(100, score))

    return PostureMetricsResponse(
        snapshot_id="00000000-0000-0000-0000-000000000000",
        overall_score=score,
        total_assets=total_assets,
        total_critical_assets=total_critical_assets,
        open_critical_events=open_critical_events,
        top_risks=None,
        timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    )


@router.get("/history", response_model=PostureHistoryResponse)
async def get_posture_history(
    limit: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get historical posture score snapshots for trendlines."""
    result = await db.execute(
        select(PostureMetrics)
        .order_by(PostureMetrics.timestamp.desc())
        .limit(limit)
    )
    snapshots = result.scalars().all()
    return PostureHistoryResponse(
        items=[PostureMetricsResponse.model_validate(s) for s in reversed(list(snapshots))]
    )
