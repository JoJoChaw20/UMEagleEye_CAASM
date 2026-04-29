"""
UMEagleEye - Posture metrics and executive reporting API routes.
"""

from typing import Optional, List, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timezone

from app.core.dependencies import get_db, get_current_user
from app.db.models import PostureMetrics, User, Asset, Event
from app.db.enums import Severity
from app.schemas.models import PostureMetricsResponse, PostureHistoryResponse

router = APIRouter(prefix="/posture", tags=["Posture"])


@router.get("/current", response_model=PostureMetricsResponse)
async def get_current_posture(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the live current posture score snapshot (FR-08-01)."""
    total_assets = (await db.execute(select(func.count()).select_from(Asset))).scalar() or 0
    total_critical_assets = (await db.execute(select(func.count()).select_from(Asset).where(Asset.criticality_score >= 8))).scalar() or 0
    
    open_critical = (await db.execute(select(func.count()).select_from(Event).where(Event.severity == Severity.CRITICAL))).scalar() or 0
    open_high = (await db.execute(select(func.count()).select_from(Event).where(Event.severity == Severity.HIGH))).scalar() or 0
    
    drift_types = ["port_opened", "port_closed", "version_downgrade", "config_change", "new_package"]
    unresolved_drifts = (await db.execute(select(func.count()).select_from(Event).where(Event.event_type.in_(drift_types)))).scalar() or 0

    # Penalties (matching PostureService)
    critical_penalty = min(open_critical * 10, 40)
    high_penalty = min(open_high * 5, 20)
    drift_penalty = min(unresolved_drifts * 3, 20)
    
    score = max(0, min(100, 100 - critical_penalty - high_penalty - drift_penalty))

    return PostureMetricsResponse(
        snapshot_id="00000000-0000-0000-0000-000000000000",
        overall_score=score,
        total_assets=total_assets,
        total_critical_assets=total_critical_assets,
        open_critical_events=open_critical + open_high,
        top_risks=[],
        timestamp=datetime.now(timezone.utc),
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
