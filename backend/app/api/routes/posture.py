"""
UMEagleEye - Posture metrics and executive reporting API routes.
"""

import uuid as uuid_module
from typing import Optional, List, Any
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.dependencies import get_db, get_current_user
from app.db.models import PostureMetrics, User, Asset, Event
from app.db.enums import Severity
from app.schemas.models import PostureMetricsResponse, PostureHistoryResponse

router = APIRouter(prefix="/posture", tags=["Posture"])

DRIFT_TYPES = ["port_opened", "port_closed", "version_downgrade", "config_change", "new_package"]


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
    
    unresolved_drifts = (await db.execute(select(func.count()).select_from(Event).where(Event.event_type.in_(DRIFT_TYPES)))).scalar() or 0

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
    limit: int = Query(14, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get historical posture score snapshots for trendlines."""
    # Always synthesize a full `limit`-day view so the chart always has data.
    # Real PostureMetrics rows are still written by Celery for long-term history,
    # but we compute each day on-the-fly to guarantee a complete trendline.
    now = datetime.now(timezone.utc)
    synthetic = []
    for i in range(limit - 1, -1, -1):
        day_end = (now - timedelta(days=i)).replace(hour=23, minute=59, second=59, microsecond=999999)

        total_assets = (await db.execute(
            select(func.count()).select_from(Asset).where(Asset.created_at <= day_end)
        )).scalar() or 0

        total_critical_assets = (await db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.criticality_score >= 8, Asset.created_at <= day_end
            )
        )).scalar() or 0

        open_critical = (await db.execute(
            select(func.count()).select_from(Event).where(
                Event.severity == Severity.CRITICAL, Event.timestamp <= day_end
            )
        )).scalar() or 0

        open_high = (await db.execute(
            select(func.count()).select_from(Event).where(
                Event.severity == Severity.HIGH, Event.timestamp <= day_end
            )
        )).scalar() or 0

        unresolved_drifts = (await db.execute(
            select(func.count()).select_from(Event).where(
                Event.event_type.in_(DRIFT_TYPES), Event.timestamp <= day_end
            )
        )).scalar() or 0

        score = max(0, min(100,
            100 - min(open_critical * 10, 40) - min(open_high * 5, 20) - min(unresolved_drifts * 3, 20)
        ))

        synthetic.append(PostureMetricsResponse(
            snapshot_id=uuid_module.UUID(int=0),
            overall_score=score,
            total_assets=total_assets,
            total_critical_assets=total_critical_assets,
            open_critical_events=open_critical + open_high,
            top_risks=[],
            timestamp=day_end,
        ))

    return PostureHistoryResponse(items=synthetic)
