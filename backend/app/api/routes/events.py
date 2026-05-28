"""
UMEagleEye - Events API routes for querying drift and security alerts.
"""

from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.core.dependencies import get_db, get_current_user
from app.db.models import Event, Asset, User
from app.db.enums import Severity, EventType
from app.schemas.models import EventResponse, EventListResponse

router = APIRouter(prefix="/events", tags=["Events"])


@router.get("", response_model=EventListResponse)
async def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    asset_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all events with filtering and pagination."""
    query = select(Event)

    if severity:
        try:
            query = query.where(Event.severity == Severity(severity))
        except ValueError:
            pass
    if event_type:
        try:
            query = query.where(Event.event_type == EventType(event_type))
        except ValueError:
            pass
    if asset_id:
        query = query.where(Event.asset_id == asset_id)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    query = (
        query
        .options(selectinload(Event.asset))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .order_by(Event.timestamp.desc())
    )
    result = await db.execute(query)
    events = result.scalars().all()

    items = []
    for evt in events:
        resp = EventResponse(
            event_id=evt.event_id,
            asset_id=evt.asset_id,
            asset_hostname=evt.asset.hostname if evt.asset else None,
            asset_ip=str(evt.asset.ip_address) if (evt.asset and evt.asset.ip_address) else None,
            event_type=evt.event_type,
            severity=evt.severity,
            details=evt.details,
            composite_risk_score=float(evt.composite_risk_score) if evt.composite_risk_score is not None else None,
            timestamp=evt.timestamp,
        )
        items.append(resp)

    return EventListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{event_id}", response_model=EventResponse)
async def get_event(
    event_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single event by ID."""
    result = await db.execute(
        select(Event).options(selectinload(Event.asset)).where(Event.event_id == event_id)
    )
    evt = result.scalar_one_or_none()
    if not evt:
        raise HTTPException(status_code=404, detail="Event not found")
    return EventResponse(
        event_id=evt.event_id,
        asset_id=evt.asset_id,
        asset_hostname=evt.asset.hostname if evt.asset else None,
        asset_ip=str(evt.asset.ip_address) if (evt.asset and evt.asset.ip_address) else None,
        event_type=evt.event_type,
        severity=evt.severity,
        details=evt.details,
        composite_risk_score=float(evt.composite_risk_score) if evt.composite_risk_score is not None else None,
        timestamp=evt.timestamp,
    )


@router.post("/{event_id}/advisory", status_code=202)
async def trigger_event_advisory(
    event_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Trigger AI advisory generation for a specific event."""
    from app.tasks.advisory_tasks import generate_advisory

    # Verify event exists
    result = await db.execute(select(Event).where(Event.event_id == event_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Event not found")

    task = generate_advisory.delay(
        str(event_id), 
        triggered_by_chat_id=current_user.telegram_chat_id
    )
    return {"task_id": task.id, "status": "QUEUED"}


@router.get("/stats/summary")
async def get_event_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get aggregate event statistics for the Alerts dashboard."""
    from datetime import timedelta, datetime, timezone
    from app.db.models import Advisory
    from app.db.enums import AdvisoryStatus

    # Total events
    total = (await db.execute(select(func.count(Event.event_id)))).scalar() or 0

    # By severity
    severity_counts = {}
    for sev in Severity:
        count = (await db.execute(
            select(func.count(Event.event_id)).where(Event.severity == sev)
        )).scalar() or 0
        severity_counts[sev.value] = count

    # By event type
    type_counts = {}
    for etype in EventType:
        count = (await db.execute(
            select(func.count(Event.event_id)).where(Event.event_type == etype)
        )).scalar() or 0
        if count > 0:
            type_counts[etype.value] = count

    # Average risk score
    avg_score = (await db.execute(
        select(func.avg(Event.composite_risk_score)).where(
            Event.composite_risk_score.isnot(None)
        )
    )).scalar()

    # Resolution rate (advisories resolved / total)
    total_advisories = (await db.execute(
        select(func.count(Advisory.advisory_id))
    )).scalar() or 0
    resolved_advisories = (await db.execute(
        select(func.count(Advisory.advisory_id)).where(
            Advisory.status == AdvisoryStatus.RESOLVED
        )
    )).scalar() or 0
    resolution_rate = (resolved_advisories / total_advisories * 100) if total_advisories > 0 else 100

    # Daily trend (last 7 days)
    daily_trend = []
    for i in range(6, -1, -1):
        day_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        day_count = (await db.execute(
            select(func.count(Event.event_id)).where(
                Event.timestamp >= day_start,
                Event.timestamp < day_end,
            )
        )).scalar() or 0
        daily_trend.append({
            "date": day_start.strftime("%b %d"),
            "count": day_count,
        })

    return {
        "total_alerts": total,
        "by_severity": severity_counts,
        "by_type": type_counts,
        "avg_risk_score": round(float(avg_score), 1) if avg_score else 0,
        "resolution_rate": round(resolution_rate, 1),
        "daily_trend": daily_trend,
    }
