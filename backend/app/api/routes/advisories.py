"""
UMEagleEye - Advisory API routes with lifecycle state transitions (FR-06).
"""

from typing import Optional
from uuid import UUID
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.dependencies import get_db, get_current_user, require_roles
from app.db.models import Advisory, AuditLog, User
from app.db.enums import AdvisoryStatus
from app.schemas.models import AdvisoryResponse, AdvisoryStatusUpdate, AdvisoryListResponse

router = APIRouter(prefix="/advisories", tags=["Advisories"])


@router.get("", response_model=AdvisoryListResponse)
async def list_advisories(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status: Optional[str] = None,
    assigned_to: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all advisories with filtering."""
    query = select(Advisory)

    if status:
        query = query.where(Advisory.status == status)
    if assigned_to:
        query = query.where(Advisory.assigned_to == assigned_to)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    query = query.offset((page - 1) * page_size).limit(page_size)
    query = query.order_by(Advisory.created_at.desc())
    result = await db.execute(query)
    advisories = result.scalars().all()

    return AdvisoryListResponse(
        items=[AdvisoryResponse.model_validate(a) for a in advisories],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.patch("/{advisory_id}/status", response_model=AdvisoryResponse)
async def update_advisory_status(
    advisory_id: UUID,
    payload: AdvisoryStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["tenant_superadmin", "tenant_admin"])),
):
    """Transition an advisory's status with immutable audit logging (FR-06-02)."""
    result = await db.execute(select(Advisory).where(Advisory.advisory_id == advisory_id))
    advisory = result.scalar_one_or_none()
    if not advisory:
        raise HTTPException(status_code=404, detail="Advisory not found")

    previous_status = advisory.status.value

    # Update status
    advisory.status = payload.status
    if payload.assigned_to:
        advisory.assigned_to = payload.assigned_to

    # Set resolved_at if transitioning to resolved
    if payload.status == AdvisoryStatus.RESOLVED:
        advisory.resolved_at = datetime.now(timezone.utc)

    # Immutable audit log entry
    db.add(AuditLog(
        user_id=current_user.user_id,
        action_type="alert_status_changed",
        target_entity=f"advisories/{advisory_id}",
        previous_state={"status": previous_status},
        new_state={"status": payload.status.value},
    ))

    await db.flush()
    await db.refresh(advisory)
    return advisory
