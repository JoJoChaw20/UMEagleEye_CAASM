"""
UMEagleEye - Asset CRUD API routes with Golden Image baseline management.
"""

from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.dependencies import get_db, get_current_user, require_roles
from app.db.models import Asset, AuditLog, User
from app.schemas.models import (
    AssetCreate, AssetUpdate, AssetResponse, AssetListResponse, BaselineSetRequest, SBOMScanRequest
)

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=AssetListResponse)
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    device_type: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all assets with pagination and filtering."""
    query = select(Asset)

    if device_type:
        query = query.where(Asset.device_type == device_type)
    if search:
        query = query.where(
            (Asset.hostname.ilike(f"%{search}%")) |
            (Asset.ip_address.cast(String).ilike(f"%{search}%"))
        )

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    # Paginate
    query = query.offset((page - 1) * page_size).limit(page_size)
    query = query.order_by(Asset.updated_at.desc())
    result = await db.execute(query)
    assets = result.scalars().all()

    return AssetListResponse(
        items=[AssetResponse.model_validate(a) for a in assets],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single asset by ID."""
    result = await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ops_lead", "security_engineer"])),
):
    """Manually create a new asset record."""
    asset = Asset(**payload.model_dump())
    db.add(asset)
    await db.flush()
    await db.refresh(asset)
    return asset


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: UUID,
    payload: AssetUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ops_lead", "security_engineer"])),
):
    """Update asset attributes."""
    result = await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(asset, key, value)

    await db.flush()
    await db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ops_lead"])),
):
    """Delete an asset record. Ops Lead only."""
    result = await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    await db.delete(asset)


@router.post("/{asset_id}/baseline", response_model=AssetResponse)
async def set_baseline(
    asset_id: UUID,
    payload: BaselineSetRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ops_lead", "security_engineer"])),
):
    """Capture the current state as the Golden Image baseline (FR-03-01).
    Requires explicit confirmation to overwrite existing baseline."""
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Confirm must be True to set baseline")

    result = await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    previous_baseline = asset.baseline_state

    # Build baseline from current state
    baseline = {
        "hostname": asset.hostname,
        "ip_address": str(asset.ip_address),
        "os_info": asset.os_info,
        "device_type": asset.device_type.value if asset.device_type else None,
        "captured_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "captured_by": str(current_user.user_id),
    }
    asset.baseline_state = baseline

    # Audit log
    db.add(AuditLog(
        user_id=current_user.user_id,
        action_type="baseline_modified",
        target_entity=f"assets/{asset_id}",
        previous_state=previous_baseline,
        new_state=baseline,
    ))

    await db.flush()
    await db.refresh(asset)
    return asset


@router.get("/{asset_id}/baseline", response_model=dict)
async def get_baseline(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the Golden Image baseline for an asset."""
    result = await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not asset.baseline_state:
        raise HTTPException(status_code=404, detail="No baseline set for this asset")
    return asset.baseline_state


@router.post("/{asset_id}/scan-sbom", status_code=status.HTTP_202_ACCEPTED)
async def scan_asset_sbom(
    asset_id: UUID,
    payload: SBOMScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ops_lead", "security_engineer"])),
):
    """Trigger an async SBOM generation and vulnerability scan for an asset (FR-02)."""
    from app.tasks.sbom_tasks import generate_asset_sbom

    # Verify asset exists
    result = await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    task = generate_asset_sbom.delay(
        asset_id=str(asset_id),
        target=payload.target
    )

    return {"task_id": task.id, "status": "QUEUED"}
