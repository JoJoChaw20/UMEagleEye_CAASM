"""
UMEagleEye - SBOM API routes.
List SBOMs, view dependencies, and retrieve SBOM statistics (FR-02).
"""

from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.dependencies import get_db, get_current_user
from app.db.models import SBOM, Dependency, User
from app.schemas.models import (
    SBOMResponse, SBOMDetailResponse, SBOMListResponse,
    DependencyResponse, DependencyListResponse,
)

router = APIRouter(prefix="/sboms", tags=["SBOM"])


# ───────────────────────────────────────────────────────────────
# List / stats
# ───────────────────────────────────────────────────────────────

@router.get("", response_model=SBOMListResponse)
async def list_sboms(
    page: int = Query(1, ge=1),
    page_size: int = Query(15, ge=1, le=100),
    asset_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all SBOMs with optional asset filter and pagination."""
    query = select(SBOM)
    if asset_id:
        query = query.where(SBOM.asset_id == asset_id)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    query = query.order_by(SBOM.generated_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    sboms = result.scalars().all()

    items = []
    for sbom in sboms:
        resp = SBOMResponse.model_validate(sbom)
        # Resolve component_count from summary or full raw_data
        if sbom.raw_data:
            if "component_count" in sbom.raw_data:
                resp.component_count = sbom.raw_data["component_count"]
            elif "components" in sbom.raw_data:
                resp.component_count = len(sbom.raw_data["components"])
        items.append(resp)

    return SBOMListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get("/stats/summary")
async def get_sbom_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Aggregate SBOM statistics for the dashboard."""
    total_sboms = (await db.execute(select(func.count(SBOM.sbom_id)))).scalar() or 0
    total_deps = (await db.execute(select(func.count(Dependency.dependency_id)))).scalar() or 0

    # Assets with at least one SBOM
    assets_scanned = (await db.execute(
        select(func.count(func.distinct(SBOM.asset_id)))
    )).scalar() or 0

    # Package manager distribution
    pm_rows = (await db.execute(
        select(Dependency.package_manager, func.count(Dependency.dependency_id))
        .group_by(Dependency.package_manager)
        .order_by(func.count(Dependency.dependency_id).desc())
    )).all()
    by_pm = {(pm or "system"): cnt for pm, cnt in pm_rows}

    # Latest SBOM per asset (summary of last scan times)
    latest_scan = (await db.execute(
        select(func.max(SBOM.generated_at))
    )).scalar()

    return {
        "total_sboms": total_sboms,
        "total_dependencies": total_deps,
        "assets_scanned": assets_scanned,
        "by_package_manager": by_pm,
        "latest_scan": latest_scan.isoformat() if latest_scan else None,
    }


# ───────────────────────────────────────────────────────────────
# Single SBOM
# ───────────────────────────────────────────────────────────────

@router.get("/{sbom_id}", response_model=SBOMDetailResponse)
async def get_sbom(
    sbom_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve a single SBOM with full raw data."""
    result = await db.execute(select(SBOM).where(SBOM.sbom_id == sbom_id))
    sbom = result.scalar_one_or_none()
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return sbom


# ───────────────────────────────────────────────────────────────
# Dependencies per SBOM
# ───────────────────────────────────────────────────────────────

@router.get("/{sbom_id}/dependencies", response_model=DependencyListResponse)
async def list_sbom_dependencies(
    sbom_id: UUID,
    package_manager: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(500, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all dependencies for a specific SBOM with optional filtering."""
    query = select(Dependency).where(Dependency.sbom_id == sbom_id)
    if package_manager:
        query = query.where(Dependency.package_manager == package_manager)
    if search:
        query = query.where(Dependency.name.ilike(f"%{search}%"))

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    result = await db.execute(query.order_by(Dependency.name).limit(limit))
    deps = result.scalars().all()

    return DependencyListResponse(
        items=[DependencyResponse.model_validate(d) for d in deps],
        total=total,
    )


# ───────────────────────────────────────────────────────────────
# Asset-scoped helpers (convenience wrappers)
# ───────────────────────────────────────────────────────────────

@router.get("/asset/{asset_id}/sboms", response_model=SBOMListResponse)
async def list_asset_sboms(
    asset_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all SBOMs for a specific asset, newest first."""
    query = select(SBOM).where(SBOM.asset_id == asset_id)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    query = query.order_by(SBOM.generated_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    sboms = result.scalars().all()

    items = []
    for sbom in sboms:
        resp = SBOMResponse.model_validate(sbom)
        if sbom.raw_data:
            if "component_count" in sbom.raw_data:
                resp.component_count = sbom.raw_data["component_count"]
            elif "components" in sbom.raw_data:
                resp.component_count = len(sbom.raw_data["components"])
        items.append(resp)

    return SBOMListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get("/asset/{asset_id}/dependencies", response_model=DependencyListResponse)
async def list_asset_dependencies(
    asset_id: UUID,
    package_manager: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(500, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all dependencies across all SBOMs for an asset."""
    query = select(Dependency).where(Dependency.asset_id == asset_id)
    if package_manager:
        query = query.where(Dependency.package_manager == package_manager)
    if search:
        query = query.where(Dependency.name.ilike(f"%{search}%"))

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    result = await db.execute(query.order_by(Dependency.name).limit(limit))
    deps = result.scalars().all()

    return DependencyListResponse(
        items=[DependencyResponse.model_validate(d) for d in deps],
        total=total,
    )
