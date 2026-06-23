"""
UMEagleEye - Asset Relationship Graph API routes.
Provides endpoints for graph retrieval, blast-radius analysis,
relationship inference, and manual relationship CRUD.
"""

from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.core.dependencies import get_db, get_current_user, require_roles
from app.db.models import Asset, AssetRelationship, User
from app.db.enums import RelationshipType
from app.schemas.models import (
    AssetRelationshipCreate, AssetRelationshipResponse,
    AssetGraphResponse, BlastRadiusResponse,
)

router = APIRouter(prefix="/relationships", tags=["Asset Relationships"])


@router.get("/graph", response_model=AssetGraphResponse)
async def get_asset_graph(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the full asset relationship graph for visualisation."""
    from app.services.relationship import RelationshipService
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app.core.config import settings

    # Use sync session for the service (which uses sync SQLAlchemy)
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    session = Session(engine)
    try:
        result = RelationshipService.get_asset_graph(session)
        return result
    finally:
        session.close()


@router.get("/graph/{asset_id}", response_model=AssetGraphResponse)
async def get_asset_subgraph(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a subgraph centered on a specific asset."""
    from app.services.relationship import RelationshipService
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app.core.config import settings

    # Verify asset exists
    result = await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    session = Session(engine)
    try:
        graph = RelationshipService.get_asset_graph(session, asset_id=asset_id)
        return graph
    finally:
        session.close()


@router.get("/blast-radius/{asset_id}", response_model=BlastRadiusResponse)
async def get_blast_radius(
    asset_id: UUID,
    max_depth: int = Query(3, ge=1, le=10),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Compute blast-radius estimation for a specific asset.

    Returns all downstream assets that would be affected if
    the given asset were compromised, up to max_depth hops.
    """
    from app.services.relationship import RelationshipService
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app.core.config import settings

    # Verify asset exists
    result = await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    session = Session(engine)
    try:
        blast = RelationshipService.compute_blast_radius(
            session, asset_id, max_depth=max_depth
        )
        return blast
    finally:
        session.close()


@router.post("/infer")
async def trigger_inference(
    current_user: User = Depends(require_roles(["tenant_superadmin", "tenant_admin"])),
):
    """Run relationship inference synchronously and return the result."""
    from app.services.relationship import RelationshipService
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from app.core.config import settings

    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    session = Session(engine)
    try:
        result = RelationshipService.infer_relationships(session)
        return {
            "message": f"Inferred {result['new_relationships']} new relationships ({result['total_relationships']} total)",
            "new_relationships": result["new_relationships"],
            "total_relationships": result["total_relationships"],
            "total_assets": result["total_assets"],
        }
    finally:
        session.close()


@router.post("", response_model=AssetRelationshipResponse, status_code=status.HTTP_201_CREATED)
async def create_relationship(
    payload: AssetRelationshipCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["tenant_superadmin", "tenant_admin"])),
):
    """Manually create an asset relationship."""
    # Verify both assets exist
    for aid in [payload.source_asset_id, payload.target_asset_id]:
        result = await db.execute(select(Asset).where(Asset.asset_id == aid))
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail=f"Asset {aid} not found")

    # Check for duplicates
    existing = await db.execute(
        select(AssetRelationship).where(
            AssetRelationship.source_asset_id == payload.source_asset_id,
            AssetRelationship.target_asset_id == payload.target_asset_id,
            AssetRelationship.relationship_type == payload.relationship_type,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Relationship already exists")

    rel = AssetRelationship(
        source_asset_id=payload.source_asset_id,
        target_asset_id=payload.target_asset_id,
        relationship_type=RelationshipType(payload.relationship_type),
        metadata_json=payload.metadata_json,
        confidence=payload.confidence or 1.0,
    )
    db.add(rel)
    await db.flush()
    await db.refresh(rel)
    return rel


@router.delete("/{relationship_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_relationship(
    relationship_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["tenant_superadmin"])),
):
    """Delete an asset relationship. Ops Lead only."""
    result = await db.execute(
        select(AssetRelationship).where(
            AssetRelationship.relationship_id == relationship_id
        )
    )
    rel = result.scalar_one_or_none()
    if not rel:
        raise HTTPException(status_code=404, detail="Relationship not found")
    await db.delete(rel)
