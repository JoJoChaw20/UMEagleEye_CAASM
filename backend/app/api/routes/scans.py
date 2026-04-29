"""
UMEagleEye - Scan API routes for triggering and monitoring discovery scans.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user, require_roles
from app.core.config import settings
from app.db.models import User
from app.schemas.models import ScanRequest, ScanStatusResponse

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/active", response_model=ScanStatusResponse)
async def trigger_active_scan(
    payload: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ops_lead", "security_engineer"])),
):
    """Trigger an active network scan (Nmap/Masscan). Ops Lead or Security Engineer only."""
    from app.tasks.discovery_tasks import run_active_scan

    target = payload.target_subnet or settings.SCAN_DEFAULT_SUBNET
    rate = payload.rate_limit or settings.SCAN_RATE_LIMIT

    task = run_active_scan.delay(
        target_subnet=target,
        scan_type=payload.scan_type,
        rate_limit=rate,
        initiated_by=str(current_user.user_id),
    )

    return ScanStatusResponse(task_id=task.id, status="QUEUED")


@router.post("/passive", response_model=ScanStatusResponse)
async def trigger_passive_scan(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ops_lead", "security_engineer"])),
):
    """Start passive network listener (Scapy). Ops Lead or Security Engineer only."""
    from app.tasks.discovery_tasks import run_passive_scan

    task = run_passive_scan.delay(
        initiated_by=str(current_user.user_id),
    )

    return ScanStatusResponse(task_id=task.id, status="QUEUED")


@router.get("/status/{task_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    task_id: str,
    current_user: User = Depends(get_current_user),
):
    """Check the status of a running scan task."""
    from app.tasks.celery_app import celery_app

    result = celery_app.AsyncResult(task_id)
    response = ScanStatusResponse(
        task_id=task_id,
        status=result.status,
    )
    if result.ready():
        response.result = result.result if isinstance(result.result, dict) else {"message": str(result.result)}

    return response


@router.post("/drift-audit", response_model=ScanStatusResponse)
async def trigger_drift_audit(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ops_lead", "security_engineer"])),
):
    """Trigger a manual drift audit against all baselined assets."""
    from app.tasks.drift_tasks import run_drift_audit

    task = run_drift_audit.delay()

    return ScanStatusResponse(task_id=task.id, status="QUEUED")
