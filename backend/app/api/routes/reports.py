"""
UMEagleEye - Reports API routes (FR-08).
"""

import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, get_current_user, require_roles, get_current_user_for_download
from app.db.models import User

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("/generate")
async def generate_report(
    report_type: str = "weekly",
    current_user: User = Depends(require_roles(["tenant_superadmin", "tenant_admin"])),
):
    """Trigger async PDF report generation (FR-08-02)."""
    from app.tasks.report_tasks import generate_pdf_report
    task = generate_pdf_report.delay(report_type=report_type)
    return {"task_id": task.id, "status": "QUEUED", "report_type": report_type}


@router.post("/snapshot")
async def trigger_posture_snapshot(
    current_user: User = Depends(require_roles(["tenant_superadmin", "tenant_admin"])),
):
    """Trigger an immediate posture score snapshot."""
    from app.tasks.report_tasks import generate_posture_snapshot
    task = generate_posture_snapshot.delay()
    return {"task_id": task.id, "status": "QUEUED"}


@router.get("/list")
async def list_reports(
    current_user: User = Depends(get_current_user),
):
    """List available PDF reports."""
    report_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "reports"))
    if not os.path.exists(report_dir):
        return {"reports": []}

    reports = []
    for f in sorted(os.listdir(report_dir), reverse=True):
        if f.endswith(".pdf"):
            filepath = os.path.join(report_dir, f)
            reports.append({
                "filename": f,
                "size_bytes": os.path.getsize(filepath),
                "created": os.path.getctime(filepath),
            })

    return {"reports": reports[:20]}


@router.get("/download/{filename}")
async def download_report(
    filename: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_for_download),
):
    """Download a generated PDF report (FR-08-03). Supports ?token= query param."""
    # Check roles manually
    if current_user.role.value not in ["superadmin", "tenant_superadmin", "tenant_admin", "business_owner"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    report_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "reports"))
    filepath = os.path.join(report_dir, filename)

    if not os.path.exists(filepath) or not filename.endswith(".pdf"):
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(
        filepath,
        media_type="application/pdf",
        filename=filename,
    )
