"""
UMEagleEye - Report generation and posture snapshot Celery tasks (FR-08).
"""

import logging
import os
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.posture import PostureService
from app.services.report import ReportService
from app.db.models import PostureMetrics

logger = logging.getLogger(__name__)


def get_sync_session() -> Session:
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


@celery_app.task(name="app.tasks.report_tasks.generate_posture_snapshot")
def generate_posture_snapshot():
    """Daily posture metric snapshot stored in the database."""
    session = get_sync_session()
    try:
        posture = PostureService.compute_posture_score(session)

        snapshot = PostureMetrics(
            overall_score=posture["overall_score"],
            total_assets=posture["total_assets"],
            total_critical_assets=posture["total_critical_assets"],
            open_critical_events=posture["open_critical_events"],
            top_risks=posture.get("top_risks"),
        )
        session.add(snapshot)
        session.commit()

        logger.info(f"Posture snapshot saved: score={posture['overall_score']}")
        return {
            "status": "saved",
            "score": posture["overall_score"],
            "snapshot_id": str(snapshot.snapshot_id),
        }

    except Exception as e:
        session.rollback()
        logger.error(f"Posture snapshot error: {e}")
        raise
    finally:
        session.close()


@celery_app.task(name="app.tasks.report_tasks.generate_pdf_report", bind=True)
def generate_pdf_report(self, report_type: str = "weekly"):
    """Generate PDF posture report and save to local storage / GCS (FR-08-02, FR-08-03)."""
    session = get_sync_session()
    try:
        posture = PostureService.compute_posture_score(session)
        metrics = PostureService.aggregate_weekly_metrics(session)

        # Generate PDF
        pdf_bytes = ReportService.generate_posture_pdf(posture, metrics)

        # Save locally
        report_dir = os.path.join(os.path.dirname(__file__), "..", "..", "data", "reports")
        os.makedirs(report_dir, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"umeagleeye_{report_type}_report_{timestamp}.pdf"
        filepath = os.path.join(report_dir, filename)

        with open(filepath, "wb") as f:
            f.write(pdf_bytes)

        logger.info(f"PDF report generated: {filepath} ({len(pdf_bytes)} bytes)")

        # Try GCS upload if configured
        gcs_path = None
        if settings.GCS_SERVICE_ACCOUNT_KEY and settings.GCS_BUCKET_NAME:
            try:
                gcs_path = _upload_to_gcs(pdf_bytes, filename)
            except Exception as e:
                logger.warning(f"GCS upload failed (using local storage): {e}")

        return {
            "status": "generated",
            "filename": filename,
            "local_path": filepath,
            "gcs_path": gcs_path,
            "size_bytes": len(pdf_bytes),
            "posture_score": posture["overall_score"],
        }

    except Exception as e:
        logger.error(f"Report generation error: {e}")
        raise
    finally:
        session.close()


def _upload_to_gcs(pdf_bytes: bytes, filename: str) -> str:
    """Upload PDF to Google Cloud Storage (FR-08-03)."""
    try:
        from google.cloud import storage

        client = storage.Client()
        bucket = client.bucket(settings.GCS_BUCKET_NAME)
        blob = bucket.blob(f"reports/{filename}")
        blob.upload_from_string(pdf_bytes, content_type="application/pdf")

        # Generate signed URL (1 hour expiry)
        url = blob.generate_signed_url(expiration=3600)
        logger.info(f"Report uploaded to GCS: {url}")
        return url

    except Exception as e:
        logger.error(f"GCS upload error: {e}")
        raise
