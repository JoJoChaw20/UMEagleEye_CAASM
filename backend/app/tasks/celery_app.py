"""
UMEagleEye - Celery application instance and configuration.
"""

from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

celery_app = Celery(
    "umeagleeye",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Kuala_Lumpur",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,

    # Auto-discover tasks in these modules
    include=[
        "app.tasks.discovery_tasks",
        "app.tasks.sbom_tasks",
        "app.tasks.drift_tasks",
        "app.tasks.cti_tasks",
        "app.tasks.advisory_tasks",
        "app.tasks.report_tasks",
        "app.tasks.sla_tasks",
    ],
)

# ── Celery Beat Schedule (periodic tasks) ──
celery_app.conf.beat_schedule = {
    # Discovery cycle every 15 minutes (configurable)
    "periodic-active-scan": {
        "task": "app.tasks.discovery_tasks.run_scheduled_scan",
        "schedule": settings.DISCOVERY_CYCLE_MINUTES * 60,  # seconds
        "args": (),
    },
    # Drift auditing after each scan cycle
    "periodic-drift-audit": {
        "task": "app.tasks.drift_tasks.run_drift_audit",
        "schedule": (settings.DISCOVERY_CYCLE_MINUTES + 2) * 60,
        "args": (),
    },
    # Daily CTI ingestion from MyCERT
    "daily-cti-ingestion": {
        "task": "app.tasks.cti_tasks.ingest_mycert_feeds",
        "schedule": crontab(hour=6, minute=0),  # Daily at 6 AM MYT
        "args": (),
    },
    # Daily NVD CVE update
    "daily-nvd-update": {
        "task": "app.tasks.sbom_tasks.update_nvd_cves",
        "schedule": crontab(hour=7, minute=0),
        "args": (),
    },
    # SLA monitoring every 30 minutes
    "sla-monitor": {
        "task": "app.tasks.sla_tasks.check_sla_breaches",
        "schedule": 1800,
        "args": (),
    },
    # Daily posture snapshot
    "daily-posture-snapshot": {
        "task": "app.tasks.report_tasks.generate_posture_snapshot",
        "schedule": crontab(hour=0, minute=0),
        "args": (),
    },
}
