"""
UMEagleEye - Drift detection Celery tasks (FR-03-02).
Pushes drift alerts to Telegram within 5 minutes of detection.
"""

import logging
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.drift import DriftService
from app.services.telegram_notifier import notify_drift_event, notify_pdpa_violation
from app.db.models import Asset, Event

logger = logging.getLogger(__name__)


def get_sync_session() -> Session:
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


@celery_app.task(name="app.tasks.drift_tasks.run_drift_audit")
def run_drift_audit():
    """Compare all baselined assets against current state and generate drift events.
    Pushes Telegram alerts within 5 minutes of detection (FR-05-03).
    """
    session = get_sync_session()
    try:
        result = session.execute(
            select(Asset).where(Asset.baseline_state.isnot(None))
        )
        assets = result.scalars().all()

        total_drifts = 0
        for asset in assets:
            baseline_data = asset.baseline_state
            baseline_state = baseline_data.get("os_info") if baseline_data else {}
            current_state = asset.os_info or {}

            drift_events = DriftService.compute_drift(
                baseline=baseline_state,
                current_state=current_state,
                asset_id=str(asset.asset_id),
            )

            for drift in drift_events:
                event = Event(
                    asset_id=asset.asset_id,
                    event_type=drift["event_type"],
                    severity=drift["severity"],
                    details=drift["details"],
                )
                session.add(event)
                total_drifts += 1

                # ── Telegram push within task (≤5 min detection window) ──
                details = drift.get("details", {})
                notify_drift_event(
                    asset_ip=str(asset.ip_address),
                    asset_hostname=asset.hostname or "",
                    event_type=drift["event_type"].value if hasattr(drift["event_type"], "value") else str(drift["event_type"]),
                    severity=drift["severity"].value if hasattr(drift["severity"], "value") else str(drift["severity"]),
                    changed_attribute=details.get("attribute", details.get("action", "configuration")),
                    previous_value=str(details.get("baseline_value", details.get("previous", "N/A"))),
                    new_value=str(details.get("current_value", details.get("new", "N/A"))),
                    evidence=details,
                )

                # ── PDPA compliance check ──
                # If a previously compliant asset loses TLS, auth, or gains critical CVE
                _check_pdpa_violation(asset, drift, session)

        session.commit()
        logger.info(f"Drift audit complete: {total_drifts} events across {len(assets)} baselined assets")
        return {"total_drifts": total_drifts, "assets_audited": len(assets)}

    except Exception as e:
        session.rollback()
        logger.error(f"Drift audit error: {e}")
        raise
    finally:
        session.close()


def _check_pdpa_violation(asset, drift: dict, session: Session):
    """Detect PDPA compliance drift and trigger immediate Critical notification."""
    details = drift.get("details", {})
    event_type = str(drift.get("event_type", ""))

    # PDPA-relevant triggers: TLS expiry, auth disabled, new critical CVE, config change
    pdpa_triggers = {
        "tls_expiry": "TLS certificate expired or will expire within 7 days",
        "auth_disabled": "Authentication/access control has been disabled",
        "cve_detected": "New Critical CVE detected on a previously compliant asset",
        "config_change": "Security configuration changed on a sensitive asset",
        "port_opened": "New port opened on asset (potential unauthorized access vector)",
    }

    triggered_control = None
    for trigger_key, description in pdpa_triggers.items():
        if trigger_key in event_type.lower():
            triggered_control = description
            break

    # Also check severity — only alert on Critical/High for PDPA
    severity = str(drift.get("severity", "")).lower()
    if triggered_control and severity in ("critical", "high") and asset.baseline_state:
        notify_pdpa_violation(
            asset_ip=str(asset.ip_address),
            asset_hostname=asset.hostname or "",
            control_lost=triggered_control,
            details=str(details)[:300],
        )
        logger.warning(f"PDPA violation triggered for {asset.ip_address}: {triggered_control}")
