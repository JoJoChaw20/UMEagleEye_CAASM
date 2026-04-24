"""
UMEagleEye - Posture Metrics Service (FR-08-01).
Score calculation and weekly metrics aggregation.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timezone
from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from app.db.models import Asset, Event, Advisory, PostureMetrics
from app.db.enums import Severity, AdvisoryStatus

logger = logging.getLogger(__name__)


class PostureService:
    """Posture score calculation and metrics aggregation."""

    @staticmethod
    def compute_posture_score(session: Session) -> Dict[str, Any]:
        """Compute the overall security posture score (0-100).

        Formula:
            score = 100 - (critical_penalty + high_penalty + drift_penalty + sla_penalty)
            critical_penalty = open_critical_events × 10 (capped at 40)
            high_penalty     = open_high_events × 5 (capped at 20)
            drift_penalty    = unresolved_drifts × 3 (capped at 20)
            sla_penalty      = sla_breaches × 5 (capped at 20)
        """
        # Count open critical events
        open_critical = session.execute(
            select(func.count(Event.event_id)).where(
                Event.severity == Severity.CRITICAL,
            )
        ).scalar() or 0

        # Count open high events
        open_high = session.execute(
            select(func.count(Event.event_id)).where(
                Event.severity == Severity.HIGH,
            )
        ).scalar() or 0

        # Count unresolved drift events
        drift_types = ["port_opened", "port_closed", "version_downgrade", "config_change", "new_package"]
        unresolved_drifts = session.execute(
            select(func.count(Event.event_id)).where(
                Event.event_type.in_(drift_types),
            )
        ).scalar() or 0

        # Count SLA breaches (Critical advisories still open)
        sla_breaches = session.execute(
            select(func.count(Advisory.advisory_id)).where(
                and_(
                    Advisory.status == AdvisoryStatus.OPEN,
                )
            )
        ).scalar() or 0

        # Calculate penalties
        critical_penalty = min(open_critical * 10, 40)
        high_penalty = min(open_high * 5, 20)
        drift_penalty = min(unresolved_drifts * 3, 20)
        sla_penalty_val = min(sla_breaches * 5, 20)

        score = max(0, min(100, 100 - critical_penalty - high_penalty - drift_penalty - sla_penalty_val))

        # Asset counts
        total_assets = session.execute(select(func.count(Asset.asset_id))).scalar() or 0
        critical_assets = session.execute(
            select(func.count(Asset.asset_id)).where(Asset.criticality_score >= 8)
        ).scalar() or 0

        # Top risks
        top_events = session.execute(
            select(Event).where(
                Event.severity.in_([Severity.CRITICAL, Severity.HIGH])
            ).order_by(Event.composite_risk_score.desc().nullslast()).limit(5)
        ).scalars().all()

        top_risks = [
            {
                "event_type": e.event_type.value,
                "severity": e.severity.value,
                "risk_score": float(e.composite_risk_score) if e.composite_risk_score else 0,
                "details": {k: str(v)[:100] for k, v in (e.details or {}).items()},
            }
            for e in top_events
        ]

        return {
            "overall_score": score,
            "total_assets": total_assets,
            "total_critical_assets": critical_assets,
            "open_critical_events": open_critical + open_high,
            "top_risks": top_risks,
            "breakdown": {
                "critical_penalty": critical_penalty,
                "high_penalty": high_penalty,
                "drift_penalty": drift_penalty,
                "sla_penalty": sla_penalty_val,
            },
        }

    @staticmethod
    def aggregate_weekly_metrics(session: Session) -> Dict[str, Any]:
        """Aggregate weekly data for executive reporting (FR-08-01).

        Returns JSON payload with: total assets, drift events, top CVEs, SLA rate.
        """
        from datetime import timedelta
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)

        total_assets = session.execute(select(func.count(Asset.asset_id))).scalar() or 0

        # Weekly drift events
        drift_count = session.execute(
            select(func.count(Event.event_id)).where(
                Event.timestamp >= week_ago,
            )
        ).scalar() or 0

        # Top CVEs this week
        cve_events = session.execute(
            select(Event).where(
                and_(Event.event_type == "cve_detected", Event.timestamp >= week_ago)
            ).order_by(Event.composite_risk_score.desc().nullslast()).limit(5)
        ).scalars().all()

        top_cves = [
            {
                "cve_id": e.details.get("cve_id", "Unknown"),
                "cvss": e.details.get("cvss_base_score", 0),
                "package": e.details.get("package_name", ""),
            }
            for e in cve_events
        ]

        # SLA resolution rate
        total_advisories = session.execute(
            select(func.count(Advisory.advisory_id)).where(
                Advisory.created_at >= week_ago,
            )
        ).scalar() or 0

        resolved_advisories = session.execute(
            select(func.count(Advisory.advisory_id)).where(
                and_(Advisory.created_at >= week_ago, Advisory.status == AdvisoryStatus.RESOLVED)
            )
        ).scalar() or 0

        sla_rate = (resolved_advisories / total_advisories * 100) if total_advisories > 0 else 100

        return {
            "period": "weekly",
            "total_assets": total_assets,
            "drift_events": drift_count,
            "top_cves": top_cves,
            "sla_resolution_rate": round(sla_rate, 1),
            "total_advisories": total_advisories,
            "resolved_advisories": resolved_advisories,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
