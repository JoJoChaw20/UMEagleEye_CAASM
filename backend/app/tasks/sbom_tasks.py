"""
UMEagleEye - SBOM generation and CVE correlation Celery tasks (FR-02).
"""

import json
import logging
import tempfile
import os
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.sbom import SBOMService
from app.services.vulnerability import VulnerabilityService
from app.db.models import Asset, SBOM, Event
from app.db.enums import SBOMFormat, EventType, Severity

logger = logging.getLogger(__name__)


def get_sync_session() -> Session:
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


@celery_app.task(name="app.tasks.sbom_tasks.generate_asset_sbom", bind=True)
def generate_asset_sbom(self, asset_id: str, target: str):
    """Generate SBOM for an asset and run vulnerability correlation."""
    session = get_sync_session()
    try:
        # Generate SBOM via Syft
        sbom_data = SBOMService.generate_sbom(target)
        if not sbom_data:
            return {"error": f"Failed to generate SBOM for {target}"}

        # Store SBOM record
        sbom = SBOM(
            asset_id=asset_id,
            format=SBOMFormat.CYCLONEDX,
            format_version="1.5",
            raw_data=sbom_data,
            tool_used="syft",
        )
        session.add(sbom)
        session.flush()

        # Write SBOM to temp file for Grype
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(sbom_data, f)
            sbom_path = f.name

        try:
            # Run Grype CVE correlation
            findings = VulnerabilityService.run_grype_scan(sbom_path)

            # Get asset for risk scoring
            asset = session.execute(
                select(Asset).where(Asset.asset_id == asset_id)
            ).scalar_one_or_none()

            # Create Event records for each CVE finding
            for finding in findings:
                risk_score = VulnerabilityService.compute_composite_risk_score(
                    cvss_base_score=finding["cvss_base_score"],
                    is_internet_facing=asset.is_internet_facing if asset else False,
                    criticality_score=asset.criticality_score if asset else 5,
                    has_drift=False,
                )

                severity = Severity.LOW
                if finding["cvss_base_score"] >= 9.0:
                    severity = Severity.CRITICAL
                elif finding["cvss_base_score"] >= 7.0:
                    severity = Severity.HIGH
                elif finding["cvss_base_score"] >= 4.0:
                    severity = Severity.MEDIUM

                event = Event(
                    asset_id=asset_id,
                    event_type=EventType.CVE_DETECTED,
                    severity=severity,
                    composite_risk_score=risk_score,
                    details={
                        "cve_id": finding["cve_id"],
                        "cvss_base_score": finding["cvss_base_score"],
                        "package_name": finding["package_name"],
                        "package_version": finding["package_version"],
                        "fix_versions": finding["fix_versions"],
                        "description": finding["description"][:500],
                    },
                )
                session.add(event)

        finally:
            os.unlink(sbom_path)

        session.commit()

        deps = SBOMService.parse_dependencies(sbom_data)
        return {
            "sbom_id": str(sbom.sbom_id),
            "components": len(deps),
            "vulnerabilities": len(findings),
        }

    except Exception as e:
        session.rollback()
        logger.error(f"SBOM generation error: {e}")
        raise
    finally:
        session.close()


@celery_app.task(name="app.tasks.sbom_tasks.update_nvd_cves")
def update_nvd_cves():
    """Daily NVD CVE database update job."""
    logger.info("Running daily NVD CVE update")
    # Grype updates its own DB
    import subprocess
    try:
        subprocess.run(["grype", "db", "update"], capture_output=True, timeout=300)
        logger.info("Grype vulnerability database updated")
        return {"status": "updated"}
    except Exception as e:
        logger.error(f"NVD update error: {e}")
        return {"status": "error", "message": str(e)}
