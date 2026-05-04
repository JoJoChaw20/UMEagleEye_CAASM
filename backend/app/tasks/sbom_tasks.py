"""
UMEagleEye - SBOM generation and CVE correlation Celery tasks (FR-02).
Full pipeline: Syft → GCS → Dependencies → Grype → EPSS → NVD → Risk Score.
"""

import json
import logging
import asyncio
import tempfile
import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.sbom import SBOMService
from app.services.vulnerability import VulnerabilityService
from app.db.models import Asset, SBOM, Event, Dependency, CTIIndicator
from app.db.enums import SBOMFormat, EventType, Severity

logger = logging.getLogger(__name__)


def get_sync_session() -> Session:
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


@celery_app.task(name="app.tasks.sbom_tasks.generate_asset_sbom", bind=True)
def generate_asset_sbom(self, asset_id: str, target: str):
    """Generate SBOM for an asset and run full vulnerability correlation pipeline.

    Pipeline:
        1. FR-02-01: Syft SBOM generation → GCS upload
        2. FR-02-02: Parse dependencies → Link to asset in DB
        3. FR-02-03: Grype CVE scan → NVD CWE enrichment
        4. FR-02-04: EPSS scoring → CTI proximity → Composite risk score
    """
    session = get_sync_session()
    try:
        # ── FR-02-01: Generate SBOM via Syft ──
        sbom_data = SBOMService.generate_sbom(target)
        if not sbom_data:
            return {"error": f"Failed to generate SBOM for {target}"}

        # Upload raw SBOM JSON to GCS
        gcs_path = SBOMService.upload_sbom_to_gcs(sbom_data, asset_id)

        # Store SBOM record (lightweight summary in DB, full JSON in GCS)
        component_count = len(sbom_data.get("components", []))
        sbom_summary = {
            "bomFormat": sbom_data.get("bomFormat", "CycloneDX"),
            "specVersion": sbom_data.get("specVersion", "1.5"),
            "serialNumber": sbom_data.get("serialNumber", ""),
            "component_count": component_count,
        }

        sbom = SBOM(
            asset_id=asset_id,
            format=SBOMFormat.CYCLONEDX,
            format_version="1.5",
            raw_data=sbom_summary if gcs_path else sbom_data,
            tool_used="syft",
            gcs_path=gcs_path,
        )
        session.add(sbom)
        session.flush()

        # ── FR-02-02: Parse and link dependencies ──
        deps = SBOMService.parse_dependencies(sbom_data)
        for dep in deps:
            dependency = Dependency(
                asset_id=asset_id,
                sbom_id=sbom.sbom_id,
                name=dep["name"],
                version=dep["version"],
                package_manager=dep.get("package_manager", "system"),
                purl=dep.get("purl", ""),
                licenses=dep.get("licenses", []),
            )
            session.add(dependency)

        session.flush()
        logger.info(f"Linked {len(deps)} dependencies to asset {asset_id}")

        # ── FR-02-03: Run Grype CVE correlation ──
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(sbom_data, f)
            sbom_path = f.name

        try:
            findings = VulnerabilityService.run_grype_scan(sbom_path)
        finally:
            os.unlink(sbom_path)

        if not findings:
            session.commit()
            return {
                "sbom_id": str(sbom.sbom_id),
                "gcs_path": gcs_path,
                "components": len(deps),
                "vulnerabilities": 0,
            }

        # ── FR-02-04: Batch-fetch EPSS scores ──
        # Filter out GHSA IDs as FIRST.org EPSS API only accepts CVE-* format
        cve_ids = [
            f["cve_id"] for f in findings 
            if f["cve_id"] and f["cve_id"].startswith("CVE-")
        ]
        epss_scores = VulnerabilityService.fetch_epss_scores(cve_ids)

        # Get asset for criticality and exposure data
        asset = session.execute(
            select(Asset).where(Asset.asset_id == asset_id)
        ).scalar_one_or_none()

        # Check which CVEs have CTI indicator matches (MyCERT/OTX proximity)
        cti_matched_cves = set()
        try:
            cti_results = session.execute(
                select(CTIIndicator.value).where(
                    CTIIndicator.value.in_(cve_ids)
                )
            ).scalars().all()
            cti_matched_cves = set(cti_results)
        except Exception:
            logger.debug("No CTI CVE matches found (expected for most scans)")

        # ── Create Event records for each CVE finding (with deduplication) ──
        for finding in findings:
            cve_id = finding["cve_id"]
            epss_prob = epss_scores.get(cve_id, 0.0)
            has_cti_match = cve_id in cti_matched_cves

            # Compute composite risk score with new EPSS-weighted formula
            risk_score = VulnerabilityService.compute_composite_risk_score(
                cvss_base_score=finding["cvss_base_score"],
                epss_probability=epss_prob,
                criticality_score=asset.criticality_score if asset else 5,
                has_cti_match=has_cti_match,
            )

            # Determine severity from CVSS or fall back to Grype's textual severity
            severity = Severity.LOW
            if finding["cvss_base_score"] >= 9.0:
                severity = Severity.CRITICAL
            elif finding["cvss_base_score"] >= 7.0:
                severity = Severity.HIGH
            elif finding["cvss_base_score"] >= 4.0:
                severity = Severity.MEDIUM
            elif finding["cvss_base_score"] == 0.0:
                # Fallback to Grype's textual severity
                g_sev = finding.get("severity", "").lower()
                if g_sev == "critical":
                    severity = Severity.CRITICAL
                elif g_sev == "high":
                    severity = Severity.HIGH
                elif g_sev == "medium":
                    severity = Severity.MEDIUM

            # Check for existing open event for this CVE + Package on this asset
            from sqlalchemy import and_
            existing_event = session.execute(
                select(Event).where(
                    and_(
                        Event.asset_id == asset_id,
                        Event.event_type == EventType.CVE_DETECTED,
                        Event.details["cve_id"].astext == cve_id,
                        Event.details["package_name"].astext == finding["package_name"]
                    )
                )
            ).scalar_one_or_none()

            if existing_event:
                # Update existing event
                existing_event.timestamp = datetime.now(timezone.utc)
                existing_event.composite_risk_score = risk_score
                existing_event.severity = severity
                # Update details with fresh EPSS/CTI info
                updated_details = dict(existing_event.details)
                updated_details["epss_score"] = epss_prob
                updated_details["has_cti_match"] = has_cti_match
                existing_event.details = updated_details
                logger.debug(f"Updated existing alert for {cve_id} on asset {asset_id}")
            else:
                # Create new event
                event = Event(
                    asset_id=asset_id,
                    event_type=EventType.CVE_DETECTED,
                    severity=severity,
                    composite_risk_score=risk_score,
                    details={
                        "cve_id": cve_id,
                        "cvss_base_score": finding["cvss_base_score"],
                        "epss_score": epss_prob,
                        "package_name": finding["package_name"],
                        "package_version": finding["package_version"],
                        "fix_versions": finding["fix_versions"],
                        "description": finding["description"][:500],
                        "cwe_ids": finding.get("cwe_ids", []),
                        "has_cti_match": has_cti_match,
                    },
                )
                session.add(event)
                logger.debug(f"Created new alert for {cve_id} on asset {asset_id}")

        session.commit()

        return {
            "sbom_id": str(sbom.sbom_id),
            "gcs_path": gcs_path,
            "components": len(deps),
            "vulnerabilities": len(findings),
            "epss_enriched": len(epss_scores),
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


@celery_app.task(name="app.tasks.sbom_tasks.enrich_nvd_cwe_daily")
def enrich_nvd_cwe_daily():
    """Daily NVD CWE enrichment job (FR-02-03).

    Queries cve_detected events from the last 24h that lack CWE data
    and supplements them with NVD REST API weakness mappings.
    """
    from datetime import timedelta, datetime, timezone

    logger.info("Running daily NVD CWE enrichment")
    session = get_sync_session()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        events = session.execute(
            select(Event).where(
                Event.event_type == EventType.CVE_DETECTED,
                Event.timestamp >= cutoff,
            ).limit(100)
        ).scalars().all()

        enriched = 0
        for event in events:
            cve_id = event.details.get("cve_id", "")
            existing_cwes = event.details.get("cwe_ids", [])

            # Skip if already enriched
            if existing_cwes or not cve_id:
                continue

            nvd_data = loop.run_until_complete(
                VulnerabilityService.fetch_nvd_cwe(cve_id)
            )
            if nvd_data and nvd_data.get("cwe_ids"):
                updated_details = dict(event.details)
                updated_details["cwe_ids"] = nvd_data["cwe_ids"]
                if nvd_data.get("description") and not updated_details.get("description"):
                    updated_details["description"] = nvd_data["description"][:500]
                event.details = updated_details
                enriched += 1

        session.commit()
        logger.info(f"NVD CWE enrichment complete: {enriched}/{len(events)} events enriched")
        return {"status": "complete", "enriched": enriched, "total_checked": len(events)}

    except Exception as e:
        session.rollback()
        logger.error(f"NVD CWE enrichment error: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        session.close()
        loop.close()
