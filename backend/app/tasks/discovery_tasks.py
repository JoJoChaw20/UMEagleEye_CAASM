"""
UMEagleEye - Discovery Celery tasks for async scan orchestration.
"""

import logging
from datetime import datetime, timezone
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.tasks.celery_app import celery_app
from app.core.config import settings
from app.services.discovery import DiscoveryService
from app.db.models import Asset
from app.db.enums import DeviceType
from app.db.database import Base

logger = logging.getLogger(__name__)


def get_sync_session() -> Session:
    """Create a synchronous DB session for Celery workers."""
    engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)
    return Session(engine)


def upsert_discovered_assets(hosts: list, session: Session) -> dict:
    """Insert or update assets in the database from scan results.

    Returns summary dict with counts of new/updated assets.
    """
    new_count = 0
    updated_count = 0

    for host in hosts:
        ip = host.get("ip_address")
        if not ip:
            continue

        existing = session.execute(
            select(Asset).where(Asset.ip_address == ip)
        ).scalar_one_or_none()

        if existing:
            # Update existing asset
            if host.get("hostname"):
                existing.hostname = host["hostname"]
            if host.get("mac_address"):
                existing.mac_address = host["mac_address"]
            if host.get("os_info"):
                existing.os_info = host["os_info"]
            if host.get("hardware_vendor"):
                existing.hardware_vendor = host["hardware_vendor"]

            # Store current scan data in os_info for drift comparison
            current_state = existing.os_info or {}
            current_state["open_ports"] = host.get("ports", [])
            current_state["scan_source"] = host.get("scan_source", "unknown")
            existing.os_info = current_state
            existing.last_scanned = datetime.now(timezone.utc)
            updated_count += 1
        else:
            # Create new asset
            asset = Asset(
                ip_address=ip,
                hostname=host.get("hostname"),
                mac_address=host.get("mac_address"),
                os_info=host.get("os_info", {}),
                hardware_vendor=host.get("hardware_vendor"),
                device_type=DeviceType.UNKNOWN,
                last_scanned=datetime.now(timezone.utc),
            )
            # Store port data in os_info
            os_info = asset.os_info or {}
            os_info["open_ports"] = host.get("ports", [])
            os_info["scan_source"] = host.get("scan_source", "unknown")
            asset.os_info = os_info
            session.add(asset)
            new_count += 1

    session.commit()
    return {"new_assets": new_count, "updated_assets": updated_count}


@celery_app.task(name="app.tasks.discovery_tasks.run_active_scan", bind=True)
def run_active_scan(
    self,
    target_subnet: str = None,
    scan_type: str = "nmap",
    rate_limit: int = 1000,
    initiated_by: str = "system",
):
    """Run an active network scan and persist results."""
    target = target_subnet or settings.SCAN_DEFAULT_SUBNET
    logger.info(f"Active scan initiated by {initiated_by}: {scan_type} on {target}")

    if scan_type == "nmap":
        hosts = DiscoveryService.run_nmap_scan(target, rate_limit)
    elif scan_type == "masscan":
        hosts = DiscoveryService.run_masscan(target, rate_limit=rate_limit)
    else:
        return {"error": f"Unknown scan type: {scan_type}"}

    logger.info(f"Discovered {len(hosts)} hosts via {scan_type}")

    # Persist to database
    session = get_sync_session()
    try:
        summary = upsert_discovered_assets(hosts, session)
        summary["scan_type"] = scan_type
        summary["target"] = target
        summary["total_discovered"] = len(hosts)
        return summary
    finally:
        session.close()


@celery_app.task(name="app.tasks.discovery_tasks.run_passive_scan", bind=True)
def run_passive_scan(self, duration: int = 60, initiated_by: str = "system"):
    """Run a passive network listener and persist results."""
    logger.info(f"Passive scan initiated by {initiated_by} for {duration}s")

    hosts = DiscoveryService.run_passive_listener(duration=duration)
    logger.info(f"Passive listener discovered {len(hosts)} devices")

    session = get_sync_session()
    try:
        summary = upsert_discovered_assets(hosts, session)
        summary["scan_type"] = "passive"
        summary["total_discovered"] = len(hosts)
        return summary
    finally:
        session.close()


@celery_app.task(name="app.tasks.discovery_tasks.run_scheduled_scan")
def run_scheduled_scan():
    """Periodic scheduled scan triggered by Celery beat."""
    logger.info("Running scheduled discovery scan")
    return run_active_scan(
        target_subnet=settings.SCAN_DEFAULT_SUBNET,
        scan_type="nmap",
        rate_limit=settings.SCAN_RATE_LIMIT,
        initiated_by="celery_beat",
    )
