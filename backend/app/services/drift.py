"""
UMEagleEye - Drift Detection Service (FR-03-02, FR-03-03).
Compares live asset state against Golden Image baseline.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.db.enums import Severity, EventType

logger = logging.getLogger(__name__)


class DriftService:
    """Golden Image baseline comparison and drift event generation."""

    @staticmethod
    def compute_drift(
        baseline: Dict[str, Any],
        current_state: Dict[str, Any],
        asset_id: str,
    ) -> List[Dict[str, Any]]:
        """Compare current asset state against Golden Image baseline (FR-03-02).

        Args:
            baseline: The stored Golden Image state (JSONB from baseline_state)
            current_state: The current live state (from os_info including ports)
            asset_id: UUID of the asset being audited

        Returns:
            List of drift event dictionaries ready for Event table insertion
        """
        drift_events = []

        # ── Compare Open Ports ──
        baseline_ports = set()
        for p in baseline.get("open_ports", []):
            baseline_ports.add((p.get("port"), p.get("protocol", "tcp")))

        current_ports = set()
        for p in current_state.get("open_ports", []):
            current_ports.add((p.get("port"), p.get("protocol", "tcp")))

        # New ports opened
        new_ports = current_ports - baseline_ports
        for port, proto in new_ports:
            # Find service details for this port
            service_info = next(
                (p for p in current_state.get("open_ports", [])
                 if p.get("port") == port and p.get("protocol") == proto),
                {}
            )
            drift_events.append({
                "asset_id": asset_id,
                "event_type": EventType.PORT_OPENED,
                "severity": DriftService._classify_port_severity(port),
                "details": {
                    "changed_attribute": "open_ports",
                    "action": "port_opened",
                    "port": port,
                    "protocol": proto,
                    "service": service_info.get("service_name", ""),
                    "previous_value": "closed",
                    "new_value": "open",
                },
            })

        # Ports closed (that were in baseline)
        closed_ports = baseline_ports - current_ports
        for port, proto in closed_ports:
            drift_events.append({
                "asset_id": asset_id,
                "event_type": EventType.PORT_CLOSED,
                "severity": Severity.LOW,
                "details": {
                    "changed_attribute": "open_ports",
                    "action": "port_closed",
                    "port": port,
                    "protocol": proto,
                    "previous_value": "open",
                    "new_value": "closed",
                },
            })

        # ── Compare Installed Packages ──
        baseline_pkgs = {
            p.get("name"): p.get("version")
            for p in baseline.get("packages", [])
        }
        current_pkgs = {
            p.get("name"): p.get("version")
            for p in current_state.get("packages", [])
        }

        # New packages
        for pkg_name in set(current_pkgs.keys()) - set(baseline_pkgs.keys()):
            drift_events.append({
                "asset_id": asset_id,
                "event_type": EventType.NEW_PACKAGE,
                "severity": Severity.MEDIUM,
                "details": {
                    "changed_attribute": "packages",
                    "action": "new_package",
                    "package": pkg_name,
                    "version": current_pkgs[pkg_name],
                    "previous_value": None,
                    "new_value": current_pkgs[pkg_name],
                },
            })

        # Removed packages
        for pkg_name in set(baseline_pkgs.keys()) - set(current_pkgs.keys()):
            drift_events.append({
                "asset_id": asset_id,
                "event_type": EventType.REMOVED_PACKAGE,
                "severity": Severity.MEDIUM,
                "details": {
                    "changed_attribute": "packages",
                    "action": "removed_package",
                    "package": pkg_name,
                    "previous_value": baseline_pkgs[pkg_name],
                    "new_value": None,
                },
            })

        # Version changes
        for pkg_name in set(current_pkgs.keys()) & set(baseline_pkgs.keys()):
            if current_pkgs[pkg_name] != baseline_pkgs[pkg_name]:
                old_ver = baseline_pkgs[pkg_name] or ""
                new_ver = current_pkgs[pkg_name] or ""
                # Determine if upgrade or downgrade
                is_downgrade = DriftService._is_version_downgrade(old_ver, new_ver)
                drift_events.append({
                    "asset_id": asset_id,
                    "event_type": EventType.VERSION_DOWNGRADE if is_downgrade else EventType.VERSION_UPGRADE,
                    "severity": Severity.HIGH if is_downgrade else Severity.LOW,
                    "details": {
                        "changed_attribute": "packages",
                        "action": "version_downgrade" if is_downgrade else "version_upgrade",
                        "package": pkg_name,
                        "previous_value": old_ver,
                        "new_value": new_ver,
                    },
                })

        # ── Compare OS info changes ──
        if baseline and current_state:
            if baseline.get("name") != current_state.get("name"):
                drift_events.append({
                    "asset_id": asset_id,
                    "event_type": EventType.CONFIG_CHANGE,
                    "severity": Severity.HIGH,
                    "details": {
                        "changed_attribute": "os_info",
                        "action": "os_changed",
                        "previous_value": baseline.get("name"),
                        "new_value": current_state.get("name"),
                    },
                })

        logger.info(f"Drift analysis for asset {asset_id}: {len(drift_events)} deviations found")
        return drift_events

    @staticmethod
    def _classify_port_severity(port: int) -> Severity:
        """Classify the severity of a newly opened port."""
        critical_ports = {22, 23, 3389, 445, 135, 139, 1433, 3306, 5432, 27017}
        high_ports = {21, 25, 53, 80, 443, 8080, 8443, 8888, 9090}

        if port in critical_ports:
            return Severity.CRITICAL
        elif port in high_ports:
            return Severity.HIGH
        elif port < 1024:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _is_version_downgrade(old_version: str, new_version: str) -> bool:
        """Simple heuristic to detect version downgrades."""
        try:
            old_parts = [int(x) for x in old_version.split(".") if x.isdigit()]
            new_parts = [int(x) for x in new_version.split(".") if x.isdigit()]
            return new_parts < old_parts
        except (ValueError, AttributeError):
            return False
