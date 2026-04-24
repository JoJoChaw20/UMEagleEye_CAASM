"""
UMEagleEye - Shared enums for database models matching PRD schema.
"""

import enum


class DeviceType(str, enum.Enum):
    """Asset device type classification."""
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK = "network"
    IOT = "iot"
    UNKNOWN = "unknown"


class Severity(str, enum.Enum):
    """Alert/event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, enum.Enum):
    """Types of security/drift events."""
    PORT_OPENED = "port_opened"
    PORT_CLOSED = "port_closed"
    VERSION_DOWNGRADE = "version_downgrade"
    VERSION_UPGRADE = "version_upgrade"
    CVE_DETECTED = "cve_detected"
    NEW_DEVICE = "new_device"
    CONFIG_CHANGE = "config_change"
    NEW_PACKAGE = "new_package"
    REMOVED_PACKAGE = "removed_package"
    CTI_MATCH = "cti_match"


class IndicatorType(str, enum.Enum):
    """CTI indicator types."""
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"


class AdvisoryStatus(str, enum.Enum):
    """Advisory lifecycle states (FR-06)."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"


class UserRole(str, enum.Enum):
    """RBAC roles matching PRD personas."""
    OPS_LEAD = "ops_lead"
    SECURITY_ENGINEER = "security_engineer"
    BUSINESS_OWNER = "business_owner"
    MSSP_ANALYST = "mssp_analyst"


class SBOMFormat(str, enum.Enum):
    """SBOM format standards."""
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
