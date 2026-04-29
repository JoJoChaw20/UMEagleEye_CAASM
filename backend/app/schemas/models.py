"""
UMEagleEye - Pydantic schemas for assets, scans, events, advisories, SBOMs, CTI, and posture.
"""

from datetime import datetime
from typing import Optional, List, Any, Dict
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.db.enums import (
    DeviceType, Severity, EventType, IndicatorType,
    AdvisoryStatus, SBOMFormat
)


# ═══════════════════════════════════════════════════════════════
# Asset Schemas
# ═══════════════════════════════════════════════════════════════
class AssetCreate(BaseModel):
    hostname: Optional[str] = None
    ip_address: str
    mac_address: Optional[str] = None
    owner: Optional[str] = None
    device_type: DeviceType = DeviceType.UNKNOWN
    hardware_vendor: Optional[str] = None
    os_info: Optional[Dict[str, Any]] = None
    criticality_score: int = Field(default=5, ge=1, le=10)
    is_internet_facing: bool = False


class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    owner: Optional[str] = None
    device_type: Optional[DeviceType] = None
    hardware_vendor: Optional[str] = None
    os_info: Optional[Dict[str, Any]] = None
    criticality_score: Optional[int] = Field(default=None, ge=1, le=10)
    is_internet_facing: Optional[bool] = None


class AssetResponse(BaseModel):
    asset_id: UUID
    hostname: Optional[str]
    ip_address: str
    mac_address: Optional[str]
    owner: Optional[str]
    device_type: DeviceType
    hardware_vendor: Optional[str]
    os_info: Optional[Dict[str, Any]]
    criticality_score: int
    baseline_state: Optional[Dict[str, Any]]
    is_internet_facing: bool
    last_scanned: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    @field_validator("ip_address", mode="before")
    @classmethod
    def cast_ip(cls, v):
        return str(v) if v else v

    model_config = {"from_attributes": True}


class AssetListResponse(BaseModel):
    items: List[AssetResponse]
    total: int
    page: int
    page_size: int


class BaselineSetRequest(BaseModel):
    """Request to set the Golden Image baseline for an asset."""
    confirm: bool = Field(..., description="Must be True to confirm baseline overwrite")


# ═══════════════════════════════════════════════════════════════
# Scan Schemas
# ═══════════════════════════════════════════════════════════════
class ScanRequest(BaseModel):
    target_subnet: Optional[str] = None
    scan_type: str = Field(default="nmap", pattern="^(nmap|masscan|passive)$")
    rate_limit: Optional[int] = Field(default=None, ge=100, le=10000)


class ScanStatusResponse(BaseModel):
    task_id: str
    status: str
    result: Optional[Dict[str, Any]] = None


# ═══════════════════════════════════════════════════════════════
# Event Schemas
# ═══════════════════════════════════════════════════════════════
class EventResponse(BaseModel):
    event_id: UUID
    asset_id: UUID
    event_type: EventType
    severity: Severity
    details: Dict[str, Any]
    composite_risk_score: Optional[float]
    timestamp: datetime

    model_config = {"from_attributes": True}


class EventListResponse(BaseModel):
    items: List[EventResponse]
    total: int
    page: int
    page_size: int


# ═══════════════════════════════════════════════════════════════
# Advisory Schemas
# ═══════════════════════════════════════════════════════════════
class AdvisoryResponse(BaseModel):
    advisory_id: UUID
    event_id: UUID
    summary: str
    recommended_action: str
    status: AdvisoryStatus
    assigned_to: Optional[UUID]
    created_at: datetime
    resolved_at: Optional[datetime]

    model_config = {"from_attributes": True}


class AdvisoryStatusUpdate(BaseModel):
    status: AdvisoryStatus
    assigned_to: Optional[UUID] = None


class AdvisoryListResponse(BaseModel):
    items: List[AdvisoryResponse]
    total: int
    page: int
    page_size: int


# ═══════════════════════════════════════════════════════════════
# SBOM Schemas
# ═══════════════════════════════════════════════════════════════
class SBOMResponse(BaseModel):
    sbom_id: UUID
    asset_id: UUID
    format: SBOMFormat
    format_version: str
    generated_at: datetime
    tool_used: str
    gcs_path: Optional[str]
    component_count: Optional[int] = None

    model_config = {"from_attributes": True}


class SBOMDetailResponse(SBOMResponse):
    raw_data: Dict[str, Any]


class SBOMScanRequest(BaseModel):
    """Request to trigger an SBOM scan for an asset."""
    target: Optional[str] = Field(
        default="dir:/app",
        description="Scan target (e.g., 'dir:/app' or 'image:tag'). Defaults to backend /app for testing."
    )


# ═══════════════════════════════════════════════════════════════
# CTI Indicator Schemas
# ═══════════════════════════════════════════════════════════════
class CTIIndicatorResponse(BaseModel):
    indicator_id: UUID
    source: str
    indicator_type: IndicatorType
    value: str
    confidence_score: Optional[float]
    attack_tactic: Optional[str]
    attack_technique: Optional[str]
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class CTIListResponse(BaseModel):
    items: List[CTIIndicatorResponse]
    total: int


# ═══════════════════════════════════════════════════════════════
# Posture Metrics Schemas
# ═══════════════════════════════════════════════════════════════
class PostureMetricsResponse(BaseModel):
    snapshot_id: UUID
    overall_score: int
    total_assets: int
    total_critical_assets: int
    open_critical_events: int
    top_risks: Optional[List[Any]] = None
    timestamp: datetime

    model_config = {"from_attributes": True}


class PostureHistoryResponse(BaseModel):
    items: List[PostureMetricsResponse]


# ═══════════════════════════════════════════════════════════════
# Audit Log Schemas
# ═══════════════════════════════════════════════════════════════
class AuditLogResponse(BaseModel):
    log_id: UUID
    user_id: UUID
    action_type: str
    target_entity: Optional[str]
    previous_state: Optional[Dict[str, Any]]
    new_state: Optional[Dict[str, Any]]
    timestamp: datetime

    model_config = {"from_attributes": True}


class AuditLogListResponse(BaseModel):
    items: List[AuditLogResponse]
    total: int
    page: int
    page_size: int
