"""
UMEagleEye - SQLAlchemy ORM models for all 8 PRD tables.
Implements the data schema defined in PRD Section 6.2.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import (
    String, Text, SmallInteger, Integer, Numeric,
    DateTime, ForeignKey, Enum, Table, Column, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET, MACADDR
from pgvector.sqlalchemy import Vector

from app.db.database import Base
from app.db.enums import (
    DeviceType, Severity, EventType, IndicatorType,
    AdvisoryStatus, UserRole, SBOMFormat
)


def utcnow():
    return datetime.now(timezone.utc)


def new_uuid():
    return uuid.uuid4()


# ── Junction Table: Event <-> CTI_Indicator (Many-to-Many) ──
event_cti_indicators = Table(
    "event_cti_indicators",
    Base.metadata,
    Column("event_id", UUID(as_uuid=True), ForeignKey("events.event_id", ondelete="CASCADE"), primary_key=True),
    Column("indicator_id", UUID(as_uuid=True), ForeignKey("cti_indicators.indicator_id", ondelete="CASCADE"), primary_key=True),
)


# ═══════════════════════════════════════════════════════════════
# Table 1: Asset (Core Entity)
# ═══════════════════════════════════════════════════════════════
class Asset(Base):
    __tablename__ = "assets"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str] = mapped_column(INET, nullable=False, index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(MACADDR, nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_type: Mapped[DeviceType] = mapped_column(
        Enum(DeviceType), default=DeviceType.UNKNOWN, nullable=False
    )
    hardware_vendor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_info: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    criticality_score: Mapped[int] = mapped_column(SmallInteger, default=5, nullable=False)
    baseline_state: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    is_internet_facing: Mapped[bool] = mapped_column(default=False, nullable=False)
    last_scanned: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    # Relationships
    sboms: Mapped[List["SBOM"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    events: Mapped[List["Event"]] = relationship(back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_assets_ip_hostname", "ip_address", "hostname"),
    )


# ═══════════════════════════════════════════════════════════════
# Table 2: SBOM (Software Inventory)
# ═══════════════════════════════════════════════════════════════
class SBOM(Base):
    __tablename__ = "sboms"

    sbom_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False
    )
    format: Mapped[SBOMFormat] = mapped_column(
        Enum(SBOMFormat), default=SBOMFormat.CYCLONEDX, nullable=False
    )
    format_version: Mapped[str] = mapped_column(String(20), default="1.5", nullable=False)
    raw_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    tool_used: Mapped[str] = mapped_column(String(100), default="syft", nullable=False)
    gcs_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # Relationships
    asset: Mapped["Asset"] = relationship(back_populates="sboms")


# ═══════════════════════════════════════════════════════════════
# Table 3: Event (Drift and Security Alerts)
# ═══════════════════════════════════════════════════════════════
class Event(Base):
    __tablename__ = "events"

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[EventType] = mapped_column(Enum(EventType), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM, nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    composite_risk_score: Mapped[Optional[float]] = mapped_column(Numeric(8, 2), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    # Relationships
    asset: Mapped["Asset"] = relationship(back_populates="events")
    advisories: Mapped[List["Advisory"]] = relationship(back_populates="event", cascade="all, delete-orphan")
    cti_indicators: Mapped[List["CTIIndicator"]] = relationship(
        secondary=event_cti_indicators, back_populates="events"
    )

    __table_args__ = (
        Index("ix_events_severity_timestamp", "severity", "timestamp"),
    )


# ═══════════════════════════════════════════════════════════════
# Table 4: CTI_Indicator
# ═══════════════════════════════════════════════════════════════
class CTIIndicator(Base):
    __tablename__ = "cti_indicators"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    source: Mapped[str] = mapped_column(String(100), default="MyCERT", nullable=False)
    indicator_type: Mapped[IndicatorType] = mapped_column(Enum(IndicatorType), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    confidence_score: Mapped[Optional[float]] = mapped_column(Numeric(3, 2), nullable=True)
    attack_tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    attack_technique: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    # Relationships
    events: Mapped[List["Event"]] = relationship(
        secondary=event_cti_indicators, back_populates="cti_indicators"
    )


# ═══════════════════════════════════════════════════════════════
# Table 5: Advisory (AI-Generated Guidance)
# ═══════════════════════════════════════════════════════════════
class Advisory(Base):
    __tablename__ = "advisories"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("events.event_id", ondelete="CASCADE"), nullable=False
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[AdvisoryStatus] = mapped_column(
        Enum(AdvisoryStatus), default=AdvisoryStatus.OPEN, nullable=False
    )
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    event: Mapped["Event"] = relationship(back_populates="advisories")
    assignee: Mapped[Optional["User"]] = relationship(back_populates="assigned_advisories")


# ═══════════════════════════════════════════════════════════════
# Table 6: Posture Metrics (Executive Trendlines)
# ═══════════════════════════════════════════════════════════════
class PostureMetrics(Base):
    __tablename__ = "posture_metrics"

    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    overall_score: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    total_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_critical_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    open_critical_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    top_risks: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )


# ═══════════════════════════════════════════════════════════════
# Table 7: User and Role (IAM Support)
# ═══════════════════════════════════════════════════════════════
class User(Base):
    __tablename__ = "users"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole), default=UserRole.BUSINESS_OWNER, nullable=False
    )
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    totp_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    assigned_advisories: Mapped[List["Advisory"]] = relationship(back_populates="assignee")
    audit_logs: Mapped[List["AuditLog"]] = relationship(back_populates="user")


# ═══════════════════════════════════════════════════════════════
# Table 8: Audit Log (Immutable)
# ═══════════════════════════════════════════════════════════════
class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target_entity: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    previous_state: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    new_state: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    # Relationships
    user: Mapped["User"] = relationship(back_populates="audit_logs")


# ═══════════════════════════════════════════════════════════════
# RAG Embedding (for pgvector - advisory knowledge base)
# ═══════════════════════════════════════════════════════════════
class PlaybookChunk(Base):
    """Stores embedded playbook chunks for RAG retrieval."""
    __tablename__ = "playbook_chunks"

    chunk_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=new_uuid
    )
    source_document: Mapped[str] = mapped_column(String(512), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    embedding: Mapped[list] = mapped_column(Vector(768), nullable=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
