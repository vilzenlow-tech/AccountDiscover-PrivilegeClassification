"""Discovery jobs, targets, scan profiles, schedules, blackout windows, bulk imports."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from app.db_types import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models._base import created_at, updated_at, uuid_pk
from app.models.enums import JobStatus, Platform, ScanMode


class ScanProfile(Base):
    """Reusable scan profile.

    Encodes what to collect, timeouts, retries, concurrency, mode, credential
    policy (inherit from asset/connector vs pinned), and evidence depth.
    """

    __tablename__ = "scan_profiles"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    platforms: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    mode: Mapped[ScanMode] = mapped_column(
        PgEnum(ScanMode, name="scan_mode_enum", create_type=False),
        nullable=False,
        default=ScanMode.safe,
    )
    probe_selection: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    target_scope: Mapped[dict] = mapped_column(JSONB, nullable=False, default=lambda: {"all_enabled": True})
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    concurrency_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    throttle_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    credential_strategy: Mapped[str] = mapped_column(String(32), nullable=False, default="asset")
    # asset | connector | pinned

    # When True, the scan will also collect and evaluate password policies for
    # each target platform.  Opt-in: adds extra commands, and some platforms
    # only have live stubs (fully implemented in future phases).
    collect_password_policy: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()


class ScanBlackoutWindow(Base):
    """Weekly blackout windows during which scans must not run."""

    __tablename__ = "scan_blackout_windows"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    cron: Mapped[str] = mapped_column(String(64), nullable=False)  # RFC-ish; evaluated in scheduler
    duration_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    scope: Mapped[str] = mapped_column(String(32), nullable=False, default="global")
    tags: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()


class ScheduledScan(Base):
    """Scheduled/recurring scan definition."""

    __tablename__ = "scheduled_scans"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    cron: Mapped[str] = mapped_column(String(64), nullable=False)
    profile_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_profiles.id"), nullable=False
    )
    scope: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # { "all_enabled": true } | { "asset_ids": [...] } | { "group_ids": [...] }
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()


class DiscoveryJob(Base):
    """A single scan job — either on-demand or scheduled."""

    __tablename__ = "discovery_jobs"

    id: Mapped[uuid.UUID] = uuid_pk()
    scope_description: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[dict] = mapped_column(JSONB, nullable=False)
    profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_profiles.id"), nullable=True
    )
    triggered_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    triggered_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    # manual | scheduled | bulk | api
    status: Mapped[JobStatus] = mapped_column(
        PgEnum(JobStatus, name="job_status_enum", create_type=False),
        nullable=False,
        default=JobStatus.pending,
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    totals: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancelled_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    targets: Mapped[list["DiscoveryJobTarget"]] = relationship(
        "DiscoveryJobTarget", back_populates="job", cascade="all, delete-orphan"
    )


class DiscoveryJobTarget(Base):
    """One (job, asset, collector) tuple."""

    __tablename__ = "discovery_job_targets"

    id: Mapped[uuid.UUID] = uuid_pk()
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    platform: Mapped[Platform] = mapped_column(
        PgEnum(Platform, name="platform_enum", create_type=False), nullable=False
    )
    status: Mapped[JobStatus] = mapped_column(
        PgEnum(JobStatus, name="job_status_enum", create_type=False),
        nullable=False,
        default=JobStatus.pending,
        index=True,
    )
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_bucket: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    stats: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    job: Mapped[DiscoveryJob] = relationship("DiscoveryJob", back_populates="targets")


class BulkImportJob(Base):
    """Bulk target import batch (CSV/Excel/paste)."""

    __tablename__ = "bulk_import_jobs"

    id: Mapped[uuid.UUID] = uuid_pk()
    source: Mapped[str] = mapped_column(String(32), nullable=False)  # csv|xlsx|paste
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    uploaded_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    total_rows: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    imported_rows: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duplicate_rows: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    invalid_rows: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = created_at()
