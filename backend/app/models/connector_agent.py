"""Connector Agent Framework models.

Represents lightweight agents deployed in remote/segmented environments that:
  - communicate outbound-only over TCP 443 to the console
  - poll for jobs, execute scans locally, upload results securely
  - never require inbound connections from the console

Distinct from the scan-protocol Connector model (SSH/WinRM/DB connectors).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, ForeignKey, Index, Integer, SmallInteger, String, Text
)
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from app.db_types import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models._base import created_at, updated_at, uuid_pk
from app.models.enums import (
    ConnectorAgentStatus,
    ConnectorAgentJobStatus,
    ConnectorAgentJobType,
)


# ── Agent registration & identity ─────────────────────────────────────────────

class ConnectorAgent(Base):
    """An enrolled remote connector agent.

    Each agent has a unique identity (connector_id), a status, and a
    configuration snapshot.  Agents communicate via their connector_id +
    bearer token (or mTLS certificate) over outbound HTTPS only.
    """
    __tablename__ = "connector_agents"

    id: Mapped[uuid.UUID] = uuid_pk()

    # Identity
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Deployment metadata (reported by agent at enrollment)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_platform: Mapped[str | None] = mapped_column(String(64), nullable=True)   # linux/windows/macos
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Location / site
    site: Mapped[str | None] = mapped_column(String(128), nullable=True)
    location: Mapped[str | None] = mapped_column(String(128), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Auth token (hashed).  Never store plaintext.
    # On enrollment: token = secrets.token_urlsafe(48)
    # Stored as: bcrypt/SHA-256(token)
    token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    token_prefix: Mapped[str | None] = mapped_column(String(12), nullable=True)  # first 8 chars for display

    # Certificate-based auth (optional / future mTLS)
    cert_serial: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cert_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cert_expires_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # Status
    status: Mapped[ConnectorAgentStatus] = mapped_column(
        PgEnum(ConnectorAgentStatus, name="connector_agent_status_enum", create_type=False),
        nullable=False,
        default=ConnectorAgentStatus.pending,
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Heartbeat tracking
    last_seen_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # Approval tracking
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Who created / last modified this record in the console
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    # Relationships
    settings: Mapped[ConnectorAgentSettings | None] = relationship(
        "ConnectorAgentSettings",
        back_populates="agent",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    heartbeats: Mapped[list[ConnectorAgentHeartbeat]] = relationship(
        "ConnectorAgentHeartbeat",
        back_populates="agent",
        cascade="all, delete-orphan",
        order_by="ConnectorAgentHeartbeat.received_at.desc()",
    )
    jobs: Mapped[list[ConnectorAgentJob]] = relationship(
        "ConnectorAgentJob",
        back_populates="agent",
        cascade="all, delete-orphan",
        order_by="ConnectorAgentJob.created_at.desc()",
    )
    enrollment_tokens: Mapped[list[ConnectorEnrollmentToken]] = relationship(
        "ConnectorEnrollmentToken",
        back_populates="agent",
        cascade="all, delete-orphan",
    )


class ConnectorEnrollmentToken(Base):
    """One-time registration token used to enroll a new agent.

    Generated by a console admin, handed to the operator deploying the agent.
    Consumed (single-use) when the agent completes enrollment.
    """
    __tablename__ = "connector_enrollment_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()

    # Links to the connector once created, NULL before enrollment completes
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connector_agents.id", ondelete="CASCADE"),
        nullable=True,
    )

    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    token_prefix: Mapped[str] = mapped_column(String(12), nullable=False)

    # Pre-filled context for the expected agent
    expected_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expected_site: Mapped[str | None] = mapped_column(String(128), nullable=True)
    expected_environment: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Auto-approve flag (no manual approval step required)
    auto_approve: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(nullable=True)
    is_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = created_at()

    # Relationships
    agent: Mapped[ConnectorAgent | None] = relationship(
        "ConnectorAgent", back_populates="enrollment_tokens"
    )


# ── Per-agent settings (console-managed) ──────────────────────────────────────

class ConnectorAgentSettings(Base):
    """Console-managed configuration pushed to each connector agent.

    The agent periodically pulls this via GET /connectors/{id}/config.
    All values are JSON-serialisable so agents can cache the full blob.
    """
    __tablename__ = "connector_agent_settings"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connector_agents.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    # Polling
    heartbeat_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    job_poll_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    config_refresh_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)

    # Retry
    retry_max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    retry_backoff_base_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    retry_backoff_max_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)

    # Execution
    job_timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    max_concurrent_jobs: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=2)
    result_chunk_size_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=50)

    # Storage
    offline_queue_max_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=500)
    result_retention_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=72)
    log_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)

    # Security
    verify_console_certificate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    verify_console_fingerprint: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    console_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    token_rotation_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)

    # Proxy (stored as JSONB for flexibility)
    proxy_config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # e.g. {"enabled": true, "url": "http://proxy:3128", "no_proxy": ".internal"}

    # Logging
    log_level: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    sanitize_secrets_in_logs: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Scope constraints (what this agent is allowed to scan)
    allowed_scan_profiles: Mapped[list | None] = mapped_column(JSONB, nullable=True)  # list[str]
    allowed_scan_modes: Mapped[list | None] = mapped_column(JSONB, nullable=True)      # ["safe","deep"]
    allowed_environments: Mapped[list | None] = mapped_column(JSONB, nullable=True)    # ["prod","staging"]
    allowed_tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)            # list[tag_id]
    denied_tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)             # list[tag_id]
    max_targets_per_job: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    # Upgrade
    auto_upgrade: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    upgrade_channel: Mapped[str] = mapped_column(String(32), nullable=False, default="stable")

    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    # Relationships
    agent: Mapped[ConnectorAgent] = relationship(
        "ConnectorAgent", back_populates="settings"
    )


# ── Heartbeat ─────────────────────────────────────────────────────────────────

class ConnectorAgentHeartbeat(Base):
    """Individual heartbeat record sent by the agent.

    Console keeps last N heartbeats per agent for trend analysis.
    """
    __tablename__ = "connector_agent_heartbeats"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connector_agents.id", ondelete="CASCADE"),
        nullable=False,
    )

    received_at: Mapped[datetime] = mapped_column(nullable=False)
    agent_timestamp: Mapped[datetime | None] = mapped_column(nullable=True)  # clock from agent

    # Health payload from the agent
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)  # agent self-reported status
    active_jobs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    queued_results: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    queue_size_mb: Mapped[float | None] = mapped_column(nullable=True)
    cpu_percent: Mapped[float | None] = mapped_column(nullable=True)
    memory_mb: Mapped[float | None] = mapped_column(nullable=True)
    disk_free_mb: Mapped[float | None] = mapped_column(nullable=True)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Full health payload (anything extra)
    payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_connector_agent_heartbeats_agent_received", "agent_id", "received_at"),
    )

    agent: Mapped[ConnectorAgent] = relationship(
        "ConnectorAgent", back_populates="heartbeats"
    )


# ── Jobs ──────────────────────────────────────────────────────────────────────

class ConnectorAgentJob(Base):
    """A job dispatched to a connector agent for execution.

    The agent polls for PENDING jobs, updates status as it progresses,
    and uploads results when complete.
    """
    __tablename__ = "connector_agent_jobs"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connector_agents.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Optional link to the scan job initiated from console
    discovery_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )

    job_type: Mapped[ConnectorAgentJobType] = mapped_column(
        PgEnum(ConnectorAgentJobType, name="connector_agent_job_type_enum", create_type=False),
        nullable=False,
        default=ConnectorAgentJobType.on_demand,
    )
    status: Mapped[ConnectorAgentJobStatus] = mapped_column(
        PgEnum(ConnectorAgentJobStatus, name="connector_agent_job_status_enum", create_type=False),
        nullable=False,
        default=ConnectorAgentJobStatus.pending,
    )

    # Job payload — what the agent must do (targets, credentials, profile, etc.)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # e.g.:
    # {
    #   "targets": [{"asset_id": "...", "hostname": "...", "platform": "..."}],
    #   "scan_profile": "standard",
    #   "scan_mode": "safe",
    #   "credential_id": "...",
    #   "timeout_seconds": 3600
    # }

    # Integrity
    payload_checksum: Mapped[str | None] = mapped_column(String(128), nullable=True)  # sha256 of payload

    # Priority (lower = higher priority)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=50)

    # Timing
    scheduled_at: Mapped[datetime | None] = mapped_column(nullable=True)
    accepted_at: Mapped[datetime | None] = mapped_column(nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)   # job TTL

    # Progress
    progress_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    targets_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    targets_done: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    targets_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Result summary (after completion)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        # use_alter breaks the circular dependency with connector_agent_results for SQLite DROP
        ForeignKey("connector_agent_results.id", ondelete="SET NULL", use_alter=True,
                   name="fk_caj_result_id"),
        nullable=True,
    )

    # Cancellation
    cancel_requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # Who created this job
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    __table_args__ = (
        Index("ix_connector_agent_jobs_agent_status", "agent_id", "status"),
        Index("ix_connector_agent_jobs_status", "status"),
    )

    agent: Mapped[ConnectorAgent] = relationship(
        "ConnectorAgent", back_populates="jobs"
    )
    result: Mapped[ConnectorAgentResult | None] = relationship(
        "ConnectorAgentResult",
        foreign_keys=[result_id],
        lazy="joined",
    )


# ── Job Results ───────────────────────────────────────────────────────────────

class ConnectorAgentResult(Base):
    """Scan result uploaded by a connector agent after job completion.

    Large results are received in chunks; this record tracks assembly.
    Once all chunks received and verified the console processes the data.
    """
    __tablename__ = "connector_agent_results"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connector_agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connector_agent_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Chunked upload tracking
    chunk_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    chunks_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Content
    content_type: Mapped[str] = mapped_column(String(64), nullable=False, default="application/json")
    content_encoding: Mapped[str] = mapped_column(String(32), nullable=False, default="gzip")
    checksum: Mapped[str | None] = mapped_column(String(128), nullable=True)  # sha256 of full payload
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Processing
    processed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    processing_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Summary counts extracted from result
    accounts_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    assets_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Full result payload (after reassembly)
    payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    __table_args__ = (
        Index("ix_connector_agent_results_agent_job", "agent_id", "job_id"),
    )


class ConnectorAgentResultChunk(Base):
    """Individual chunk of a multi-part result upload."""
    __tablename__ = "connector_agent_result_chunks"

    id: Mapped[uuid.UUID] = uuid_pk()
    result_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connector_agent_results.id", ondelete="CASCADE"),
        nullable=False,
    )
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    data: Mapped[str] = mapped_column(Text, nullable=False)          # base64-encoded compressed chunk
    checksum: Mapped[str] = mapped_column(String(128), nullable=False)  # sha256 of chunk data
    received_at: Mapped[datetime] = mapped_column(nullable=False)

    __table_args__ = (
        Index("ix_connector_result_chunks_result_idx", "result_id", "chunk_index", unique=True),
    )


# ── Logs ──────────────────────────────────────────────────────────────────────

class ConnectorAgentLog(Base):
    """Diagnostic log batch uploaded by a connector agent."""
    __tablename__ = "connector_agent_logs"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connector_agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    agent_timestamp: Mapped[datetime | None] = mapped_column(nullable=True)
    received_at: Mapped[datetime] = mapped_column(nullable=False)

    __table_args__ = (
        Index("ix_connector_agent_logs_agent_received", "agent_id", "received_at"),
    )

    agent: Mapped[ConnectorAgent] = relationship("ConnectorAgent")
