"""Pydantic schemas for Connector Agent Framework."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import (
    ConnectorAgentStatus,
    ConnectorAgentJobStatus,
    ConnectorAgentJobType,
)


# ── Enrollment ────────────────────────────────────────────────────────────────

class GenerateEnrollmentTokenRequest(BaseModel):
    expected_hostname: str | None = None
    expected_site: str | None = None
    expected_environment: str | None = None
    auto_approve: bool = False
    expires_in_seconds: int = Field(default=86400, ge=300, le=604800)  # 5m–7d


class GenerateEnrollmentTokenResponse(BaseModel):
    token: str           # plaintext — shown ONCE
    token_prefix: str
    expires_at: datetime
    auto_approve: bool


class EnrollRequest(BaseModel):
    """Sent by a new agent when first registering with the console."""
    registration_token: str
    hostname: str = Field(max_length=255)
    ip_address: str | None = Field(default=None, max_length=64)
    os_platform: str = Field(max_length=64)
    os_version: str | None = Field(default=None, max_length=128)
    agent_version: str = Field(max_length=32)
    site: str | None = Field(default=None, max_length=128)
    location: str | None = Field(default=None, max_length=128)
    environment: str | None = Field(default=None, max_length=64)
    name: str | None = None   # optional suggested name; console uses hostname if absent


class EnrollResponse(BaseModel):
    """Returned to agent after successful enrollment / pending approval."""
    connector_id: uuid.UUID
    status: ConnectorAgentStatus
    token: str | None = None      # bearer token; only set when auto_approve=True
    token_prefix: str | None = None
    message: str


class EnrollStatusResponse(BaseModel):
    """Agent polls this to check if its enrollment has been approved."""
    connector_id: uuid.UUID
    status: ConnectorAgentStatus
    token: str | None = None     # populated once approved
    token_prefix: str | None = None


# ── Agent CRUD (console side) ─────────────────────────────────────────────────

class ConnectorAgentCreate(BaseModel):
    name: str = Field(max_length=128)
    description: str | None = None
    site: str | None = None
    location: str | None = None
    environment: str | None = None


class ConnectorAgentUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    description: str | None = None
    site: str | None = None
    location: str | None = None
    environment: str | None = None
    is_enabled: bool | None = None


class ConnectorAgentOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    hostname: str | None
    ip_address: str | None
    os_platform: str | None
    os_version: str | None
    agent_version: str | None
    site: str | None
    location: str | None
    environment: str | None
    token_prefix: str | None
    cert_fingerprint: str | None
    cert_expires_at: datetime | None
    status: ConnectorAgentStatus
    is_enabled: bool
    last_seen_at: datetime | None
    last_heartbeat_at: datetime | None
    approved_by: str | None
    approved_at: datetime | None
    revoked_at: datetime | None
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    settings: ConnectorAgentSettingsOut | None = None

    model_config = {"from_attributes": True}


# ── Settings ──────────────────────────────────────────────────────────────────

class ConnectorAgentSettingsIn(BaseModel):
    heartbeat_interval_seconds: int = Field(default=30, ge=5, le=300)
    job_poll_interval_seconds: int = Field(default=10, ge=5, le=300)
    config_refresh_interval_seconds: int = Field(default=3600, ge=60)

    retry_max_attempts: int = Field(default=5, ge=1, le=20)
    retry_backoff_base_seconds: int = Field(default=2, ge=1, le=30)
    retry_backoff_max_seconds: int = Field(default=300, ge=30, le=3600)

    job_timeout_seconds: int = Field(default=3600, ge=60, le=86400)
    max_concurrent_jobs: int = Field(default=2, ge=1, le=20)
    result_chunk_size_mb: int = Field(default=50, ge=1, le=500)

    offline_queue_max_mb: int = Field(default=500, ge=50, le=10000)
    result_retention_hours: int = Field(default=72, ge=1, le=720)
    log_retention_days: int = Field(default=30, ge=1, le=365)

    verify_console_certificate: bool = True
    verify_console_fingerprint: bool = False
    console_fingerprint: str | None = None
    token_rotation_days: int = Field(default=90, ge=7, le=365)

    proxy_config: dict | None = None
    log_level: str = Field(default="info", pattern="^(debug|info|warning|error)$")
    sanitize_secrets_in_logs: bool = True

    allowed_scan_profiles: list[str] | None = None
    allowed_scan_modes: list[str] | None = None
    allowed_environments: list[str] | None = None
    allowed_tags: list[str] | None = None
    denied_tags: list[str] | None = None
    max_targets_per_job: int = Field(default=100, ge=1, le=10000)

    auto_upgrade: bool = False
    upgrade_channel: str = Field(default="stable", pattern="^(stable|beta|edge)$")


class ConnectorAgentSettingsOut(ConnectorAgentSettingsIn):
    id: uuid.UUID
    agent_id: uuid.UUID
    updated_by: str | None
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Heartbeat ─────────────────────────────────────────────────────────────────

class HeartbeatRequest(BaseModel):
    """Payload sent by agent on each heartbeat poll."""
    agent_timestamp: datetime | None = None
    agent_version: str | None = None
    status: str | None = None
    active_jobs: int = 0
    queued_results: int = 0
    queue_size_mb: float | None = None
    cpu_percent: float | None = None
    memory_mb: float | None = None
    disk_free_mb: float | None = None
    error_count: int = 0
    payload: dict | None = None


class HeartbeatResponse(BaseModel):
    """Console response to heartbeat. Carries instructions to the agent."""
    acknowledged: bool = True
    server_time: datetime
    # If console has pending settings update, bump this version so agent knows to pull config
    config_version: int | None = None
    # Carry urgent commands: "stop", "rotate_token", "upgrade"
    command: str | None = None
    command_payload: dict | None = None


# ── Jobs (agent-facing) ───────────────────────────────────────────────────────

class ConnectorJobOut(BaseModel):
    """Job record returned to the agent when it polls for work."""
    id: uuid.UUID
    job_type: ConnectorAgentJobType
    payload: dict
    payload_checksum: str | None
    priority: int
    expires_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class JobStatusUpdate(BaseModel):
    """Agent posts this to update job progress."""
    status: ConnectorAgentJobStatus
    progress_pct: int = Field(default=0, ge=0, le=100)
    progress_message: str | None = None
    targets_total: int | None = None
    targets_done: int | None = None
    targets_failed: int | None = None
    error_message: str | None = None


class ConnectorAgentJobOut(BaseModel):
    """Full job record as seen from the console."""
    id: uuid.UUID
    agent_id: uuid.UUID
    discovery_job_id: uuid.UUID | None
    job_type: ConnectorAgentJobType
    status: ConnectorAgentJobStatus
    priority: int
    progress_pct: int
    progress_message: str | None
    targets_total: int
    targets_done: int
    targets_failed: int
    error_message: str | None
    scheduled_at: datetime | None
    accepted_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    expires_at: datetime | None
    cancel_requested_by: str | None
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    result_id: uuid.UUID | None

    model_config = {"from_attributes": True}


class DispatchJobRequest(BaseModel):
    """Console dispatches a job to a connector agent."""
    job_type: ConnectorAgentJobType = ConnectorAgentJobType.on_demand
    payload: dict = Field(default_factory=dict)
    priority: int = Field(default=50, ge=0, le=100)
    expires_in_seconds: int | None = Field(default=None, ge=60, le=86400)
    # e.g. payload = {
    #   "targets": [{"asset_id": "...", "hostname": "...", "platform": "linux"}],
    #   "scan_profile": "standard",
    #   "scan_mode": "safe",
    #   "credential_id": "...",
    # }


# ── Results (agent-facing) ────────────────────────────────────────────────────

class ResultUploadRequest(BaseModel):
    """Agent uploads (possibly chunked) scan results."""
    job_id: uuid.UUID
    chunk_index: int = Field(ge=0, le=9999)
    chunk_count: int = Field(ge=1, le=10000)
    # Max 50 MB per chunk as base64 (~68 MB raw; matches default result_chunk_size_mb=50)
    data: str = Field(max_length=72_000_000)
    checksum: str = Field(min_length=64, max_length=64)  # sha256 hex
    total_checksum: str | None = Field(default=None, min_length=64, max_length=64)
    content_encoding: str = Field(default="gzip", pattern="^(gzip|identity)$")


class ResultUploadResponse(BaseModel):
    result_id: uuid.UUID
    chunks_received: int
    is_complete: bool
    acknowledged: bool = True


# ── Logs (agent-facing) ───────────────────────────────────────────────────────

class LogEntry(BaseModel):
    level: str = Field(default="info", pattern="^(debug|info|warning|error|critical)$")
    message: str = Field(max_length=8192)
    context: dict | None = None
    timestamp: datetime | None = None
    job_id: uuid.UUID | None = None


class LogUploadRequest(BaseModel):
    entries: list[LogEntry] = Field(min_length=1, max_length=1000)


# ── Revocation & Approval ─────────────────────────────────────────────────────

class ApproveConnectorRequest(BaseModel):
    notes: str | None = None


class RevokeConnectorRequest(BaseModel):
    reason: str = Field(max_length=512)


class TokenRotateResponse(BaseModel):
    token: str
    token_prefix: str
    expires_at: datetime


# ── Heartbeat summary for list ────────────────────────────────────────────────

class ConnectorAgentHeartbeatOut(BaseModel):
    id: uuid.UUID
    received_at: datetime
    agent_version: str | None
    status: str | None
    active_jobs: int
    queued_results: int
    queue_size_mb: float | None
    cpu_percent: float | None
    memory_mb: float | None
    disk_free_mb: float | None
    error_count: int

    model_config = {"from_attributes": True}
