"""Scan DTOs."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import JobStatus, Platform, ScanMode


class ScanLaunchRequest(BaseModel):
    asset_ids: list[uuid.UUID] = []
    group_ids: list[uuid.UUID] = []
    all_enabled: bool = False
    profile_id: uuid.UUID | None = None
    note: str | None = None
    # One-shot override: when set, takes precedence over the profile setting.
    # When None, the profile's collect_password_policy value is used (False if
    # no profile is selected).
    collect_password_policy: bool | None = None


class DiscoveryJobOut(BaseModel):
    id: uuid.UUID
    scope_description: str
    status: JobStatus
    triggered_by: str | None
    triggered_kind: str
    started_at: datetime | None
    finished_at: datetime | None
    totals: dict | None
    created_at: datetime

    model_config = {"from_attributes": True}


class DiscoveryJobTargetOut(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID
    asset_id: uuid.UUID
    # Asset fields resolved at query time (not stored on the target row itself)
    hostname: str | None = None
    ip_address: str | None = None
    platform: Platform
    status: JobStatus
    attempt: int
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None
    error_bucket: str | None
    error_detail: str | None
    stats: dict | None

    model_config = {"from_attributes": True}


class ScanProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    platforms: list[Platform]
    mode: ScanMode = ScanMode.safe
    probe_selection: dict | None = None
    target_scope: dict = Field(default_factory=lambda: {"all_enabled": True})
    timeout_seconds: int = 300
    retry_count: int = 1
    concurrency_limit: int = 10
    throttle_ms: int = 0
    credential_strategy: str = "asset"
    # When True every scan that uses this profile will also collect and
    # evaluate password policies on each target.
    collect_password_policy: bool = False


class ScanProfileOut(ScanProfileIn):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScheduledScanIn(BaseModel):
    name: str
    description: str | None = None
    cron: str
    profile_id: uuid.UUID
    scope: dict
    enabled: bool = True
    requires_approval: bool = False


class ScheduledScanOut(ScheduledScanIn):
    id: uuid.UUID
    last_run_at: datetime | None
    next_run_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class BlackoutIn(BaseModel):
    name: str
    cron: str
    duration_minutes: int
    scope: str = "global"
    tags: dict | None = None


class BlackoutOut(BlackoutIn):
    id: uuid.UUID
    model_config = {"from_attributes": True}


class DashboardMetrics(BaseModel):
    total_assets: int
    total_accounts: int
    privileged_accounts: int
    newly_privileged_last_7d: int
    dormant_privileged: int
    shared_privileged: int
    unknown_review_required: int
    last_scan_at: datetime | None
    open_alerts: int
    by_platform: dict[str, int]
    by_classification: dict[str, int]
    local_admin_sprawl: list[dict]
