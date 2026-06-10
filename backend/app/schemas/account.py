"""Canonical account DTOs."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.enums import (
    AuthSource,
    EnabledStatus,
    InteractiveStatus,
    Platform,
    PrincipalType,
    PrivilegeClass,
)


class EntitlementOut(BaseModel):
    id: uuid.UUID
    kind: str
    name: str
    scope: str | None
    source: str | None
    inherited: bool
    via: str | None
    attributes: dict | None

    model_config = {"from_attributes": True}


class AccountOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    asset_hostname: str | None = None
    platform: Platform
    source_type: str
    account_name: str
    principal_type: PrincipalType
    auth_source: AuthSource
    enabled_status: EnabledStatus
    interactive_status: InteractiveStatus
    last_login: datetime | None
    last_login_source: str | None
    privilege_classification: PrivilegeClass
    privilege_confidence: int
    risk_score: int
    is_shared: bool
    password_never_expires: bool
    owner: str | None
    evidence_summary: dict | None
    discovered_at: datetime
    updated_at: datetime

    # Windows interactive classification (null on non-Windows accounts)
    interactive_confidence: int | None = None
    interactive_detection_method: str | None = None
    interactive_last_observed_logon_type: str | None = None
    allows_local_logon: bool | None = None
    allows_remote_interactive_logon: bool | None = None
    allows_service_logon: bool | None = None
    allows_batch_logon: bool | None = None
    allows_network_logon: bool | None = None
    review_required_reason: str | None = None
    principal_source: str | None = None

    model_config = {"from_attributes": True}


class AccountDetailOut(AccountOut):
    entitlements: list[EntitlementOut]
    raw_evidence_refs: list | None
    interactive_evidence_summary: dict | None = None


class AccountFilter(BaseModel):
    platform: Platform | None = None
    environment: str | None = None
    owner: str | None = None
    business_unit: str | None = None
    classification: PrivilegeClass | None = None
    enabled_status: EnabledStatus | None = None
    interactive_status: InteractiveStatus | None = None
    source_type: str | None = None          # e.g. windows_local, windows_gmsa
    principal_source: str | None = None     # Local | ActiveDirectory | Unknown
    asset_id: uuid.UUID | None = None
    dormant_days: int | None = None
    only_privileged: bool = False
    since: datetime | None = None
    search: str | None = None


class DeltaItem(BaseModel):
    account_id: uuid.UUID
    account_name: str
    asset_hostname: str
    platform: Platform
    change: str  # new_privileged | removed_privileged | upgraded | downgraded | became_dormant
    before: PrivilegeClass | None
    after: PrivilegeClass | None
    explanation: str


class DeltaResponse(BaseModel):
    baseline_job_id: uuid.UUID
    current_job_id: uuid.UUID
    items: list[DeltaItem]
    summary: dict[str, int]
