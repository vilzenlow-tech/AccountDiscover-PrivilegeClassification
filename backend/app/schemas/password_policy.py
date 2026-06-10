"""Password Policy DTOs — request/response schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models.enums import (
    Platform,
    PolicyFindingReviewState,
    PolicyFindingSeverity,
    PolicyScope,
    PolicySource,
)


# ── Shared sub-models ─────────────────────────────────────────────────────────

class AssetRef(BaseModel):
    id: uuid.UUID
    hostname: str
    platform: Platform
    model_config = {"from_attributes": True}


# ── PasswordPolicy ─────────────────────────────────────────────────────────────

class PasswordPolicyIn(BaseModel):
    """Used by scanner workers and manual imports to upsert a policy snapshot."""
    asset_id: uuid.UUID
    job_id: uuid.UUID | None = None
    platform: Platform
    policy_source: PolicySource
    policy_scope: PolicyScope
    policy_name: str | None = None
    is_effective_policy: bool = False
    applies_to: dict[str, Any] | None = None
    precedence: int | None = None

    # Core settings — all optional; None = not collected
    min_password_length: int | None = None
    complexity_enabled: bool | None = None
    password_history_count: int | None = None
    min_password_age_days: int | None = None
    max_password_age_days: int | None = None
    reversible_encryption_enabled: bool | None = None

    # Lockout
    lockout_threshold: int | None = None
    lockout_duration_minutes: int | None = None
    reset_lockout_counter_after_minutes: int | None = None

    # Unix / PAM
    dictionary_check_enabled: bool | None = None
    min_char_classes: int | None = None
    min_uppercase: int | None = None
    min_lowercase: int | None = None
    min_digits: int | None = None
    min_special_chars: int | None = None

    # External
    external_policy_enforced: bool | None = None
    requires_external_review: bool | None = None

    # Evidence
    evidence_summary: dict[str, Any] | None = None
    raw_evidence_ref: str | None = None
    collection_error: str | None = None
    confidence_score: int = Field(default=0, ge=0, le=100)
    discovered_at: datetime


class PasswordPolicyOut(PasswordPolicyIn):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    # Computed summary flags — returned by the API for display convenience
    has_weak_length: bool | None = None        # min_length < 12
    has_no_complexity: bool | None = None      # complexity_enabled is False
    has_no_lockout: bool | None = None         # lockout_threshold == 0
    has_no_expiry: bool | None = None          # max_password_age_days == 0
    finding_count: int = 0
    critical_finding_count: int = 0

    # Nested asset info (populated by API join)
    hostname: str | None = None

    model_config = {"from_attributes": True}


# ── AccountPolicyException ─────────────────────────────────────────────────────

class AccountPolicyExceptionIn(BaseModel):
    asset_id: uuid.UUID
    account_id: uuid.UUID | None = None
    policy_id: uuid.UUID | None = None
    exception_type: str = Field(
        ...,
        description=(
            "password_never_expires | password_not_required | check_policy_off | "
            "check_expiration_off | lockout_exempt | under_weaker_policy | "
            "privileged_account_weak_policy | under_external_policy | "
            "unknown_effective_policy | service_account_exception | fgpp_not_applied"
        ),
    )
    description: str | None = None
    effective_policy_source: str | None = None
    expected_policy_source: str | None = None
    evidence: dict[str, Any] | None = None
    discovered_at: datetime


class AccountPolicyExceptionOut(AccountPolicyExceptionIn):
    id: uuid.UUID
    account_name: str | None = None
    asset_hostname: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── PasswordPolicyFinding ──────────────────────────────────────────────────────

class PasswordPolicyFindingOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    account_id: uuid.UUID | None
    policy_id: uuid.UUID | None
    exception_id: uuid.UUID | None

    rule_key: str
    severity: PolicyFindingSeverity
    title: str
    description: str
    recommendation: str | None
    affected_scope: str | None
    evidence: dict[str, Any] | None
    is_exception_finding: bool

    review_state: PolicyFindingReviewState
    reviewed_by: str | None
    reviewed_at: datetime | None
    review_comment: str | None

    discovered_at: datetime
    created_at: datetime

    # Convenience fields populated via join
    hostname: str | None = None
    platform: Platform | None = None
    account_name: str | None = None

    model_config = {"from_attributes": True}


class PolicyFindingReviewIn(BaseModel):
    state: PolicyFindingReviewState
    comment: str | None = None


# ── Policy comparison ──────────────────────────────────────────────────────────

class PolicyCompareRequest(BaseModel):
    asset_ids: list[uuid.UUID] = Field(..., min_length=2, max_length=20)


class PolicyCompareCell(BaseModel):
    asset_id: uuid.UUID
    hostname: str
    value: Any          # the raw setting value (int, bool, None)
    source: str | None  # policy_source label
    is_effective: bool
    is_weak: bool       # True if this value alone triggers a finding


class PolicyCompareRow(BaseModel):
    setting: str        # snake_case field name
    label: str          # human-readable label
    baseline: Any       # recommended value
    values: list[PolicyCompareCell]
    has_inconsistency: bool
    worst_severity: PolicyFindingSeverity | None


class PolicyCompareResult(BaseModel):
    assets: list[AssetRef]
    rows: list[PolicyCompareRow]
    inconsistency_count: int
    worst_severity: PolicyFindingSeverity | None


# ── Summary stats ──────────────────────────────────────────────────────────────

class PasswordPolicySummary(BaseModel):
    total_assets_with_policy: int
    total_policies: int
    effective_policies: int
    assets_with_no_policy: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    open_findings: int
    total_exceptions: int
    privileged_account_exceptions: int
    assets_with_weak_length: int
    assets_with_no_complexity: int
    assets_with_no_lockout: int
    assets_with_reversible_encryption: int
    by_platform: dict[str, int]
    by_policy_source: dict[str, int]
