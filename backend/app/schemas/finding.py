"""Finding and rule DTOs."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import ExceptionScope, Platform, PrivilegeClass, ReviewState


class FindingOut(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID | None
    connector_agent_job_id: uuid.UUID | None = None
    account_id: uuid.UUID
    rule_id: uuid.UUID
    rule_key: str
    rule_version: int
    classification: PrivilegeClass
    confidence: int
    risk_score: int
    is_winning: bool
    direct: bool
    inheritance_path: str | None
    explanation: str
    matched_evidence: dict | None
    evaluated_at: datetime
    latest_review_state: ReviewState | None = None
    latest_review_comment: str | None = None
    latest_review_reviewer: str | None = None
    latest_review_at: datetime | None = None
    account_name: str | None = None
    normalized_account_name: str | None = None
    asset_id: uuid.UUID | None = None
    asset_hostname: str | None = None
    asset_ip_address: str | None = None
    platform: Platform | None = None
    application_tag: str | None = None
    environment: str | None = None
    account_source: str | None = None
    account_type: str | None = None
    enabled_status: str | None = None
    interactive_status: str | None = None
    last_login: datetime | None = None
    activity_status: str | None = None
    pam_managed: bool | None = None
    owner: str | None = None
    password_never_expires: bool | None = None
    is_shared: bool | None = None
    discovered_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class ReviewStateIn(BaseModel):
    finding_id: uuid.UUID
    state: ReviewState
    comment: str | None = None


class RuleIn(BaseModel):
    rule_key: str = Field(min_length=1, max_length=128)
    name: str
    description: str | None = None
    platform: Platform | None = None
    predicate: dict
    classify_as: PrivilegeClass
    confidence: int = 90
    risk_modifier: int = 0
    explanation_template: str
    priority: int = 100
    enabled: bool = True


class RuleOut(RuleIn):
    id: uuid.UUID
    version: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ExceptionIn(BaseModel):
    name: str
    description: str | None = None
    scope: ExceptionScope
    target: dict
    rule_keys: list[str] | None = None
    downgrade_to: PrivilegeClass | None = None
    approved_by: str
    approved_at: datetime
    expires_at: datetime | None = None
    active: bool = True


class ExceptionOut(ExceptionIn):
    id: uuid.UUID
    active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
