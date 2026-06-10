"""Privilege findings and reviewer state."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, SmallInteger, String, Text
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from app.db_types import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models._base import created_at, updated_at, uuid_pk
from app.models.enums import PrivilegeClass, ReviewState


class PrivilegeFinding(Base):
    """Append-only record of a rule match for an account in a given job."""

    __tablename__ = "privilege_findings"

    id: Mapped[uuid.UUID] = uuid_pk()
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=True
    )
    connector_agent_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connector_agent_jobs.id", ondelete="CASCADE"), nullable=True, index=True
    )
    account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("accounts_normalized.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("classification_rules.id"), nullable=False
    )
    rule_key: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    rule_version: Mapped[int] = mapped_column(nullable=False, default=1)
    classification: Mapped[PrivilegeClass] = mapped_column(
        PgEnum(PrivilegeClass, name="privilege_class_enum", create_type=False),
        nullable=False,
        index=True,
    )
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    is_winning: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    direct: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    inheritance_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    matched_evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    created_at: Mapped[datetime] = created_at()


class FindingReviewState(Base):
    """Reviewer state transitions for a finding. Append-only."""

    __tablename__ = "finding_review_states"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("privilege_findings.id", ondelete="CASCADE"), nullable=False
    )
    state: Mapped[ReviewState] = mapped_column(
        PgEnum(ReviewState, name="review_state_enum", create_type=False), nullable=False
    )
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = created_at()
