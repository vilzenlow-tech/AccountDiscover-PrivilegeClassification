"""Canonical account model, entitlements, and raw discovery result storage."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from app.db_types import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models._base import created_at, updated_at, uuid_pk
from app.models.enums import (
    ActivityStatus,
    AuthSource,
    EnabledStatus,
    InteractiveStatus,
    Platform,
    PrincipalType,
    PrivilegeClass,
)


class DiscoveryResultRaw(Base):
    """One row per probe executed during a scan.

    Stores the exact command/query, timing, exit code, and output excerpt.
    Large outputs are stored inline via JSONB compression; if output storage
    becomes an issue, `raw_ref` can point to object storage.
    """

    __tablename__ = "discovery_results_raw"

    id: Mapped[uuid.UUID] = uuid_pk()
    job_target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_job_targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    probe_key: Mapped[str] = mapped_column(String(128), nullable=False)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stderr_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    output: Mapped[dict | list | str | None] = mapped_column(JSONB, nullable=True)
    output_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class Account(Base):
    """Canonical account row.

    A unique account is identified by (asset_id, account_name, auth_source).
    """

    __tablename__ = "accounts_normalized"
    __table_args__ = (
        UniqueConstraint(
            "asset_id", "account_name", "auth_source", name="uq_account_per_asset_auth"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    platform: Mapped[Platform] = mapped_column(
        PgEnum(Platform, name="platform_enum", create_type=False), nullable=False, index=True
    )
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    account_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    principal_type: Mapped[PrincipalType] = mapped_column(
        PgEnum(PrincipalType, name="principal_type_enum", create_type=False),
        nullable=False,
        default=PrincipalType.unknown,
    )
    auth_source: Mapped[AuthSource] = mapped_column(
        PgEnum(AuthSource, name="auth_source_enum", create_type=False),
        nullable=False,
        default=AuthSource.unknown,
    )
    enabled_status: Mapped[EnabledStatus] = mapped_column(
        PgEnum(EnabledStatus, name="enabled_status_enum", create_type=False),
        nullable=False,
        default=EnabledStatus.unknown,
    )
    interactive_status: Mapped[InteractiveStatus] = mapped_column(
        PgEnum(InteractiveStatus, name="interactive_status_enum", create_type=False),
        nullable=False,
        default=InteractiveStatus.unknown,
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_source: Mapped[str | None] = mapped_column(String(128), nullable=True)

    privilege_classification: Mapped[PrivilegeClass] = mapped_column(
        PgEnum(PrivilegeClass, name="privilege_class_enum", create_type=False),
        nullable=False,
        default=PrivilegeClass.unknown_review_required,
        index=True,
    )
    privilege_confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0, index=True)

    is_shared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    password_never_expires: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # ── Password / account aging evidence (review §4.3) ───────────────────────
    password_last_changed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    account_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    platform_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # True = positive evidence of zero logins; None = no evidence either way.
    never_logged_in: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # 'mock' | 'live' — provenance stamp (review G-04).
    collection_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    activity_status: Mapped[ActivityStatus] = mapped_column(
        PgEnum(ActivityStatus, name="activity_status_enum", create_type=False),
        nullable=False,
        default=ActivityStatus.no_evidence,
        index=True,
    )

    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    raw_evidence_refs: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # ── Windows interactive classification columns ────────────────────────────
    # Added for Windows-only evidence-based interactive capability detection.
    # All nullable; non-Windows rows leave them NULL.
    interactive_confidence: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    interactive_detection_method: Mapped[str | None] = mapped_column(String(128), nullable=True)
    interactive_evidence_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    interactive_last_observed_logon_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    allows_local_logon: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    allows_remote_interactive_logon: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    allows_service_logon: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    allows_batch_logon: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    allows_network_logon: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    review_required_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Raw PrincipalSource from WinRM (Local / ActiveDirectory / Unknown)
    principal_source: Mapped[str | None] = mapped_column(String(32), nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = updated_at()
    created_at: Mapped[datetime] = created_at()

    asset: Mapped["Asset"] = relationship("Asset", lazy="joined", foreign_keys=[asset_id])

    @property
    def asset_hostname(self) -> str | None:
        return self.asset.hostname if self.asset else None

    entitlements: Mapped[list["AccountEntitlement"]] = relationship(
        "AccountEntitlement", back_populates="account", cascade="all, delete-orphan", lazy="selectin"
    )


class AccountEntitlement(Base):
    """A single entitlement (group, role, sudo rule, grant, server role, db role, etc.).

    Rich enough to cover all platforms with one model. The rules engine reads
    `kind`, `name`, `scope`, and `attributes` to decide what to flag.
    """

    __tablename__ = "account_entitlements"

    id: Mapped[uuid.UUID] = uuid_pk()
    account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("accounts_normalized.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # e.g.: local_group, ad_group, sudo_rule, sudoers_alias, rbac_role, rbac_profile,
    # rbac_authorization, fixed_server_role, fixed_db_role, mongo_role, mysql_grant, ...
    name: Mapped[str] = mapped_column(Text, nullable=False)  # full grant text can exceed 255 chars
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)  # db name, host, OU
    source: Mapped[str | None] = mapped_column(Text, nullable=True)  # direct|inherited via X
    inherited: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    via: Mapped[str | None] = mapped_column(String(512), nullable=True)  # path of inheritance
    attributes: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    account: Mapped[Account] = relationship("Account", back_populates="entitlements")
