"""Add password policy discovery tables.

Creates:
  Enums:
    policy_source_enum
    policy_scope_enum
    policy_finding_severity_enum
    policy_finding_review_state_enum

  Tables:
    password_policies
    account_policy_exceptions
    password_policy_findings

Revision ID: 0008
Revises: 0007
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


# ── Enum helpers ──────────────────────────────────────────────────────────────

def _create_enum(name: str, values: list[str]) -> None:
    e = postgresql.ENUM(*values, name=name)
    e.create(op.get_bind(), checkfirst=True)


def _drop_enum(name: str) -> None:
    postgresql.ENUM(name=name).drop(op.get_bind(), checkfirst=True)


def upgrade() -> None:
    # ── Enums ─────────────────────────────────────────────────────────────────
    _create_enum("policy_source_enum", [
        "local_policy", "domain_policy", "fine_grained_ad",
        "pam_module", "pam_tally", "login_defs",
        "database_native", "external_idp", "unknown",
    ])
    _create_enum("policy_scope_enum", [
        "host", "domain", "database", "database_login",
        "account", "group", "global_",
    ])
    _create_enum("policy_finding_severity_enum", [
        "critical", "high", "medium", "low", "info",
    ])
    _create_enum("policy_finding_review_state_enum", [
        "open", "acknowledged", "risk_accepted", "remediated", "false_positive",
    ])

    # ── password_policies ─────────────────────────────────────────────────────
    op.create_table(
        "password_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("discovery_jobs.id", ondelete="SET NULL"), nullable=True),

        sa.Column("platform", postgresql.ENUM(name="platform_enum", create_type=False),
                  nullable=False),
        sa.Column("policy_source", postgresql.ENUM(name="policy_source_enum", create_type=False),
                  nullable=False),
        sa.Column("policy_scope", postgresql.ENUM(name="policy_scope_enum", create_type=False),
                  nullable=False),

        sa.Column("policy_name", sa.String(255), nullable=True),
        sa.Column("is_effective_policy", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("applies_to", postgresql.JSONB, nullable=True),
        sa.Column("precedence", sa.SmallInteger, nullable=True),

        # Core password settings
        sa.Column("min_password_length", sa.SmallInteger, nullable=True),
        sa.Column("complexity_enabled", sa.Boolean, nullable=True),
        sa.Column("password_history_count", sa.SmallInteger, nullable=True),
        sa.Column("min_password_age_days", sa.SmallInteger, nullable=True),
        sa.Column("max_password_age_days", sa.SmallInteger, nullable=True),
        sa.Column("reversible_encryption_enabled", sa.Boolean, nullable=True),

        # Lockout settings
        sa.Column("lockout_threshold", sa.SmallInteger, nullable=True),
        sa.Column("lockout_duration_minutes", sa.SmallInteger, nullable=True),
        sa.Column("reset_lockout_counter_after_minutes", sa.SmallInteger, nullable=True),

        # Unix / PAM-specific
        sa.Column("dictionary_check_enabled", sa.Boolean, nullable=True),
        sa.Column("min_char_classes", sa.SmallInteger, nullable=True),
        sa.Column("min_uppercase", sa.SmallInteger, nullable=True),
        sa.Column("min_lowercase", sa.SmallInteger, nullable=True),
        sa.Column("min_digits", sa.SmallInteger, nullable=True),
        sa.Column("min_special_chars", sa.SmallInteger, nullable=True),

        # External policy flags
        sa.Column("external_policy_enforced", sa.Boolean, nullable=True),
        sa.Column("requires_external_review", sa.Boolean, nullable=True),

        # Evidence
        sa.Column("evidence_summary", postgresql.JSONB, nullable=True),
        sa.Column("raw_evidence_ref", sa.String(255), nullable=True),
        sa.Column("collection_error", sa.String(512), nullable=True),

        # Metadata
        sa.Column("confidence_score", sa.SmallInteger, nullable=False, server_default="0"),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
                  nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
                  nullable=False),

        sa.UniqueConstraint("asset_id", "policy_source", "policy_name",
                            name="uq_pwpol_asset_source_name"),
    )
    op.create_index("ix_password_policies_asset_id", "password_policies", ["asset_id"])
    op.create_index("ix_password_policies_platform", "password_policies", ["platform"])
    op.create_index("ix_password_policies_policy_source", "password_policies", ["policy_source"])
    op.create_index("ix_password_policies_is_effective", "password_policies", ["is_effective_policy"])
    op.create_index("ix_password_policies_discovered_at", "password_policies", ["discovered_at"])

    # ── account_policy_exceptions ─────────────────────────────────────────────
    op.create_table(
        "account_policy_exceptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("account_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("accounts_normalized.id", ondelete="CASCADE"), nullable=True),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("password_policies.id", ondelete="SET NULL"), nullable=True),

        sa.Column("exception_type", sa.String(64), nullable=False),
        sa.Column("description", sa.String(512), nullable=True),
        sa.Column("effective_policy_source", sa.String(128), nullable=True),
        sa.Column("expected_policy_source", sa.String(128), nullable=True),
        sa.Column("evidence", postgresql.JSONB, nullable=True),

        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
                  nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
                  nullable=False),
    )
    op.create_index("ix_acct_pol_exc_asset_id", "account_policy_exceptions", ["asset_id"])
    op.create_index("ix_acct_pol_exc_account_id", "account_policy_exceptions", ["account_id"])
    op.create_index("ix_acct_pol_exc_exception_type", "account_policy_exceptions", ["exception_type"])
    op.create_index("ix_acct_pol_exc_discovered_at", "account_policy_exceptions", ["discovered_at"])

    # ── password_policy_findings ──────────────────────────────────────────────
    op.create_table(
        "password_policy_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("account_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("accounts_normalized.id", ondelete="CASCADE"), nullable=True),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("password_policies.id", ondelete="CASCADE"), nullable=True),
        sa.Column("exception_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("account_policy_exceptions.id", ondelete="CASCADE"), nullable=True),

        sa.Column("rule_key", sa.String(32), nullable=False),
        sa.Column("severity", postgresql.ENUM(name="policy_finding_severity_enum",
                  create_type=False), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("recommendation", sa.Text, nullable=True),
        sa.Column("affected_scope", sa.String(256), nullable=True),
        sa.Column("evidence", postgresql.JSONB, nullable=True),
        sa.Column("is_exception_finding", sa.Boolean, nullable=False, server_default="false"),

        sa.Column("review_state",
                  postgresql.ENUM(name="policy_finding_review_state_enum", create_type=False),
                  nullable=False, server_default="open"),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_comment", sa.Text, nullable=True),

        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
                  nullable=False),
    )
    op.create_index("ix_pwpol_findings_asset_id", "password_policy_findings", ["asset_id"])
    op.create_index("ix_pwpol_findings_account_id", "password_policy_findings", ["account_id"])
    op.create_index("ix_pwpol_findings_policy_id", "password_policy_findings", ["policy_id"])
    op.create_index("ix_pwpol_findings_rule_key", "password_policy_findings", ["rule_key"])
    op.create_index("ix_pwpol_findings_severity", "password_policy_findings", ["severity"])
    op.create_index("ix_pwpol_findings_review_state", "password_policy_findings", ["review_state"])
    op.create_index("ix_pwpol_findings_is_exception", "password_policy_findings", ["is_exception_finding"])
    op.create_index("ix_pwpol_findings_discovered_at", "password_policy_findings", ["discovered_at"])


def downgrade() -> None:
    op.drop_table("password_policy_findings")
    op.drop_table("account_policy_exceptions")
    op.drop_table("password_policies")

    _drop_enum("policy_finding_review_state_enum")
    _drop_enum("policy_finding_severity_enum")
    _drop_enum("policy_scope_enum")
    _drop_enum("policy_source_enum")
