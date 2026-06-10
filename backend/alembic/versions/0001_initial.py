"""Initial schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-01-01
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


# Enum helpers --------------------------------------------------------------
PLATFORM = ("rhel", "solaris", "aix", "windows", "mysql", "mssql", "mongodb")
CONNECTOR_KIND = ("ssh", "winrm", "wmi", "mysql", "mssql", "mongodb")
AUTH_SOURCE = ("local", "ad", "ldap", "db_native", "os_integrated", "unknown")
PRINCIPAL_TYPE = ("human", "service", "shared", "built_in", "system", "application", "unknown")
ENABLED_STATUS = ("enabled", "disabled", "locked", "unknown")
INTERACTIVE_STATUS = ("interactive", "non_interactive", "unknown")
PRIVILEGE_CLASS = (
    "full_admin",
    "admin_equivalent",
    "operator_high_impact",
    "delegated_admin",
    "privileged_service",
    "sensitive_non_admin",
    "dormant_privileged",
    "non_privileged",
    "unknown_review_required",
)
JOB_STATUS = (
    "pending",
    "queued",
    "running",
    "success",
    "partial_success",
    "failed",
    "timed_out",
    "unreachable",
    "auth_failed",
    "cancelled",
)
SCAN_MODE = ("safe", "deep")
REVIEW_STATE = ("unreviewed", "acknowledged", "risk_accepted", "remediated", "false_positive")
EXCEPTION_SCOPE = ("account", "asset", "group", "global")
VAULT_BACKEND = ("local", "cyberark", "hashicorp", "azure", "aws")


def upgrade() -> None:
    # --- enums ---
    def make_enum(name: str, values: tuple[str, ...]) -> sa.Enum:
        return postgresql.ENUM(*values, name=name, create_type=False)

    platform = make_enum("platform_enum", PLATFORM)
    connector_kind = make_enum("connector_kind_enum", CONNECTOR_KIND)
    auth_source = make_enum("auth_source_enum", AUTH_SOURCE)
    principal_type = make_enum("principal_type_enum", PRINCIPAL_TYPE)
    enabled_status = make_enum("enabled_status_enum", ENABLED_STATUS)
    interactive_status = make_enum("interactive_status_enum", INTERACTIVE_STATUS)
    privilege_class = make_enum("privilege_class_enum", PRIVILEGE_CLASS)
    job_status = make_enum("job_status_enum", JOB_STATUS)
    scan_mode = make_enum("scan_mode_enum", SCAN_MODE)
    review_state = make_enum("review_state_enum", REVIEW_STATE)
    exception_scope = make_enum("exception_scope_enum", EXCEPTION_SCOPE)
    vault_backend = make_enum("vault_backend_enum", VAULT_BACKEND)

    for e in (
        platform,
        connector_kind,
        auth_source,
        principal_type,
        enabled_status,
        interactive_status,
        privilege_class,
        job_status,
        scan_mode,
        review_state,
        exception_scope,
        vault_backend,
    ):
        e.create(op.get_bind(), checkfirst=True)

    # --- users & roles ---
    op.create_table(
        "roles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("description", sa.String(255), nullable=True),
    )
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("must_change_password", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("failed_login_attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "user_roles",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    )

    # --- assets ---
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False, index=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("instance", sa.String(128), nullable=True),
        sa.Column("port", sa.Integer, nullable=True),
        sa.Column("environment", sa.String(32), nullable=True, index=True),
        sa.Column("platform", platform, nullable=False, index=True),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("business_unit", sa.String(128), nullable=True, index=True),
        sa.Column("criticality", sa.String(16), nullable=True),
        sa.Column("connection_type", sa.String(32), nullable=True),
        sa.Column("discovery_enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("jump_host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("tags", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("hostname", "instance", name="uq_asset_host_instance"),
    )
    op.create_table(
        "asset_groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "asset_group_members",
        sa.Column("group_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("asset_groups.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    )

    # --- credentials & connectors ---
    op.create_table(
        "credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.String(512), nullable=True),
        sa.Column("vault_backend", vault_backend, nullable=False),
        sa.Column("vault_ref", sa.String(512), nullable=False),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("auth_method", sa.String(32), nullable=False),
        sa.Column("rotation_policy_days", sa.Integer, nullable=True),
        sa.Column("last_rotated_at", sa.String(40), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "connectors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("kind", connector_kind, nullable=False),
        sa.Column("default_port", sa.Integer, nullable=True),
        sa.Column("options", postgresql.JSONB, nullable=True),
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True),
        sa.Column("proxy_host", sa.String(255), nullable=True),
        sa.Column("proxy_port", sa.Integer, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # --- scan profiles, blackout, schedules ---
    op.create_table(
        "scan_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.String(512), nullable=True),
        sa.Column("platforms", postgresql.JSONB, nullable=False),
        sa.Column("mode", scan_mode, nullable=False, server_default="safe"),
        sa.Column("probe_selection", postgresql.JSONB, nullable=True),
        sa.Column("timeout_seconds", sa.Integer, nullable=False, server_default="300"),
        sa.Column("retry_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("concurrency_limit", sa.Integer, nullable=False, server_default="10"),
        sa.Column("throttle_ms", sa.Integer, nullable=False, server_default="0"),
        sa.Column("credential_strategy", sa.String(32), nullable=False, server_default="asset"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "scan_blackout_windows",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("cron", sa.String(64), nullable=False),
        sa.Column("duration_minutes", sa.Integer, nullable=False, server_default="60"),
        sa.Column("scope", sa.String(32), nullable=False, server_default="global"),
        sa.Column("tags", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "scheduled_scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.String(512), nullable=True),
        sa.Column("cron", sa.String(64), nullable=False),
        sa.Column("profile_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_profiles.id"), nullable=False),
        sa.Column("scope", postgresql.JSONB, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requires_approval", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # --- discovery jobs / targets ---
    op.create_table(
        "discovery_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scope_description", sa.String(255), nullable=False),
        sa.Column("scope", postgresql.JSONB, nullable=False),
        sa.Column("profile_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_profiles.id"), nullable=True),
        sa.Column("triggered_by", sa.String(255), nullable=True),
        sa.Column("triggered_kind", sa.String(32), nullable=False, server_default="manual"),
        sa.Column("status", job_status, nullable=False, server_default="pending", index=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("totals", postgresql.JSONB, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("cancelled_reason", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "discovery_job_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("platform", platform, nullable=False),
        sa.Column("status", job_status, nullable=False, server_default="pending", index=True),
        sa.Column("attempt", sa.Integer, nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("error_bucket", sa.String(64), nullable=True),
        sa.Column("error_detail", sa.Text, nullable=True),
        sa.Column("stats", postgresql.JSONB, nullable=True),
    )
    op.create_table(
        "bulk_import_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("filename", sa.String(255), nullable=True),
        sa.Column("uploaded_by", sa.String(255), nullable=True),
        sa.Column("total_rows", sa.Integer, nullable=False, server_default="0"),
        sa.Column("imported_rows", sa.Integer, nullable=False, server_default="0"),
        sa.Column("duplicate_rows", sa.Integer, nullable=False, server_default="0"),
        sa.Column("invalid_rows", sa.Integer, nullable=False, server_default="0"),
        sa.Column("errors", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # --- raw results & accounts ---
    op.create_table(
        "discovery_results_raw",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job_target_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("discovery_job_targets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("probe_key", sa.String(128), nullable=False),
        sa.Column("command", sa.Text, nullable=False),
        sa.Column("exit_code", sa.Integer, nullable=True),
        sa.Column("stderr_excerpt", sa.Text, nullable=True),
        sa.Column("output", postgresql.JSONB, nullable=True),
        sa.Column("output_hash", sa.String(64), nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )
    op.create_table(
        "accounts_normalized",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("platform", platform, nullable=False, index=True),
        sa.Column("source_type", sa.String(64), nullable=False),
        sa.Column("account_name", sa.String(255), nullable=False, index=True),
        sa.Column("principal_type", principal_type, nullable=False, server_default="unknown"),
        sa.Column("auth_source", auth_source, nullable=False, server_default="unknown"),
        sa.Column("enabled_status", enabled_status, nullable=False, server_default="unknown"),
        sa.Column("interactive_status", interactive_status, nullable=False, server_default="unknown"),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_source", sa.String(128), nullable=True),
        sa.Column("privilege_classification", privilege_class, nullable=False, server_default="unknown_review_required", index=True),
        sa.Column("privilege_confidence", sa.SmallInteger, nullable=False, server_default="0"),
        sa.Column("risk_score", sa.SmallInteger, nullable=False, server_default="0", index=True),
        sa.Column("is_shared", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("password_never_expires", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("evidence_summary", postgresql.JSONB, nullable=True),
        sa.Column("raw_evidence_refs", postgresql.JSONB, nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("asset_id", "account_name", "auth_source", name="uq_account_per_asset_auth"),
    )
    op.create_table(
        "account_entitlements",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("accounts_normalized.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("kind", sa.String(64), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False, index=True),
        sa.Column("scope", sa.String(255), nullable=True),
        sa.Column("source", sa.String(255), nullable=True),
        sa.Column("inherited", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("via", sa.String(512), nullable=True),
        sa.Column("attributes", postgresql.JSONB, nullable=True),
    )

    # --- rules & findings ---
    op.create_table(
        "classification_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_key", sa.String(128), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("platform", platform, nullable=True),
        sa.Column("predicate", postgresql.JSONB, nullable=False),
        sa.Column("classify_as", privilege_class, nullable=False),
        sa.Column("confidence", sa.SmallInteger, nullable=False, server_default="90"),
        sa.Column("risk_modifier", sa.SmallInteger, nullable=False, server_default="0"),
        sa.Column("explanation_template", sa.Text, nullable=False),
        sa.Column("priority", sa.Integer, nullable=False, server_default="100"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "privilege_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("accounts_normalized.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("classification_rules.id"), nullable=False),
        sa.Column("rule_key", sa.String(128), nullable=False, index=True),
        sa.Column("rule_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("classification", privilege_class, nullable=False, index=True),
        sa.Column("confidence", sa.SmallInteger, nullable=False, server_default="0"),
        sa.Column("risk_score", sa.SmallInteger, nullable=False, server_default="0"),
        sa.Column("is_winning", sa.Boolean, nullable=False, server_default=sa.false(), index=True),
        sa.Column("direct", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("inheritance_path", sa.String(1024), nullable=True),
        sa.Column("explanation", sa.Text, nullable=False),
        sa.Column("matched_evidence", postgresql.JSONB, nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "finding_review_states",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("privilege_findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("state", review_state, nullable=False),
        sa.Column("comment", sa.Text, nullable=True),
        sa.Column("reviewer", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # --- exceptions ---
    op.create_table(
        "privilege_exceptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("scope", exception_scope, nullable=False),
        sa.Column("target", postgresql.JSONB, nullable=False),
        sa.Column("rule_keys", postgresql.JSONB, nullable=True),
        sa.Column("downgrade_to", privilege_class, nullable=True),
        sa.Column("approved_by", sa.String(255), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # --- audit & notifications ---
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("actor_id", sa.String(255), nullable=True, index=True),
        sa.Column("actor_email", sa.String(255), nullable=True),
        sa.Column("action", sa.String(128), nullable=False, index=True),
        sa.Column("subject_type", sa.String(64), nullable=True),
        sa.Column("subject_id", sa.String(64), nullable=True),
        sa.Column("ip", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(255), nullable=True),
        sa.Column("context", postgresql.JSONB, nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )
    op.create_table(
        "notifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(64), nullable=False, index=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="info"),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("body", sa.Text, nullable=True),
        sa.Column("context", postgresql.JSONB, nullable=True),
        sa.Column("acknowledged", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    for t in (
        "notifications",
        "audit_logs",
        "privilege_exceptions",
        "finding_review_states",
        "privilege_findings",
        "classification_rules",
        "account_entitlements",
        "accounts_normalized",
        "discovery_results_raw",
        "bulk_import_jobs",
        "discovery_job_targets",
        "discovery_jobs",
        "scheduled_scans",
        "scan_blackout_windows",
        "scan_profiles",
        "connectors",
        "credentials",
        "asset_group_members",
        "asset_groups",
        "assets",
        "user_roles",
        "users",
        "roles",
    ):
        op.drop_table(t)

    for e in (
        "vault_backend_enum",
        "exception_scope_enum",
        "review_state_enum",
        "scan_mode_enum",
        "job_status_enum",
        "privilege_class_enum",
        "interactive_status_enum",
        "enabled_status_enum",
        "principal_type_enum",
        "auth_source_enum",
        "connector_kind_enum",
        "platform_enum",
    ):
        op.execute(f"DROP TYPE IF EXISTS {e}")
