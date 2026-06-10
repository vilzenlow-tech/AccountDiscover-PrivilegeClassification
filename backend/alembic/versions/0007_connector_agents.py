"""Add connector agent framework.

Creates:
  connector_agent_status_enum
  connector_agent_job_type_enum
  connector_agent_job_status_enum
  connector_agents
  connector_enrollment_tokens
  connector_agent_settings
  connector_agent_heartbeats
  connector_agent_jobs
  connector_agent_results
  connector_agent_result_chunks
  connector_agent_logs

Revision ID: 0007
Revises: 0006
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

# ── Enum helpers ──────────────────────────────────────────────────────────────

def _create_enum(name: str, values: list[str]) -> None:
    e = postgresql.ENUM(*values, name=name)
    e.create(op.get_bind(), checkfirst=True)

def _drop_enum(name: str) -> None:
    postgresql.ENUM(name=name).drop(op.get_bind(), checkfirst=True)


def upgrade() -> None:
    _create_enum("connector_agent_status_enum", [
        "pending", "approved", "online", "offline", "stale",
        "disabled", "revoked", "error",
    ])
    _create_enum("connector_agent_job_type_enum", [
        "discovery_basic", "discovery_credentialed", "bulk_scan",
        "scheduled", "on_demand", "config_sync", "health_check",
    ])
    _create_enum("connector_agent_job_status_enum", [
        "pending", "accepted", "running", "partial_success",
        "success", "failed", "cancelled", "timed_out",
    ])

    # ── connector_agents ──────────────────────────────────────────────────────
    op.create_table(
        "connector_agents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.String(512), nullable=True),

        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("os_platform", sa.String(64), nullable=True),
        sa.Column("os_version", sa.String(128), nullable=True),
        sa.Column("agent_version", sa.String(32), nullable=True),

        sa.Column("site", sa.String(128), nullable=True),
        sa.Column("location", sa.String(128), nullable=True),
        sa.Column("environment", sa.String(64), nullable=True),

        sa.Column("token_hash", sa.String(128), nullable=True),
        sa.Column("token_prefix", sa.String(12), nullable=True),
        sa.Column("cert_serial", sa.String(128), nullable=True),
        sa.Column("cert_fingerprint", sa.String(128), nullable=True),
        sa.Column("cert_expires_at", sa.DateTime(timezone=True), nullable=True),

        sa.Column("status",
            postgresql.ENUM("pending","approved","online","offline","stale","disabled","revoked","error",
                            name="connector_agent_status_enum", create_type=False),
            nullable=False, server_default="pending"),
        sa.Column("is_enabled", sa.Boolean, nullable=False, server_default="true"),

        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),

        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(255), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(512), nullable=True),

        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("updated_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # ── connector_enrollment_tokens ───────────────────────────────────────────
    op.create_table(
        "connector_enrollment_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("connector_agents.id", ondelete="CASCADE"), nullable=True),
        sa.Column("token_hash", sa.String(128), nullable=False),
        sa.Column("token_prefix", sa.String(12), nullable=False),
        sa.Column("expected_hostname", sa.String(255), nullable=True),
        sa.Column("expected_site", sa.String(128), nullable=True),
        sa.Column("expected_environment", sa.String(64), nullable=True),
        sa.Column("auto_approve", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_used", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("is_revoked", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # ── connector_agent_settings ──────────────────────────────────────────────
    op.create_table(
        "connector_agent_settings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("connector_agents.id", ondelete="CASCADE"), nullable=False, unique=True),

        sa.Column("heartbeat_interval_seconds", sa.Integer, nullable=False, server_default="30"),
        sa.Column("job_poll_interval_seconds", sa.Integer, nullable=False, server_default="10"),
        sa.Column("config_refresh_interval_seconds", sa.Integer, nullable=False, server_default="3600"),

        sa.Column("retry_max_attempts", sa.Integer, nullable=False, server_default="5"),
        sa.Column("retry_backoff_base_seconds", sa.Integer, nullable=False, server_default="2"),
        sa.Column("retry_backoff_max_seconds", sa.Integer, nullable=False, server_default="300"),

        sa.Column("job_timeout_seconds", sa.Integer, nullable=False, server_default="3600"),
        sa.Column("max_concurrent_jobs", sa.SmallInteger, nullable=False, server_default="2"),
        sa.Column("result_chunk_size_mb", sa.Integer, nullable=False, server_default="50"),

        sa.Column("offline_queue_max_mb", sa.Integer, nullable=False, server_default="500"),
        sa.Column("result_retention_hours", sa.Integer, nullable=False, server_default="72"),
        sa.Column("log_retention_days", sa.Integer, nullable=False, server_default="30"),

        sa.Column("verify_console_certificate", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("verify_console_fingerprint", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("console_fingerprint", sa.String(128), nullable=True),
        sa.Column("token_rotation_days", sa.Integer, nullable=False, server_default="90"),

        sa.Column("proxy_config", postgresql.JSONB, nullable=True),
        sa.Column("log_level", sa.String(16), nullable=False, server_default="info"),
        sa.Column("sanitize_secrets_in_logs", sa.Boolean, nullable=False, server_default="true"),

        sa.Column("allowed_scan_profiles", postgresql.JSONB, nullable=True),
        sa.Column("allowed_scan_modes", postgresql.JSONB, nullable=True),
        sa.Column("allowed_environments", postgresql.JSONB, nullable=True),
        sa.Column("allowed_tags", postgresql.JSONB, nullable=True),
        sa.Column("denied_tags", postgresql.JSONB, nullable=True),
        sa.Column("max_targets_per_job", sa.Integer, nullable=False, server_default="100"),

        sa.Column("auto_upgrade", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("upgrade_channel", sa.String(32), nullable=False, server_default="stable"),

        sa.Column("updated_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # ── connector_agent_heartbeats ────────────────────────────────────────────
    op.create_table(
        "connector_agent_heartbeats",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("connector_agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("agent_version", sa.String(32), nullable=True),
        sa.Column("status", sa.String(32), nullable=True),
        sa.Column("active_jobs", sa.Integer, nullable=False, server_default="0"),
        sa.Column("queued_results", sa.Integer, nullable=False, server_default="0"),
        sa.Column("queue_size_mb", sa.Float, nullable=True),
        sa.Column("cpu_percent", sa.Float, nullable=True),
        sa.Column("memory_mb", sa.Float, nullable=True),
        sa.Column("disk_free_mb", sa.Float, nullable=True),
        sa.Column("error_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("payload", postgresql.JSONB, nullable=True),
    )
    op.create_index("ix_connector_agent_heartbeats_agent_received",
                    "connector_agent_heartbeats", ["agent_id", "received_at"])

    # ── connector_agent_results (create before jobs — jobs FK to results) ─────
    op.create_table(
        "connector_agent_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("connector_agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("chunk_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("chunks_received", sa.Integer, nullable=False, server_default="0"),
        sa.Column("is_complete", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("content_type", sa.String(64), nullable=False, server_default="application/json"),
        sa.Column("content_encoding", sa.String(32), nullable=False, server_default="gzip"),
        sa.Column("checksum", sa.String(128), nullable=True),
        sa.Column("size_bytes", sa.Integer, nullable=False, server_default="0"),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("processing_error", sa.Text, nullable=True),
        sa.Column("accounts_discovered", sa.Integer, nullable=False, server_default="0"),
        sa.Column("assets_scanned", sa.Integer, nullable=False, server_default="0"),
        sa.Column("payload", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index("ix_connector_agent_results_agent_job",
                    "connector_agent_results", ["agent_id", "job_id"])

    # ── connector_agent_jobs ──────────────────────────────────────────────────
    op.create_table(
        "connector_agent_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("connector_agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("discovery_job_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("discovery_jobs.id", ondelete="SET NULL"), nullable=True),

        sa.Column("job_type",
            postgresql.ENUM("discovery_basic","discovery_credentialed","bulk_scan",
                            "scheduled","on_demand","config_sync","health_check",
                            name="connector_agent_job_type_enum", create_type=False),
            nullable=False, server_default="on_demand"),
        sa.Column("status",
            postgresql.ENUM("pending","accepted","running","partial_success",
                            "success","failed","cancelled","timed_out",
                            name="connector_agent_job_status_enum", create_type=False),
            nullable=False, server_default="pending"),

        sa.Column("payload", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("payload_checksum", sa.String(128), nullable=True),
        sa.Column("priority", sa.Integer, nullable=False, server_default="50"),

        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),

        sa.Column("progress_pct", sa.Integer, nullable=False, server_default="0"),
        sa.Column("progress_message", sa.String(512), nullable=True),
        sa.Column("targets_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("targets_done", sa.Integer, nullable=False, server_default="0"),
        sa.Column("targets_failed", sa.Integer, nullable=False, server_default="0"),

        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("result_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("connector_agent_results.id", ondelete="SET NULL"), nullable=True),

        sa.Column("cancel_requested_by", sa.String(255), nullable=True),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),

        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index("ix_connector_agent_jobs_agent_status",
                    "connector_agent_jobs", ["agent_id", "status"])
    op.create_index("ix_connector_agent_jobs_status",
                    "connector_agent_jobs", ["status"])

    # ── connector_agent_result_chunks ─────────────────────────────────────────
    op.create_table(
        "connector_agent_result_chunks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("result_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("connector_agent_results.id", ondelete="CASCADE"), nullable=False),
        sa.Column("chunk_index", sa.Integer, nullable=False),
        sa.Column("data", sa.Text, nullable=False),
        sa.Column("checksum", sa.String(128), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_connector_result_chunks_result_idx",
                    "connector_agent_result_chunks", ["result_id", "chunk_index"], unique=True)

    # ── connector_agent_logs ──────────────────────────────────────────────────
    op.create_table(
        "connector_agent_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("connector_agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("level", sa.String(16), nullable=False, server_default="info"),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("context", postgresql.JSONB, nullable=True),
        sa.Column("agent_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_connector_agent_logs_agent_received",
                    "connector_agent_logs", ["agent_id", "received_at"])


def downgrade() -> None:
    op.drop_table("connector_agent_logs")
    op.drop_table("connector_agent_result_chunks")
    op.drop_table("connector_agent_jobs")
    op.drop_table("connector_agent_results")
    op.drop_table("connector_agent_heartbeats")
    op.drop_table("connector_agent_settings")
    op.drop_table("connector_enrollment_tokens")
    op.drop_table("connector_agents")
    _drop_enum("connector_agent_job_status_enum")
    _drop_enum("connector_agent_job_type_enum")
    _drop_enum("connector_agent_status_enum")
