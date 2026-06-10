"""Activity status, password aging, and collection provenance.

Revision ID: 0012
Revises: 0011
Create Date: 2026-06-10
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # PG 12+ permits ADD VALUE inside a transaction as long as the new value
    # is not used within the same migration.
    op.execute("ALTER TYPE enabled_status_enum ADD VALUE IF NOT EXISTS 'expired'")
    op.execute(
        "CREATE TYPE activity_status_enum AS ENUM "
        "('active','inactive_30d','inactive_90d','never_logged_in','no_evidence')"
    )
    op.add_column("accounts_normalized", sa.Column("password_last_changed", sa.DateTime(timezone=True), nullable=True))
    op.add_column("accounts_normalized", sa.Column("password_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("accounts_normalized", sa.Column("account_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("accounts_normalized", sa.Column("platform_created_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("accounts_normalized", sa.Column("never_logged_in", sa.Boolean(), nullable=True))
    op.add_column("accounts_normalized", sa.Column("collection_mode", sa.String(8), nullable=True))
    op.add_column(
        "accounts_normalized",
        sa.Column(
            "activity_status",
            postgresql.ENUM(name="activity_status_enum", create_type=False),
            nullable=False,
            server_default="no_evidence",
        ),
    )
    op.create_index("ix_accounts_normalized_activity_status", "accounts_normalized", ["activity_status"])


def downgrade() -> None:
    op.drop_index("ix_accounts_normalized_activity_status", table_name="accounts_normalized")
    for col in (
        "activity_status", "collection_mode", "never_logged_in", "platform_created_at",
        "account_expires_at", "password_expires_at", "password_last_changed",
    ):
        op.drop_column("accounts_normalized", col)
    op.execute("DROP TYPE activity_status_enum")
    # The 'expired' value stays on enabled_status_enum — Postgres cannot drop enum values.
