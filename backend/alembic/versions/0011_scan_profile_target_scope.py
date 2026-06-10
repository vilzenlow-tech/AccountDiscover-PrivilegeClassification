"""Add target scope to scan profiles.

Revision ID: 0011
Revises: 0010
Create Date: 2026-05-11
"""
from alembic import op
import sqlalchemy as sa

from app.db_types import JSONB

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_profiles",
        sa.Column("target_scope", JSONB, nullable=False, server_default=sa.text("'{\"all_enabled\": true}'")),
    )
    op.alter_column("scan_profiles", "target_scope", server_default=None)


def downgrade() -> None:
    op.drop_column("scan_profiles", "target_scope")
