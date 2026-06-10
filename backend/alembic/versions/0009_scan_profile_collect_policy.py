"""Add collect_password_policy to scan_profiles.

Revision ID: 0009
Revises: 0008
Create Date: 2026-04-28
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_profiles",
        sa.Column(
            "collect_password_policy",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_profiles", "collect_password_policy")
