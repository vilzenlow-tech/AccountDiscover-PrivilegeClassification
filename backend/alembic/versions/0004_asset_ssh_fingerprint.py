"""Add ssh_host_fingerprint column to assets for TOFU host-key verification.

Revision ID: 0004
Revises: 0003
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("ssh_host_fingerprint", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assets", "ssh_host_fingerprint")
