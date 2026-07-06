"""User management metadata.

Revision ID: 0013
Revises: 0012
Create Date: 2026-06-28
"""
from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("username", sa.String(80), nullable=True))
    op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("created_by", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("updated_by", sa.String(255), nullable=True))
    op.create_unique_constraint("uq_users_username", "users", ["username"])


def downgrade() -> None:
    op.drop_constraint("uq_users_username", "users", type_="unique")
    for column in ("updated_by", "created_by", "last_login_at", "username"):
        op.drop_column("users", column)
