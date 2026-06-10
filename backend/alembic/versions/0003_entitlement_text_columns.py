"""Widen account_entitlements name/scope/source to Text.

Revision ID: 0003
Revises: 0002
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("account_entitlements", "name",   existing_type=sa.String(255), type_=sa.Text, existing_nullable=False)
    op.alter_column("account_entitlements", "scope",  existing_type=sa.String(255), type_=sa.Text, existing_nullable=True)
    op.alter_column("account_entitlements", "source", existing_type=sa.String(255), type_=sa.Text, existing_nullable=True)


def downgrade() -> None:
    op.alter_column("account_entitlements", "name",   existing_type=sa.Text, type_=sa.String(255), existing_nullable=False)
    op.alter_column("account_entitlements", "scope",  existing_type=sa.Text, type_=sa.String(255), existing_nullable=True)
    op.alter_column("account_entitlements", "source", existing_type=sa.Text, type_=sa.String(255), existing_nullable=True)
