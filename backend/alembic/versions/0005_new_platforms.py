"""Extend platform_enum and connector_kind_enum with new platform values.

Adds:
  platform_enum     — centos, ubuntu, sles, hpux, oracle_db, postgresql, redis
  connector_kind_enum — oracle, postgresql, redis

Revision ID: 0005
Revises: 0004

Note: ALTER TYPE ... ADD VALUE cannot run inside a transaction in PostgreSQL.
      Alembic's autocommit_block() is used here.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


_NEW_PLATFORMS = ["centos", "ubuntu", "sles", "hpux", "oracle_db", "postgresql", "redis"]
_NEW_CONNECTOR_KINDS = ["oracle", "postgresql", "redis"]


def upgrade() -> None:
    # ALTER TYPE … ADD VALUE must execute outside a transaction block.
    connection = op.get_bind()
    connection.execute(sa.text("COMMIT"))

    for val in _NEW_PLATFORMS:
        connection.execute(
            sa.text(f"ALTER TYPE platform_enum ADD VALUE IF NOT EXISTS '{val}'")
        )
    for val in _NEW_CONNECTOR_KINDS:
        connection.execute(
            sa.text(f"ALTER TYPE connector_kind_enum ADD VALUE IF NOT EXISTS '{val}'")
        )


def downgrade() -> None:
    # PostgreSQL does not support removing values from an ENUM type without
    # recreating it.  This migration is intentionally non-reversible.
    pass
