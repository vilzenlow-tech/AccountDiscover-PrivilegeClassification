"""Portable SQLAlchemy column types.

Production uses PostgreSQL-specific types (JSONB, native UUID) for
efficiency.  Tests run against SQLite, which has no JSONB or native UUID
support.  This module provides TypeDecorators that transparently switch
between implementations so the same ORM models work on both dialects.

Usage in models
---------------
  from app.db_types import JSONB, UUID
  # Use exactly as you would use the pg-dialect equivalents.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID


class JSONB(sa.TypeDecorator):
    """JSONB on PostgreSQL, plain JSON on every other dialect (e.g. SQLite)."""

    impl = sa.JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: sa.engine.Dialect) -> sa.types.TypeEngine:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_JSONB())
        return dialect.type_descriptor(sa.JSON())

    def process_bind_param(self, value, dialect):  # type: ignore[override]
        return value

    def process_result_value(self, value, dialect):  # type: ignore[override]
        return value


class UUID(sa.TypeDecorator):
    """Native UUID on PostgreSQL, CHAR(36) on SQLite (stored as string)."""

    impl = sa.String
    cache_ok = True

    def __init__(self, as_uuid: bool = True, **kwargs):  # noqa: D107
        self.as_uuid = as_uuid
        super().__init__(length=36, **kwargs)

    def load_dialect_impl(self, dialect: sa.engine.Dialect) -> sa.types.TypeEngine:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=self.as_uuid))
        return dialect.type_descriptor(sa.String(36))

    def process_bind_param(self, value, dialect):  # type: ignore[override]
        if value is None:
            return value
        if dialect.name == "postgresql":
            return value  # let psycopg handle it
        import uuid as _uuid
        return str(value) if isinstance(value, _uuid.UUID) else value

    def process_result_value(self, value, dialect):  # type: ignore[override]
        if value is None:
            return value
        if self.as_uuid and dialect.name != "postgresql":
            import uuid as _uuid
            try:
                return _uuid.UUID(value)
            except (ValueError, AttributeError):
                return value
        return value
