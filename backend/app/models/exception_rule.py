"""Approved exceptions and suppression rules."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from app.db_types import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._base import created_at, updated_at, uuid_pk
from app.models.enums import ExceptionScope, PrivilegeClass


class PrivilegeException(Base):
    """Auditor-approved exception that suppresses or downgrades a classification."""

    __tablename__ = "privilege_exceptions"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope: Mapped[ExceptionScope] = mapped_column(
        PgEnum(ExceptionScope, name="exception_scope_enum", create_type=False), nullable=False
    )
    target: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # { "account_id": "..." } | { "asset_id": "..." } | { "group_id": "..." } | {}
    rule_keys: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    downgrade_to: Mapped[PrivilegeClass | None] = mapped_column(
        PgEnum(PrivilegeClass, name="privilege_class_enum", create_type=False), nullable=True
    )
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()
