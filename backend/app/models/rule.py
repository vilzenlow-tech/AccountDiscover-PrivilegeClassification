"""Classification rules."""
from __future__ import annotations
from datetime import datetime

import uuid

from sqlalchemy import Boolean, Integer, SmallInteger, String, Text
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from app.db_types import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models._base import created_at, updated_at, uuid_pk
from app.models.enums import Platform, PrivilegeClass


class ClassificationRule(Base):
    """A deterministic classification rule.

    `predicate` is a structured, declarative expression, not code. The rules
    engine evaluates it against normalized evidence (account + entitlements).
    """

    __tablename__ = "classification_rules"

    id: Mapped[uuid.UUID] = uuid_pk()
    rule_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    platform: Mapped[Platform | None] = mapped_column(
        PgEnum(Platform, name="platform_enum", create_type=False), nullable=True
    )
    predicate: Mapped[dict] = mapped_column(JSONB, nullable=False)
    classify_as: Mapped[PrivilegeClass] = mapped_column(
        PgEnum(PrivilegeClass, name="privilege_class_enum", create_type=False), nullable=False
    )
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=90)
    risk_modifier: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    explanation_template: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()
