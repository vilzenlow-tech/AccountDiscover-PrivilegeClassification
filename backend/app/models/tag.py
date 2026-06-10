"""Tag and AssetTag ORM models."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from app.db_types import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models._base import created_at, updated_at, uuid_pk
from app.models.enums import TagCategory, TagStatus


class Tag(Base):
    """Managed tag catalog entry."""

    __tablename__ = "tags"
    __table_args__ = (
        UniqueConstraint("tag_name", name="uq_tag_name"),
        UniqueConstraint("tag_code", name="uq_tag_code"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tag_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tag_code: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    category: Mapped[TagCategory] = mapped_column(
        PgEnum(TagCategory, name="tag_category_enum", create_type=False),
        nullable=False,
        default=TagCategory.custom,
        index=True,
    )
    color: Mapped[str] = mapped_column(String(7), nullable=False, default="#6366f1")
    status: Mapped[TagStatus] = mapped_column(
        PgEnum(TagStatus, name="tag_status_enum", create_type=False),
        nullable=False,
        default=TagStatus.active,
        index=True,
    )
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    # Relationship — back-populated from AssetTag
    asset_assignments: Mapped[list["AssetTag"]] = relationship(
        "AssetTag", back_populates="tag", cascade="all, delete-orphan"
    )


class AssetTag(Base):
    """Many-to-many association between Asset and Tag with assignment metadata."""

    __tablename__ = "asset_tags"
    __table_args__ = (
        UniqueConstraint("asset_id", "tag_id", name="uq_asset_tag"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tag_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tags.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    assigned_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    tag: Mapped["Tag"] = relationship("Tag", back_populates="asset_assignments", lazy="joined")
