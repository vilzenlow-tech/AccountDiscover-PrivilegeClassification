"""Asset and asset group ORM models."""
from __future__ import annotations
from datetime import datetime

import uuid

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Table, UniqueConstraint
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from app.db_types import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models._base import created_at, updated_at, uuid_pk
from app.models.enums import Platform


asset_group_members = Table(
    "asset_group_members",
    Base.metadata,
    Column("group_id", UUID(as_uuid=True), ForeignKey("asset_groups.id", ondelete="CASCADE"), primary_key=True),
    Column("asset_id", UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("hostname", "instance", name="uq_asset_host_instance"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    instance: Mapped[str | None] = mapped_column(String(128), nullable=True)  # DB instance name
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    environment: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    platform: Mapped[Platform] = mapped_column(
        PgEnum(Platform, name="platform_enum", create_type=False), nullable=False, index=True
    )
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    business_unit: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    criticality: Mapped[str | None] = mapped_column(String(16), nullable=True)  # low/med/high/crit
    connection_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    discovery_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    jump_host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True
    )
    tags: Mapped[dict | None] = mapped_column(type_=__import__("sqlalchemy").JSON, nullable=True)
    connector_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("connectors.id", ondelete="SET NULL"), nullable=True
    )
    # SHA-256 host-key fingerprint (base64, no padding) stored on first SSH
    # connection (TOFU). Verified on every subsequent connection.
    ssh_host_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    groups: Mapped[list["AssetGroup"]] = relationship(
        "AssetGroup", secondary=asset_group_members, back_populates="assets"
    )
    tag_assignments: Mapped[list["AssetTag"]] = relationship(  # type: ignore[name-defined]
        "AssetTag", foreign_keys="AssetTag.asset_id", cascade="all, delete-orphan", lazy="selectin"
    )


class AssetGroup(Base):
    __tablename__ = "asset_groups"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    assets: Mapped[list[Asset]] = relationship(
        "Asset", secondary=asset_group_members, back_populates="groups"
    )
