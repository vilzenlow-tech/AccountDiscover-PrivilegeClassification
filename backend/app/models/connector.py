"""Connector and credential reference models.

Credential secrets are NEVER stored here. This row is only metadata; the
secret material lives in the configured vault and is fetched at scan launch.
"""
from __future__ import annotations
from datetime import datetime

import uuid

from sqlalchemy import Boolean, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from app.db_types import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models._base import created_at, updated_at, uuid_pk
from app.models.enums import ConnectorKind, VaultBackend


class Credential(Base):
    """Credential reference.

    `vault_ref` is an opaque pointer (e.g. `cyberark://safe/account` or
    `vault://kv/data/adpct/windows-prod`). The actual secret is resolved at
    runtime via the credential vault service.
    """

    __tablename__ = "credentials"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    vault_backend: Mapped[VaultBackend] = mapped_column(
        PgEnum(VaultBackend, name="vault_backend_enum", create_type=False), nullable=False
    )
    vault_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_method: Mapped[str] = mapped_column(String(32), nullable=False)  # password|key|token|cert
    rotation_policy_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_rotated_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()


class Connector(Base):
    """A configured discovery connector for a platform.

    A connector bundles "how to connect" (kind + options) with a default
    credential. Per-asset scoped overrides are supported on the asset side.
    """

    __tablename__ = "connectors"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    kind: Mapped[ConnectorKind] = mapped_column(
        PgEnum(ConnectorKind, name="connector_kind_enum", create_type=False), nullable=False
    )
    default_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    options: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True
    )
    proxy_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    proxy_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    credential: Mapped[Credential | None] = relationship("Credential", lazy="joined")
