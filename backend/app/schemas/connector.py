"""Connector and credential DTOs."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field, SecretStr, computed_field

from app.models.enums import ConnectorKind, VaultBackend


class CredentialIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    vault_backend: VaultBackend
    vault_ref: str
    username: str
    auth_method: str  # password|key|token|cert
    rotation_policy_days: int | None = None
    is_active: bool = True
    # Only used when vault_backend=local. Write-only; never echoed back.
    secret_material: SecretStr | None = None


class CredentialOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    vault_backend: VaultBackend
    vault_ref: str
    username: str
    auth_method: str
    rotation_policy_days: int | None
    last_rotated_at: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    @computed_field  # type: ignore[misc]
    @property
    def rotation_overdue(self) -> bool:
        """True when the credential has exceeded its rotation policy age."""
        if not self.rotation_policy_days or not self.last_rotated_at:
            return False
        try:
            rotated = datetime.fromisoformat(self.last_rotated_at)
            if rotated.tzinfo is None:
                rotated = rotated.replace(tzinfo=UTC)
            age_days = (datetime.now(UTC) - rotated).days
            return age_days > self.rotation_policy_days
        except (ValueError, TypeError):
            return False

    model_config = {"from_attributes": True}


class ConnectorIn(BaseModel):
    name: str
    kind: ConnectorKind
    default_port: int | None = None
    options: dict | None = None
    credential_id: uuid.UUID | None = None
    proxy_host: str | None = None
    proxy_port: int | None = None
    is_active: bool = True


class ConnectorOut(ConnectorIn):
    id: uuid.UUID
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TestConnectionRequest(BaseModel):
    asset_id: uuid.UUID
    connector_id: uuid.UUID | None = None
    credential_id: uuid.UUID | None = None


class TestConnectionResult(BaseModel):
    success: bool
    latency_ms: int
    message: str
    details: dict | None = None
