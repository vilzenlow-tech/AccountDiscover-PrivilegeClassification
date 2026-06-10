"""Asset DTOs."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import Platform
from app.schemas.tag import TagSummary


class AssetIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: str | None = None
    instance: str | None = None
    port: int | None = None
    environment: str | None = None
    platform: Platform
    owner: str | None = None
    business_unit: str | None = None
    criticality: str | None = None
    connection_type: str | None = None
    discovery_enabled: bool = True
    jump_host_id: uuid.UUID | None = None
    tags: dict | None = None
    connector_id: uuid.UUID | None = None


class AssetGroupSummary(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None = None
    asset_count: int = 0


class AssetOut(AssetIn):
    id: uuid.UUID
    connector_name: str | None = None
    tag_summaries: list[TagSummary] = []
    group_summaries: list[AssetGroupSummary] = []
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class BulkImportResult(BaseModel):
    total_rows: int
    imported_rows: int
    duplicate_rows: int
    invalid_rows: int
    errors: list[dict]
    job_id: uuid.UUID


class AssetGroupIn(BaseModel):
    name: str
    description: str | None = None
    asset_ids: list[uuid.UUID] = []


class AssetGroupOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None = None
    asset_ids: list[uuid.UUID] = []
    asset_count: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class AssetGroupUpdate(BaseModel):
    name: str
    description: str | None = None
    asset_ids: list[uuid.UUID] = []
