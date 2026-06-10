"""Tag DTOs."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import TagCategory, TagStatus


class TagIn(BaseModel):
    tag_name: str = Field(min_length=1, max_length=100)
    tag_code: str | None = Field(default=None, max_length=50)
    description: str | None = Field(default=None, max_length=512)
    category: TagCategory = TagCategory.custom
    color: str = Field(default="#6366f1", pattern=r"^#[0-9a-fA-F]{6}$")
    status: TagStatus = TagStatus.active


class TagOut(TagIn):
    id: uuid.UUID
    usage_count: int = 0
    created_by: str | None = None
    updated_by: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TagStatusPatch(BaseModel):
    status: TagStatus


class TagSummary(BaseModel):
    """Lightweight tag representation embedded in Asset responses."""
    id: uuid.UUID
    tag_name: str
    tag_code: str | None
    color: str
    category: str
    assigned_at: datetime | None = None
    assigned_by: str | None = None

    model_config = {"from_attributes": True}


class AssetTagsAssign(BaseModel):
    tag_ids: list[uuid.UUID] = Field(min_length=1)


class AssetTagsRemove(BaseModel):
    tag_ids: list[uuid.UUID] = Field(min_length=1)


class BulkTagAssign(BaseModel):
    asset_ids: list[uuid.UUID] = Field(min_length=1)
    tag_ids: list[uuid.UUID] = Field(min_length=1)


class BulkTagRemove(BaseModel):
    asset_ids: list[uuid.UUID] = Field(min_length=1)
    tag_ids: list[uuid.UUID] = Field(min_length=1)
