"""User management DTOs."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserAdminOut(BaseModel):
    id: str
    username: str
    display_name: str | None
    email: str
    roles: list[str]
    status: str
    must_change_password: bool
    last_login_at: datetime | None
    created_by: str | None
    created_at: datetime
    updated_by: str | None
    updated_at: datetime


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    display_name: str | None = Field(default=None, max_length=255)
    email: EmailStr
    role: str
    temporary_password: str = Field(min_length=12, max_length=256)
    must_change_password: bool = True
    is_active: bool = True


class UserUpdateRequest(BaseModel):
    username: str | None = Field(default=None, min_length=3, max_length=80)
    display_name: str | None = Field(default=None, max_length=255)
    email: EmailStr | None = None
    role: str | None = None
    must_change_password: bool | None = None


class UserStatusRequest(BaseModel):
    is_active: bool


class ResetPasswordRequest(BaseModel):
    temporary_password: str = Field(min_length=12, max_length=256)
    must_change_password: bool = True


class RoleOut(BaseModel):
    id: str
    name: str
    description: str | None
    permissions: list[str]
