"""Auth DTOs."""
from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    must_change_password: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)
    confirm_password: str | None = Field(default=None, min_length=12, max_length=256)


class UserOut(BaseModel):
    id: str
    username: str | None = None
    email: str
    full_name: str | None = None
    roles: list[str]
    is_active: bool
    must_change_password: bool
    permissions: list[str] = []
