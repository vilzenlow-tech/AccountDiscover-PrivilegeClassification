"""Password hashing, JWT issuance, and RBAC helpers."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import bcrypt as _bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db

_settings = get_settings()
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


# --- Password hashing ---

def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# --- JWT ---

def _now() -> datetime:
    return datetime.now(tz=UTC)


def create_access_token(sub: str, roles: list[str], extra: dict[str, Any] | None = None) -> str:
    exp = _now() + timedelta(minutes=_settings.access_token_ttl_min)
    payload = {"sub": sub, "roles": roles, "type": "access", "exp": exp, "iat": _now()}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, _settings.secret_key, algorithm=_settings.jwt_alg)


def create_refresh_token(sub: str) -> str:
    exp = _now() + timedelta(minutes=_settings.refresh_token_ttl_min)
    payload = {"sub": sub, "type": "refresh", "exp": exp, "iat": _now()}
    return jwt.encode(payload, _settings.secret_key, algorithm=_settings.jwt_alg)


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, _settings.secret_key, algorithms=[_settings.jwt_alg])
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


# --- Current user dependency ---

Permission = Literal[
    "users:create",
    "users:read",
    "users:update",
    "users:disable",
    "users:reset_password",
    "roles:manage",
    "assets:read",
    "assets:manage",
    "tags:read",
    "tags:manage",
    "scans:launch",
    "scans:schedule",
    "scans:cancel",
    "scans:retry",
    "scans:read",
    "accounts:read",
    "findings:read",
    "findings:review",
    "privileged_findings:read",
    "connectors:read",
    "connectors:manage",
    "credentials:read_metadata",
    "credentials:manage",
    "credentials:use",
    "reports:export",
    "audit:read",
    "settings:manage",
]

ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "admin": {
        "users:create", "users:read", "users:update", "users:disable",
        "users:reset_password", "roles:manage", "assets:read", "assets:manage",
        "tags:read", "tags:manage", "scans:launch", "scans:schedule",
        "scans:cancel", "scans:retry", "scans:read", "accounts:read",
        "findings:read", "findings:review", "privileged_findings:read",
        "connectors:read", "connectors:manage", "credentials:read_metadata",
        "credentials:manage", "credentials:use", "reports:export",
        "audit:read", "settings:manage",
    },
    "security_analyst": {
        "assets:read", "accounts:read", "tags:read", "scans:launch",
        "scans:cancel", "scans:retry", "scans:read", "findings:read",
        "findings:review", "privileged_findings:read", "connectors:read",
        "credentials:read_metadata", "credentials:use", "reports:export",
    },
    "operator": {
        "assets:read", "accounts:read", "tags:read", "scans:launch",
        "scans:read", "findings:read", "connectors:read",
        "credentials:read_metadata", "credentials:use",
    },
    "auditor": {
        "assets:read", "accounts:read", "tags:read", "scans:read",
        "findings:read", "privileged_findings:read", "reports:export",
        "audit:read",
    },
    "viewer": {"assets:read", "accounts:read", "tags:read", "scans:read"},
}


def permissions_for_roles(roles: list[str]) -> set[Permission]:
    permissions: set[Permission] = set()
    for role in roles:
        permissions.update(ROLE_PERMISSIONS.get(role, set()))
    return permissions


class Principal:
    __slots__ = ("id", "email", "roles", "permissions")

    def __init__(self, id: str, email: str, roles: list[str]) -> None:
        self.id = id
        self.email = email
        self.roles = roles
        self.permissions = permissions_for_roles(roles)

    def has_role(self, *allowed: str) -> bool:
        return any(r in self.roles for r in allowed)

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions


def get_current_principal(
    request: Request, token: str | None = Depends(oauth2), db: Session = Depends(get_db)
) -> Principal:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    data = decode_token(token)
    if data.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token type")
    # Minimal DB touch to ensure the user still exists and is active.
    from app.models.user import User  # local import to avoid cycle

    user = db.query(User).filter(User.id == data["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive")
    if user.must_change_password and request.url.path not in {
        "/api/v1/auth/change-password",
        "/api/v1/auth/me",
    }:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required before accessing this resource",
        )
    return Principal(id=str(user.id), email=user.email, roles=[r.name for r in user.roles])


def require_roles(*allowed: str):
    """Dependency factory to require one of the listed roles."""

    def _inner(p: Principal = Depends(get_current_principal)) -> Principal:
        if not p.has_role(*allowed):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(allowed)}",
            )
        return p

    return _inner


def require_permissions(*required: Permission):
    """Dependency factory to require every listed permission."""

    def _inner(
        request: Request,
        db: Session = Depends(get_db),
        p: Principal = Depends(get_current_principal),
    ) -> Principal:
        missing = [permission for permission in required if not p.has_permission(permission)]
        if missing:
            from app.services.audit import log_action

            log_action(
                db,
                "auth.unauthorized",
                actor_id=p.id,
                actor_email=p.email,
                ip=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                context={
                    "path": request.url.path,
                    "method": request.method,
                    "missing_permissions": missing,
                },
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {', '.join(missing)}",
            )
        return p

    return _inner
