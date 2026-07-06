"""User and role management endpoints."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import Role, User
from app.schemas.common import Page
from app.schemas.user_management import (
    ResetPasswordRequest,
    RoleOut,
    UserAdminOut,
    UserCreateRequest,
    UserStatusRequest,
    UserUpdateRequest,
)
from app.security import (
    ROLE_PERMISSIONS,
    Principal,
    hash_password,
    require_permissions,
)
from app.services.audit import log_action
from app.api.v1.auth import validate_password_strength

router = APIRouter(tags=["users"])


def _normalize_username(value: str) -> str:
    return value.strip().lower()


def _role_or_404(db: Session, name: str) -> Role:
    role = db.query(Role).filter(Role.name == name).first()
    if not role:
        raise HTTPException(status_code=400, detail="Unknown role")
    return role


def _status(user: User) -> str:
    if not user.is_active:
        return "disabled"
    if user.failed_login_attempts >= 10:
        return "locked"
    if user.must_change_password:
        return "pending_password_change"
    return "active"


def _out(user: User) -> UserAdminOut:
    return UserAdminOut(
        id=str(user.id),
        username=user.username or user.email.split("@")[0],
        display_name=user.full_name,
        email=user.email,
        roles=[role.name for role in user.roles],
        status=_status(user),
        must_change_password=user.must_change_password,
        last_login_at=user.last_login_at,
        created_by=user.created_by,
        created_at=user.created_at,
        updated_by=user.updated_by,
        updated_at=user.updated_at,
    )


def _audit_context(request: Request) -> dict[str, str | None]:
    return {
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
    }


@router.get("/users", response_model=Page[UserAdminOut])
def list_users(
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permissions("users:read")),
):
    limit = min(limit, 200)
    query = db.query(User)
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(or_(User.email.ilike(term), User.full_name.ilike(term), User.username.ilike(term)))
    total = query.count()
    users = query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()
    return Page(items=[_out(user) for user in users], total=total, limit=limit, offset=offset)


@router.post("/users", response_model=UserAdminOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permissions("users:create")),
):
    username = _normalize_username(body.username)
    email = body.email.lower()
    if db.query(User).filter(or_(User.email == email, User.username == username)).first():
        raise HTTPException(status_code=409, detail="Username or email already exists")
    validate_password_strength(body.temporary_password, username=username, email=email)
    role = _role_or_404(db, body.role)
    user = User(
        username=username,
        email=email,
        full_name=body.display_name,
        password_hash=hash_password(body.temporary_password),
        is_active=body.is_active,
        must_change_password=body.must_change_password,
        created_by=principal.email,
        updated_by=principal.email,
    )
    user.roles = [role]
    db.add(user)
    db.flush()
    log_action(
        db,
        "user.created",
        actor_id=principal.id,
        actor_email=principal.email,
        subject_type="user",
        subject_id=str(user.id),
        context={"email": email, "username": username, "role": body.role},
        **_audit_context(request),
    )
    db.commit()
    db.refresh(user)
    return _out(user)


@router.get("/users/{user_id}", response_model=UserAdminOut)
def get_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permissions("users:read")),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _out(user)


@router.patch("/users/{user_id}", response_model=UserAdminOut)
def update_user(
    user_id: uuid.UUID,
    body: UserUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permissions("users:update")),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    changes: dict[str, object] = {}
    if body.username is not None:
        username = _normalize_username(body.username)
        if db.query(User).filter(User.id != user.id, User.username == username).first():
            raise HTTPException(status_code=409, detail="Username already exists")
        user.username = username
        changes["username"] = username
    if body.email is not None:
        email = body.email.lower()
        if db.query(User).filter(User.id != user.id, User.email == email).first():
            raise HTTPException(status_code=409, detail="Email already exists")
        user.email = email
        changes["email"] = email
    if body.display_name is not None:
        user.full_name = body.display_name
        changes["display_name"] = body.display_name
    if body.role is not None:
        user.roles = [_role_or_404(db, body.role)]
        changes["role"] = body.role
    if body.must_change_password is not None:
        user.must_change_password = body.must_change_password
        changes["must_change_password"] = body.must_change_password
    user.updated_by = principal.email
    log_action(
        db,
        "user.updated",
        actor_id=principal.id,
        actor_email=principal.email,
        subject_type="user",
        subject_id=str(user.id),
        context=changes,
        **_audit_context(request),
    )
    db.commit()
    db.refresh(user)
    return _out(user)


@router.patch("/users/{user_id}/status", response_model=UserAdminOut)
def update_user_status(
    user_id: uuid.UUID,
    body: UserStatusRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permissions("users:disable")),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = body.is_active
    user.failed_login_attempts = 0 if body.is_active else user.failed_login_attempts
    user.updated_by = principal.email
    log_action(
        db,
        "user.enabled" if body.is_active else "user.disabled",
        actor_id=principal.id,
        actor_email=principal.email,
        subject_type="user",
        subject_id=str(user.id),
        **_audit_context(request),
    )
    db.commit()
    db.refresh(user)
    return _out(user)


@router.post("/users/{user_id}/reset-password")
def reset_password(
    user_id: uuid.UUID,
    body: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permissions("users:reset_password")),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    validate_password_strength(body.temporary_password, username=user.username, email=user.email)
    user.password_hash = hash_password(body.temporary_password)
    user.must_change_password = body.must_change_password
    user.failed_login_attempts = 0
    user.updated_by = principal.email
    log_action(
        db,
        "user.password_reset",
        actor_id=principal.id,
        actor_email=principal.email,
        subject_type="user",
        subject_id=str(user.id),
        **_audit_context(request),
    )
    db.commit()
    return {"detail": "Password reset"}


@router.patch("/users/{user_id}/role", response_model=UserAdminOut)
def update_user_role(
    user_id: uuid.UUID,
    body: UserUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permissions("roles:manage")),
):
    if not body.role:
        raise HTTPException(status_code=400, detail="Role is required")
    return update_user(user_id, UserUpdateRequest(role=body.role), request, db, principal)


@router.get("/roles", response_model=list[RoleOut])
def list_roles(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permissions("users:read")),
):
    roles = db.query(Role).order_by(Role.name.asc()).all()
    return [
        RoleOut(
            id=str(role.id),
            name=role.name,
            description=role.description,
            permissions=sorted(ROLE_PERMISSIONS.get(role.name, set())),
        )
        for role in roles
    ]


@router.get("/permissions", response_model=list[str])
def list_permissions(_: Principal = Depends(require_permissions("roles:manage"))):
    return sorted({permission for permissions in ROLE_PERMISSIONS.values() for permission in permissions})
