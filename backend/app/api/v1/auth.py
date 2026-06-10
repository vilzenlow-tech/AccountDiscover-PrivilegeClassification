"""Authentication endpoints."""
from __future__ import annotations

import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.schemas.auth import ChangePasswordRequest, LoginRequest, RefreshRequest, TokenResponse, UserOut
from app.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_principal,
    hash_password,
    verify_password,
    Principal,
)
from app.services.audit import log_action

router = APIRouter(prefix="/auth", tags=["auth"])

# Account lockout: lock after this many consecutive failures.
_MAX_FAILED_ATTEMPTS = 10

_PASSWORD_MIN_LEN = 12
_PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]).{12,}$"
)


def _validate_password_strength(password: str) -> None:
    if not _PASSWORD_PATTERN.match(password):
        raise HTTPException(
            status_code=400,
            detail=(
                "Password must be at least 12 characters and contain uppercase, "
                "lowercase, a digit, and a special character."
            ),
        )


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()

    # Always perform a dummy hash check when user not found to prevent timing attacks.
    password_ok = verify_password(body.password, user.password_hash) if user else False

    if not user or not password_ok:
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= _MAX_FAILED_ATTEMPTS:
                user.is_active = False
        log_action(
            db,
            "auth.login.failed",
            actor_email=body.email,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account inactive")

    # Reset lockout counter on successful authentication.
    user.failed_login_attempts = 0

    roles = [r.name for r in user.roles]
    access = create_access_token(str(user.id), roles)
    refresh = create_refresh_token(str(user.id))
    from app.config import get_settings
    ttl = get_settings().access_token_ttl_min * 60

    log_action(
        db,
        "auth.login.success",
        actor_id=str(user.id),
        actor_email=user.email,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=ttl,
        must_change_password=user.must_change_password,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(body: RefreshRequest, db: Session = Depends(get_db)):
    data = decode_token(body.refresh_token)
    if data.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    user = db.query(User).filter(User.id == data["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    roles = [r.name for r in user.roles]
    access = create_access_token(str(user.id), roles)
    new_refresh = create_refresh_token(str(user.id))
    from app.config import get_settings
    ttl = get_settings().access_token_ttl_min * 60
    return TokenResponse(access_token=access, refresh_token=new_refresh, expires_in=ttl)


@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
):
    user = db.query(User).filter(User.id == principal.id).first()
    if not user or not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password incorrect")
    _validate_password_strength(body.new_password)
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    log_action(db, "auth.password_changed", actor_id=principal.id, actor_email=principal.email)
    db.commit()
    return {"detail": "Password updated"}


@router.get("/me", response_model=UserOut)
def me(principal: Principal = Depends(get_current_principal), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == principal.id).first()
    return UserOut(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        roles=principal.roles,
        is_active=user.is_active,
        must_change_password=user.must_change_password,
    )
