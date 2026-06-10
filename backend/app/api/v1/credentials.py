"""Credential management — metadata only, no secrets returned."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.connector import Credential
from app.schemas.common import Page
from app.schemas.connector import CredentialIn, CredentialOut
from app.security import Principal, require_roles
from app.services.audit import log_action
from app.services.vault import get_vault

router = APIRouter(prefix="/credentials", tags=["credentials"])


@router.get("", response_model=Page[CredentialOut])
def list_credentials(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("admin", "security_analyst")),
):
    q = db.query(Credential)
    total = q.count()
    items = q.offset(offset).limit(limit).all()
    return Page(items=[CredentialOut.model_validate(c) for c in items], total=total, limit=limit, offset=offset)


@router.post("", response_model=CredentialOut, status_code=201)
def create_credential(
    body: CredentialIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    # If local vault and secret_material provided, store it.
    if body.secret_material and body.vault_backend.value == "local":
        vault = get_vault()
        if hasattr(vault, "store"):
            vault.store(body.vault_ref, body.secret_material.get_secret_value())

    cred = Credential(
        name=body.name,
        description=body.description,
        vault_backend=body.vault_backend,
        vault_ref=body.vault_ref,
        username=body.username,
        auth_method=body.auth_method,
        rotation_policy_days=body.rotation_policy_days,
        is_active=body.is_active,
        # Record when a secret was provided so rotation age can be tracked.
        last_rotated_at=datetime.now(UTC).isoformat() if body.secret_material else None,
    )
    db.add(cred)
    log_action(db, "credential.created", actor_id=p.id, actor_email=p.email, subject_type="credential", subject_id=body.name)
    db.commit()
    db.refresh(cred)
    return CredentialOut.model_validate(cred)


@router.get("/{cred_id}", response_model=CredentialOut)
def get_credential(
    cred_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("admin", "security_analyst")),
):
    c = db.query(Credential).filter(Credential.id == cred_id).first()
    if not c:
        raise HTTPException(404, "Credential not found")
    return CredentialOut.model_validate(c)


@router.put("/{cred_id}", response_model=CredentialOut)
def update_credential(
    cred_id: uuid.UUID,
    body: CredentialIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    c = db.query(Credential).filter(Credential.id == cred_id).first()
    if not c:
        raise HTTPException(404, "Credential not found")

    if body.secret_material and body.vault_backend.value == "local":
        vault = get_vault()
        if hasattr(vault, "store"):
            vault.store(body.vault_ref, body.secret_material.get_secret_value())

    for k, v in body.model_dump(exclude={"secret_material"}).items():
        setattr(c, k, v)
    # Update rotation timestamp whenever a new secret is supplied.
    if body.secret_material:
        c.last_rotated_at = datetime.now(UTC).isoformat()
    log_action(db, "credential.updated", actor_id=p.id, actor_email=p.email, subject_type="credential", subject_id=str(cred_id))
    db.commit()
    db.refresh(c)
    return CredentialOut.model_validate(c)


@router.delete("/{cred_id}", status_code=204)
def delete_credential(
    cred_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin")),
):
    c = db.query(Credential).filter(Credential.id == cred_id).first()
    if not c:
        raise HTTPException(404, "Credential not found")
    db.delete(c)
    log_action(db, "credential.deleted", actor_id=p.id, actor_email=p.email, subject_id=str(cred_id))
    db.commit()
