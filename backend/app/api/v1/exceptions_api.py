"""Privilege exceptions CRUD."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.exception_rule import PrivilegeException
from app.schemas.common import Page
from app.schemas.finding import ExceptionIn, ExceptionOut
from app.security import Principal, get_current_principal, require_roles
from app.services.audit import log_action

router = APIRouter(prefix="/exceptions", tags=["exceptions"])


@router.get("", response_model=Page[ExceptionOut])
def list_exceptions(limit: int = 50, offset: int = 0, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    q = db.query(PrivilegeException)
    return Page(items=[ExceptionOut.model_validate(e) for e in q.offset(offset).limit(limit)], total=q.count(), limit=limit, offset=offset)


@router.post("", response_model=ExceptionOut, status_code=201)
def create_exception(body: ExceptionIn, db: Session = Depends(get_db), p: Principal = Depends(require_roles("admin"))):
    row = PrivilegeException(**body.model_dump())
    db.add(row)
    log_action(db, "exception.created", actor_id=p.id, actor_email=p.email, context={"name": body.name})
    db.commit()
    db.refresh(row)
    return ExceptionOut.model_validate(row)


@router.get("/{exc_id}", response_model=ExceptionOut)
def get_exception(exc_id: uuid.UUID, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    e = db.query(PrivilegeException).filter(PrivilegeException.id == exc_id).first()
    if not e:
        raise HTTPException(404, "Exception not found")
    return ExceptionOut.model_validate(e)


@router.put("/{exc_id}", response_model=ExceptionOut)
def update_exception(
    exc_id: uuid.UUID,
    body: ExceptionIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin")),
):
    e = db.query(PrivilegeException).filter(PrivilegeException.id == exc_id).first()
    if not e:
        raise HTTPException(404, "Exception not found")
    for k, v in body.model_dump().items():
        setattr(e, k, v)
    log_action(db, "exception.updated", actor_id=p.id, actor_email=p.email, subject_id=str(exc_id))
    db.commit()
    db.refresh(e)
    return ExceptionOut.model_validate(e)


@router.delete("/{exc_id}", status_code=204)
def delete_exception(exc_id: uuid.UUID, db: Session = Depends(get_db), p: Principal = Depends(require_roles("admin"))):
    e = db.query(PrivilegeException).filter(PrivilegeException.id == exc_id).first()
    if not e:
        raise HTTPException(404, "Not found")
    db.delete(e)
    log_action(db, "exception.deleted", actor_id=p.id, actor_email=p.email, subject_id=str(exc_id))
    db.commit()
