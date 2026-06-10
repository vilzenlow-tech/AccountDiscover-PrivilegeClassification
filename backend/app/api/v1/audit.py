"""Audit log read endpoint."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.audit import AuditLog
from app.schemas.common import Page
from app.security import Principal, require_roles

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditLogOut:
    pass


from pydantic import BaseModel


class AuditLogItem(BaseModel):
    id: str
    actor_id: str | None
    actor_email: str | None
    action: str
    subject_type: str | None
    subject_id: str | None
    ip: str | None
    context: dict | None
    occurred_at: datetime

    model_config = {"from_attributes": True}


@router.get("", response_model=Page[AuditLogItem])
def list_audit(
    action: str | None = None,
    actor_email: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("admin", "auditor")),
):
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action.ilike(f"%{action}%"))
    if actor_email:
        q = q.filter(AuditLog.actor_email == actor_email)
    total = q.count()
    items = q.order_by(AuditLog.occurred_at.desc()).offset(offset).limit(limit).all()

    return Page(
        items=[
            AuditLogItem(
                id=str(a.id),
                actor_id=a.actor_id,
                actor_email=a.actor_email,
                action=a.action,
                subject_type=a.subject_type,
                subject_id=a.subject_id,
                ip=a.ip,
                context=a.context,
                occurred_at=a.occurred_at,
            )
            for a in items
        ],
        total=total,
        limit=limit,
        offset=offset,
    )
