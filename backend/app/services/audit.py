"""Audit log service — append-only writes."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def log_action(
    db: Session,
    action: str,
    *,
    actor_id: str | None = None,
    actor_email: str | None = None,
    subject_type: str | None = None,
    subject_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    context: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        subject_type=subject_type,
        subject_id=str(subject_id) if subject_id else None,
        ip=ip,
        user_agent=user_agent,
        context=context,
        occurred_at=datetime.now(UTC),
    )
    db.add(entry)
    db.flush()
    return entry
