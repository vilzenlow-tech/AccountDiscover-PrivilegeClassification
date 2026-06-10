"""Scheduled scan CRUD."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.job import ScheduledScan
from app.schemas.common import Page
from app.schemas.scan import ScheduledScanIn, ScheduledScanOut
from app.security import Principal, get_current_principal, require_roles
from app.services.audit import log_action

router = APIRouter(prefix="/schedules", tags=["schedules"])
SCHEDULE_TIMEZONE = timezone(timedelta(hours=8), "GMT+8")


def _next_run_for(cron_expr: str) -> datetime:
    try:
        trigger = CronTrigger.from_crontab(cron_expr, timezone=SCHEDULE_TIMEZONE)
    except ValueError as exc:
        raise HTTPException(400, f"Invalid cron expression: {exc}") from exc
    next_run = trigger.get_next_fire_time(None, datetime.now(SCHEDULE_TIMEZONE))
    if not next_run:
        raise HTTPException(400, "Cron expression does not yield a next run time")
    return next_run


@router.get("", response_model=Page[ScheduledScanOut])
def list_schedules(limit: int = 50, offset: int = 0, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    q = db.query(ScheduledScan)
    return Page(items=[ScheduledScanOut.model_validate(s) for s in q.offset(offset).limit(limit)], total=q.count(), limit=limit, offset=offset)


@router.post("", response_model=ScheduledScanOut, status_code=201)
def create_schedule(body: ScheduledScanIn, db: Session = Depends(get_db), p: Principal = Depends(require_roles("admin", "security_analyst"))):
    row = ScheduledScan(**body.model_dump(), next_run_at=_next_run_for(body.cron) if body.enabled else None)
    db.add(row)
    log_action(db, "schedule.created", actor_id=p.id, actor_email=p.email)
    db.commit()
    db.refresh(row)
    return ScheduledScanOut.model_validate(row)


@router.put("/{schedule_id}", response_model=ScheduledScanOut)
def update_schedule(schedule_id: uuid.UUID, body: ScheduledScanIn, db: Session = Depends(get_db), p: Principal = Depends(require_roles("admin", "security_analyst"))):
    row = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not row:
        raise HTTPException(404, "Not found")
    for k, v in body.model_dump().items():
        setattr(row, k, v)
    row.next_run_at = _next_run_for(body.cron) if body.enabled else None
    log_action(db, "schedule.updated", actor_id=p.id, actor_email=p.email, subject_id=str(schedule_id))
    db.commit()
    db.refresh(row)
    return ScheduledScanOut.model_validate(row)


@router.delete("/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: uuid.UUID, db: Session = Depends(get_db), p: Principal = Depends(require_roles("admin"))):
    row = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not row:
        raise HTTPException(404, "Not found")
    db.delete(row)
    db.commit()
