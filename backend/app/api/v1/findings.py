"""Privilege findings and review state endpoints."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.finding import FindingReviewState, PrivilegeFinding
from app.schemas.common import Page
from app.schemas.finding import FindingOut, ReviewStateIn
from app.security import Principal, get_current_principal, require_roles
from app.services.audit import log_action

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=Page[FindingOut])
def list_findings(
    job_id: uuid.UUID | None = None,
    connector_agent_job_id: uuid.UUID | None = None,
    account_id: uuid.UUID | None = None,
    classification: str | None = None,
    is_winning: bool | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(PrivilegeFinding)
    if job_id:
        q = q.filter(PrivilegeFinding.job_id == job_id)
    if connector_agent_job_id:
        q = q.filter(PrivilegeFinding.connector_agent_job_id == connector_agent_job_id)
    if account_id:
        q = q.filter(PrivilegeFinding.account_id == account_id)
    if classification:
        q = q.filter(PrivilegeFinding.classification == classification)
    if is_winning is not None:
        q = q.filter(PrivilegeFinding.is_winning.is_(is_winning))
    total = q.count()
    items = q.order_by(PrivilegeFinding.risk_score.desc()).offset(offset).limit(limit).all()
    return Page(items=[FindingOut.model_validate(f) for f in items], total=total, limit=limit, offset=offset)


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: uuid.UUID, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    f = db.query(PrivilegeFinding).filter(PrivilegeFinding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    return FindingOut.model_validate(f)


@router.post("/review", status_code=201)
def set_review_state(
    body: ReviewStateIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst", "auditor")),
):
    f = db.query(PrivilegeFinding).filter(PrivilegeFinding.id == body.finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    review = FindingReviewState(
        finding_id=body.finding_id,
        state=body.state,
        comment=body.comment,
        reviewer=p.email,
    )
    db.add(review)
    log_action(db, "finding.reviewed", actor_id=p.id, actor_email=p.email, subject_id=str(body.finding_id), context={"state": body.state.value})
    db.commit()
    return {"detail": "Review state recorded", "state": body.state.value}
