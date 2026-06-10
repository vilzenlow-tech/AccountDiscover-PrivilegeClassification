"""Classification rules CRUD."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.rule import ClassificationRule
from app.schemas.common import Page
from app.schemas.finding import RuleIn, RuleOut
from app.security import Principal, get_current_principal, require_roles
from app.services.audit import log_action

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=Page[RuleOut])
def list_rules(
    platform: str | None = None,
    enabled: bool | None = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(ClassificationRule)
    if platform:
        q = q.filter(ClassificationRule.platform == platform)
    if enabled is not None:
        q = q.filter(ClassificationRule.enabled.is_(enabled))
    total = q.count()
    items = q.order_by(ClassificationRule.priority).offset(offset).limit(limit).all()
    return Page(items=[RuleOut.model_validate(r) for r in items], total=total, limit=limit, offset=offset)


@router.post("", response_model=RuleOut, status_code=201)
def create_rule(
    body: RuleIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin")),
):
    row = ClassificationRule(**body.model_dump())
    db.add(row)
    log_action(db, "rule.created", actor_id=p.id, actor_email=p.email, subject_type="rule", subject_id=body.rule_key)
    db.commit()
    db.refresh(row)
    return RuleOut.model_validate(row)


@router.get("/{rule_id}", response_model=RuleOut)
def get_rule(rule_id: uuid.UUID, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    r = db.query(ClassificationRule).filter(ClassificationRule.id == rule_id).first()
    if not r:
        raise HTTPException(404, "Rule not found")
    return RuleOut.model_validate(r)


@router.put("/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: uuid.UUID,
    body: RuleIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin")),
):
    r = db.query(ClassificationRule).filter(ClassificationRule.id == rule_id).first()
    if not r:
        raise HTTPException(404, "Rule not found")
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    r.version += 1
    log_action(db, "rule.updated", actor_id=p.id, actor_email=p.email, subject_id=str(rule_id))
    db.commit()
    db.refresh(r)
    return RuleOut.model_validate(r)


@router.delete("/{rule_id}", status_code=204)
def delete_rule(rule_id: uuid.UUID, db: Session = Depends(get_db), p: Principal = Depends(require_roles("admin"))):
    r = db.query(ClassificationRule).filter(ClassificationRule.id == rule_id).first()
    if not r:
        raise HTTPException(404, "Rule not found")
    db.delete(r)
    log_action(db, "rule.deleted", actor_id=p.id, actor_email=p.email, subject_id=str(rule_id))
    db.commit()


@router.post("/seed-builtins", status_code=201)
def seed_builtins(
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin")),
):
    """Insert any built-in rules that are not yet present in the database.

    Safe to call multiple times — existing rules (matched by rule_key) are
    never overwritten.  Returns the list of newly inserted rule keys.
    """
    from app.rules_engine.builtin_rules import BUILTIN_RULES

    created = []
    for rd in BUILTIN_RULES:
        if not db.query(ClassificationRule).filter(ClassificationRule.rule_key == rd["rule_key"]).first():
            db.add(ClassificationRule(**rd))
            created.append(rd["rule_key"])
    db.commit()
    log_action(
        db, "rules.seed_builtins",
        actor_id=p.id, actor_email=p.email,
        subject_type="rule", subject_id="builtin",
    )
    return {"created": created, "message": f"{len(created)} rule(s) inserted"}
