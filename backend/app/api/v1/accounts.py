"""Account discovery results endpoints."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.account import Account
from app.models.enums import PrivilegeClass
from app.schemas.account import AccountDetailOut, AccountFilter, AccountOut
from app.schemas.common import Page
from app.security import Principal, get_current_principal

router = APIRouter(prefix="/accounts", tags=["accounts"])

PRIVILEGED_CLASSES = {
    PrivilegeClass.full_admin,
    PrivilegeClass.admin_equivalent,
    PrivilegeClass.operator_high_impact,
    PrivilegeClass.delegated_admin,
    PrivilegeClass.privileged_service,
    PrivilegeClass.sensitive_non_admin,
    PrivilegeClass.dormant_privileged,
}


@router.get("", response_model=Page[AccountOut])
def list_accounts(
    platform: str | None = None,
    environment: str | None = None,
    business_unit: str | None = None,
    classification: str | None = None,
    enabled_status: str | None = None,
    interactive_status: str | None = None,
    source_type: str | None = None,
    principal_source: str | None = None,
    asset_id: uuid.UUID | None = None,
    only_privileged: bool = False,
    only_shared: bool = False,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    from app.models.asset import Asset

    q = db.query(Account)
    if platform:
        q = q.filter(Account.platform == platform)
    if asset_id:
        q = q.filter(Account.asset_id == asset_id)
    if classification:
        q = q.filter(Account.privilege_classification == classification)
    if enabled_status:
        q = q.filter(Account.enabled_status == enabled_status)
    if interactive_status:
        q = q.filter(Account.interactive_status == interactive_status)
    if source_type:
        q = q.filter(Account.source_type == source_type)
    if principal_source:
        q = q.filter(Account.principal_source == principal_source)
    if only_privileged:
        q = q.filter(Account.privilege_classification.in_([c.value for c in PRIVILEGED_CLASSES]))
    if only_shared:
        q = q.filter(Account.is_shared.is_(True))
    if environment or business_unit or search:
        q = q.join(Asset, Account.asset_id == Asset.id)
        if environment:
            q = q.filter(Asset.environment == environment)
        if business_unit:
            q = q.filter(Asset.business_unit == business_unit)
        if search:
            q = q.filter(Account.account_name.ilike(f"%{search}%"))
    total = q.count()
    items = q.order_by(Account.risk_score.desc(), Account.account_name).offset(offset).limit(limit).all()
    return Page(items=[AccountOut.model_validate(a) for a in items], total=total, limit=limit, offset=offset)


@router.get("/privileged", response_model=Page[AccountOut])
def list_privileged_accounts(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(Account).filter(Account.privilege_classification.in_([c.value for c in PRIVILEGED_CLASSES]))
    total = q.count()
    items = q.order_by(Account.risk_score.desc()).offset(offset).limit(limit).all()
    return Page(items=[AccountOut.model_validate(a) for a in items], total=total, limit=limit, offset=offset)


@router.get("/dormant-privileged", response_model=Page[AccountOut])
def list_dormant_privileged(limit: int = 50, offset: int = 0, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    q = db.query(Account).filter(Account.privilege_classification == PrivilegeClass.dormant_privileged)
    total = q.count()
    items = q.offset(offset).limit(limit).all()
    return Page(items=[AccountOut.model_validate(a) for a in items], total=total, limit=limit, offset=offset)


@router.get("/{account_id}", response_model=AccountDetailOut)
def get_account(account_id: uuid.UUID, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    acc = db.query(Account).filter(Account.id == account_id).first()
    if not acc:
        raise HTTPException(404, "Account not found")
    return AccountDetailOut.model_validate(acc)
