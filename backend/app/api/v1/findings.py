"""Privilege findings and review state endpoints."""
from __future__ import annotations

import uuid
import csv
import io

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import String, and_, cast, func, or_
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.account import Account
from app.models.asset import Asset
from app.models.enums import ActivityStatus, EnabledStatus, InteractiveStatus, Platform, PrincipalType, PrivilegeClass, ReviewState
from app.models.finding import FindingReviewState, PrivilegeFinding
from app.schemas.common import Page
from app.schemas.finding import FindingOut, ReviewStateIn
from app.security import Principal, require_permissions, require_roles
from app.services.audit import log_action

router = APIRouter(prefix="/findings", tags=["findings"])

_SORTS = {
    "risk_score": PrivilegeFinding.risk_score,
    "severity": PrivilegeFinding.risk_score,
    "confidence": PrivilegeFinding.confidence,
    "account": Account.account_name,
    "asset": Asset.hostname,
    "platform": Account.platform,
    "classification": PrivilegeFinding.classification,
    "last_login": Account.last_login,
    "last_discovered": PrivilegeFinding.evaluated_at,
}

_VISIBLE_PRIVILEGE_CLASSES = [
    PrivilegeClass.full_admin,
    PrivilegeClass.admin_equivalent,
    PrivilegeClass.operator_high_impact,
    PrivilegeClass.delegated_admin,
    PrivilegeClass.privileged_service,
    PrivilegeClass.sensitive_non_admin,
    PrivilegeClass.dormant_privileged,
    PrivilegeClass.unknown_review_required,
]


def _asset_tag(asset: Asset | None) -> str | None:
    if not asset or not asset.tags:
        return None
    tags = asset.tags
    value = (
        tags.get("application")
        or tags.get("application_tag")
        or tags.get("app")
        or tags.get("app_code")
        or tags.get("system")
    )
    return str(value) if value is not None else None


def _pam_managed(account: Account | None, asset: Asset | None) -> bool | None:
    tags = {}
    if asset and asset.tags:
        tags.update(asset.tags)
    evidence = account.evidence_summary if account and account.evidence_summary else {}
    for key in ("pam_managed", "pam", "managed_by_pam", "pam_onboarded"):
        if key in evidence:
            return bool(evidence[key])
        if key in tags:
            return bool(tags[key])
    return None


def _account_type(account: Account | None) -> str | None:
    if not account:
        return None
    if account.platform.value in {"mysql", "mssql", "mongodb", "oracle_db", "postgresql", "redis"}:
        return "database login"
    if account.principal_type:
        return account.principal_type.value
    return "unknown"


def _finding_out(row: tuple[PrivilegeFinding, Account, Asset, FindingReviewState | None]) -> FindingOut:
    finding, account, asset, review = row
    return FindingOut(
        id=finding.id,
        job_id=finding.job_id,
        connector_agent_job_id=finding.connector_agent_job_id,
        account_id=finding.account_id,
        rule_id=finding.rule_id,
        rule_key=finding.rule_key,
        rule_version=finding.rule_version,
        classification=finding.classification,
        confidence=finding.confidence,
        risk_score=finding.risk_score,
        is_winning=finding.is_winning,
        direct=finding.direct,
        inheritance_path=finding.inheritance_path,
        explanation=finding.explanation,
        matched_evidence=finding.matched_evidence,
        evaluated_at=finding.evaluated_at,
        latest_review_state=review.state if review else None,
        latest_review_comment=review.comment if review else None,
        latest_review_reviewer=review.reviewer if review else None,
        latest_review_at=review.created_at if review else None,
        account_name=account.account_name if account else None,
        normalized_account_name=(account.account_name.lower() if account and account.account_name else None),
        asset_id=account.asset_id if account else None,
        asset_hostname=asset.hostname if asset else None,
        asset_ip_address=asset.ip_address if asset else None,
        platform=account.platform if account else None,
        application_tag=_asset_tag(asset),
        environment=asset.environment if asset else None,
        account_source=account.auth_source.value if account and account.auth_source else None,
        account_type=_account_type(account),
        enabled_status=account.enabled_status.value if account and account.enabled_status else None,
        interactive_status=account.interactive_status.value if account and account.interactive_status else None,
        last_login=account.last_login if account else None,
        activity_status=account.activity_status.value if account and account.activity_status else None,
        pam_managed=_pam_managed(account, asset),
        owner=account.owner or asset.owner if account and asset else None,
        password_never_expires=account.password_never_expires if account else None,
        is_shared=account.is_shared if account else None,
        discovered_at=account.discovered_at if account else None,
        updated_at=account.updated_at if account else None,
    )


def _apply_real_privilege_visibility(q, *, real_only: bool, privileged_only: bool):
    if real_only:
        q = q.filter(or_(Account.collection_mode.is_(None), Account.collection_mode != "mock"))
    if privileged_only:
        q = q.filter(PrivilegeFinding.classification.in_(_VISIBLE_PRIVILEGE_CLASSES))
    return q


@router.get("", response_model=Page[FindingOut])
def list_findings(
    job_id: uuid.UUID | None = None,
    connector_agent_job_id: uuid.UUID | None = None,
    account_id: uuid.UUID | None = None,
    search: str | None = None,
    severity: str | None = None,
    platform: Platform | None = None,
    environment: str | None = None,
    application_tag: str | None = None,
    classification: str | None = None,
    direct: bool | None = None,
    enabled_status: EnabledStatus | None = None,
    interactive_status: InteractiveStatus | None = None,
    pam_managed: bool | None = None,
    owner: str | None = None,
    review_state: ReviewState | None = None,
    dormant_privileged: bool | None = None,
    service_account: bool | None = None,
    shared_account: bool | None = None,
    no_owner: bool | None = None,
    password_never_expires: bool | None = None,
    unresolved_privilege_path: bool | None = None,
    is_winning: bool | None = None,
    real_only: bool = True,
    privileged_only: bool = True,
    sort: str = "risk_score",
    direction: str = "desc",
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permissions("privileged_findings:read")),
):
    latest_review_at = (
        db.query(
            FindingReviewState.finding_id.label("finding_id"),
            func.max(FindingReviewState.created_at).label("created_at"),
        )
        .group_by(FindingReviewState.finding_id)
        .subquery()
    )
    q = (
        db.query(PrivilegeFinding, Account, Asset, FindingReviewState)
        .join(Account, Account.id == PrivilegeFinding.account_id)
        .join(Asset, Asset.id == Account.asset_id)
        .outerjoin(
            latest_review_at,
            latest_review_at.c.finding_id == PrivilegeFinding.id,
        )
        .outerjoin(
            FindingReviewState,
            and_(
                FindingReviewState.finding_id == PrivilegeFinding.id,
                FindingReviewState.created_at == latest_review_at.c.created_at,
            ),
        )
    )
    if job_id:
        q = q.filter(PrivilegeFinding.job_id == job_id)
    if connector_agent_job_id:
        q = q.filter(PrivilegeFinding.connector_agent_job_id == connector_agent_job_id)
    if account_id:
        q = q.filter(PrivilegeFinding.account_id == account_id)
    q = _apply_real_privilege_visibility(q, real_only=real_only, privileged_only=privileged_only)
    if search:
        terms = [t.strip().lower() for t in search.split() if t.strip()]
        for term in terms:
            like = f"%{term}%"
            q = q.filter(or_(
                func.lower(Account.account_name).like(like),
                func.lower(Asset.hostname).like(like),
                func.lower(func.coalesce(Asset.ip_address, "")).like(like),
                func.lower(cast(Account.platform, String)).like(like),
                func.lower(cast(PrivilegeFinding.classification, String)).like(like),
                func.lower(PrivilegeFinding.rule_key).like(like),
                func.lower(PrivilegeFinding.explanation).like(like),
                func.lower(func.coalesce(PrivilegeFinding.inheritance_path, "")).like(like),
                func.lower(func.coalesce(Account.owner, "")).like(like),
                func.lower(func.coalesce(Asset.owner, "")).like(like),
                func.lower(func.coalesce(Asset.instance, "")).like(like),
                func.lower(cast(PrivilegeFinding.matched_evidence, String)).like(like),
                func.lower(cast(PrivilegeFinding.job_id, String)).like(like),
            ))
    if severity:
        bands = {
            "critical": PrivilegeFinding.risk_score >= 90,
            "high": and_(PrivilegeFinding.risk_score >= 75, PrivilegeFinding.risk_score < 90),
            "medium": and_(PrivilegeFinding.risk_score >= 50, PrivilegeFinding.risk_score < 75),
            "low": and_(PrivilegeFinding.risk_score < 50),
            "review_required": PrivilegeFinding.classification == PrivilegeClass.unknown_review_required,
        }
        if severity in bands:
            q = q.filter(bands[severity])
    if platform:
        q = q.filter(Account.platform == platform)
    if environment:
        q = q.filter(func.lower(func.coalesce(Asset.environment, "")) == environment.lower())
    if application_tag:
        like = f"%{application_tag.lower()}%"
        q = q.filter(or_(
            func.lower(cast(Asset.tags, String)).like(like),
            func.lower(func.coalesce(Asset.business_unit, "")).like(like),
        ))
    if classification:
        q = q.filter(PrivilegeFinding.classification == classification)
    if direct is not None:
        q = q.filter(PrivilegeFinding.direct.is_(direct))
    if enabled_status:
        q = q.filter(Account.enabled_status == enabled_status)
    if interactive_status:
        q = q.filter(Account.interactive_status == interactive_status)
    if pam_managed is not None:
        value = "true" if pam_managed else "false"
        q = q.filter(or_(
            func.lower(cast(Account.evidence_summary, String)).like(f'%"{value}"%'),
            func.lower(cast(Account.evidence_summary, String)).like(f'%{value}%'),
            func.lower(cast(Asset.tags, String)).like(f'%"{value}"%'),
            func.lower(cast(Asset.tags, String)).like(f'%{value}%'),
        ))
    if owner:
        like = f"%{owner.lower()}%"
        q = q.filter(or_(func.lower(func.coalesce(Account.owner, "")).like(like), func.lower(func.coalesce(Asset.owner, "")).like(like)))
    if review_state:
        q = q.filter(FindingReviewState.state == review_state)
    if dormant_privileged is not None:
        condition = Account.activity_status.in_([ActivityStatus.inactive_30d, ActivityStatus.inactive_90d, ActivityStatus.never_logged_in])
        q = q.filter(condition if dormant_privileged else ~condition)
    if service_account is not None:
        condition = Account.principal_type == PrincipalType.service
        q = q.filter(condition if service_account else ~condition)
    if shared_account is not None:
        q = q.filter(Account.is_shared.is_(shared_account))
    if no_owner is not None:
        condition = and_(or_(Account.owner.is_(None), Account.owner == ""), or_(Asset.owner.is_(None), Asset.owner == ""))
        q = q.filter(condition if no_owner else ~condition)
    if password_never_expires is not None:
        q = q.filter(Account.password_never_expires.is_(password_never_expires))
    if unresolved_privilege_path is not None:
        condition = or_(
            func.lower(func.coalesce(PrivilegeFinding.inheritance_path, "")).like("%unresolved%"),
            func.lower(cast(PrivilegeFinding.matched_evidence, String)).like("%unresolved%"),
            func.lower(cast(PrivilegeFinding.matched_evidence, String)).like("%sid%"),
        )
        q = q.filter(condition if unresolved_privilege_path else ~condition)
    if is_winning is not None:
        q = q.filter(PrivilegeFinding.is_winning.is_(is_winning))
    total = q.count()
    sort_col = _SORTS.get(sort, PrivilegeFinding.risk_score)
    order = sort_col.asc() if direction == "asc" else sort_col.desc()
    items = q.order_by(order, PrivilegeFinding.evaluated_at.desc()).offset(offset).limit(min(limit, 200)).all()
    return Page(items=[_finding_out(row) for row in items], total=total, limit=min(limit, 200), offset=offset)


@router.get("/export/csv")
def export_findings_csv(
    search: str | None = None,
    severity: str | None = None,
    platform: Platform | None = None,
    classification: str | None = None,
    direct: bool | None = None,
    pam_managed: bool | None = None,
    owner: str | None = None,
    is_winning: bool | None = True,
    real_only: bool = True,
    privileged_only: bool = True,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_permissions("privileged_findings:read", "reports:export")),
):
    q = (
        db.query(PrivilegeFinding, Account, Asset, FindingReviewState)
        .join(Account, Account.id == PrivilegeFinding.account_id)
        .join(Asset, Asset.id == Account.asset_id)
        .outerjoin(FindingReviewState, FindingReviewState.finding_id == PrivilegeFinding.id)
    )
    q = _apply_real_privilege_visibility(q, real_only=real_only, privileged_only=privileged_only)
    if search:
        terms = [t.strip().lower() for t in search.split() if t.strip()]
        for term in terms:
            like = f"%{term}%"
            q = q.filter(or_(
                func.lower(Account.account_name).like(like),
                func.lower(Asset.hostname).like(like),
                func.lower(func.coalesce(Asset.ip_address, "")).like(like),
                func.lower(cast(Account.platform, String)).like(like),
                func.lower(cast(PrivilegeFinding.classification, String)).like(like),
                func.lower(PrivilegeFinding.rule_key).like(like),
                func.lower(PrivilegeFinding.explanation).like(like),
                func.lower(func.coalesce(PrivilegeFinding.inheritance_path, "")).like(like),
                func.lower(cast(PrivilegeFinding.matched_evidence, String)).like(like),
            ))
    if severity:
        bands = {
            "critical": PrivilegeFinding.risk_score >= 90,
            "high": and_(PrivilegeFinding.risk_score >= 75, PrivilegeFinding.risk_score < 90),
            "medium": and_(PrivilegeFinding.risk_score >= 50, PrivilegeFinding.risk_score < 75),
            "low": and_(PrivilegeFinding.risk_score < 50),
            "review_required": PrivilegeFinding.classification == PrivilegeClass.unknown_review_required,
        }
        if severity in bands:
            q = q.filter(bands[severity])
    if platform:
        q = q.filter(Account.platform == platform)
    if classification:
        q = q.filter(PrivilegeFinding.classification == classification)
    if direct is not None:
        q = q.filter(PrivilegeFinding.direct.is_(direct))
    if pam_managed is not None:
        value = "true" if pam_managed else "false"
        q = q.filter(or_(
            func.lower(cast(Account.evidence_summary, String)).like(f'%"{value}"%'),
            func.lower(cast(Account.evidence_summary, String)).like(f'%{value}%'),
            func.lower(cast(Asset.tags, String)).like(f'%"{value}"%'),
            func.lower(cast(Asset.tags, String)).like(f'%{value}%'),
        ))
    if owner:
        like = f"%{owner.lower()}%"
        q = q.filter(or_(func.lower(func.coalesce(Account.owner, "")).like(like), func.lower(func.coalesce(Asset.owner, "")).like(like)))
    if is_winning is not None:
        q = q.filter(PrivilegeFinding.is_winning.is_(is_winning))

    rows = [_finding_out(row) for row in q.order_by(PrivilegeFinding.risk_score.desc(), PrivilegeFinding.evaluated_at.desc()).limit(5000).all()]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=[
        "finding_id", "severity", "account_name", "asset_hostname", "asset_ip_address",
        "platform", "classification", "risk_score", "confidence", "direct",
        "privilege_path", "pam_managed", "owner", "interactive_status",
        "enabled_status", "last_login", "review_state", "last_discovered",
        "rule_key", "explanation",
    ])
    writer.writeheader()
    for row in rows:
        risk = "critical" if row.risk_score >= 90 else "high" if row.risk_score >= 75 else "medium" if row.risk_score >= 50 else "low"
        if row.classification == PrivilegeClass.unknown_review_required:
            risk = "review_required"
        writer.writerow({
            "finding_id": row.id,
            "severity": risk,
            "account_name": row.account_name,
            "asset_hostname": row.asset_hostname,
            "asset_ip_address": row.asset_ip_address,
            "platform": row.platform.value if row.platform else None,
            "classification": row.classification.value,
            "risk_score": row.risk_score,
            "confidence": row.confidence,
            "direct": row.direct,
            "privilege_path": "direct" if row.direct else row.inheritance_path,
            "pam_managed": row.pam_managed,
            "owner": row.owner,
            "interactive_status": row.interactive_status,
            "enabled_status": row.enabled_status,
            "last_login": row.last_login.isoformat() if row.last_login else None,
            "review_state": row.latest_review_state.value if row.latest_review_state else "unreviewed",
            "last_discovered": row.evaluated_at.isoformat(),
            "rule_key": row.rule_key,
            "explanation": row.explanation,
        })
    log_action(db, "finding.exported", actor_id=p.id, actor_email=p.email, context={"count": len(rows), "filters": {"search": search, "severity": severity, "platform": platform.value if platform else None, "classification": classification}})
    db.commit()
    out.seek(0)
    return StreamingResponse(
        iter([out.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=privilege-findings.csv"},
    )


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permissions("privileged_findings:read")),
):
    row = (
        db.query(PrivilegeFinding, Account, Asset, FindingReviewState)
        .join(Account, Account.id == PrivilegeFinding.account_id)
        .join(Asset, Asset.id == Account.asset_id)
        .outerjoin(FindingReviewState, FindingReviewState.finding_id == PrivilegeFinding.id)
        .filter(PrivilegeFinding.id == finding_id)
        .order_by(FindingReviewState.created_at.desc().nullslast())
        .first()
    )
    if not row:
        raise HTTPException(404, "Finding not found")
    return _finding_out(row)


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
