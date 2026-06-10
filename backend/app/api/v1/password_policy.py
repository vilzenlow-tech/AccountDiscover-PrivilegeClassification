"""Password Policy Discovery API.

Endpoints
---------
GET    /password-policy                   List policies (filterable)
POST   /password-policy                   Upsert a policy (scanner / import)
GET    /password-policy/summary           Dashboard summary stats
GET    /password-policy/findings          List findings (filterable)
POST   /password-policy/findings/{id}/review  Set review state on a finding
GET    /password-policy/exceptions        List account-level exceptions
POST   /password-policy/compare           Compare policies across assets
GET    /password-policy/export/csv        CSV export
GET    /password-policy/export/excel      Excel export
GET    /password-policy/{id}              Get a single policy
PUT    /password-policy/{id}              Update a policy
DELETE /password-policy/{id}              Delete a policy
GET    /password-policy/{id}/exceptions   Exceptions for a specific policy

Also wires into the assets router via a sub-path:
GET    /assets/{asset_id}/password-policy  All policies for an asset
"""
from __future__ import annotations

import csv
import io
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.asset import Asset
from app.models.password_policy import (
    AccountPolicyException,
    PasswordPolicy,
    PasswordPolicyFinding,
)
from app.models.enums import (
    Platform,
    PolicyFindingReviewState,
    PolicyFindingSeverity,
    PolicySource,
)
from app.schemas.common import Page
from app.schemas.password_policy import (
    AccountPolicyExceptionIn,
    AccountPolicyExceptionOut,
    PasswordPolicyFindingOut,
    PasswordPolicyIn,
    PasswordPolicyOut,
    PasswordPolicySummary,
    PolicyCompareRequest,
    PolicyCompareResult,
    PolicyCompareRow,
    PolicyCompareCell,
    PolicyFindingReviewIn,
    AssetRef,
)
from app.security import Principal, get_current_principal, require_roles
from app.services.audit import log_action
from app.services.password_policy_rules import evaluate_policy

router = APIRouter(prefix="/password-policy", tags=["password-policy"])

# ── Helpers ───────────────────────────────────────────────────────────────────

_WEAK_TESTS: dict[str, Any] = {
    "min_password_length": lambda v: v is not None and v < 12,
    "complexity_enabled": lambda v: v is False,
    "lockout_threshold": lambda v: v is not None and v == 0,
    "max_password_age_days": lambda v: v is not None and v == 0,
    "reversible_encryption_enabled": lambda v: v is True,
}

_SETTING_LABELS: dict[str, str] = {
    "min_password_length": "Minimum Password Length",
    "complexity_enabled": "Password Complexity",
    "password_history_count": "Password History Count",
    "min_password_age_days": "Minimum Password Age (days)",
    "max_password_age_days": "Maximum Password Age (days)",
    "reversible_encryption_enabled": "Reversible Encryption",
    "lockout_threshold": "Lockout Threshold (attempts)",
    "lockout_duration_minutes": "Lockout Duration (minutes)",
    "reset_lockout_counter_after_minutes": "Reset Lockout Counter After (minutes)",
    "dictionary_check_enabled": "Dictionary Check",
    "external_policy_enforced": "External Policy Enforced",
}

_BASELINE: dict[str, Any] = {
    "min_password_length": 12,
    "complexity_enabled": True,
    "password_history_count": 10,
    "min_password_age_days": 1,
    "max_password_age_days": 90,
    "reversible_encryption_enabled": False,
    "lockout_threshold": 5,
    "lockout_duration_minutes": 30,
    "dictionary_check_enabled": True,
}


def _enrich(policy: PasswordPolicy, db: Session) -> PasswordPolicyOut:
    """Compute derived flags and finding counts then build the output DTO."""
    finding_q = db.query(PasswordPolicyFinding).filter(
        PasswordPolicyFinding.policy_id == policy.id
    )
    total_findings = finding_q.count()
    crit_findings = finding_q.filter(
        PasswordPolicyFinding.severity == PolicyFindingSeverity.critical
    ).count()

    hostname = policy.asset.hostname if policy.asset else None
    out = PasswordPolicyOut.model_validate(policy)
    out.hostname = hostname
    out.finding_count = total_findings
    out.critical_finding_count = crit_findings
    ml = policy.min_password_length
    out.has_weak_length = (ml is not None and ml < 12)
    out.has_no_complexity = (policy.complexity_enabled is False)
    out.has_no_lockout = (policy.lockout_threshold == 0)
    out.has_no_expiry = (policy.max_password_age_days == 0)
    return out


def _enrich_exception(exc: AccountPolicyException) -> AccountPolicyExceptionOut:
    out = AccountPolicyExceptionOut.model_validate(exc)
    if exc.account:
        out.account_name = getattr(exc.account, "account_name", None)
    if exc.policy and exc.policy.asset:
        out.asset_hostname = exc.policy.asset.hostname
    elif exc.asset_id:
        out.asset_hostname = None  # asset_id available but asset not joined
    return out


def _enrich_finding(f: PasswordPolicyFinding, db: Session) -> PasswordPolicyFindingOut:
    out = PasswordPolicyFindingOut.model_validate(f)
    asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
    if asset:
        out.hostname = asset.hostname
        out.platform = asset.platform
    if f.account_id:
        from app.models.account import Account
        acc = db.query(Account).filter(Account.id == f.account_id).first()
        if acc:
            out.account_name = acc.account_name
    return out


# ── Policy endpoints ──────────────────────────────────────────────────────────

@router.get("", response_model=Page[PasswordPolicyOut])
def list_policies(
    asset_id: uuid.UUID | None = None,
    platform: Platform | None = None,
    policy_source: PolicySource | None = None,
    is_effective_policy: bool | None = None,
    has_weak_length: bool | None = None,
    has_no_lockout: bool | None = None,
    has_no_complexity: bool | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(PasswordPolicy)
    if asset_id:
        q = q.filter(PasswordPolicy.asset_id == asset_id)
    if platform:
        q = q.filter(PasswordPolicy.platform == platform)
    if policy_source:
        q = q.filter(PasswordPolicy.policy_source == policy_source)
    if is_effective_policy is not None:
        q = q.filter(PasswordPolicy.is_effective_policy.is_(is_effective_policy))
    if has_weak_length:
        q = q.filter(PasswordPolicy.min_password_length < 12)
    if has_no_lockout:
        q = q.filter(PasswordPolicy.lockout_threshold == 0)
    if has_no_complexity:
        q = q.filter(PasswordPolicy.complexity_enabled.is_(False))

    total = q.count()
    policies = q.order_by(PasswordPolicy.discovered_at.desc()).offset(offset).limit(limit).all()
    return Page(
        items=[_enrich(p, db) for p in policies],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/summary", response_model=PasswordPolicySummary)
def get_summary(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    # Asset-level stats
    total_assets = db.query(Asset).count()
    assets_with_policy = (
        db.query(func.count(func.distinct(PasswordPolicy.asset_id))).scalar() or 0
    )

    # Finding counts by severity
    def _finding_count(sev: str) -> int:
        return (
            db.query(PasswordPolicyFinding)
            .filter(PasswordPolicyFinding.severity == sev)
            .count()
        )

    open_findings = (
        db.query(PasswordPolicyFinding)
        .filter(PasswordPolicyFinding.review_state == PolicyFindingReviewState.open)
        .count()
    )

    # Weak policy counts
    weak_length = (
        db.query(func.count(func.distinct(PasswordPolicy.asset_id)))
        .filter(PasswordPolicy.min_password_length < 12)
        .scalar() or 0
    )
    no_complexity = (
        db.query(func.count(func.distinct(PasswordPolicy.asset_id)))
        .filter(PasswordPolicy.complexity_enabled.is_(False))
        .scalar() or 0
    )
    no_lockout = (
        db.query(func.count(func.distinct(PasswordPolicy.asset_id)))
        .filter(PasswordPolicy.lockout_threshold == 0)
        .scalar() or 0
    )
    rev_enc = (
        db.query(func.count(func.distinct(PasswordPolicy.asset_id)))
        .filter(PasswordPolicy.reversible_encryption_enabled.is_(True))
        .scalar() or 0
    )

    total_exc = db.query(AccountPolicyException).count()
    priv_exc = (
        db.query(AccountPolicyException)
        .filter(AccountPolicyException.exception_type == "privileged_account_weak_policy")
        .count()
    )

    # By-platform and by-source counts
    by_platform: dict[str, int] = {}
    for row in (
        db.query(PasswordPolicy.platform, func.count().label("cnt"))
        .group_by(PasswordPolicy.platform)
        .all()
    ):
        by_platform[row.platform.value] = row.cnt

    by_source: dict[str, int] = {}
    for row in (
        db.query(PasswordPolicy.policy_source, func.count().label("cnt"))
        .group_by(PasswordPolicy.policy_source)
        .all()
    ):
        by_source[row.policy_source.value] = row.cnt

    effective_count = (
        db.query(PasswordPolicy).filter(PasswordPolicy.is_effective_policy.is_(True)).count()
    )

    return PasswordPolicySummary(
        total_assets_with_policy=assets_with_policy,
        total_policies=db.query(PasswordPolicy).count(),
        effective_policies=effective_count,
        assets_with_no_policy=max(0, total_assets - assets_with_policy),
        critical_findings=_finding_count("critical"),
        high_findings=_finding_count("high"),
        medium_findings=_finding_count("medium"),
        low_findings=_finding_count("low"),
        open_findings=open_findings,
        total_exceptions=total_exc,
        privileged_account_exceptions=priv_exc,
        assets_with_weak_length=weak_length,
        assets_with_no_complexity=no_complexity,
        assets_with_no_lockout=no_lockout,
        assets_with_reversible_encryption=rev_enc,
        by_platform=by_platform,
        by_policy_source=by_source,
    )


@router.post("", response_model=PasswordPolicyOut, status_code=201)
def upsert_policy(
    body: PasswordPolicyIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    """Create or update a password policy record and re-run the rules engine."""
    asset = db.query(Asset).filter(Asset.id == body.asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")

    # Upsert: find existing row by unique key
    existing = (
        db.query(PasswordPolicy)
        .filter(
            PasswordPolicy.asset_id == body.asset_id,
            PasswordPolicy.policy_source == body.policy_source,
            PasswordPolicy.policy_name == body.policy_name,
        )
        .first()
    )
    if existing:
        for k, v in body.model_dump(exclude={"asset_id"}).items():
            if hasattr(existing, k) and v is not None:
                setattr(existing, k, v)
        policy = existing
    else:
        policy = PasswordPolicy(**body.model_dump())
        db.add(policy)

    db.flush()

    # Re-run rules engine — delete stale findings first
    db.query(PasswordPolicyFinding).filter(
        PasswordPolicyFinding.policy_id == policy.id,
        PasswordPolicyFinding.is_exception_finding.is_(False),
    ).delete(synchronize_session=False)

    exceptions = (
        db.query(AccountPolicyException)
        .filter(AccountPolicyException.policy_id == policy.id)
        .all()
    )
    new_findings = evaluate_policy(policy, exceptions)
    for f in new_findings:
        db.add(f)

    log_action(
        db, "password_policy.upserted",
        actor_id=p.id, actor_email=p.email,
        subject_type="password_policy", subject_id=str(policy.id),
        context={"asset_id": str(body.asset_id), "source": body.policy_source.value},
    )
    db.commit()
    db.refresh(policy)
    return _enrich(policy, db)


@router.get("/findings", response_model=Page[PasswordPolicyFindingOut])
def list_findings(
    asset_id: uuid.UUID | None = None,
    account_id: uuid.UUID | None = None,
    policy_id: uuid.UUID | None = None,
    severity: PolicyFindingSeverity | None = None,
    rule_key: str | None = None,
    review_state: PolicyFindingReviewState | None = None,
    is_exception_finding: bool | None = None,
    platform: Platform | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(PasswordPolicyFinding)
    if asset_id:
        q = q.filter(PasswordPolicyFinding.asset_id == asset_id)
    if account_id:
        q = q.filter(PasswordPolicyFinding.account_id == account_id)
    if policy_id:
        q = q.filter(PasswordPolicyFinding.policy_id == policy_id)
    if severity:
        q = q.filter(PasswordPolicyFinding.severity == severity)
    if rule_key:
        q = q.filter(PasswordPolicyFinding.rule_key == rule_key)
    if review_state:
        q = q.filter(PasswordPolicyFinding.review_state == review_state)
    if is_exception_finding is not None:
        q = q.filter(PasswordPolicyFinding.is_exception_finding.is_(is_exception_finding))
    if platform:
        # Join to asset to filter by platform
        q = q.join(Asset, Asset.id == PasswordPolicyFinding.asset_id).filter(
            Asset.platform == platform
        )

    total = q.count()
    # Severity ordering: critical first
    _sev_order = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
    }
    items = (
        q.order_by(PasswordPolicyFinding.discovered_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return Page(
        items=[_enrich_finding(f, db) for f in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/findings/{finding_id}", response_model=PasswordPolicyFindingOut)
def get_finding(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    f = db.query(PasswordPolicyFinding).filter(PasswordPolicyFinding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    return _enrich_finding(f, db)


@router.post("/findings/{finding_id}/review", status_code=200)
def review_finding(
    finding_id: uuid.UUID,
    body: PolicyFindingReviewIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst", "auditor")),
):
    f = db.query(PasswordPolicyFinding).filter(PasswordPolicyFinding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    f.review_state = body.state
    f.reviewed_by = p.email
    f.reviewed_at = datetime.now(UTC)
    f.review_comment = body.comment
    log_action(
        db, "password_policy_finding.reviewed",
        actor_id=p.id, actor_email=p.email,
        subject_type="password_policy_finding", subject_id=str(finding_id),
        context={"state": body.state.value},
    )
    db.commit()
    return {"detail": "Review state recorded", "state": body.state.value}


@router.get("/exceptions", response_model=Page[AccountPolicyExceptionOut])
def list_exceptions(
    asset_id: uuid.UUID | None = None,
    account_id: uuid.UUID | None = None,
    exception_type: str | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(AccountPolicyException)
    if asset_id:
        q = q.filter(AccountPolicyException.asset_id == asset_id)
    if account_id:
        q = q.filter(AccountPolicyException.account_id == account_id)
    if exception_type:
        q = q.filter(AccountPolicyException.exception_type == exception_type)
    total = q.count()
    items = q.order_by(AccountPolicyException.discovered_at.desc()).offset(offset).limit(limit).all()
    return Page(
        items=[_enrich_exception(e) for e in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/exceptions", response_model=AccountPolicyExceptionOut, status_code=201)
def create_exception(
    body: AccountPolicyExceptionIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    exc = AccountPolicyException(**body.model_dump())
    db.add(exc)
    db.flush()

    # If linked to a policy, re-run exception findings for that policy
    if exc.policy_id:
        policy = db.query(PasswordPolicy).filter(PasswordPolicy.id == exc.policy_id).first()
        if policy:
            db.query(PasswordPolicyFinding).filter(
                PasswordPolicyFinding.policy_id == policy.id,
                PasswordPolicyFinding.is_exception_finding.is_(True),
            ).delete(synchronize_session=False)
            all_exceptions = (
                db.query(AccountPolicyException)
                .filter(AccountPolicyException.policy_id == policy.id)
                .all()
            )
            for f in evaluate_policy(policy, all_exceptions):
                if f.is_exception_finding:
                    db.add(f)

    log_action(
        db, "password_policy_exception.created",
        actor_id=p.id, actor_email=p.email,
        subject_type="account_policy_exception", subject_id=str(exc.id),
    )
    db.commit()
    db.refresh(exc)
    return _enrich_exception(exc)


@router.post("/compare", response_model=PolicyCompareResult)
def compare_policies(
    body: PolicyCompareRequest,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    """Compare effective password policies across 2–20 assets."""
    assets = db.query(Asset).filter(Asset.id.in_(body.asset_ids)).all()
    asset_map: dict[str, Asset] = {str(a.id): a for a in assets}
    missing = [str(i) for i in body.asset_ids if str(i) not in asset_map]
    if missing:
        raise HTTPException(404, f"Assets not found: {', '.join(missing)}")

    # Fetch the effective policy per asset (prefer is_effective_policy=True,
    # fall back to latest discovered row)
    policies_by_asset: dict[str, PasswordPolicy | None] = {}
    for asset_id_key in asset_map:
        eff = (
            db.query(PasswordPolicy)
            .filter(
                PasswordPolicy.asset_id == uuid.UUID(asset_id_key),
                PasswordPolicy.is_effective_policy.is_(True),
            )
            .first()
        )
        if not eff:
            eff = (
                db.query(PasswordPolicy)
                .filter(PasswordPolicy.asset_id == uuid.UUID(asset_id_key))
                .order_by(PasswordPolicy.discovered_at.desc())
                .first()
            )
        policies_by_asset[asset_id_key] = eff

    compare_fields = list(_SETTING_LABELS.keys())
    rows: list[PolicyCompareRow] = []
    inconsistency_count = 0
    worst: PolicyFindingSeverity | None = None

    sev_rank = {
        PolicyFindingSeverity.critical: 0,
        PolicyFindingSeverity.high: 1,
        PolicyFindingSeverity.medium: 2,
        PolicyFindingSeverity.low: 3,
        PolicyFindingSeverity.info: 4,
    }

    def _update_worst(sev: PolicyFindingSeverity) -> None:
        nonlocal worst
        if worst is None or sev_rank[sev] < sev_rank[worst]:
            worst = sev

    for field in compare_fields:
        cells: list[PolicyCompareCell] = []
        values_seen: set = set()
        for aid, pol in policies_by_asset.items():
            val = getattr(pol, field, None) if pol else None
            is_weak = bool(_WEAK_TESTS.get(field, lambda _: False)(val))
            cells.append(
                PolicyCompareCell(
                    asset_id=uuid.UUID(aid),
                    hostname=asset_map[aid].hostname,
                    value=val,
                    source=pol.policy_source.value if pol else None,
                    is_effective=bool(pol and pol.is_effective_policy),
                    is_weak=is_weak,
                )
            )
            values_seen.add(repr(val))

        has_inconsistency = len(values_seen) > 1
        if has_inconsistency:
            inconsistency_count += 1
            _update_worst(PolicyFindingSeverity.medium)
        # Report worst severity for any weak cell
        for c in cells:
            if c.is_weak:
                sev_for_field = {
                    "min_password_length": PolicyFindingSeverity.high,
                    "complexity_enabled": PolicyFindingSeverity.high,
                    "lockout_threshold": PolicyFindingSeverity.high,
                    "max_password_age_days": PolicyFindingSeverity.medium,
                    "reversible_encryption_enabled": PolicyFindingSeverity.critical,
                }.get(field, PolicyFindingSeverity.medium)
                _update_worst(sev_for_field)

        rows.append(
            PolicyCompareRow(
                setting=field,
                label=_SETTING_LABELS[field],
                baseline=_BASELINE.get(field),
                values=cells,
                has_inconsistency=has_inconsistency,
                worst_severity=worst if has_inconsistency else None,
            )
        )

    return PolicyCompareResult(
        assets=[AssetRef(id=a.id, hostname=a.hostname, platform=a.platform) for a in assets],
        rows=rows,
        inconsistency_count=inconsistency_count,
        worst_severity=worst,
    )


@router.get("/export/csv")
def export_csv(
    asset_id: uuid.UUID | None = None,
    platform: Platform | None = None,
    is_effective_policy: bool | None = None,
    db: Session = Depends(get_db),
    p: Principal = Depends(get_current_principal),
):
    q = db.query(PasswordPolicy)
    if asset_id:
        q = q.filter(PasswordPolicy.asset_id == asset_id)
    if platform:
        q = q.filter(PasswordPolicy.platform == platform)
    if is_effective_policy is not None:
        q = q.filter(PasswordPolicy.is_effective_policy.is_(is_effective_policy))

    policies = q.order_by(PasswordPolicy.discovered_at.desc()).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "asset_hostname", "asset_id", "platform", "policy_source", "policy_scope",
        "policy_name", "is_effective_policy", "min_password_length", "complexity_enabled",
        "password_history_count", "min_password_age_days", "max_password_age_days",
        "reversible_encryption_enabled", "lockout_threshold", "lockout_duration_minutes",
        "reset_lockout_counter_after_minutes", "dictionary_check_enabled",
        "external_policy_enforced", "requires_external_review",
        "confidence_score", "collection_error", "discovered_at",
    ])
    for pol in policies:
        hostname = pol.asset.hostname if pol.asset else ""
        writer.writerow([
            hostname, str(pol.asset_id), pol.platform.value, pol.policy_source.value,
            pol.policy_scope.value, pol.policy_name or "", pol.is_effective_policy,
            pol.min_password_length, pol.complexity_enabled, pol.password_history_count,
            pol.min_password_age_days, pol.max_password_age_days,
            pol.reversible_encryption_enabled, pol.lockout_threshold,
            pol.lockout_duration_minutes, pol.reset_lockout_counter_after_minutes,
            pol.dictionary_check_enabled, pol.external_policy_enforced,
            pol.requires_external_review, pol.confidence_score,
            pol.collection_error or "", pol.discovered_at.isoformat(),
        ])

    log_action(
        db, "password_policy.exported_csv",
        actor_id=p.id, actor_email=p.email,
        context={"rows": len(policies)},
    )
    db.commit()

    content = buf.getvalue().encode("utf-8-sig")
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=password_policies.csv"},
    )


@router.get("/export/excel")
def export_excel(
    asset_id: uuid.UUID | None = None,
    platform: Platform | None = None,
    is_effective_policy: bool | None = None,
    db: Session = Depends(get_db),
    p: Principal = Depends(get_current_principal),
):
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment
    except ImportError:
        raise HTTPException(501, "openpyxl is not installed on this server")

    q = db.query(PasswordPolicy)
    if asset_id:
        q = q.filter(PasswordPolicy.asset_id == asset_id)
    if platform:
        q = q.filter(PasswordPolicy.platform == platform)
    if is_effective_policy is not None:
        q = q.filter(PasswordPolicy.is_effective_policy.is_(is_effective_policy))

    policies = q.order_by(PasswordPolicy.discovered_at.desc()).all()
    findings = (
        db.query(PasswordPolicyFinding)
        .filter(PasswordPolicyFinding.review_state == PolicyFindingReviewState.open)
        .all()
    )
    exceptions = db.query(AccountPolicyException).all()

    wb = openpyxl.Workbook()

    # ── Sheet 1: Password Policies ────────────────────────────────────────────
    ws = wb.active
    ws.title = "Password Policies"
    header_fill = PatternFill("solid", fgColor="1E293B")
    header_font = Font(bold=True, color="FFFFFF")
    headers = [
        "Hostname", "Platform", "Policy Source", "Policy Name", "Effective",
        "Min Length", "Complexity", "History", "Min Age (d)", "Max Age (d)",
        "Rev. Encryption", "Lockout Threshold", "Lockout Duration (m)",
        "Reset Counter (m)", "Dict. Check", "External Policy",
        "Confidence %", "Collection Error", "Discovered At",
    ]
    ws.append(headers)
    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center")

    red_fill = PatternFill("solid", fgColor="FEE2E2")
    for pol in policies:
        hostname = pol.asset.hostname if pol.asset else ""
        row = [
            hostname, pol.platform.value, pol.policy_source.value,
            pol.policy_name or "", "Yes" if pol.is_effective_policy else "No",
            pol.min_password_length, pol.complexity_enabled, pol.password_history_count,
            pol.min_password_age_days, pol.max_password_age_days,
            pol.reversible_encryption_enabled, pol.lockout_threshold,
            pol.lockout_duration_minutes, pol.reset_lockout_counter_after_minutes,
            pol.dictionary_check_enabled, pol.external_policy_enforced,
            pol.confidence_score, pol.collection_error or "",
            pol.discovered_at.strftime("%Y-%m-%d %H:%M UTC"),
        ]
        ws.append(row)
        # Highlight weak settings
        r = ws.max_row
        if pol.min_password_length is not None and pol.min_password_length < 12:
            ws.cell(r, 6).fill = red_fill
        if pol.complexity_enabled is False:
            ws.cell(r, 7).fill = red_fill
        if pol.lockout_threshold == 0:
            ws.cell(r, 12).fill = red_fill

    # ── Sheet 2: Findings ─────────────────────────────────────────────────────
    ws2 = wb.create_sheet("Findings")
    ws2.append(["Rule Key", "Severity", "Title", "Asset Hostname", "Account",
                "Affected Scope", "Review State", "Discovered At"])
    for cell in ws2[1]:
        cell.fill = header_fill
        cell.font = header_font
    sev_colors = {
        "critical": "DC2626", "high": "EA580C",
        "medium": "D97706", "low": "65A30D", "info": "0284C7",
    }
    for f in findings:
        asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
        ws2.append([
            f.rule_key, f.severity.value, f.title,
            asset.hostname if asset else str(f.asset_id),
            str(f.account_id) if f.account_id else "",
            f.affected_scope or "", f.review_state.value,
            f.discovered_at.strftime("%Y-%m-%d %H:%M UTC"),
        ])
        color = sev_colors.get(f.severity.value, "6B7280")
        ws2.cell(ws2.max_row, 2).font = Font(bold=True, color=color)

    # ── Sheet 3: Account Exceptions ───────────────────────────────────────────
    ws3 = wb.create_sheet("Account Exceptions")
    ws3.append(["Exception Type", "Asset Hostname", "Account ID",
                "Effective Policy", "Expected Policy", "Discovered At"])
    for cell in ws3[1]:
        cell.fill = header_fill
        cell.font = header_font
    for exc in exceptions:
        asset = db.query(Asset).filter(Asset.id == exc.asset_id).first()
        ws3.append([
            exc.exception_type,
            asset.hostname if asset else str(exc.asset_id),
            str(exc.account_id) if exc.account_id else "",
            exc.effective_policy_source or "",
            exc.expected_policy_source or "",
            exc.discovered_at.strftime("%Y-%m-%d %H:%M UTC"),
        ])

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)

    log_action(
        db, "password_policy.exported_excel",
        actor_id=p.id, actor_email=p.email,
        context={"policies": len(policies), "findings": len(findings)},
    )
    db.commit()

    return Response(
        content=buf.read(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=password_policies.xlsx"},
    )


@router.get("/{policy_id}", response_model=PasswordPolicyOut)
def get_policy(
    policy_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    pol = db.query(PasswordPolicy).filter(PasswordPolicy.id == policy_id).first()
    if not pol:
        raise HTTPException(404, "Policy not found")
    return _enrich(pol, db)


@router.put("/{policy_id}", response_model=PasswordPolicyOut)
def update_policy(
    policy_id: uuid.UUID,
    body: PasswordPolicyIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    pol = db.query(PasswordPolicy).filter(PasswordPolicy.id == policy_id).first()
    if not pol:
        raise HTTPException(404, "Policy not found")

    for k, v in body.model_dump(exclude={"asset_id"}).items():
        if hasattr(pol, k):
            setattr(pol, k, v)

    # Re-run rules
    db.query(PasswordPolicyFinding).filter(
        PasswordPolicyFinding.policy_id == pol.id,
        PasswordPolicyFinding.is_exception_finding.is_(False),
    ).delete(synchronize_session=False)
    exceptions = (
        db.query(AccountPolicyException).filter(AccountPolicyException.policy_id == pol.id).all()
    )
    for f in evaluate_policy(pol, exceptions):
        db.add(f)

    log_action(
        db, "password_policy.updated",
        actor_id=p.id, actor_email=p.email,
        subject_type="password_policy", subject_id=str(policy_id),
    )
    db.commit()
    db.refresh(pol)
    return _enrich(pol, db)


@router.delete("/{policy_id}", status_code=204)
def delete_policy(
    policy_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin")),
):
    pol = db.query(PasswordPolicy).filter(PasswordPolicy.id == policy_id).first()
    if not pol:
        raise HTTPException(404, "Policy not found")
    log_action(
        db, "password_policy.deleted",
        actor_id=p.id, actor_email=p.email,
        subject_type="password_policy", subject_id=str(policy_id),
    )
    db.delete(pol)
    db.commit()


@router.get("/{policy_id}/exceptions", response_model=list[AccountPolicyExceptionOut])
def get_policy_exceptions(
    policy_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    pol = db.query(PasswordPolicy).filter(PasswordPolicy.id == policy_id).first()
    if not pol:
        raise HTTPException(404, "Policy not found")
    excs = (
        db.query(AccountPolicyException)
        .filter(AccountPolicyException.policy_id == policy_id)
        .all()
    )
    return [_enrich_exception(e) for e in excs]
