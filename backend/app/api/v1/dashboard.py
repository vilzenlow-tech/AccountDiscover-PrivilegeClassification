"""Dashboard metrics endpoint."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from sqlalchemy import exists

from app.models.account import Account
from app.models.asset import Asset
from app.models.enums import PrivilegeClass
from app.models.finding import FindingReviewState, PrivilegeFinding
from app.models.job import DiscoveryJob
from app.schemas.scan import DashboardMetrics
from app.security import Principal, get_current_principal

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

PRIVILEGED_CLASSES = [
    PrivilegeClass.full_admin,
    PrivilegeClass.admin_equivalent,
    PrivilegeClass.operator_high_impact,
    PrivilegeClass.delegated_admin,
    PrivilegeClass.privileged_service,
    PrivilegeClass.dormant_privileged,
]


@router.get("/metrics", response_model=DashboardMetrics)
def get_metrics(db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    total_assets = db.query(func.count(Asset.id)).scalar() or 0
    total_accounts = db.query(func.count(Account.id)).scalar() or 0
    privileged = (
        db.query(func.count(Account.id))
        .filter(Account.privilege_classification.in_([c.value for c in PRIVILEGED_CLASSES]))
        .scalar()
        or 0
    )
    dormant = (
        db.query(func.count(Account.id))
        .filter(Account.privilege_classification == PrivilegeClass.dormant_privileged)
        .scalar()
        or 0
    )
    shared = db.query(func.count(Account.id)).filter(Account.is_shared.is_(True)).scalar() or 0
    unknown = (
        db.query(func.count(Account.id))
        .filter(Account.privilege_classification == PrivilegeClass.unknown_review_required)
        .scalar()
        or 0
    )
    week_ago = datetime.now(UTC) - timedelta(days=7)
    newly_priv = (
        db.query(func.count(Account.id))
        .filter(
            Account.privilege_classification.in_([c.value for c in PRIVILEGED_CLASSES]),
            Account.discovered_at >= week_ago,
        )
        .scalar()
        or 0
    )

    last_scan = (
        db.query(func.max(DiscoveryJob.finished_at))
        .filter(DiscoveryJob.status.in_(["success", "partial_success"]))
        .scalar()
    )
    # "Open alerts" = winning findings that have never been reviewed.
    # These are the active privilege alerts an analyst still needs to action.
    open_alerts = (
        db.query(func.count(PrivilegeFinding.id))
        .filter(PrivilegeFinding.is_winning.is_(True))
        .filter(
            ~exists().where(FindingReviewState.finding_id == PrivilegeFinding.id)
        )
        .scalar()
        or 0
    )

    platform_rows = (
        db.query(Account.platform, func.count(Account.id))
        .group_by(Account.platform)
        .all()
    )
    by_platform = {r[0].value: r[1] for r in platform_rows}

    class_rows = (
        db.query(Account.privilege_classification, func.count(Account.id))
        .group_by(Account.privilege_classification)
        .all()
    )
    by_classification = {r[0].value: r[1] for r in class_rows}

    # Local admin sprawl: assets with >3 local admins.
    sprawl_rows = (
        db.query(Account.asset_id, func.count(Account.id).label("n"))
        .filter(Account.privilege_classification == PrivilegeClass.full_admin)
        .group_by(Account.asset_id)
        .having(func.count(Account.id) > 3)
        .limit(10)
        .all()
    )
    asset_map = {a.id: a.hostname for a in db.query(Asset).all()}
    local_admin_sprawl = [
        {"asset_id": str(r.asset_id), "hostname": asset_map.get(r.asset_id, "?"), "count": r.n}
        for r in sprawl_rows
    ]

    return DashboardMetrics(
        total_assets=total_assets,
        total_accounts=total_accounts,
        privileged_accounts=privileged,
        newly_privileged_last_7d=newly_priv,
        dormant_privileged=dormant,
        shared_privileged=shared,
        unknown_review_required=unknown,
        last_scan_at=last_scan,
        open_alerts=open_alerts,
        by_platform=by_platform,
        by_classification=by_classification,
        local_admin_sprawl=local_admin_sprawl,
    )
