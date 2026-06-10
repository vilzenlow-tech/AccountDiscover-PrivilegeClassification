"""Account activity tiering, housekeeping risk matrix, and nightly recompute.

Pure functions — `compute_activity_status` and `housekeeping_risk` take all
inputs as arguments so they are unit-testable without a database or settings.
"""
from __future__ import annotations

from datetime import UTC, datetime

from app.config import get_settings
from app.models.enums import ActivityStatus, PrivilegeClass

PRIVILEGED_CLASSES = {
    PrivilegeClass.full_admin,
    PrivilegeClass.admin_equivalent,
    PrivilegeClass.operator_high_impact,
    PrivilegeClass.delegated_admin,
    PrivilegeClass.privileged_service,
    PrivilegeClass.dormant_privileged,
}


def compute_activity_status(
    last_login: datetime | None,
    never_logged_in: bool | None,
    *,
    now: datetime | None = None,
    warn_days: int | None = None,
    critical_days: int | None = None,
) -> ActivityStatus:
    """Tier an account's activity. 'no evidence' is distinct from 'never logged in'."""
    settings = get_settings()
    warn = warn_days if warn_days is not None else settings.inactivity_warn_days
    critical = critical_days if critical_days is not None else settings.inactivity_critical_days
    now = now or datetime.now(UTC)

    if never_logged_in:
        return ActivityStatus.never_logged_in
    if last_login is None:
        return ActivityStatus.no_evidence
    age_days = (now - last_login).days
    if age_days > critical:
        return ActivityStatus.inactive_90d
    if age_days > warn:
        return ActivityStatus.inactive_30d
    return ActivityStatus.active


def housekeeping_risk(
    activity: ActivityStatus, privilege: PrivilegeClass
) -> tuple[str, str]:
    """Governance risk matrix -> (risk_rating, recommended_action).

    >30d: Medium / housekeeping. >90d: High / disable-or-delete review.
    Privileged >30d: High / immediate review. Privileged >90d: Critical.
    No evidence: review required. Never logged in: Medium/High by privilege.
    """
    privileged = privilege in PRIVILEGED_CLASSES
    if activity == ActivityStatus.inactive_90d:
        if privileged:
            return "critical", "Disable, remove privilege, or PAM review required"
        return "high", "Disable or delete review required"
    if activity == ActivityStatus.inactive_30d:
        if privileged:
            return "high", "Immediate review required"
        return "medium", "Housekeeping required"
    if activity == ActivityStatus.never_logged_in:
        if privileged:
            return "high", "Validate provisioning; likely removable"
        return "medium", "Aging-based cleanup candidate"
    if activity == ActivityStatus.no_evidence:
        return "review_required", "Evidence incomplete — verify collection source"
    return "low", "No action"


def recompute_all_activity(db) -> int:
    """Recompute activity_status for every account. Returns count changed."""
    from app.models.account import Account

    changed = 0
    for acc in db.query(Account).yield_per(500):
        new_status = compute_activity_status(acc.last_login, acc.never_logged_in)
        if acc.activity_status != new_status:
            acc.activity_status = new_status
            changed += 1
    db.commit()
    return changed
