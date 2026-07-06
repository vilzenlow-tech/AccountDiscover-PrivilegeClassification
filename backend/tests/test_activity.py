"""Unit tests for the activity tiering engine and housekeeping risk matrix."""
from datetime import UTC, datetime, timedelta

from app.models.enums import ActivityStatus, PrivilegeClass
from app.services.activity import compute_activity_status, housekeeping_risk

NOW = datetime(2026, 6, 10, tzinfo=UTC)


def _login(days_ago: int) -> datetime:
    return NOW - timedelta(days=days_ago)


def test_active_within_warn_window():
    s = compute_activity_status(_login(10), False, now=NOW, warn_days=30, critical_days=90)
    assert s == ActivityStatus.active


def test_inactive_30d_tier():
    s = compute_activity_status(_login(45), False, now=NOW, warn_days=30, critical_days=90)
    assert s == ActivityStatus.inactive_30d


def test_inactive_90d_tier():
    s = compute_activity_status(_login(120), False, now=NOW, warn_days=30, critical_days=90)
    assert s == ActivityStatus.inactive_90d


def test_never_logged_in_beats_no_evidence():
    s = compute_activity_status(None, True, now=NOW, warn_days=30, critical_days=90)
    assert s == ActivityStatus.never_logged_in


def test_no_evidence_when_login_unknown():
    s = compute_activity_status(None, None, now=NOW, warn_days=30, critical_days=90)
    assert s == ActivityStatus.no_evidence


def test_risk_matrix_privileged_90d_critical():
    rating, action = housekeeping_risk(ActivityStatus.inactive_90d, PrivilegeClass.full_admin)
    assert rating == "critical"


def test_risk_matrix_nonprivileged_90d_high():
    rating, _ = housekeeping_risk(ActivityStatus.inactive_90d, PrivilegeClass.non_privileged)
    assert rating == "high"


def test_risk_matrix_privileged_30d_high():
    rating, _ = housekeeping_risk(ActivityStatus.inactive_30d, PrivilegeClass.admin_equivalent)
    assert rating == "high"


def test_risk_matrix_nonprivileged_30d_medium():
    rating, _ = housekeeping_risk(ActivityStatus.inactive_30d, PrivilegeClass.non_privileged)
    assert rating == "medium"


def test_risk_matrix_no_evidence_review_required():
    rating, _ = housekeeping_risk(ActivityStatus.no_evidence, PrivilegeClass.non_privileged)
    assert rating == "review_required"


def test_risk_matrix_never_logged_in_by_privilege():
    high, _ = housekeeping_risk(ActivityStatus.never_logged_in, PrivilegeClass.full_admin)
    med, _ = housekeeping_risk(ActivityStatus.never_logged_in, PrivilegeClass.non_privileged)
    assert (high, med) == ("high", "medium")


def test_mock_mode_rejected_in_prod():
    import pytest
    from app.config import validate_startup_settings

    class _S:
        env = "production"
        demo_mode = False
        secret_key = "x" * 64
        demo_seed_enabled = False
        collector_mode = "mock"

    with pytest.raises(RuntimeError, match="COLLECTOR_MODE=mock"):
        validate_startup_settings(_S())


def test_mock_mode_allowed_in_dev():
    from app.config import validate_startup_settings

    class _S:
        env = "development"
        demo_mode = False
        secret_key = "dev-only-change-me"
        demo_seed_enabled = False
        collector_mode = "mock"

    validate_startup_settings(_S())  # must not raise
