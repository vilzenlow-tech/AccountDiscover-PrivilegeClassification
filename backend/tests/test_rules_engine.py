"""Unit tests for the privilege classification rules engine.

These tests run entirely in-process with no database or network calls.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.collectors.base import NormalizedAccount, NormalizedEntitlement
from app.models.enums import (
    AuthSource,
    EnabledStatus,
    InteractiveStatus,
    PrivilegeClass,
    PrincipalType,
)
from app.rules_engine.builtin_rules import BUILTIN_RULES
from app.rules_engine.engine import RulesEngine, RuleSpec


# Accounts that logged in recently should NOT be classified as dormant.
_RECENT_LOGIN = datetime.now(UTC) - timedelta(days=1)


def _make_engine(platform_filter: str | None = None) -> RulesEngine:
    specs = []
    for rd in BUILTIN_RULES:
        if platform_filter and rd.get("platform") and rd["platform"] != platform_filter:
            continue
        specs.append(
            RuleSpec(
                id=str(uuid.uuid4()),
                rule_key=rd["rule_key"],
                name=rd["name"],
                platform=rd.get("platform"),
                predicate=rd["predicate"],
                classify_as=PrivilegeClass(rd["classify_as"]),
                confidence=rd["confidence"],
                risk_modifier=rd["risk_modifier"],
                explanation_template=rd["explanation_template"],
                priority=rd["priority"],
                version=1,
            )
        )
    return RulesEngine(specs, dormancy_days=90)


def _account(
    name: str = "testuser",
    entitlements: list[NormalizedEntitlement] | None = None,
    principal_type: PrincipalType = PrincipalType.human,
    last_login: datetime | None = None,
    interactive: InteractiveStatus = InteractiveStatus.interactive,
    evidence: dict | None = None,
) -> NormalizedAccount:
    return NormalizedAccount(
        account_name=name,
        source_type="test",
        principal_type=principal_type,
        auth_source=AuthSource.local,
        enabled_status=EnabledStatus.enabled,
        interactive_status=interactive,
        last_login=last_login,
        evidence_summary=evidence or {},
        entitlements=entitlements or [],
    )


# ---------------------------------------------------------------------------
# RHEL rules
# ---------------------------------------------------------------------------

class TestRHELRules:
    def test_uid0_is_full_admin(self):
        engine = _make_engine("rhel")
        acc = _account(
            name="root",
            entitlements=[NormalizedEntitlement(kind="unix_uid0", name="root")],
            evidence={"uid": 0},
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.full_admin
        assert result.winning_confidence >= 99

    def test_non_uid0_root_named_account_is_not_classified_full_admin_by_uid0_rule(self):
        engine = _make_engine("rhel")
        acc = _account(name="fakeroots", entitlements=[], evidence={"uid": 1001})
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.non_privileged

    def test_broad_sudo_is_admin_equivalent(self):
        engine = _make_engine("rhel")
        acc = _account(
            name="oracle",
            entitlements=[
                NormalizedEntitlement(
                    kind="sudo_rule",
                    name="oracle ALL=(ALL) NOPASSWD: ALL",
                    attributes={"broad": True, "nopasswd": True},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification in (
            PrivilegeClass.admin_equivalent,
            PrivilegeClass.full_admin,
        )

    def test_limited_sudo_not_admin_equivalent(self):
        engine = _make_engine("rhel")
        acc = _account(
            name="deplsvc",
            entitlements=[
                NormalizedEntitlement(
                    kind="sudo_rule",
                    name="deplsvc ALL=(root) NOPASSWD: /usr/bin/systemctl restart app",
                    attributes={"broad": False, "nopasswd": True},
                )
            ],
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.non_privileged

    def test_service_account_broad_sudo_is_privileged_service(self):
        engine = _make_engine()
        acc = _account(
            name="backup_svc",
            principal_type=PrincipalType.service,
            entitlements=[
                NormalizedEntitlement(
                    kind="sudo_rule",
                    name="backup_svc ALL=(ALL) NOPASSWD: ALL",
                    attributes={"broad": True},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        # Service accounts with broad sudo may be classified as privileged_service
        # or admin_equivalent depending on which rule wins — both indicate high risk.
        assert result.winning_classification in (
            PrivilegeClass.privileged_service,
            PrivilegeClass.admin_equivalent,
        )

    def test_dormant_privileged_is_detected(self):
        engine = _make_engine("rhel")
        old_login = datetime.now(UTC) - timedelta(days=200)
        acc = _account(
            name="inactive_admin",
            entitlements=[NormalizedEntitlement(kind="unix_uid0", name="root")],
            evidence={"uid": 0},
            last_login=old_login,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.dormant_privileged
        assert result.dormant is True

    def test_no_login_dormant(self):
        engine = _make_engine("rhel")
        acc = _account(
            name="old_root",
            entitlements=[NormalizedEntitlement(kind="unix_uid0", name="root")],
            evidence={"uid": 0},
            last_login=None,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.dormant_privileged


# ---------------------------------------------------------------------------
# Solaris rules
# ---------------------------------------------------------------------------

class TestSolarisRules:
    def test_primary_administrator_profile_is_admin_equivalent(self):
        engine = _make_engine("solaris")
        acc = _account(
            name="oraops",
            entitlements=[
                NormalizedEntitlement(
                    kind="solaris_rbac_profile",
                    name="Primary Administrator",
                    attributes={"broad": True, "auths": "solaris.*,solaris.grant"},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification in (
            PrivilegeClass.admin_equivalent,
            PrivilegeClass.full_admin,
        )

    def test_non_broad_profile_is_not_admin(self):
        engine = _make_engine("solaris")
        acc = _account(
            name="auditor",
            entitlements=[
                NormalizedEntitlement(
                    kind="solaris_rbac_profile",
                    name="Audit Review",
                    attributes={"broad": False, "auths": "solaris.audit.read"},
                )
            ],
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.non_privileged


# ---------------------------------------------------------------------------
# Windows rules
# ---------------------------------------------------------------------------

class TestWindowsRules:
    def test_local_administrators_is_full_admin(self):
        engine = _make_engine("windows")
        acc = _account(
            name="Administrator",
            entitlements=[
                NormalizedEntitlement(
                    kind="windows_local_group",
                    name="Administrators",
                    attributes={"is_administrators": True, "high_impact": True},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.full_admin

    def test_backup_operators_is_operator_high_impact(self):
        engine = _make_engine("windows")
        acc = _account(
            name="svc_backup",
            entitlements=[
                NormalizedEntitlement(
                    kind="windows_local_group",
                    name="Backup Operators",
                    attributes={"is_administrators": False, "high_impact": True},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.operator_high_impact

    def test_non_admin_group_is_not_privileged(self):
        engine = _make_engine("windows")
        acc = _account(
            name="jdoe",
            entitlements=[
                NormalizedEntitlement(
                    kind="windows_local_group",
                    name="Users",
                    attributes={"is_administrators": False, "high_impact": False},
                )
            ],
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.non_privileged


# ---------------------------------------------------------------------------
# MySQL rules
# ---------------------------------------------------------------------------

class TestMySQLRules:
    def test_global_all_privileges_is_full_admin(self):
        engine = _make_engine("mysql")
        acc = _account(
            name="root@localhost",
            entitlements=[
                NormalizedEntitlement(
                    kind="mysql_grant",
                    name="ALL PRIVILEGES",
                    scope="*.*",
                    attributes={"global_admin": True, "with_grant_option": True},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.full_admin

    def test_scoped_select_is_not_privileged(self):
        engine = _make_engine("mysql")
        acc = _account(
            name="readonly@%",
            entitlements=[
                NormalizedEntitlement(
                    kind="mysql_grant",
                    name="SELECT",
                    scope="app.*",
                    attributes={"global_admin": False},
                )
            ],
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.non_privileged


# ---------------------------------------------------------------------------
# MSSQL rules
# ---------------------------------------------------------------------------

class TestMSSQLRules:
    def test_sysadmin_is_full_admin(self):
        engine = _make_engine("mssql")
        acc = _account(
            name="sa",
            entitlements=[
                NormalizedEntitlement(
                    kind="mssql_server_role",
                    name="sysadmin",
                    scope="server",
                    attributes={"high_risk": True},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.full_admin

    def test_securityadmin_is_admin_equivalent(self):
        engine = _make_engine("mssql")
        acc = _account(
            name="sec_admin",
            entitlements=[
                NormalizedEntitlement(
                    kind="mssql_server_role",
                    name="securityadmin",
                    scope="server",
                    attributes={"high_risk": True},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.admin_equivalent

    def test_db_owner_is_delegated_admin(self):
        engine = _make_engine("mssql")
        acc = _account(
            name="app_user",
            entitlements=[
                NormalizedEntitlement(
                    kind="mssql_db_role",
                    name="db_owner",
                    scope="AppDB",
                    attributes={"high_risk": True},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.delegated_admin


# ---------------------------------------------------------------------------
# MongoDB rules
# ---------------------------------------------------------------------------

class TestMongoRules:
    def test_root_role_is_full_admin(self):
        engine = _make_engine("mongodb")
        acc = _account(
            name="admin@admin",
            entitlements=[
                NormalizedEntitlement(
                    kind="mongo_role",
                    name="root",
                    scope="admin",
                    attributes={"admin_critical": True},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.full_admin

    def test_userAdminAnyDatabase_is_admin_equivalent(self):
        engine = _make_engine("mongodb")
        acc = _account(
            name="userAdmin@admin",
            entitlements=[
                NormalizedEntitlement(
                    kind="mongo_role",
                    name="userAdminAnyDatabase",
                    scope="admin",
                    attributes={"admin_critical": True},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.admin_equivalent

    def test_backup_role_is_operator_high_impact(self):
        engine = _make_engine("mongodb")
        acc = _account(
            name="backup@admin",
            entitlements=[
                NormalizedEntitlement(
                    kind="mongo_role",
                    name="backup",
                    scope="admin",
                    # admin_critical must be False so only the backup/restore name
                    # rule fires (operator_high_impact), not the generic
                    # admin_critical rule (admin_equivalent).
                    attributes={"admin_critical": False},
                )
            ],
            last_login=_RECENT_LOGIN,
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.operator_high_impact

    def test_read_only_role_is_not_privileged(self):
        engine = _make_engine("mongodb")
        acc = _account(
            name="reporter@appdb",
            entitlements=[
                NormalizedEntitlement(
                    kind="mongo_role",
                    name="read",
                    scope="appdb",
                    attributes={"admin_critical": False},
                )
            ],
        )
        result = engine.evaluate(acc)
        assert result.winning_classification == PrivilegeClass.non_privileged


# ---------------------------------------------------------------------------
# Explanation quality
# ---------------------------------------------------------------------------

class TestExplanations:
    def test_explanation_contains_account_name(self):
        engine = _make_engine("rhel")
        acc = _account(
            name="myroot",
            entitlements=[NormalizedEntitlement(kind="unix_uid0", name="root")],
            evidence={"uid": 0},
        )
        result = engine.evaluate(acc)
        assert result.matches
        assert "myroot" in result.matches[0].explanation

    def test_all_matches_recorded(self):
        engine = _make_engine()
        acc = _account(
            name="superuser",
            entitlements=[
                NormalizedEntitlement(kind="unix_uid0", name="root"),
                NormalizedEntitlement(
                    kind="sudo_rule",
                    name="superuser ALL=(ALL) ALL",
                    attributes={"broad": True},
                ),
            ],
            evidence={"uid": 0},
        )
        result = engine.evaluate(acc)
        # Both uid0 and broad-sudo rules should have matched.
        assert len(result.matches) >= 2
