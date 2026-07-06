from __future__ import annotations

import importlib.util
import json
import os
import socket
from datetime import datetime
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_lab_database_accounts.db")

from app.collectors.base import Credential, Target
from app.collectors.mongodb import MongoCollector
from app.collectors.mysql import MySQLCollector
from app.models.enums import InteractiveStatus, Platform, PrincipalType


ROOT = Path(__file__).resolve().parents[2]
LAB_MODULE_PATH = ROOT / "scripts" / "lab_accounts.py"

spec = importlib.util.spec_from_file_location("lab_accounts", LAB_MODULE_PATH)
lab_accounts = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(lab_accounts)


def _load_expected(name: str) -> list[dict]:
    path = Path(__file__).parent / "fixtures" / name
    return json.loads(path.read_text())["accounts"]


def _is_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def test_database_seed_plan_contains_mysql_and_mongo_accounts_without_secret():
    plan = "\n".join(lab_accounts.build_rhel_database_seed_plan())

    assert "adt_mysql_admin" in plan
    assert "adt_mysql_backup_svc" in plan
    assert "adt_mongo_root_admin" in plan
    assert "adt_mongo_backup_svc" in plan
    assert "LAB_SECRET_SHOULD_NOT_APPEAR" not in plan


def test_database_cleanup_plan_only_targets_lab_accounts():
    plan = "\n".join(lab_accounts.build_rhel_database_cleanup_plan())

    for name in lab_accounts.MYSQL_ACCOUNTS:
        assert name in plan
    for name in lab_accounts.MONGO_ACCOUNTS:
        assert name in plan
    assert "DROP USER IF EXISTS 'root'" not in plan
    assert "dropUser('admin')" not in plan


def test_os_seed_plans_create_login_evidence():
    rhel_plan = "\n".join(lab_accounts.build_rhel_seed_plan())
    windows_plan = lab_accounts.build_windows_seed_script()

    assert "adpct_login_users" in rhel_plan
    assert "su - \"$login_user\" -c true" in rhel_plan
    assert "adt_linux_never_login" not in rhel_plan.split("adpct_login_users=", 1)[1].splitlines()[0]
    assert "$loginEvidenceUsers" in windows_plan
    assert "Start-ScheduledTask" in windows_plan
    assert "adt_win_never_login" not in windows_plan.split("$loginEvidenceUsers = @(", 1)[1].split(")", 1)[0]


def test_expected_mysql_fixture_covers_requested_accounts():
    expected = {entry["account_name"]: entry for entry in _load_expected("lab_expected_mysql_accounts.json")}

    assert set(expected) == set(lab_accounts.MYSQL_EXPECTED_ACCOUNT_NAMES)
    assert expected["adt_mysql_interactive@%"]["expected_interactive_status"] == "interactive"
    assert expected["adt_mysql_interactive_expired@%"]["expected_password_state"] == "expired"
    assert expected["adt_mysql_svc_expired@%"]["expected_interactive_status"] == "non_interactive"
    assert expected["adt_mysql_interactive_expiring@%"]["expected_password_state"] == "expiring_soon"
    assert expected["adt_mysql_app_expiring@%"]["expected_interactive_status"] == "non_interactive"
    assert expected["adt_mysql_admin@%"]["expected_privilege"] == "full_admin"
    assert expected["adt_mysql_backup_svc@%"]["expected_principal_type"] == "service"
    assert expected["adt_mysql_locked@%"]["enabled_status"] == "locked"


def test_database_seed_plan_configures_mysql_password_policy_accounts():
    plan = "\n".join(lab_accounts.build_rhel_database_seed_plan())

    assert "INSTALL COMPONENT 'file://component_validate_password'" in plan
    assert "SET PERSIST default_password_lifetime = 90" in plan
    assert "SET PERSIST password_history = 5" in plan
    assert "ALTER USER 'adt_mysql_interactive_expired'@'%' PASSWORD EXPIRE" in plan
    assert "ALTER USER 'adt_mysql_svc_expired'@'%' PASSWORD EXPIRE" in plan
    assert "ALTER USER 'adt_mysql_interactive_expiring'@'%' PASSWORD EXPIRE INTERVAL 7 DAY" in plan
    assert "ALTER USER 'adt_mysql_app_expiring'@'%' PASSWORD EXPIRE INTERVAL 7 DAY" in plan
    assert "adpct_lab_account_login_events" in plan
    assert "'adt_mysql_interactive'@'%'" in plan
    assert "adt_mongo_interactive@admin" in plan


def test_expected_mongodb_fixture_covers_requested_accounts():
    expected = {entry["account_name"]: entry for entry in _load_expected("lab_expected_mongodb_accounts.json")}

    assert set(expected) == set(lab_accounts.MONGO_EXPECTED_ACCOUNT_NAMES)
    assert expected["adt_mongo_interactive@admin"]["expected_interactive_status"] == "interactive"
    assert expected["adt_mongo_root_admin@admin"]["expected_privilege"] == "full_admin"
    assert expected["adt_mongo_backup_svc@admin"]["expected_principal_type"] == "service"
    assert expected["adt_mongo_app_rw@adpct_lab_app"]["expected_role"] == "readWrite"


@pytest.mark.integration
def test_mysql_lab_live_scan_matches_expected_accounts():
    host = os.getenv("MYSQL_TEST_HOST", "192.168.7.130")
    username = os.getenv("MYSQL_TEST_USERNAME")
    password = os.getenv("MYSQL_TEST_PASSWORD")
    port = int(os.getenv("MYSQL_TEST_PORT", "3306"))

    if not username or password is None:
        pytest.skip("MYSQL_TEST_USERNAME and MYSQL_TEST_PASSWORD are not set")
    if not _is_reachable(host, port):
        pytest.skip(f"MySQL lab host {host}:{port} is unreachable")

    result = MySQLCollector().collect_live(
        Target("lab-mysql", host, host, None, port, Platform.mysql, {}),
        Credential(username=username, auth_method="password", secret=password),
    )
    accounts = {account.account_name: account for account in result.accounts}

    for expected in _load_expected("lab_expected_mysql_accounts.json"):
        account = accounts.get(expected["account_name"])
        assert account is not None, expected["account_name"]
        assert account.enabled_status.value == expected["enabled_status"]
        assert account.principal_type.value == expected["expected_principal_type"]
        assert account.interactive_status.value == expected["expected_interactive_status"]


@pytest.mark.integration
def test_mongodb_lab_live_scan_matches_expected_accounts():
    host = os.getenv("MONGO_TEST_HOST", "192.168.7.130")
    username = os.getenv("MONGO_TEST_USERNAME")
    password = os.getenv("MONGO_TEST_PASSWORD")
    port = int(os.getenv("MONGO_TEST_PORT", "27017"))

    if not username or password is None:
        pytest.skip("MONGO_TEST_USERNAME and MONGO_TEST_PASSWORD are not set")
    if not _is_reachable(host, port):
        pytest.skip(f"MongoDB lab host {host}:{port} is unreachable")

    result = MongoCollector().collect_live(
        Target("lab-mongo", host, host, None, port, Platform.mongodb, {}),
        Credential(username=username, auth_method="password", secret=password),
    )
    accounts = {account.account_name: account for account in result.accounts}

    for expected in _load_expected("lab_expected_mongodb_accounts.json"):
        account = accounts.get(expected["account_name"])
        assert account is not None, expected["account_name"]
        assert account.principal_type.value == expected["expected_principal_type"]
        assert account.interactive_status.value == expected["expected_interactive_status"]


def test_mongodb_human_and_shared_accounts_are_interactive():
    human = MongoCollector._interactive_status_for_principal(PrincipalType.human)
    shared = MongoCollector._interactive_status_for_principal(PrincipalType.shared)
    service = MongoCollector._interactive_status_for_principal(PrincipalType.service)
    app = MongoCollector._interactive_status_for_principal(PrincipalType.application)

    assert human == InteractiveStatus.interactive
    assert shared == InteractiveStatus.interactive
    assert service == InteractiveStatus.non_interactive
    assert app == InteractiveStatus.non_interactive


def test_mysql_human_and_shared_accounts_are_interactive():
    human = MySQLCollector._interactive_status_for_principal(PrincipalType.human)
    shared = MySQLCollector._interactive_status_for_principal(PrincipalType.shared)
    service = MySQLCollector._interactive_status_for_principal(PrincipalType.service)
    app = MySQLCollector._interactive_status_for_principal(PrincipalType.application)

    assert human == InteractiveStatus.interactive
    assert shared == InteractiveStatus.interactive
    assert service == InteractiveStatus.non_interactive
    assert app == InteractiveStatus.non_interactive


def test_mysql_lab_metadata_overrides_account_classification():
    principal, interactive = MySQLCollector._coerce_lab_account_metadata(
        {"principal_type": "service", "interactive_status": "non_interactive"}
    )

    assert principal == PrincipalType.service
    assert interactive == InteractiveStatus.non_interactive


def test_mysql_password_expiry_metadata_is_normalized():
    last_changed = datetime(2026, 6, 11, 8, 0, 0)
    expired = MySQLCollector._password_expiry_metadata("Y", 7, last_changed)
    expiring = MySQLCollector._password_expiry_metadata("N", 7, last_changed)
    never = MySQLCollector._password_expiry_metadata("N", 0, last_changed)

    assert expired["password_expired"] is True
    assert expired["password_expires_at"] == last_changed
    assert expiring["password_expired"] is False
    assert expiring["password_expires_at"].isoformat() == "2026-06-18T08:00:00"
    assert never["password_never_expires"] is True
    assert never["password_expires_at"] is None


def test_mysql_raw_probe_rows_are_json_safe():
    rows = MySQLCollector._json_safe_rows(
        [{"User": "adt_mysql_interactive", "password_last_changed": datetime(2026, 6, 11, 8, 0, 0)}]
    )

    assert rows == [{"User": "adt_mysql_interactive", "password_last_changed": "2026-06-11T08:00:00"}]


def test_database_lab_login_events_are_normalized():
    mysql_login = MySQLCollector._coerce_lab_login_event("2026-06-11 08:00:00")
    mongo_login = MongoCollector._coerce_lab_login_event("2026-06-11T08:00:00Z")

    assert mysql_login is not None
    assert mysql_login.isoformat() == "2026-06-11T08:00:00+00:00"
    assert mongo_login is not None
    assert mongo_login.isoformat() == "2026-06-11T08:00:00+00:00"
