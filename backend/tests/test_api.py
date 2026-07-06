"""Integration tests for the FastAPI application.

Uses an in-memory SQLite database via SQLAlchemy so no external Postgres
instance is required in CI. Celery tasks are mocked to execute synchronously.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.collectors.base import CollectionResult, NormalizedAccount, ProbeResult, Target
from app.collectors.rhel import RHELCollector
from app.config import Settings
from app.db import Base, get_db
from app.main import app
from app.models.user import Role, User
from app.models.account import Account
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.connector import Connector, Credential
from app.models.enums import AuthSource, EnabledStatus, InteractiveStatus, Platform, PrincipalType, PrivilegeClass, ConnectorKind, VaultBackend
from app.models.finding import PrivilegeFinding
from app.models.rule import ClassificationRule
from app.rules_engine.builtin_rules import BUILTIN_RULES
from app.security import hash_password

# ---------------------------------------------------------------------------
# SQLite test DB
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite:///./test_adpct.db"

_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False)


def override_get_db():
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()


app.dependency_overrides[get_db] = override_get_db


def _startup_settings(**overrides):
    values = {
        "APP_ENV": "production",
        "APP_SECRET_KEY": "x" * 64,
        "COLLECTOR_MODE": "live",
        "DATABASE_URL": "postgresql+psycopg://adpct:adpct@postgres:5432/adpct",
        "DEMO_MODE": False,
        "DEMO_SEED_ENABLED": False,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture(scope="session", autouse=True)
def create_tables():
    Base.metadata.create_all(bind=_engine)
    yield
    Base.metadata.drop_all(bind=_engine)
    import os
    if os.path.exists("test_adpct.db"):
        os.remove("test_adpct.db")


@pytest.fixture(scope="session")
def _seed_db():
    with TestSessionLocal() as db:
        admin_role = Role(name="admin", description="Admin")
        viewer_role = Role(name="viewer", description="Viewer")
        operator_role = Role(name="operator", description="Operator")
        analyst_role = Role(name="security_analyst", description="Analyst")
        auditor_role = Role(name="auditor", description="Auditor")
        db.add_all([admin_role, viewer_role, operator_role, analyst_role, auditor_role])
        db.flush()

        admin_user = User(
            email="admin@test.local",
            password_hash=hash_password("TestPass123!"),
            roles=[admin_role],
            must_change_password=False,
        )
        viewer_user = User(
            email="viewer@test.local",
            password_hash=hash_password("TestPass123!"),
            roles=[viewer_role],
            must_change_password=False,
        )
        auditor_user = User(
            email="auditor@test.local",
            password_hash=hash_password("TestPass123!"),
            roles=[auditor_role],
            must_change_password=False,
        )
        db.add_all([admin_user, viewer_user, auditor_user])
        db.flush()

        asset = Asset(
            hostname="test-rhel-01.local",
            ip_address="192.168.1.10",
            platform=Platform.rhel,
            environment="test",
        )
        db.add(asset)
        db.flush()

        for rd in BUILTIN_RULES[:5]:
            db.add(ClassificationRule(**rd))
        db.commit()
        return {"admin_email": "admin@test.local", "viewer_email": "viewer@test.local", "auditor_email": "auditor@test.local", "asset_id": str(asset.id)}


@pytest.fixture
def client(_seed_db):
    return TestClient(app)


@pytest.fixture
def admin_token(client, _seed_db):
    r = client.post("/api/v1/auth/login", json={"email": _seed_db["admin_email"], "password": "TestPass123!"})
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.fixture
def viewer_token(client, _seed_db):
    r = client.post("/api/v1/auth/login", json={"email": _seed_db["viewer_email"], "password": "TestPass123!"})
    assert r.status_code == 200
    return r.json()["access_token"]


@pytest.fixture
def auditor_token(client, _seed_db):
    r = client.post("/api/v1/auth/login", json={"email": _seed_db["auditor_email"], "password": "TestPass123!"})
    assert r.status_code == 200
    return r.json()["access_token"]


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestAuth:
    def test_login_success(self, client, _seed_db):
        r = client.post("/api/v1/auth/login", json={"email": _seed_db["admin_email"], "password": "TestPass123!"})
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data

    def test_login_wrong_password(self, client, _seed_db):
        r = client.post("/api/v1/auth/login", json={"email": _seed_db["admin_email"], "password": "WRONG"})
        assert r.status_code == 401

    def test_me_requires_auth(self, client):
        r = client.get("/api/v1/auth/me")
        assert r.status_code == 401

    def test_me_with_token(self, client, admin_token):
        r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert r.json()["email"] == "admin@test.local"
        assert "admin" in r.json()["roles"]

    def test_refresh_token(self, client, _seed_db):
        r = client.post("/api/v1/auth/login", json={"email": _seed_db["admin_email"], "password": "TestPass123!"})
        refresh = r.json()["refresh_token"]
        r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert r2.status_code == 200
        assert "access_token" in r2.json()

    def test_user_can_change_password_with_correct_current_password(self, client, admin_token):
        created = client.post(
            "/api/v1/users",
            json={
                "username": "changepw",
                "display_name": "Change Password",
                "email": "changepw@example.com",
                "role": "viewer",
                "temporary_password": "TempPass123!",
                "must_change_password": False,
                "is_active": True,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert created.status_code == 201
        login = client.post("/api/v1/auth/login", json={"email": "changepw@example.com", "password": "TempPass123!"})
        token = login.json()["access_token"]
        r = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "TempPass123!", "new_password": "BetterPass123!", "confirm_password": "BetterPass123!"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    def test_user_cannot_change_password_with_wrong_current_password(self, client, viewer_token):
        r = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "wrong", "new_password": "ViewerBetter123!", "confirm_password": "ViewerBetter123!"},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 400

    def test_weak_password_is_rejected(self, client, viewer_token):
        r = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "TestPass123!", "new_password": "weakpassword", "confirm_password": "weakpassword"},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 400


class TestUserManagement:
    def test_admin_can_create_assign_disable_and_reset_user(self, client, admin_token):
        created = client.post(
            "/api/v1/users",
            json={
                "username": "operator1",
                "display_name": "Operator One",
                "email": "operator1@example.com",
                "role": "operator",
                "temporary_password": "TempPass123!",
                "must_change_password": True,
                "is_active": True,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert created.status_code == 201
        user_id = created.json()["id"]

        role = client.patch(
            f"/api/v1/users/{user_id}/role",
            json={"role": "auditor"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert role.status_code == 200
        assert role.json()["roles"] == ["auditor"]

        disabled = client.patch(
            f"/api/v1/users/{user_id}/status",
            json={"is_active": False},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert disabled.status_code == 200
        assert disabled.json()["status"] == "disabled"

        reset = client.post(
            f"/api/v1/users/{user_id}/reset-password",
            json={"temporary_password": "ResetPass123!", "must_change_password": True},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert reset.status_code == 200

    def test_operator_cannot_access_user_management_api(self, client, viewer_token):
        r = client.get("/api/v1/users", headers={"Authorization": f"Bearer {viewer_token}"})
        assert r.status_code == 403
        with TestSessionLocal() as db:
            assert db.query(AuditLog).filter(AuditLog.action == "auth.unauthorized").count() >= 1

    def test_must_change_password_blocks_normal_application_access(self, client, admin_token):
        created = client.post(
            "/api/v1/users",
            json={
                "username": "mustchange",
                "display_name": "Must Change",
                "email": "mustchange@example.com",
                "role": "viewer",
                "temporary_password": "TempPass123!",
                "must_change_password": True,
                "is_active": True,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert created.status_code == 201
        login = client.post("/api/v1/auth/login", json={"email": "mustchange@example.com", "password": "TempPass123!"})
        token = login.json()["access_token"]
        blocked = client.get("/api/v1/assets", headers={"Authorization": f"Bearer {token}"})
        assert blocked.status_code == 403

    def test_disabled_user_cannot_login(self, client, admin_token):
        created = client.post(
            "/api/v1/users",
            json={
                "username": "disabled1",
                "display_name": "Disabled User",
                "email": "disabled1@example.com",
                "role": "viewer",
                "temporary_password": "TempPass123!",
                "must_change_password": False,
                "is_active": False,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert created.status_code == 201
        login = client.post("/api/v1/auth/login", json={"email": "disabled1@example.com", "password": "TempPass123!"})
        assert login.status_code in {401, 403}

    def test_unauthenticated_user_cannot_access_protected_api(self, client):
        r = client.get("/api/v1/users")
        assert r.status_code == 401

    def test_auditor_and_viewer_cannot_launch_scan(self, client, auditor_token, viewer_token):
        body = {"scan_type": "basic_discovery", "selected_platforms": ["rhel"], "all_enabled": True, "credential_mode": "none"}
        assert client.post("/api/v1/scans", json=body, headers={"Authorization": f"Bearer {auditor_token}"}).status_code == 403
        assert client.post("/api/v1/scans", json=body, headers={"Authorization": f"Bearer {viewer_token}"}).status_code == 403


# ---------------------------------------------------------------------------
# Assets tests
# ---------------------------------------------------------------------------

class TestAssets:
    def test_list_requires_auth(self, client):
        r = client.get("/api/v1/assets")
        assert r.status_code == 401

    def test_list_assets(self, client, viewer_token):
        r = client.get("/api/v1/assets", headers={"Authorization": f"Bearer {viewer_token}"})
        assert r.status_code == 200
        assert "items" in r.json()
        assert r.json()["total"] >= 1

    def test_create_asset(self, client, admin_token):
        r = client.post(
            "/api/v1/assets",
            json={"hostname": "new-rhel-01.test", "platform": "rhel", "environment": "test"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 201
        assert r.json()["hostname"] == "new-rhel-01.test"

    def test_create_asset_viewer_forbidden(self, client, viewer_token):
        r = client.post(
            "/api/v1/assets",
            json={"hostname": "no-perm.test", "platform": "rhel"},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 403

    def test_get_asset(self, client, admin_token, _seed_db):
        r = client.get(f"/api/v1/assets/{_seed_db['asset_id']}", headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert r.json()["id"] == _seed_db["asset_id"]

    def test_search_assets_by_ip_and_owner(self, client, admin_token):
        with TestSessionLocal() as db:
            db.add(
                Asset(
                    hostname="search-target.local",
                    ip_address="203.0.113.42",
                    platform=Platform.rhel,
                    owner="Identity Operations",
                    environment="prod",
                )
            )
            db.commit()

        by_ip = client.get("/api/v1/assets?search=203.0.113.42", headers={"Authorization": f"Bearer {admin_token}"})
        assert by_ip.status_code == 200
        assert any(item["hostname"] == "search-target.local" for item in by_ip.json()["items"])

        by_owner = client.get("/api/v1/assets?search=Identity", headers={"Authorization": f"Bearer {admin_token}"})
        assert by_owner.status_code == 200
        assert any(item["hostname"] == "search-target.local" for item in by_owner.json()["items"])

    def test_download_asset_import_template(self, client, admin_token):
        from io import BytesIO
        from openpyxl import load_workbook

        r = client.get(
            "/api/v1/assets/import/template/excel",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        wb = load_workbook(BytesIO(r.content))
        assert wb.sheetnames == ["Assets", "Instructions"]
        headers = [cell.value for cell in wb["Assets"][1]]
        assert headers[:2] == ["hostname", "platform"]
        assert "connector_name" in headers


# ---------------------------------------------------------------------------
# Rules tests
# ---------------------------------------------------------------------------

class TestRules:
    def test_list_rules(self, client, viewer_token):
        r = client.get("/api/v1/rules", headers={"Authorization": f"Bearer {viewer_token}"})
        assert r.status_code == 200
        assert r.json()["total"] >= 1

    def test_viewer_cannot_create_rule(self, client, viewer_token):
        r = client.post(
            "/api/v1/rules",
            json={"rule_key": "test_rule", "name": "Test", "predicate": {"uid_equals": 0}, "classify_as": "full_admin", "explanation_template": "test", "confidence": 90, "risk_modifier": 0, "priority": 100, "enabled": True},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Accounts tests
# ---------------------------------------------------------------------------

class TestAccounts:
    def test_list_accounts_empty(self, client, viewer_token):
        r = client.get("/api/v1/accounts", headers={"Authorization": f"Bearer {viewer_token}"})
        assert r.status_code == 200

    def test_privileged_accounts(self, client, viewer_token):
        r = client.get("/api/v1/accounts/privileged", headers={"Authorization": f"Bearer {viewer_token}"})
        assert r.status_code == 200

    def test_windows_local_and_domain_account_origin(self, client, admin_token, _seed_db):
        with TestSessionLocal() as db:
            asset = db.query(Asset).filter(Asset.id == _seed_db["asset_id"]).one()
            asset.platform = Platform.windows
            local_account = Account(
                asset_id=asset.id,
                platform=Platform.windows,
                source_type="windows_local",
                account_name="local_admin",
                principal_type=PrincipalType.human,
                auth_source=AuthSource.local,
                enabled_status=EnabledStatus.enabled,
                interactive_status=InteractiveStatus.unknown,
                privilege_classification=PrivilegeClass.non_privileged,
                principal_source="Local",
                evidence_summary={"sid": "S-1-5-21-local-1001"},
                discovered_at=datetime.now(UTC),
            )
            domain_account = Account(
                asset_id=asset.id,
                platform=Platform.windows,
                source_type="windows_domain_user",
                account_name="DEMO\\domain_admin",
                principal_type=PrincipalType.human,
                auth_source=AuthSource.ad,
                enabled_status=EnabledStatus.enabled,
                interactive_status=InteractiveStatus.unknown,
                privilege_classification=PrivilegeClass.non_privileged,
                principal_source="ActiveDirectory",
                evidence_summary={"domain": "DEMO", "sid": "S-1-5-21-domain-1101"},
                discovered_at=datetime.now(UTC),
            )
            db.add_all([local_account, domain_account])
            db.commit()

        local = client.get("/api/v1/accounts?account_origin=local", headers={"Authorization": f"Bearer {admin_token}"})
        assert local.status_code == 200
        assert any(item["account_name"] == "local_admin" and item["account_origin"] == "local" for item in local.json()["items"])
        assert all(item["account_name"] != "DEMO\\domain_admin" for item in local.json()["items"])

        domain = client.get("/api/v1/accounts?account_origin=domain", headers={"Authorization": f"Bearer {admin_token}"})
        assert domain.status_code == 200
        domain_item = next(item for item in domain.json()["items"] if item["account_name"] == "DEMO\\domain_admin")
        assert domain_item["account_origin"] == "domain"
        assert domain_item["account_domain"] == "DEMO"

    def test_live_account_without_scan_evidence_is_rejected(self, monkeypatch, _seed_db):
        from app.services.scan_service import _upsert_accounts

        monkeypatch.setattr("app.services.scan_service.get_settings", lambda: type("Settings", (), {"collector_mode": "live"})())
        result = CollectionResult(
            platform=Platform.rhel,
            probes=[],
            accounts=[NormalizedAccount(account_name="evidence_free", source_type="local")],
        )

        with TestSessionLocal() as db:
            asset = db.query(Asset).filter(Asset.id == _seed_db["asset_id"]).first()
            with pytest.raises(RuntimeError, match="raw scan evidence"):
                _upsert_accounts(db, asset, result)

    def test_live_account_stores_raw_evidence_refs(self, monkeypatch, _seed_db):
        from app.services.scan_service import _upsert_accounts

        monkeypatch.setattr("app.services.scan_service.get_settings", lambda: type("Settings", (), {"collector_mode": "live"})())
        result = CollectionResult(
            platform=Platform.rhel,
            probes=[
                ProbeResult(
                    probe_key="getent_passwd",
                    command="getent passwd",
                    exit_code=0,
                    stderr_excerpt=None,
                    output=["evidence_backed:x:1001:1001::/home/evidence_backed:/bin/bash"],
                    duration_ms=7,
                    collected_at=datetime.now(UTC),
                )
            ],
            accounts=[NormalizedAccount(account_name="evidence_backed", source_type="local")],
        )

        with TestSessionLocal() as db:
            asset = db.query(Asset).filter(Asset.id == _seed_db["asset_id"]).first()
            rows, _ = _upsert_accounts(db, asset, result, raw_evidence_refs=["raw-probe-id"])
            assert rows[0].raw_evidence_refs == ["raw-probe-id"]


class TestPrivilegeFindings:
    def _seed_finding(
        self,
        _seed_db,
        *,
        account_name: str = "svc_backup01",
        classification: PrivilegeClass = PrivilegeClass.operator_high_impact,
        collection_mode: str | None = None,
    ):
        with TestSessionLocal() as db:
            asset = db.query(Asset).filter(Asset.id == _seed_db["asset_id"]).first()
            rule = db.query(ClassificationRule).first()
            account = db.query(Account).filter(
                Account.asset_id == asset.id,
                Account.account_name == account_name,
                Account.auth_source == AuthSource.local,
            ).first()
            if not account:
                account = Account(
                    asset_id=asset.id,
                    platform=Platform.rhel,
                    source_type="linux_local",
                    account_name=account_name,
                    principal_type=PrincipalType.service,
                    auth_source=AuthSource.local,
                    enabled_status=EnabledStatus.enabled,
                    interactive_status=InteractiveStatus.interactive,
                    privilege_classification=classification,
                    privilege_confidence=95,
                    risk_score=88,
                    owner=None,
                    password_never_expires=True,
                    collection_mode=collection_mode,
                    evidence_summary={"pam_managed": False, "group": "Backup Operators"},
                    discovered_at=datetime.now(UTC),
                )
                db.add(account)
                db.flush()
            finding = PrivilegeFinding(
                account_id=account.id,
                rule_id=rule.id,
                rule_key=rule.rule_key,
                rule_version=rule.version,
                classification=classification,
                confidence=95,
                risk_score=88,
                is_winning=True,
                direct=True,
                inheritance_path=None,
                explanation=f"Account {account_name} is privileged through Backup Operators evidence.",
                matched_evidence={"group": "Backup Operators", "source": "unit-test"},
                evaluated_at=datetime.now(UTC),
            )
            db.add(finding)
            db.commit()
            return finding.id

    def test_findings_search_returns_enriched_rows(self, client, auditor_token, _seed_db):
        self._seed_finding(_seed_db)
        r = client.get(
            "/api/v1/findings",
            params={"search": "svc_backup backup", "pam_managed": False, "limit": 10},
            headers={"Authorization": f"Bearer {auditor_token}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] >= 1
        row = next(item for item in body["items"] if item["account_name"] == "svc_backup01")
        assert row["asset_hostname"] == "test-rhel-01.local"
        assert row["platform"] == "rhel"
        assert row["pam_managed"] is False
        assert row["owner"] is None

    def test_findings_hide_mock_and_non_privileged_by_default(self, client, auditor_token, _seed_db):
        self._seed_finding(_seed_db, account_name="mock_admin", collection_mode="mock")
        self._seed_finding(_seed_db, account_name="ordinary_user", classification=PrivilegeClass.non_privileged)
        for search in ("mock_admin", "ordinary_user"):
            r = client.get(
                "/api/v1/findings",
                params={"search": search, "limit": 50},
                headers={"Authorization": f"Bearer {auditor_token}"},
            )
            assert r.status_code == 200
            assert r.json()["total"] == 0

    def test_findings_require_privileged_finding_permission(self, client, viewer_token):
        r = client.get("/api/v1/findings", headers={"Authorization": f"Bearer {viewer_token}"})
        assert r.status_code == 403

    def test_findings_export_respects_rbac_and_filters(self, client, auditor_token, viewer_token, _seed_db):
        self._seed_finding(_seed_db)
        denied = client.get("/api/v1/findings/export/csv", headers={"Authorization": f"Bearer {viewer_token}"})
        assert denied.status_code == 403

        allowed = client.get(
            "/api/v1/findings/export/csv",
            params={"search": "svc_backup01", "pam_managed": False},
            headers={"Authorization": f"Bearer {auditor_token}"},
        )
        assert allowed.status_code == 200
        assert "text/csv" in allowed.headers["content-type"]
        assert "svc_backup01" in allowed.text


class TestProductionGuardrails:
    def test_app_env_must_be_explicit(self, monkeypatch):
        monkeypatch.delenv("APP_ENV", raising=False)
        with pytest.raises(Exception, match="APP_ENV"):
            Settings(_env_file=None, APP_SECRET_KEY="x" * 64, COLLECTOR_MODE="live")

    def test_production_startup_rejects_demo_mode(self):
        from app.config import validate_startup_settings

        with pytest.raises(RuntimeError, match="DEMO_MODE"):
            validate_startup_settings(_startup_settings(DEMO_MODE=True))

    def test_production_startup_rejects_default_secret(self):
        from app.config import validate_startup_settings

        with pytest.raises(RuntimeError, match="APP_SECRET_KEY"):
            validate_startup_settings(
                _startup_settings(APP_SECRET_KEY="dev-only-change-me", COLLECTOR_MODE="live")
            )

    def test_production_startup_rejects_demo_seed_enabled(self):
        from app.config import validate_startup_settings

        with pytest.raises(RuntimeError, match="DEMO_SEED_ENABLED"):
            validate_startup_settings(_startup_settings(DEMO_SEED_ENABLED=True))

    def test_mock_collector_cannot_run_in_production(self, monkeypatch):
        monkeypatch.setattr(
            "app.collectors.base.get_settings",
            lambda: type("Settings", (), {"env": "production", "collector_mode": "mock"})(),
        )
        target = Target(
            asset_id="asset-1",
            hostname="prod-rhel.local",
            ip_address=None,
            instance=None,
            port=None,
            platform=Platform.rhel,
        )

        with pytest.raises(RuntimeError, match="Mock collectors"):
            RHELCollector().collect(target, credential=None)


class TestScans:
    def test_launch_requires_scan_type(self, client, admin_token):
        r = client.post(
            "/api/v1/scans",
            json={"all_enabled": True, "selected_platforms": ["rhel"]},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422

    def test_launch_rejects_platform_asset_mismatch(self, client, admin_token, _seed_db):
        r = client.post(
            "/api/v1/scans",
            json={
                "scan_type": "full_discovery",
                "selected_platforms": ["mysql"],
                "asset_ids": [_seed_db["asset_id"]],
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 400
        assert "No target assets match" in r.json()["detail"]

    def test_viewer_cannot_launch_scan(self, client, viewer_token, _seed_db):
        r = client.post(
            "/api/v1/scans",
            json={
                "scan_type": "full_discovery",
                "selected_platforms": ["rhel"],
                "asset_ids": [_seed_db["asset_id"]],
            },
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 403

    def test_launch_rejects_missing_connector_for_live_scan(
        self, client, admin_token, monkeypatch
    ):
        from app.workers import tasks

        monkeypatch.setattr(tasks.dispatch_job_task, "delay", lambda job_id: None)
        monkeypatch.setattr(
            "app.api.v1.scans.get_settings",
            lambda: type("Settings", (), {"collector_mode": "live"})(),
        )
        with TestSessionLocal() as db:
            asset = Asset(
                hostname="no-connector-rhel.local",
                ip_address="192.0.2.77",
                platform=Platform.rhel,
                environment="test",
            )
            db.add(asset)
            db.flush()
            asset_id = str(asset.id)
            db.commit()

        r = client.post(
            "/api/v1/scans",
            json={
                "scan_type": "credentialed_discovery",
                "selected_platforms": ["rhel"],
                "asset_ids": [asset_id],
                "credential_mode": "asset",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 400
        assert "active connector with a linked credential" in r.json()["detail"]

    def test_launch_persists_scan_selection_metadata(self, client, admin_token, monkeypatch):
        from app.workers import tasks

        monkeypatch.setattr(tasks.dispatch_job_task, "delay", lambda job_id: None)
        monkeypatch.setattr("app.api.v1.scans.get_vault", lambda: type("Vault", (), {"resolve": lambda _self, _ref: "secret"})())
        with TestSessionLocal() as db:
            cred = Credential(
                name="scan-test-rhel",
                vault_backend=VaultBackend.local,
                vault_ref="test://scan-test-rhel",
                username="root",
                auth_method="password",
            )
            db.add(cred)
            db.flush()
            db.add(
                Connector(
                    name="scan-test-ssh",
                    kind=ConnectorKind.ssh,
                    credential_id=cred.id,
                    is_active=True,
                )
            )
            db.commit()

        r = client.post(
            "/api/v1/scans",
            json={
                "name": "RHEL password policy scan",
                "scan_type": "password_policy",
                "selected_platforms": ["rhel"],
                "credential_mode": "asset",
                "all_enabled": True,
                "note": "test launch metadata",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["name"] == "RHEL password policy scan"
        assert data["scan_type"] == "password_policy"
        assert data["selected_platforms"] == ["rhel"]
        assert data["credential_mode"] == "asset"
        assert data["collect_password_policy"] is True

    def test_launch_writes_audit_log(self, client, admin_token, monkeypatch):
        from app.workers import tasks

        monkeypatch.setattr(tasks.dispatch_job_task, "delay", lambda job_id: None)
        monkeypatch.setattr("app.api.v1.scans.get_vault", lambda: type("Vault", (), {"resolve": lambda _self, _ref: "secret"})())
        with TestSessionLocal() as db:
            asset = Asset(
                hostname="audit-rhel.local",
                ip_address="192.0.2.88",
                platform=Platform.rhel,
                environment="test",
            )
            cred = Credential(
                name="audit-rhel",
                vault_backend=VaultBackend.local,
                vault_ref="test://audit-rhel",
                username="root",
                auth_method="password",
            )
            db.add_all([asset, cred])
            db.flush()
            conn = Connector(
                name="audit-ssh",
                kind=ConnectorKind.ssh,
                credential_id=cred.id,
                is_active=True,
            )
            db.add(conn)
            db.flush()
            asset.connector_id = conn.id
            asset_id = str(asset.id)
            db.commit()

        r = client.post(
            "/api/v1/scans",
            json={
                "scan_type": "credentialed_discovery",
                "selected_platforms": ["rhel"],
                "asset_ids": [asset_id],
                "credential_mode": "asset",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 201, r.text
        job_id = r.json()["id"]

        with TestSessionLocal() as db:
            entry = (
                db.query(AuditLog)
                .filter(AuditLog.action == "scan.launched", AuditLog.subject_id == job_id)
                .first()
            )
            assert entry is not None
            assert entry.actor_email == "admin@test.local"

    def test_launch_rejects_missing_vault_secret(self, client, admin_token, monkeypatch):
        from app.workers import tasks

        monkeypatch.setattr(tasks.dispatch_job_task, "delay", lambda job_id: None)

        class MissingVault:
            def resolve(self, _ref):
                raise LookupError("missing")

        monkeypatch.setattr("app.api.v1.scans.get_vault", lambda: MissingVault())
        monkeypatch.setattr("app.api.v1.scans.get_settings", lambda: type("Settings", (), {"collector_mode": "live"})())
        with TestSessionLocal() as db:
            asset = Asset(
                hostname="vault-missing-rhel.local",
                ip_address="192.0.2.50",
                platform=Platform.rhel,
                environment="test",
            )
            cred = Credential(
                name="missing-secret-rhel",
                vault_backend=VaultBackend.local,
                vault_ref="local/missing-secret-rhel",
                username="root",
                auth_method="password",
            )
            db.add_all([asset, cred])
            db.flush()
            conn = Connector(
                name="missing-secret-ssh",
                kind=ConnectorKind.ssh,
                credential_id=cred.id,
                is_active=True,
            )
            db.add(conn)
            db.flush()
            asset.connector_id = conn.id
            asset_id = str(asset.id)
            db.commit()

        r = client.post(
            "/api/v1/scans",
            json={
                "scan_type": "credentialed_discovery",
                "selected_platforms": ["rhel"],
                "asset_ids": [asset_id],
                "credential_mode": "asset",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 400
        assert "vault secret material is missing" in r.json()["detail"]
        assert "missing-secret-rhel" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Dashboard tests
# ---------------------------------------------------------------------------

class TestDashboard:
    def test_metrics(self, client, viewer_token):
        r = client.get("/api/v1/dashboard/metrics", headers={"Authorization": f"Bearer {viewer_token}"})
        assert r.status_code == 200
        data = r.json()
        assert "total_assets" in data
        assert "privileged_accounts" in data
        assert "by_platform" in data


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_status_exposes_non_secret_runtime_flags(client):
    r = client.get("/api/v1/status")
    assert r.status_code == 200
    assert set(r.json()) == {"env", "demo_mode", "collector_mode"}


class TestHousekeepingExport:
    def test_housekeeping_csv_requires_auth(self, client):
        r = client.get("/api/v1/exports/housekeeping/csv")
        assert r.status_code == 401

    def test_housekeeping_csv_returns_csv(self, client, admin_token):
        r = client.get(
            "/api/v1/exports/housekeeping/csv",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        # Header row is always written, even with zero matching accounts.
        assert "risk_rating" in r.text.splitlines()[0]

    def test_accounts_csv_includes_account_origin(self, client, admin_token, _seed_db):
        with TestSessionLocal() as db:
            asset = db.query(Asset).filter(Asset.id == _seed_db["asset_id"]).one()
            asset.platform = Platform.windows
            db.add(Account(
                asset_id=asset.id,
                platform=Platform.windows,
                source_type="windows_domain_user",
                account_name="DEMO\\export_admin",
                principal_type=PrincipalType.human,
                auth_source=AuthSource.ad,
                enabled_status=EnabledStatus.enabled,
                interactive_status=InteractiveStatus.interactive,
                privilege_classification=PrivilegeClass.full_admin,
                principal_source="ActiveDirectory",
                evidence_summary={"domain": "DEMO"},
                discovered_at=datetime.now(UTC),
            ))
            db.commit()

        r = client.get("/api/v1/exports/accounts/csv", headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        header = r.text.splitlines()[0]
        assert "account_origin" in header
        assert "account_domain" in header
        assert "principal_source" in header
        assert "DEMO\\export_admin" in r.text
        assert ",domain,DEMO,ActiveDirectory," in r.text

    def test_accounts_filter_by_activity_status(self, client, admin_token):
        r = client.get(
            "/api/v1/accounts?activity_status=inactive_90d",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
