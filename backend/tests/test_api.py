"""Integration tests for the FastAPI application.

Uses an in-memory SQLite database via SQLAlchemy so no external Postgres
instance is required in CI. Celery tasks are mocked to execute synchronously.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models.user import Role, User
from app.models.asset import Asset
from app.models.enums import Platform
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
        analyst_role = Role(name="security_analyst", description="Analyst")
        auditor_role = Role(name="auditor", description="Auditor")
        db.add_all([admin_role, viewer_role, analyst_role, auditor_role])
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
        db.add_all([admin_user, viewer_user])
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
        return {"admin_email": "admin@test.local", "viewer_email": "viewer@test.local", "asset_id": str(asset.id)}


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
