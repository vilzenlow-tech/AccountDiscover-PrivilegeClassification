"""Settings API tests for scan profiles and schedules."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models.job import ScanProfile
from app.models.enums import ScanMode
from app.models.user import Role, User
from app.security import hash_password

TEST_DB_URL = "sqlite:///./test_settings_api.db"

_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False)


@pytest.fixture(scope="session", autouse=True)
def create_tables():
    Base.metadata.create_all(bind=_engine)
    yield
    Base.metadata.drop_all(bind=_engine)
    if os.path.exists("test_settings_api.db"):
        os.remove("test_settings_api.db")


@pytest.fixture(scope="session")
def _seed_db():
    with TestSessionLocal() as db:
        role = Role(name="admin", description="Admin")
        db.add(role)
        db.flush()
        db.add(
            User(
                email="settings-admin@test.local",
                password_hash=hash_password("TestPass123!"),
                roles=[role],
                must_change_password=False,
            )
        )
        db.commit()


@pytest.fixture
def client(_seed_db):
    def override_get_db():
        session = TestSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def admin_token(client):
    r = client.post("/api/v1/auth/login", json={"email": "settings-admin@test.local", "password": "TestPass123!"})
    assert r.status_code == 200
    return r.json()["access_token"]


def test_create_and_update_scan_profile(client, admin_token):
    payload = {
        "name": "Custom Mongo Profile",
        "description": "Mongo only",
        "platforms": ["mongodb"],
        "mode": "safe",
        "target_scope": {"all_enabled": True},
        "timeout_seconds": 120,
        "retry_count": 1,
        "concurrency_limit": 4,
        "throttle_ms": 0,
        "credential_strategy": "asset",
        "collect_password_policy": False,
    }
    created = client.post("/api/v1/scan-profiles", json=payload, headers={"Authorization": f"Bearer {admin_token}"})
    assert created.status_code == 201
    profile_id = created.json()["id"]

    updated = client.put(
        f"/api/v1/scan-profiles/{profile_id}",
        json={**payload, "name": "Custom Mongo Profile Edited", "timeout_seconds": 180},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Custom Mongo Profile Edited"
    assert updated.json()["timeout_seconds"] == 180


def test_create_and_update_schedule(client, admin_token):
    with TestSessionLocal() as db:
        profile = ScanProfile(
            name="Schedule Profile",
            platforms=["mongodb"],
            mode=ScanMode.safe,
            target_scope={"all_enabled": True},
            timeout_seconds=300,
            retry_count=1,
            concurrency_limit=5,
            throttle_ms=0,
            credential_strategy="asset",
        )
        db.add(profile)
        db.flush()
        profile_id = str(profile.id)
        db.commit()

    payload = {
        "name": "Nightly Mongo",
        "description": "Nightly database discovery",
        "cron": "0 2 * * *",
        "profile_id": profile_id,
        "scope": {"all_enabled": True},
        "enabled": True,
        "requires_approval": False,
    }
    created = client.post("/api/v1/schedules", json=payload, headers={"Authorization": f"Bearer {admin_token}"})
    assert created.status_code == 201
    schedule_id = created.json()["id"]
    assert created.json()["next_run_at"]

    updated = client.put(
        f"/api/v1/schedules/{schedule_id}",
        json={**payload, "name": "Nightly Mongo Edited", "enabled": False},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Nightly Mongo Edited"
    assert updated.json()["next_run_at"] is None
