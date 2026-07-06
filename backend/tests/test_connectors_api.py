"""Connector API tests for credential linking and connection checks."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models.asset import Asset
from app.models.connector import Connector, Credential
from app.models.enums import ConnectorKind, Platform, VaultBackend
from app.models.user import Role, User
from app.security import hash_password

TEST_DB_URL = "sqlite:///./test_connectors_api.db"

_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False)


@pytest.fixture(scope="session", autouse=True)
def create_tables():
    Base.metadata.create_all(bind=_engine)
    yield
    Base.metadata.drop_all(bind=_engine)
    if os.path.exists("test_connectors_api.db"):
        os.remove("test_connectors_api.db")


@pytest.fixture(scope="session")
def _seed_db():
    with TestSessionLocal() as db:
        role = Role(name="admin", description="Admin")
        db.add(role)
        db.flush()
        db.add(
            User(
                email="connectors-admin@test.local",
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
    r = client.post("/api/v1/auth/login", json={"email": "connectors-admin@test.local", "password": "TestPass123!"})
    assert r.status_code == 200
    return r.json()["access_token"]


class TestConnectors:
    def test_update_connector_links_credential(self, client, admin_token):
        with TestSessionLocal() as db:
            cred = Credential(
                name="link-test-credential",
                vault_backend=VaultBackend.local,
                vault_ref="local/link-test-credential",
                username="root",
                auth_method="password",
            )
            conn = Connector(name="link-test-ssh", kind=ConnectorKind.ssh, is_active=True)
            db.add_all([cred, conn])
            db.flush()
            cred_id = str(cred.id)
            conn_id = str(conn.id)
            db.commit()

        r = client.put(
            f"/api/v1/connectors/{conn_id}",
            json={
                "name": "link-test-ssh",
                "kind": "ssh",
                "default_port": 22,
                "options": {},
                "credential_id": cred_id,
                "is_active": True,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["credential_id"] == cred_id

    def test_live_test_rejects_missing_vault_secret(self, client, admin_token, monkeypatch):
        monkeypatch.setattr("app.api.v1.connectors.get_settings", lambda: type("Settings", (), {"collector_mode": "live"})())

        class MissingVault:
            def resolve(self, _ref):
                raise LookupError("missing")

        monkeypatch.setattr("app.api.v1.connectors.get_vault", lambda: MissingVault())
        with TestSessionLocal() as db:
            asset = Asset(
                hostname="connector-test-mongo.local",
                ip_address="127.0.0.1",
                platform=Platform.mongodb,
                environment="test",
            )
            cred = Credential(
                name="connector-test-mongo-root",
                vault_backend=VaultBackend.local,
                vault_ref="local/connector-test-mongo-root",
                username="root",
                auth_method="password",
            )
            db.add_all([asset, cred])
            db.flush()
            conn = Connector(
                name="connector-test-mongodb",
                kind=ConnectorKind.mongodb,
                default_port=27017,
                credential_id=cred.id,
                is_active=True,
            )
            db.add(conn)
            db.flush()
            asset_id = str(asset.id)
            conn_id = str(conn.id)
            db.commit()

        r = client.post(
            "/api/v1/connectors/test",
            json={"asset_id": asset_id, "connector_id": conn_id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["success"] is False
        assert "Secret for credential" in r.json()["message"]

    def test_live_test_reports_tcp_reachability(self, client, admin_token, monkeypatch):
        import socket
        import threading

        monkeypatch.setattr("app.api.v1.connectors.get_settings", lambda: type("Settings", (), {"collector_mode": "live"})())
        monkeypatch.setattr("app.api.v1.connectors.get_vault", lambda: type("Vault", (), {"resolve": lambda _self, _ref: "secret"})())

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def accept_once():
            try:
                conn, _addr = server.accept()
                conn.close()
            finally:
                server.close()

        threading.Thread(target=accept_once, daemon=True).start()
        with TestSessionLocal() as db:
            asset = Asset(
                hostname="connector-test-redis.local",
                ip_address="127.0.0.1",
                platform=Platform.redis,
                environment="test",
            )
            cred = Credential(
                name="connector-test-redis",
                vault_backend=VaultBackend.local,
                vault_ref="local/connector-test-redis",
                username="default",
                auth_method="password",
            )
            db.add_all([asset, cred])
            db.flush()
            conn = Connector(
                name="connector-test-redis",
                kind=ConnectorKind.redis,
                default_port=port,
                credential_id=cred.id,
                is_active=True,
            )
            db.add(conn)
            db.flush()
            asset_id = str(asset.id)
            conn_id = str(conn.id)
            db.commit()

        r = client.post(
            "/api/v1/connectors/test",
            json={"asset_id": asset_id, "connector_id": conn_id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["success"] is True
        assert r.json()["details"]["port"] == port
