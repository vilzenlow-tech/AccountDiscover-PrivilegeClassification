"""Tests for the Connector Agent Framework API.

Covers:
  - enrollment token generation
  - agent self-registration (enroll)
  - enrollment approval flow
  - heartbeat
  - config pull
  - job dispatch + poll + status update
  - result upload (single + chunked)
  - log upload
  - connector disable / revoke
  - proxy config persistence
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models.connector_agent import (
    ConnectorAgent, ConnectorEnrollmentToken, ConnectorAgentSettings,
)
from app.models.enums import ConnectorAgentStatus, Platform, PrivilegeClass
from app.models.rule import ClassificationRule
from app.models.user import Role, User
from app.security import hash_password

# ── Fixtures ──────────────────────────────────────────────────────────────────

SQLALCHEMY_TEST_URL = "sqlite:///./test_connector_agents.db"


@pytest.fixture(scope="module")
def engine():
    e = create_engine(SQLALCHEMY_TEST_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=e)
    yield e
    Base.metadata.drop_all(bind=e)


@pytest.fixture()
def db(engine):
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture()
def client(db):
    def override_get_db():
        yield db
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def admin_token(client, db):
    """Create an admin user and return a JWT."""
    # Ensure the "admin" role exists
    role = db.query(Role).filter(Role.name == "admin").first()
    if not role:
        role = Role(name="admin", description="Administrator")
        db.add(role)
        db.flush()

    user = db.query(User).filter(User.email == "admin@test.local").first()
    if not user:
        user = User(
            email="admin@test.local",
            password_hash=hash_password("Test123!"),
            full_name="Test Admin",
            is_active=True,
        )
        db.add(user)
        db.flush()
        user.roles.append(role)
        db.commit()

    r = client.post("/api/v1/auth/login", json={"email": "admin@test.local", "password": "Test123!"})
    assert r.status_code == 200, f"Login failed: {r.text}"
    return r.json()["access_token"]


@pytest.fixture()
def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def _make_approved_agent(db, name: str = "test-agent") -> tuple[ConnectorAgent, str]:
    """Insert an approved agent + return (agent, bearer_token)."""
    token = secrets.token_urlsafe(48)
    agent = ConnectorAgent(
        name=name,
        hostname=f"{name}.internal",
        os_platform="linux",
        agent_version="1.0.0",
        token_hash=_hash(token),
        token_prefix=token[:8],
        status=ConnectorAgentStatus.approved,
        is_enabled=True,
        approved_by="test",
        approved_at=datetime.now(UTC),
    )
    db.add(agent)
    db.flush()
    db.add(ConnectorAgentSettings(agent_id=agent.id))
    db.commit()
    db.refresh(agent)
    return agent, token


def _agent_headers(agent: ConnectorAgent, token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "X-Connector-ID": str(agent.id),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TEST CASES
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnrollmentTokenGeneration:
    def test_admin_can_generate_token(self, client, auth):
        r = client.post("/api/v1/connector-agents/enrollment-tokens",
                        json={"expires_in_seconds": 3600},
                        headers=auth)
        assert r.status_code == 201
        data = r.json()
        assert "token" in data
        assert len(data["token"]) > 20
        assert data["token_prefix"] == data["token"][:8]

    def test_token_auto_approve_flag(self, client, auth):
        r = client.post("/api/v1/connector-agents/enrollment-tokens",
                        json={"auto_approve": True, "expires_in_seconds": 3600},
                        headers=auth)
        assert r.status_code == 201
        assert r.json()["auto_approve"] is True

    def test_unauthenticated_cannot_generate_token(self, client):
        r = client.post("/api/v1/connector-agents/enrollment-tokens",
                        json={"expires_in_seconds": 3600})
        assert r.status_code == 401


class TestAgentEnrollment:
    def test_enroll_with_valid_token(self, client, db, auth):
        # Generate enrollment token
        r = client.post("/api/v1/connector-agents/enrollment-tokens",
                        json={"expires_in_seconds": 3600},
                        headers=auth)
        token = r.json()["token"]

        # Agent self-registers
        r2 = client.post("/api/v1/connector-agents/enroll", json={
            "registration_token": token,
            "hostname": "new-agent.internal",
            "os_platform": "linux",
            "os_version": "5.15",
            "agent_version": "1.0.0",
        })
        assert r2.status_code == 201
        data = r2.json()
        assert data["status"] == "pending"
        assert "connector_id" in data
        assert data["token"] is None  # no auto_approve

    def test_enroll_with_auto_approve_gets_token(self, client, db, auth):
        r = client.post("/api/v1/connector-agents/enrollment-tokens",
                        json={"auto_approve": True, "expires_in_seconds": 3600},
                        headers=auth)
        token = r.json()["token"]

        r2 = client.post("/api/v1/connector-agents/enroll", json={
            "registration_token": token,
            "hostname": "auto-agent.internal",
            "os_platform": "windows",
            "os_version": "10.0",
            "agent_version": "1.0.0",
        })
        assert r2.status_code == 201
        data = r2.json()
        assert data["status"] == "approved"
        assert data["token"] is not None

    def test_enroll_with_invalid_token_fails(self, client):
        r = client.post("/api/v1/connector-agents/enroll", json={
            "registration_token": "invalid-token-xyz",
            "hostname": "bad-agent.internal",
            "os_platform": "linux",
            "os_version": "5.15",
            "agent_version": "1.0.0",
        })
        assert r.status_code == 401

    def test_token_cannot_be_reused(self, client, auth):
        r = client.post("/api/v1/connector-agents/enrollment-tokens",
                        json={"auto_approve": True, "expires_in_seconds": 3600},
                        headers=auth)
        token = r.json()["token"]
        payload = {"registration_token": token, "hostname": "a.internal",
                   "os_platform": "linux", "os_version": "5.15", "agent_version": "1.0.0"}

        r2 = client.post("/api/v1/connector-agents/enroll", json=payload)
        assert r2.status_code == 201

        r3 = client.post("/api/v1/connector-agents/enroll", json=payload)
        assert r3.status_code == 401  # Token already used


class TestApprovalFlow:
    def test_pending_agent_cannot_heartbeat(self, client, db, auth):
        # Create pending agent
        r = client.post("/api/v1/connector-agents/enrollment-tokens",
                        json={"expires_in_seconds": 3600}, headers=auth)
        token = r.json()["token"]
        r2 = client.post("/api/v1/connector-agents/enroll", json={
            "registration_token": token, "hostname": "pending.internal",
            "os_platform": "linux", "os_version": "5.15", "agent_version": "1.0.0"})
        connector_id = r2.json()["connector_id"]

        # Try heartbeat without approval
        r3 = client.post(f"/api/v1/connector-agents/{connector_id}/heartbeat",
                         json={"agent_version": "1.0.0"},
                         headers={"Authorization": "Bearer fake-token", "X-Connector-ID": connector_id})
        assert r3.status_code == 401

    def test_admin_approve_connector(self, client, db, auth):
        r = client.post("/api/v1/connector-agents/enrollment-tokens",
                        json={"expires_in_seconds": 3600}, headers=auth)
        token = r.json()["token"]
        r2 = client.post("/api/v1/connector-agents/enroll", json={
            "registration_token": token, "hostname": "toapprove.internal",
            "os_platform": "linux", "os_version": "5.15", "agent_version": "1.0.0"})
        cid = r2.json()["connector_id"]

        r3 = client.post(f"/api/v1/connector-agents/{cid}/approve", json={}, headers=auth)
        assert r3.status_code == 200
        assert r3.json()["status"] == "approved"


class TestHeartbeat:
    def test_heartbeat_accepted(self, client, db):
        agent, token = _make_approved_agent(db, "hb-agent")
        r = client.post(f"/api/v1/connector-agents/{agent.id}/heartbeat",
                        json={"agent_version": "1.0.0", "active_jobs": 0, "cpu_percent": 5.2},
                        headers=_agent_headers(agent, token))
        assert r.status_code == 200
        data = r.json()
        assert data["acknowledged"] is True
        assert "server_time" in data

    def test_heartbeat_updates_last_seen(self, client, db):
        agent, token = _make_approved_agent(db, "hb-seen-agent")
        client.post(f"/api/v1/connector-agents/{agent.id}/heartbeat",
                    json={"agent_version": "1.0.0"},
                    headers=_agent_headers(agent, token))
        db.refresh(agent)
        assert agent.last_heartbeat_at is not None

    def test_revoked_agent_cannot_heartbeat(self, client, db, auth):
        agent, token = _make_approved_agent(db, "revoke-hb-agent")
        client.post(f"/api/v1/connector-agents/{agent.id}/revoke",
                    json={"reason": "test"}, headers=auth)
        r = client.post(f"/api/v1/connector-agents/{agent.id}/heartbeat",
                        json={}, headers=_agent_headers(agent, token))
        assert r.status_code == 403


class TestConfigSync:
    def test_agent_can_pull_config(self, client, db):
        agent, token = _make_approved_agent(db, "cfg-agent")
        r = client.get(f"/api/v1/connector-agents/{agent.id}/config",
                       headers=_agent_headers(agent, token))
        assert r.status_code == 200
        data = r.json()
        assert "config" in data
        assert data["config"]["connector_id"] == str(agent.id)
        assert "polling" in data["config"]
        assert "execution" in data["config"]
        assert "scope" in data["config"]

    def test_console_can_update_settings(self, client, db, auth):
        agent, token = _make_approved_agent(db, "cfg-update-agent")
        r = client.put(f"/api/v1/connector-agents/{agent.id}/settings",
                       json={"heartbeat_interval_seconds": 45, "max_concurrent_jobs": 3,
                             "log_level": "debug", "job_timeout_seconds": 1800},
                       headers=auth)
        assert r.status_code == 200
        assert r.json()["heartbeat_interval_seconds"] == 45
        assert r.json()["max_concurrent_jobs"] == 3

        # Agent pulls updated config
        r2 = client.get(f"/api/v1/connector-agents/{agent.id}/config",
                        headers=_agent_headers(agent, token))
        assert r2.json()["config"]["polling"]["heartbeat_interval_seconds"] == 45

    def test_proxy_config_persisted(self, client, db, auth):
        agent, token = _make_approved_agent(db, "proxy-agent")
        proxy_cfg = {"enabled": True, "url": "http://proxy.internal:3128", "no_proxy": ".internal"}
        r = client.put(f"/api/v1/connector-agents/{agent.id}/settings",
                       json={"proxy_config": proxy_cfg}, headers=auth)
        assert r.status_code == 200
        assert r.json()["proxy_config"]["url"] == "http://proxy.internal:3128"


class TestJobExecution:
    def test_dispatch_and_poll_job(self, client, db, auth):
        agent, token = _make_approved_agent(db, "job-agent")
        # Dispatch
        r = client.post(f"/api/v1/connector-agents/{agent.id}/jobs",
                        json={"job_type": "on_demand",
                              "payload": {"targets": [{"hostname": "srv-01.internal"}],
                                          "scan_mode": "safe", "scan_profile": "standard"}},
                        headers=auth)
        assert r.status_code == 201
        job_id = r.json()["id"]

        # Poll — agent should see the job
        r2 = client.get(f"/api/v1/connector-agents/{agent.id}/jobs/pending",
                        headers=_agent_headers(agent, token))
        assert r2.status_code == 200
        jobs = r2.json()
        assert any(j["id"] == job_id for j in jobs)

    def test_agent_updates_job_progress(self, client, db, auth):
        agent, token = _make_approved_agent(db, "job-progress-agent")
        r = client.post(f"/api/v1/connector-agents/{agent.id}/jobs",
                        json={"payload": {"targets": [{"hostname": "t1"}, {"hostname": "t2"}]}},
                        headers=auth)
        job_id = r.json()["id"]

        # Accept
        r2 = client.patch(f"/api/v1/connector-agents/{agent.id}/jobs/{job_id}/status",
                          json={"status": "accepted", "progress_pct": 0},
                          headers=_agent_headers(agent, token))
        assert r2.status_code == 200
        assert r2.json()["status"] == "accepted"

        # Running
        r3 = client.patch(f"/api/v1/connector-agents/{agent.id}/jobs/{job_id}/status",
                          json={"status": "running", "progress_pct": 50,
                                "targets_total": 2, "targets_done": 1},
                          headers=_agent_headers(agent, token))
        assert r3.json()["progress_pct"] == 50

        # Success
        r4 = client.patch(f"/api/v1/connector-agents/{agent.id}/jobs/{job_id}/status",
                          json={"status": "success", "progress_pct": 100,
                                "targets_total": 2, "targets_done": 2},
                          headers=_agent_headers(agent, token))
        assert r4.json()["status"] == "success"
        assert r4.json()["completed_at"] is not None

    def test_console_can_cancel_job(self, client, db, auth):
        agent, token = _make_approved_agent(db, "cancel-job-agent")
        r = client.post(f"/api/v1/connector-agents/{agent.id}/jobs",
                        json={"payload": {"targets": [{"hostname": "t1"}]}},
                        headers=auth)
        job_id = r.json()["id"]

        r2 = client.post(f"/api/v1/connector-agents/{agent.id}/jobs/{job_id}/cancel",
                         headers=auth)
        assert r2.status_code == 200
        assert r2.json()["status"] == "cancelled"

    def test_expired_jobs_not_returned_to_agent(self, client, db, auth):
        agent, token = _make_approved_agent(db, "expire-job-agent")
        # Dispatch job with very short expiry
        from app.models.connector_agent import ConnectorAgentJob
        from app.models.enums import ConnectorAgentJobStatus, ConnectorAgentJobType
        job = ConnectorAgentJob(
            agent_id=agent.id,
            job_type=ConnectorAgentJobType.on_demand,
            payload={},
            expires_at=datetime.now(UTC) - timedelta(seconds=1),  # already expired
        )
        db.add(job)
        db.commit()

        r = client.get(f"/api/v1/connector-agents/{agent.id}/jobs/pending",
                       headers=_agent_headers(agent, token))
        job_ids = [j["id"] for j in r.json()]
        assert str(job.id) not in job_ids


class TestResultUpload:
    def test_single_chunk_result_upload(self, client, db, auth):
        agent, token = _make_approved_agent(db, "result-agent")
        r = client.post(f"/api/v1/connector-agents/{agent.id}/jobs",
                        json={"payload": {"targets": [{"hostname": "t1"}]}}, headers=auth)
        job_id = r.json()["id"]

        # Build result payload
        result = {"job_id": job_id, "status": "success", "accounts_discovered": 5}
        compressed = gzip.compress(json.dumps(result).encode())
        data_b64 = base64.b64encode(compressed).decode()
        checksum = hashlib.sha256(compressed).hexdigest()

        r2 = client.post(f"/api/v1/connector-agents/{agent.id}/results",
                         json={"job_id": job_id, "chunk_index": 0, "chunk_count": 1,
                               "data": data_b64, "checksum": checksum,
                               "total_checksum": checksum},
                         headers=_agent_headers(agent, token))
        assert r2.status_code == 202
        assert r2.json()["is_complete"] is True
        db.expire_all()
        from app.models.connector_agent import ConnectorAgentResult
        stored = db.query(ConnectorAgentResult).filter(
            ConnectorAgentResult.job_id == uuid.UUID(job_id)
        ).one()
        assert stored.payload == result
        assert stored.accounts_discovered == 5
        assert stored.assets_scanned == 0
        assert stored.size_bytes == len(compressed)
        assert stored.processed_at is not None

    def test_single_chunk_result_upload_extracts_asset_summary(self, client, db, auth):
        agent, token = _make_approved_agent(db, "summary-agent")
        r = client.post(f"/api/v1/connector-agents/{agent.id}/jobs",
                        json={"payload": {"targets": [{"hostname": "t1"}]}}, headers=auth)
        job_id = r.json()["id"]

        result = {
            "job_id": job_id,
            "status": "success",
            "target_results": [
                {"hostname": "WIN01", "status": "success", "accounts_discovered": 2},
                {"hostname": "WIN02", "status": "failed", "accounts_discovered": 0},
            ],
        }
        compressed = gzip.compress(json.dumps(result).encode())
        checksum = hashlib.sha256(compressed).hexdigest()

        r2 = client.post(f"/api/v1/connector-agents/{agent.id}/results",
                         json={"job_id": job_id, "chunk_index": 0, "chunk_count": 1,
                               "data": base64.b64encode(compressed).decode(),
                               "checksum": checksum, "total_checksum": checksum},
                         headers=_agent_headers(agent, token))

        assert r2.status_code == 202
        db.expire_all()
        from app.models.connector_agent import ConnectorAgentResult
        stored = db.query(ConnectorAgentResult).filter(
            ConnectorAgentResult.job_id == uuid.UUID(job_id)
        ).one()
        assert stored.accounts_discovered == 2
        assert stored.assets_scanned == 1

    def test_completed_result_ingests_accounts_and_entitlements(self, client, db, auth):
        agent, token = _make_approved_agent(db, "ingest-agent")
        r = client.post(f"/api/v1/connector-agents/{agent.id}/jobs",
                        json={"payload": {"targets": [{"hostname": "192.168.7.131"}]}}, headers=auth)
        job_id = r.json()["id"]

        result = {
            "job_id": job_id,
            "status": "success",
            "accounts_discovered": 1,
            "assets_scanned": 1,
            "target_results": [{
                "hostname": "WINDOWS_PILOT",
                "platform": "windows",
                "status": "success",
                "accounts_discovered": 1,
                "accounts": [{
                    "account_name": "WINDOWS_PILOT\\admin",
                    "source_type": "windows",
                    "principal_type": "human",
                    "auth_source": "local",
                    "enabled_status": "enabled",
                    "interactive_status": "unknown",
                    "password_never_expires": False,
                    "evidence_summary": {"sid": "S-1-5-21-1-2-3-1002"},
                    "entitlements": [{
                        "kind": "windows_local_group",
                        "name": "Administrators",
                        "scope": "WINDOWS_PILOT",
                        "source": "Get-LocalGroupMember",
                    }],
                }],
            }],
        }
        compressed = gzip.compress(json.dumps(result).encode())
        checksum = hashlib.sha256(compressed).hexdigest()

        r2 = client.post(f"/api/v1/connector-agents/{agent.id}/results",
                         json={"job_id": job_id, "chunk_index": 0, "chunk_count": 1,
                               "data": base64.b64encode(compressed).decode(),
                               "checksum": checksum, "total_checksum": checksum},
                         headers=_agent_headers(agent, token))

        assert r2.status_code == 202
        db.expire_all()
        from app.models.account import Account, AccountEntitlement
        from app.models.asset import Asset
        asset = db.query(Asset).filter(Asset.hostname == "WINDOWS_PILOT").one()
        account = db.query(Account).filter(
            Account.asset_id == asset.id,
            Account.account_name == "WINDOWS_PILOT\\admin",
        ).one()
        entitlement = db.query(AccountEntitlement).filter(
            AccountEntitlement.account_id == account.id,
        ).one()
        assert entitlement.kind == "windows_local_group"
        assert entitlement.name == "Administrators"

    def test_completed_result_writes_connector_agent_findings(self, client, db, auth):
        rule = ClassificationRule(
            rule_key="windows_local_admin_full_admin_test",
            name="Windows local admin",
            platform=Platform.windows,
            predicate={"entitlement_kind_name_in": {"kind": "windows_local_group", "names": ["Administrators"]}},
            classify_as=PrivilegeClass.full_admin,
            confidence=99,
            risk_modifier=5,
            explanation_template="Account '{account}' is local admin via {matched}.",
            priority=10,
            enabled=True,
            version=1,
        )
        db.add(rule)
        db.commit()

        agent, token = _make_approved_agent(db, "finding-agent")
        r = client.post(f"/api/v1/connector-agents/{agent.id}/jobs",
                        json={"payload": {"targets": [{"hostname": "192.168.7.131"}]}}, headers=auth)
        job_id = r.json()["id"]
        result = {
            "job_id": job_id,
            "status": "success",
            "accounts_discovered": 1,
            "assets_scanned": 1,
            "target_results": [{
                "hostname": "WINDOWS_PILOT",
                "platform": "windows",
                "status": "success",
                "accounts_discovered": 1,
                "accounts": [{
                    "account_name": "WINDOWS_PILOT\\admin",
                    "source_type": "windows",
                    "principal_type": "human",
                    "auth_source": "local",
                    "enabled_status": "enabled",
                    "interactive_status": "unknown",
                    "entitlements": [{
                        "kind": "windows_local_group",
                        "name": "Administrators",
                        "scope": "WINDOWS_PILOT",
                    }],
                }],
            }],
        }
        compressed = gzip.compress(json.dumps(result).encode())
        checksum = hashlib.sha256(compressed).hexdigest()

        r2 = client.post(f"/api/v1/connector-agents/{agent.id}/results",
                         json={"job_id": job_id, "chunk_index": 0, "chunk_count": 1,
                               "data": base64.b64encode(compressed).decode(),
                               "checksum": checksum, "total_checksum": checksum},
                         headers=_agent_headers(agent, token))

        assert r2.status_code == 202
        db.expire_all()
        from app.models.account import Account
        from app.models.finding import PrivilegeFinding
        account = db.query(Account).filter(Account.account_name == "WINDOWS_PILOT\\admin").one()
        finding = db.query(PrivilegeFinding).filter(PrivilegeFinding.account_id == account.id).one()
        assert finding.job_id is None
        assert str(finding.connector_agent_job_id) == job_id
        assert finding.rule_key == "windows_local_admin_full_admin_test"
        assert finding.classification == PrivilegeClass.full_admin
        assert finding.is_winning is True

    def test_chunked_result_upload(self, client, db, auth):
        agent, token = _make_approved_agent(db, "chunked-result-agent")
        r = client.post(f"/api/v1/connector-agents/{agent.id}/jobs",
                        json={"payload": {}}, headers=auth)
        job_id = r.json()["id"]

        # Upload 3 chunks
        for i in range(3):
            chunk = gzip.compress(f"chunk-{i}".encode())
            data_b64 = base64.b64encode(chunk).decode()
            checksum = hashlib.sha256(chunk).hexdigest()
            r2 = client.post(f"/api/v1/connector-agents/{agent.id}/results",
                             json={"job_id": job_id, "chunk_index": i, "chunk_count": 3,
                                   "data": data_b64, "checksum": checksum},
                             headers=_agent_headers(agent, token))
            assert r2.status_code == 202
            expected_complete = (i == 2)
            assert r2.json()["is_complete"] == expected_complete

    def test_duplicate_chunk_idempotent(self, client, db, auth):
        agent, token = _make_approved_agent(db, "idem-agent")
        r = client.post(f"/api/v1/connector-agents/{agent.id}/jobs",
                        json={"payload": {}}, headers=auth)
        job_id = r.json()["id"]

        chunk = gzip.compress(b"data")
        data_b64 = base64.b64encode(chunk).decode()
        checksum = hashlib.sha256(chunk).hexdigest()
        payload = {"job_id": job_id, "chunk_index": 0, "chunk_count": 1,
                   "data": data_b64, "checksum": checksum}

        r1 = client.post(f"/api/v1/connector-agents/{agent.id}/results",
                         json=payload, headers=_agent_headers(agent, token))
        r2 = client.post(f"/api/v1/connector-agents/{agent.id}/results",
                         json=payload, headers=_agent_headers(agent, token))
        assert r1.status_code == 202
        assert r2.status_code == 202
        # Chunks received stays at 1 (idempotent)
        assert r2.json()["chunks_received"] == 1

    def test_bad_checksum_rejected(self, client, db, auth):
        agent, token = _make_approved_agent(db, "bad-cksum-agent")
        r = client.post(f"/api/v1/connector-agents/{agent.id}/jobs",
                        json={"payload": {}}, headers=auth)
        job_id = r.json()["id"]
        chunk = gzip.compress(b"data")
        data_b64 = base64.b64encode(chunk).decode()

        r2 = client.post(f"/api/v1/connector-agents/{agent.id}/results",
                         json={"job_id": job_id, "chunk_index": 0, "chunk_count": 1,
                               "data": data_b64, "checksum": "0" * 64},
                         headers=_agent_headers(agent, token))
        assert r2.status_code == 400


class TestLogUpload:
    def test_agent_uploads_logs(self, client, db):
        agent, token = _make_approved_agent(db, "log-agent")
        entries = [
            {"level": "info", "message": "Scan started", "timestamp": datetime.now(UTC).isoformat()},
            {"level": "warning", "message": "Retry 1/3 for srv-01", "timestamp": datetime.now(UTC).isoformat()},
            {"level": "error", "message": "Auth failed for srv-02", "timestamp": datetime.now(UTC).isoformat()},
        ]
        r = client.post(f"/api/v1/connector-agents/{agent.id}/logs",
                        json={"entries": entries},
                        headers=_agent_headers(agent, token))
        assert r.status_code == 202
        assert r.json()["accepted"] == 3

    def test_console_can_view_logs(self, client, db, auth):
        agent, token = _make_approved_agent(db, "viewlog-agent")
        client.post(f"/api/v1/connector-agents/{agent.id}/logs",
                    json={"entries": [{"level": "info", "message": "test log"}]},
                    headers=_agent_headers(agent, token))
        r = client.get(f"/api/v1/connector-agents/{agent.id}/logs", headers=auth)
        assert r.status_code == 200
        assert len(r.json()) >= 1


class TestConnectorRevoke:
    def test_revoke_invalidates_token(self, client, db, auth):
        agent, token = _make_approved_agent(db, "revoke-test-agent")

        # Confirm heartbeat works before revoke
        r1 = client.post(f"/api/v1/connector-agents/{agent.id}/heartbeat",
                         json={}, headers=_agent_headers(agent, token))
        assert r1.status_code == 200

        # Revoke
        r2 = client.post(f"/api/v1/connector-agents/{agent.id}/revoke",
                         json={"reason": "Security incident"}, headers=auth)
        assert r2.status_code == 200
        assert r2.json()["status"] == "revoked"

        # Token now invalid
        r3 = client.post(f"/api/v1/connector-agents/{agent.id}/heartbeat",
                         json={}, headers=_agent_headers(agent, token))
        assert r3.status_code == 403

    def test_revoked_connector_cannot_be_reenabled(self, client, db, auth):
        agent, token = _make_approved_agent(db, "revoke-reenable-agent")
        client.post(f"/api/v1/connector-agents/{agent.id}/revoke",
                    json={"reason": "test"}, headers=auth)
        r = client.post(f"/api/v1/connector-agents/{agent.id}/enable", headers=auth)
        assert r.status_code == 409


class TestTokenRotation:
    def test_rotate_token_invalidates_old(self, client, db, auth):
        agent, old_token = _make_approved_agent(db, "rotate-token-agent")

        # Old token works
        r1 = client.post(f"/api/v1/connector-agents/{agent.id}/heartbeat",
                         json={}, headers=_agent_headers(agent, old_token))
        assert r1.status_code == 200

        # Rotate
        r2 = client.post(f"/api/v1/connector-agents/{agent.id}/rotate-token", headers=auth)
        assert r2.status_code == 200
        new_token = r2.json()["token"]
        assert new_token != old_token

        # Old token rejected
        r3 = client.post(f"/api/v1/connector-agents/{agent.id}/heartbeat",
                         json={}, headers=_agent_headers(agent, old_token))
        assert r3.status_code == 401

        # New token works
        r4 = client.post(f"/api/v1/connector-agents/{agent.id}/heartbeat",
                         json={}, headers={
                             "Authorization": f"Bearer {new_token}",
                             "X-Connector-ID": str(agent.id),
                         })
        assert r4.status_code == 200
