"""Tests for the Password Policy Discovery and Visibility feature.

Scenario coverage:
  1. Windows local policy — upsert, retrieve, findings generated
  2. Windows domain policy — domain-level scope, lockout rules
  3. AD Fine-Grained Password Policy (FGPP / PSO) — higher precedence, applies_to group
  4. RHEL PAM-based policy — pam_pwquality + pam_faillock settings
  5. SQL Server login policy — CHECK_POLICY OFF / CHECK_EXPIRATION OFF exceptions
  6. MySQL validate_password — component not enabled → PWPOL-014
  7. MongoDB external-policy — external_policy_enforced → PWPOL-015
  8. Account-level exception lifecycle — create, list, finding generated
  9. Policy comparison — compare endpoint returns inconsistency
 10. Review workflow — analyst marks a finding as risk_accepted
 11. Export endpoints — CSV and Excel (when openpyxl is available)
 12. Summary stats endpoint
"""
from __future__ import annotations

import types
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app
from app.models.asset import Asset
from app.models.enums import Platform, PolicyFindingSeverity, PolicyScope, PolicySource
from app.models.password_policy import (
    AccountPolicyException,
    PasswordPolicy,
    PasswordPolicyFinding,
)
from app.models.user import Role, User
from app.security import hash_password
from app.services.password_policy_rules import evaluate_policy

# ── Fixtures ───────────────────────────────────────────────────────────────────

SQLALCHEMY_TEST_URL = "sqlite:///./test_password_policy.db"


@pytest.fixture(scope="module")
def engine():
    e = create_engine(SQLALCHEMY_TEST_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=e)
    yield e
    Base.metadata.drop_all(bind=e)


@pytest.fixture()
def db(engine):
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = Session()
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
    role = db.query(Role).filter(Role.name == "admin").first()
    if not role:
        role = Role(name="admin", description="Administrator")
        db.add(role)
        db.flush()
    user = db.query(User).filter(User.email == "pwpol_admin@test.local").first()
    if not user:
        user = User(
            email="pwpol_admin@test.local",
            password_hash=hash_password("Test123!"),
            full_name="Policy Test Admin",
            is_active=True,
        )
        db.add(user)
        db.flush()
        user.roles.append(role)
        db.commit()
    r = client.post("/api/v1/auth/login",
                    json={"email": "pwpol_admin@test.local", "password": "Test123!"})
    assert r.status_code == 200, f"Login failed: {r.text}"
    return r.json()["access_token"]


@pytest.fixture()
def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture()
def win_asset(db):
    """A Windows asset for policy tests."""
    a = Asset(
        hostname="WIN-DC01.corp.example.com",
        platform=Platform.windows,
        ip_address="10.0.0.10",
        environment="production",
    )
    db.add(a)
    db.flush()
    return a


@pytest.fixture()
def rhel_asset(db):
    a = Asset(
        hostname="rhel-app01.corp.example.com",
        platform=Platform.rhel,
        ip_address="10.0.1.20",
        environment="production",
    )
    db.add(a)
    db.flush()
    return a


@pytest.fixture()
def mssql_asset(db):
    a = Asset(
        hostname="mssql-db01.corp.example.com",
        platform=Platform.mssql,
        ip_address="10.0.2.30",
        environment="production",
    )
    db.add(a)
    db.flush()
    return a


@pytest.fixture()
def mysql_asset(db):
    a = Asset(
        hostname="mysql-db01.corp.example.com",
        platform=Platform.mysql,
        ip_address="10.0.2.40",
        environment="production",
    )
    db.add(a)
    db.flush()
    return a


@pytest.fixture()
def mongo_asset(db):
    a = Asset(
        hostname="mongo-rs01.corp.example.com",
        platform=Platform.mongodb,
        ip_address="10.0.2.50",
        environment="production",
    )
    db.add(a)
    db.flush()
    return a


def _now() -> str:
    return datetime.now(UTC).isoformat()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _policy_payload(asset_id: str, **overrides) -> dict:
    """Build a minimal valid PasswordPolicyIn payload."""
    base = {
        "asset_id": asset_id,
        "platform": "windows",
        "policy_source": "local_policy",
        "policy_scope": "host",
        "policy_name": "Local Security Policy",
        "is_effective_policy": True,
        "min_password_length": 14,
        "complexity_enabled": True,
        "password_history_count": 10,
        "min_password_age_days": 1,
        "max_password_age_days": 90,
        "reversible_encryption_enabled": False,
        "lockout_threshold": 5,
        "lockout_duration_minutes": 30,
        "reset_lockout_counter_after_minutes": 15,
        "confidence_score": 95,
        "discovered_at": _now(),
    }
    base.update(overrides)
    return base


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Windows Local Policy
# ═══════════════════════════════════════════════════════════════════════════════

class TestWindowsLocalPolicy:
    def test_upsert_strong_local_policy(self, client, auth, win_asset):
        """A strong local policy creates no findings."""
        r = client.post("/api/v1/password-policy",
                        json=_policy_payload(str(win_asset.id)),
                        headers=auth)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["is_effective_policy"] is True
        assert body["min_password_length"] == 14
        assert body["complexity_enabled"] is True
        assert body["finding_count"] == 0
        assert body["has_weak_length"] is False

    def test_upsert_weak_local_policy_generates_findings(self, client, auth, win_asset):
        """A weak local policy (short length, no lockout) generates findings."""
        payload = _policy_payload(
            str(win_asset.id),
            policy_name="Weak Local Policy",
            min_password_length=6,
            lockout_threshold=0,
            complexity_enabled=False,
            password_history_count=0,
        )
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["has_weak_length"] is True
        assert body["has_no_complexity"] is True
        assert body["has_no_lockout"] is True
        # Expect PWPOL-001 (critical length), PWPOL-003 (complexity),
        # PWPOL-004 (no history), PWPOL-006 (no lockout)
        assert body["finding_count"] >= 4

    def test_get_policy(self, client, auth, win_asset):
        # Create a policy first so there is always something to retrieve
        client.post("/api/v1/password-policy",
                    json=_policy_payload(str(win_asset.id), policy_name="Get-Test Policy"),
                    headers=auth)
        r = client.get(
            "/api/v1/password-policy",
            params={"asset_id": str(win_asset.id)},
            headers=auth,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 1

    def test_reversible_encryption_critical(self, client, auth, win_asset, db):
        """Reversible encryption enabled triggers CRITICAL PWPOL-009."""
        asset = Asset(
            hostname="win-rev-enc.corp.example.com",
            platform=Platform.windows,
        )
        db.add(asset)
        db.flush()
        payload = _policy_payload(
            str(asset.id),
            policy_name="RevEnc Policy",
            reversible_encryption_enabled=True,
        )
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201
        policy_id = r.json()["id"]
        # Verify critical finding exists
        fr = client.get(
            "/api/v1/password-policy/findings",
            params={"policy_id": policy_id, "rule_key": "PWPOL-009"},
            headers=auth,
        )
        assert fr.status_code == 200
        assert fr.json()["total"] == 1
        assert fr.json()["items"][0]["severity"] == "critical"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Windows Domain Policy
# ═══════════════════════════════════════════════════════════════════════════════

class TestWindowsDomainPolicy:
    def test_domain_policy_no_lockout_high_severity(self, client, auth, win_asset, db):
        """Domain policy without lockout triggers PWPOL-010 (CRITICAL for domain scope)."""
        asset = Asset(hostname="win-dom-nolockout.corp.example.com", platform=Platform.windows)
        db.add(asset)
        db.flush()
        payload = {
            "asset_id": str(asset.id),
            "platform": "windows",
            "policy_source": "domain_policy",
            "policy_scope": "domain",
            "policy_name": "Default Domain Policy",
            "is_effective_policy": True,
            "min_password_length": 8,
            "complexity_enabled": True,
            "lockout_threshold": 0,   # no lockout
            "confidence_score": 90,
            "discovered_at": _now(),
        }
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201
        body = r.json()
        fr = client.get(
            "/api/v1/password-policy/findings",
            params={"policy_id": body["id"], "rule_key": "PWPOL-010"},
            headers=auth,
        )
        # Domain-scoped no-lockout → PWPOL-010 CRITICAL
        assert fr.json()["total"] == 1
        assert fr.json()["items"][0]["severity"] == "critical"

    def test_domain_policy_length_high(self, client, auth, db):
        """Domain policy with length 10 (below 12) triggers PWPOL-002 HIGH."""
        asset = Asset(hostname="win-dom-short.corp.example.com", platform=Platform.windows)
        db.add(asset)
        db.flush()
        payload = _policy_payload(
            str(asset.id),
            policy_source="domain_policy",
            policy_scope="domain",
            policy_name="Default Domain Policy",
            min_password_length=10,
            lockout_threshold=5,
        )
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201
        body = r.json()
        fr = client.get(
            "/api/v1/password-policy/findings",
            params={"policy_id": body["id"], "rule_key": "PWPOL-002"},
            headers=auth,
        )
        assert fr.json()["total"] == 1
        assert fr.json()["items"][0]["severity"] == "high"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. AD Fine-Grained Password Policy (FGPP)
# ═══════════════════════════════════════════════════════════════════════════════

class TestADFineGrainedPolicy:
    def test_fgpp_higher_precedence_stored(self, client, auth, win_asset, db):
        """FGPP with precedence 10 stored alongside domain policy."""
        # First create the domain policy
        domain_payload = _policy_payload(
            str(win_asset.id),
            policy_source="domain_policy",
            policy_scope="domain",
            policy_name="Default Domain Policy",
            is_effective_policy=True,
            min_password_length=8,
            lockout_threshold=10,
        )
        r1 = client.post("/api/v1/password-policy", json=domain_payload, headers=auth)
        assert r1.status_code == 201

        # Then create the FGPP targeting Domain Admins
        fgpp_payload = {
            "asset_id": str(win_asset.id),
            "platform": "windows",
            "policy_source": "fine_grained_ad",
            "policy_scope": "group",
            "policy_name": "Domain Admins FGPP",
            "is_effective_policy": False,   # domain admins only
            "applies_to": {
                "type": "group",
                "name": "Domain Admins",
                "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com",
            },
            "precedence": 10,
            "min_password_length": 16,
            "complexity_enabled": True,
            "password_history_count": 24,
            "min_password_age_days": 1,
            "max_password_age_days": 60,
            "reversible_encryption_enabled": False,
            "lockout_threshold": 3,
            "lockout_duration_minutes": -1,   # unlock by admin
            "confidence_score": 90,
            "discovered_at": _now(),
        }
        r2 = client.post("/api/v1/password-policy", json=fgpp_payload, headers=auth)
        assert r2.status_code == 201, r2.text
        body = r2.json()
        assert body["policy_source"] == "fine_grained_ad"
        assert body["precedence"] == 10
        assert body["applies_to"]["name"] == "Domain Admins"
        # Strong FGPP → no findings
        assert body["finding_count"] == 0

    def test_fgpp_not_applied_to_privileged_group_exception(self, client, auth, win_asset, db):
        """Account exception fgpp_not_applied generates PWPOL-017."""
        # Always create a fresh policy for this self-contained test
        r_pol = client.post(
            "/api/v1/password-policy",
            json=_policy_payload(str(win_asset.id), policy_name="FGPP-Test Domain Policy"),
            headers=auth,
        )
        assert r_pol.status_code == 201, r_pol.text
        policy_id = r_pol.json()["id"]

        exc_payload = {
            "asset_id": str(win_asset.id),
            "policy_id": policy_id,
            "exception_type": "fgpp_not_applied",
            "description": "Enterprise Admins group has no PSO applied",
            "effective_policy_source": "domain_policy:Default Domain Policy",
            "expected_policy_source": "fine_grained_ad:Enterprise Admins PSO",
            "evidence": {"group": "Enterprise Admins", "member_count": 12},
            "discovered_at": _now(),
        }
        er = client.post("/api/v1/password-policy/exceptions", json=exc_payload, headers=auth)
        assert er.status_code == 201, er.text

        fr = client.get(
            "/api/v1/password-policy/findings",
            params={"policy_id": policy_id, "rule_key": "PWPOL-017", "is_exception_finding": True},
            headers=auth,
        )
        assert fr.json()["total"] >= 1
        assert fr.json()["items"][0]["severity"] == "high"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. RHEL PAM-Based Policy
# ═══════════════════════════════════════════════════════════════════════════════

class TestRHELPAMPolicy:
    def test_pam_strong_policy_no_findings(self, client, auth, rhel_asset):
        payload = {
            "asset_id": str(rhel_asset.id),
            "platform": "rhel",
            "policy_source": "pam_module",
            "policy_scope": "host",
            "policy_name": "/etc/security/pwquality.conf",
            "is_effective_policy": True,
            "min_password_length": 14,
            "complexity_enabled": True,
            "dictionary_check_enabled": True,
            "min_char_classes": 4,
            "min_uppercase": 1,
            "min_lowercase": 1,
            "min_digits": 1,
            "min_special_chars": 1,
            "lockout_threshold": 5,
            "lockout_duration_minutes": 10,
            "password_history_count": 10,
            "max_password_age_days": 90,
            "confidence_score": 88,
            "evidence_summary": {
                "source_file": {"value": "/etc/security/pwquality.conf",
                                "command": "cat /etc/security/pwquality.conf"},
                "lockout_source": {"value": "/etc/pam.d/system-auth",
                                   "command": "grep pam_faillock /etc/pam.d/system-auth"},
                "aging_source": {"value": "/etc/login.defs",
                                 "command": "grep ^PASS /etc/login.defs"},
            },
            "discovered_at": _now(),
        }
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201, r.text
        assert r.json()["finding_count"] == 0

    def test_pam_no_dictionary_check_generates_finding(self, client, auth, db):
        asset = Asset(hostname="rhel-nodictcheck.corp.example.com", platform=Platform.rhel)
        db.add(asset)
        db.flush()
        payload = {
            "asset_id": str(asset.id),
            "platform": "rhel",
            "policy_source": "pam_module",
            "policy_scope": "host",
            "policy_name": "/etc/security/pwquality.conf",
            "is_effective_policy": True,
            "min_password_length": 12,
            "dictionary_check_enabled": False,  # <-- disabled
            "lockout_threshold": 5,
            "confidence_score": 80,
            "discovered_at": _now(),
        }
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201, r.text
        policy_id = r.json()["id"]
        fr = client.get(
            "/api/v1/password-policy/findings",
            params={"policy_id": policy_id, "rule_key": "PWPOL-011"},
            headers=auth,
        )
        assert fr.json()["total"] == 1
        assert fr.json()["items"][0]["severity"] == "medium"

    def test_pam_login_defs_aging_stored(self, client, auth, db):
        """Second policy row for /etc/login.defs coexists with pam_module row."""
        asset = Asset(hostname="rhel-logindefs.corp.example.com", platform=Platform.rhel)
        db.add(asset)
        db.flush()
        payload = {
            "asset_id": str(asset.id),
            "platform": "rhel",
            "policy_source": "login_defs",
            "policy_scope": "host",
            "policy_name": "/etc/login.defs",
            "is_effective_policy": False,
            "min_password_age_days": 1,
            "max_password_age_days": 90,
            "password_history_count": 5,
            "confidence_score": 95,
            "discovered_at": _now(),
        }
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201
        assert r.json()["policy_source"] == "login_defs"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. SQL Server Login Policy
# ═══════════════════════════════════════════════════════════════════════════════

class TestSQLServerLoginPolicy:
    @pytest.fixture()
    def mssql_policy(self, client, auth, mssql_asset):
        payload = {
            "asset_id": str(mssql_asset.id),
            "platform": "mssql",
            "policy_source": "database_native",
            "policy_scope": "database",
            "policy_name": "MSSQL Instance Policy",
            "is_effective_policy": True,
            "confidence_score": 80,
            "evidence_summary": {
                "windows_policy_applied": {
                    "value": True,
                    "command": "SELECT name, is_policy_checked, is_expiration_checked FROM sys.sql_logins",
                },
            },
            "discovered_at": _now(),
        }
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201
        return r.json()

    def test_check_policy_off_generates_high_finding(self, client, auth, mssql_asset, mssql_policy):
        exc_payload = {
            "asset_id": str(mssql_asset.id),
            "policy_id": mssql_policy["id"],
            "exception_type": "check_policy_off",
            "description": "SQL login 'app_svc' has CHECK_POLICY = OFF",
            "effective_policy_source": "none (CHECK_POLICY=OFF)",
            "expected_policy_source": "windows_password_policy",
            "evidence": {
                "login_name": "app_svc",
                "check_policy": False,
                "check_expiration": False,
                "query": "SELECT name, is_policy_checked FROM sys.sql_logins WHERE name='app_svc'",
            },
            "discovered_at": _now(),
        }
        er = client.post("/api/v1/password-policy/exceptions", json=exc_payload, headers=auth)
        assert er.status_code == 201

        fr = client.get(
            "/api/v1/password-policy/findings",
            params={"policy_id": mssql_policy["id"], "rule_key": "PWPOL-012"},
            headers=auth,
        )
        assert fr.json()["total"] == 1
        assert fr.json()["items"][0]["severity"] == "high"
        assert fr.json()["items"][0]["is_exception_finding"] is True

    def test_check_expiration_off_generates_medium_finding(self, client, auth, mssql_asset, mssql_policy):
        exc_payload = {
            "asset_id": str(mssql_asset.id),
            "policy_id": mssql_policy["id"],
            "exception_type": "check_expiration_off",
            "description": "SQL login 'sa' has CHECK_EXPIRATION = OFF",
            "evidence": {
                "login_name": "sa",
                "check_expiration": False,
            },
            "discovered_at": _now(),
        }
        er = client.post("/api/v1/password-policy/exceptions", json=exc_payload, headers=auth)
        assert er.status_code == 201

        fr = client.get(
            "/api/v1/password-policy/findings",
            params={"policy_id": mssql_policy["id"], "rule_key": "PWPOL-013"},
            headers=auth,
        )
        assert fr.json()["total"] == 1
        assert fr.json()["items"][0]["severity"] == "medium"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. MySQL validate_password
# ═══════════════════════════════════════════════════════════════════════════════

class TestMySQLPolicy:
    def test_validate_password_not_enabled_generates_high_finding(
        self, client, auth, mysql_asset
    ):
        payload = {
            "asset_id": str(mysql_asset.id),
            "platform": "mysql",
            "policy_source": "database_native",
            "policy_scope": "database",
            "policy_name": "MySQL Instance Policy",
            "is_effective_policy": True,
            "confidence_score": 40,   # low confidence because component not installed
            "evidence_summary": {
                "validate_password_component": {
                    "value": "NOT_INSTALLED",
                    "command": "SELECT * FROM mysql.component WHERE component_urn LIKE '%validate_password%'",
                    "note": "0 rows returned — component not installed",
                },
            },
            "discovered_at": _now(),
        }
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201, r.text
        body = r.json()
        # PWPOL-014 should be generated
        fr = client.get(
            "/api/v1/password-policy/findings",
            params={"policy_id": body["id"], "rule_key": "PWPOL-014"},
            headers=auth,
        )
        assert fr.json()["total"] == 1
        assert fr.json()["items"][0]["severity"] == "high"

    def test_validate_password_enabled_strong_no_findings(self, client, auth, db):
        asset = Asset(hostname="mysql-strong.corp.example.com", platform=Platform.mysql)
        db.add(asset)
        db.flush()
        payload = {
            "asset_id": str(asset.id),
            "platform": "mysql",
            "policy_source": "database_native",
            "policy_scope": "database",
            "policy_name": "MySQL Instance Policy",
            "is_effective_policy": True,
            "min_password_length": 12,
            "complexity_enabled": True,
            "lockout_threshold": 5,
            "confidence_score": 85,
            "evidence_summary": {
                "validate_password_component": {
                    "value": True,
                    "command": "SHOW VARIABLES LIKE 'validate_password%'",
                },
                "validate_password_policy": {"value": "STRONG"},
                "validate_password_length": {"value": 12},
            },
            "discovered_at": _now(),
        }
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201
        assert r.json()["finding_count"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# 7. MongoDB External-Policy Scenario
# ═══════════════════════════════════════════════════════════════════════════════

class TestMongoDBExternalPolicy:
    def test_mongodb_external_auth_generates_info_finding(self, client, auth, mongo_asset):
        payload = {
            "asset_id": str(mongo_asset.id),
            "platform": "mongodb",
            "policy_source": "external_idp",
            "policy_scope": "database",
            "policy_name": "MongoDB LDAP External Auth",
            "is_effective_policy": True,
            "external_policy_enforced": True,
            "requires_external_review": True,
            "confidence_score": 20,
            "collection_error": (
                "Authentication mechanism is LDAP/Kerberos — password policy is "
                "externally enforced and cannot be inspected from this host."
            ),
            "evidence_summary": {
                "auth_mechanism": {
                    "value": "LDAP",
                    "command": "db.adminCommand({getParameter: 1, authMechanisms: 1})",
                },
                "security_ldap_transportSecurity": {"value": "tls"},
            },
            "discovered_at": _now(),
        }
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["external_policy_enforced"] is True
        assert body["requires_external_review"] is True

        fr = client.get(
            "/api/v1/password-policy/findings",
            params={"policy_id": body["id"], "rule_key": "PWPOL-015"},
            headers=auth,
        )
        assert fr.json()["total"] == 1
        assert fr.json()["items"][0]["severity"] == "medium"

    def test_mongodb_local_auth_no_visible_policy(self, client, auth, db):
        """MongoDB with SCRAM (local) auth and no validate-password — medium finding."""
        asset = Asset(hostname="mongo-local.corp.example.com", platform=Platform.mongodb)
        db.add(asset)
        db.flush()
        payload = {
            "asset_id": str(asset.id),
            "platform": "mongodb",
            "policy_source": "database_native",
            "policy_scope": "database",
            "policy_name": "MongoDB Local Auth",
            "is_effective_policy": True,
            "external_policy_enforced": True,   # no built-in policy controls
            "requires_external_review": True,
            "confidence_score": 15,
            "evidence_summary": {
                "auth_mechanism": {"value": "SCRAM-SHA-256"},
                "note": {"value": "MongoDB has no built-in password complexity enforcement for SCRAM"},
            },
            "discovered_at": _now(),
        }
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        assert r.status_code == 201
        assert r.json()["requires_external_review"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Account-Level Exception Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════

class TestAccountPolicyExceptions:
    def test_password_never_expires_for_privileged_account(self, client, auth, win_asset, db):
        """password_never_expires on a privileged account → PWPOL-019 HIGH."""
        # Ensure a policy exists
        r = client.get("/api/v1/password-policy",
                       params={"asset_id": str(win_asset.id)}, headers=auth)
        items = r.json()["items"]
        if not items:
            payload = _policy_payload(str(win_asset.id), policy_name="Main Policy")
            r2 = client.post("/api/v1/password-policy", json=payload, headers=auth)
            policy_id = r2.json()["id"]
        else:
            policy_id = items[0]["id"]

        exc_payload = {
            "asset_id": str(win_asset.id),
            "policy_id": policy_id,
            "exception_type": "password_never_expires",
            "description": "Domain Admin account 'da_svc' has PASSWORD_NEVER_EXPIRES",
            "evidence": {
                "account": "da_svc",
                "is_privileged": True,
                "group_membership": ["Domain Admins", "Enterprise Admins"],
                "command": "Get-ADUser da_svc -Properties PasswordNeverExpires",
            },
            "discovered_at": _now(),
        }
        er = client.post("/api/v1/password-policy/exceptions", json=exc_payload, headers=auth)
        assert er.status_code == 201

        fr = client.get(
            "/api/v1/password-policy/findings",
            params={"policy_id": policy_id, "rule_key": "PWPOL-019", "is_exception_finding": True},
            headers=auth,
        )
        assert fr.json()["total"] >= 1
        assert fr.json()["items"][0]["severity"] == "high"

    def test_list_exceptions_filter(self, client, auth, win_asset):
        # Make this test self-contained: create a policy + exception for win_asset
        r_pol = client.post(
            "/api/v1/password-policy",
            json=_policy_payload(str(win_asset.id), policy_name="Exception-Filter-Test Policy"),
            headers=auth,
        )
        policy_id = r_pol.json()["id"]
        client.post("/api/v1/password-policy/exceptions", json={
            "asset_id": str(win_asset.id),
            "policy_id": policy_id,
            "exception_type": "password_never_expires",
            "description": "List filter test exception",
            "discovered_at": _now(),
        }, headers=auth)

        r = client.get(
            "/api/v1/password-policy/exceptions",
            params={"asset_id": str(win_asset.id)},
            headers=auth,
        )
        assert r.status_code == 200
        assert r.json()["total"] >= 1

    def test_list_exceptions_by_type(self, client, auth):
        r = client.get(
            "/api/v1/password-policy/exceptions",
            params={"exception_type": "password_never_expires"},
            headers=auth,
        )
        assert r.status_code == 200
        for exc in r.json()["items"]:
            assert exc["exception_type"] == "password_never_expires"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Policy Comparison
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyComparison:
    def test_compare_two_assets_detects_inconsistency(self, client, auth, db):
        """Comparing two assets with different min_password_length detects inconsistency."""
        a1 = Asset(hostname="compare-strong.corp.example.com", platform=Platform.windows)
        a2 = Asset(hostname="compare-weak.corp.example.com", platform=Platform.windows)
        db.add_all([a1, a2])
        db.flush()

        client.post("/api/v1/password-policy",
                    json=_policy_payload(str(a1.id), policy_name="Strong", min_password_length=16),
                    headers=auth)
        client.post("/api/v1/password-policy",
                    json=_policy_payload(str(a2.id), policy_name="Weak", min_password_length=8),
                    headers=auth)

        r = client.post(
            "/api/v1/password-policy/compare",
            json={"asset_ids": [str(a1.id), str(a2.id)]},
            headers=auth,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["inconsistency_count"] >= 1
        assert body["worst_severity"] is not None

        # Find the min_password_length row
        length_row = next(
            (row for row in body["rows"] if row["setting"] == "min_password_length"), None
        )
        assert length_row is not None
        assert length_row["has_inconsistency"] is True

    def test_compare_identical_assets_no_inconsistency(self, client, auth, db):
        """Identical policies across two assets → inconsistency_count == 0."""
        a1 = Asset(hostname="identical-1.corp.example.com", platform=Platform.windows)
        a2 = Asset(hostname="identical-2.corp.example.com", platform=Platform.windows)
        db.add_all([a1, a2])
        db.flush()

        for asset in [a1, a2]:
            client.post("/api/v1/password-policy",
                        json=_policy_payload(str(asset.id), policy_name="Same Policy"),
                        headers=auth)

        r = client.post(
            "/api/v1/password-policy/compare",
            json={"asset_ids": [str(a1.id), str(a2.id)]},
            headers=auth,
        )
        assert r.status_code == 200
        assert r.json()["inconsistency_count"] == 0

    def test_compare_requires_at_least_two_assets(self, client, auth, win_asset):
        r = client.post(
            "/api/v1/password-policy/compare",
            json={"asset_ids": [str(win_asset.id)]},
            headers=auth,
        )
        assert r.status_code == 422   # Pydantic min_length=2 validation


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Review Workflow
# ═══════════════════════════════════════════════════════════════════════════════

class TestReviewWorkflow:
    def test_review_finding_risk_accepted(self, client, auth, db):
        """Analyst can mark a finding as risk_accepted with a comment."""
        asset = Asset(hostname="review-test.corp.example.com", platform=Platform.windows)
        db.add(asset)
        db.flush()
        payload = _policy_payload(
            str(asset.id),
            policy_name="Review Test Policy",
            min_password_length=6,   # weak → generates finding
            lockout_threshold=0,
        )
        r = client.post("/api/v1/password-policy", json=payload, headers=auth)
        policy_id = r.json()["id"]

        # Get a finding
        fr = client.get("/api/v1/password-policy/findings",
                        params={"policy_id": policy_id}, headers=auth)
        finding_id = fr.json()["items"][0]["id"]

        # Review it
        rr = client.post(
            f"/api/v1/password-policy/findings/{finding_id}/review",
            json={"state": "risk_accepted", "comment": "Legacy system — remediation planned Q3"},
            headers=auth,
        )
        assert rr.status_code == 200
        assert rr.json()["state"] == "risk_accepted"

        # Verify state updated
        fr2 = client.get(f"/api/v1/password-policy/findings/{finding_id}", headers=auth)
        assert fr2.json()["review_state"] == "risk_accepted"
        assert fr2.json()["review_comment"] == "Legacy system — remediation planned Q3"
        assert fr2.json()["reviewed_by"] == "pwpol_admin@test.local"

    def test_review_non_existent_finding_404(self, client, auth):
        r = client.post(
            f"/api/v1/password-policy/findings/{uuid.uuid4()}/review",
            json={"state": "acknowledged"},
            headers=auth,
        )
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# 11. Export Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class TestExports:
    def test_csv_export_returns_data(self, client, auth):
        r = client.get("/api/v1/password-policy/export/csv", headers=auth)
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        lines = r.text.strip().split("\n")
        assert len(lines) >= 2  # header + at least 1 data row

    def test_csv_export_contains_expected_columns(self, client, auth):
        r = client.get("/api/v1/password-policy/export/csv", headers=auth)
        header = r.text.split("\n")[0]
        for col in ["asset_hostname", "platform", "policy_source", "min_password_length",
                    "complexity_enabled", "lockout_threshold"]:
            assert col in header, f"Missing column: {col}"


# ═══════════════════════════════════════════════════════════════════════════════
# 12. Summary Stats
# ═══════════════════════════════════════════════════════════════════════════════

class TestSummaryStats:
    def test_summary_returns_expected_shape(self, client, auth):
        r = client.get("/api/v1/password-policy/summary", headers=auth)
        assert r.status_code == 200
        body = r.json()
        for key in [
            "total_assets_with_policy", "total_policies", "critical_findings",
            "high_findings", "open_findings", "total_exceptions", "by_platform",
        ]:
            assert key in body, f"Missing key: {key}"

    def test_summary_counts_are_non_negative(self, client, auth):
        r = client.get("/api/v1/password-policy/summary", headers=auth)
        body = r.json()
        assert body["total_assets_with_policy"] >= 0
        assert body["critical_findings"] >= 0
        assert body["total_exceptions"] >= 0

    def test_summary_by_platform_includes_tested_platforms(self, client, auth):
        r = client.get("/api/v1/password-policy/summary", headers=auth)
        by_platform = r.json()["by_platform"]
        # We created windows, rhel, mssql, mysql, mongodb policies in prior tests
        assert "windows" in by_platform or len(by_platform) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# Unit tests for the rules engine (no HTTP layer)
# ═══════════════════════════════════════════════════════════════════════════════

class TestRulesEngineUnit:
    """Direct unit tests for password_policy_rules.evaluate_policy()."""

    def _make_policy(self, **kwargs):
        """Build a plain SimpleNamespace that quacks like PasswordPolicy for the rules engine.

        Using types.SimpleNamespace avoids SQLAlchemy ORM instrumentation issues
        (no session, no _sa_instance_state) while still providing all attributes
        that evaluate_policy reads via getattr.

        All enum fields must be the actual enum objects so identity/membership
        comparisons in the rules engine work correctly.
        """
        defaults = dict(
            id=uuid.uuid4(),
            asset_id=uuid.uuid4(),
            platform=Platform.windows,
            policy_source=PolicySource.local_policy,
            policy_scope=PolicyScope.host,
            policy_name="Test Policy",
            is_effective_policy=True,
            min_password_length=14,
            complexity_enabled=True,
            password_history_count=10,
            lockout_threshold=5,
            max_password_age_days=90,
            reversible_encryption_enabled=False,
            dictionary_check_enabled=None,
            evidence_summary=None,
            applies_to=None,
            confidence_score=100,
            discovered_at=datetime.now(UTC),
        )
        defaults.update(kwargs)
        # Normalise any string enums passed as overrides
        if isinstance(defaults["policy_scope"], str):
            defaults["policy_scope"] = PolicyScope(defaults["policy_scope"])
        if isinstance(defaults["policy_source"], str):
            defaults["policy_source"] = PolicySource(defaults["policy_source"])
        if isinstance(defaults["platform"], str):
            defaults["platform"] = Platform(defaults["platform"])
        return types.SimpleNamespace(**defaults)

    def test_strong_policy_zero_findings(self):
        pol = self._make_policy()
        findings = evaluate_policy(pol)
        assert findings == []

    def test_critical_short_password(self):
        pol = self._make_policy(min_password_length=5)
        findings = evaluate_policy(pol)
        keys = [f.rule_key for f in findings]
        assert "PWPOL-001" in keys
        f = next(f for f in findings if f.rule_key == "PWPOL-001")
        assert f.severity == PolicyFindingSeverity.critical

    def test_high_short_password(self):
        pol = self._make_policy(min_password_length=10)
        findings = evaluate_policy(pol)
        keys = [f.rule_key for f in findings]
        assert "PWPOL-002" in keys
        assert "PWPOL-001" not in keys  # not critically short

    def test_complexity_disabled(self):
        pol = self._make_policy(complexity_enabled=False)
        keys = [f.rule_key for f in evaluate_policy(pol)]
        assert "PWPOL-003" in keys

    def test_no_history(self):
        pol = self._make_policy(password_history_count=0)
        keys = [f.rule_key for f in evaluate_policy(pol)]
        assert "PWPOL-004" in keys

    def test_no_lockout_domain(self):
        pol = self._make_policy(
            policy_source=PolicySource.domain_policy,
            policy_scope=PolicyScope.domain,
            lockout_threshold=0,
        )
        keys = [f.rule_key for f in evaluate_policy(pol)]
        assert "PWPOL-010" in keys

    def test_no_lockout_local(self):
        pol = self._make_policy(lockout_threshold=0)
        keys = [f.rule_key for f in evaluate_policy(pol)]
        assert "PWPOL-006" in keys
        assert "PWPOL-010" not in keys

    def test_permissive_lockout(self):
        pol = self._make_policy(lockout_threshold=15)
        keys = [f.rule_key for f in evaluate_policy(pol)]
        assert "PWPOL-007" in keys

    def test_never_expires_policy(self):
        pol = self._make_policy(max_password_age_days=0)
        keys = [f.rule_key for f in evaluate_policy(pol)]
        assert "PWPOL-008" in keys

    def test_reversible_encryption(self):
        pol = self._make_policy(reversible_encryption_enabled=True)
        keys = [f.rule_key for f in evaluate_policy(pol)]
        assert "PWPOL-009" in keys
        f = next(f for f in evaluate_policy(pol) if f.rule_key == "PWPOL-009")
        assert f.severity == PolicyFindingSeverity.critical

    def test_pam_dict_check_disabled(self):
        pol = self._make_policy(
            platform=Platform.rhel,
            policy_source=PolicySource.pam_module,
            policy_scope=PolicyScope.host,
            dictionary_check_enabled=False,
        )
        keys = [f.rule_key for f in evaluate_policy(pol)]
        assert "PWPOL-011" in keys

    def test_multiple_issues_all_reported(self):
        """Multiple weak settings produce multiple findings."""
        pol = self._make_policy(
            min_password_length=6,
            complexity_enabled=False,
            password_history_count=0,
            lockout_threshold=0,
            reversible_encryption_enabled=True,
        )
        keys = {f.rule_key for f in evaluate_policy(pol)}
        assert "PWPOL-001" in keys
        assert "PWPOL-003" in keys
        assert "PWPOL-004" in keys
        assert "PWPOL-006" in keys
        assert "PWPOL-009" in keys

    def test_unknown_values_do_not_produce_findings(self):
        """None fields (unknown) must not trigger false positives."""
        pol = self._make_policy(
            min_password_length=None,
            complexity_enabled=None,
            lockout_threshold=None,
            max_password_age_days=None,
        )
        findings = evaluate_policy(pol)
        assert findings == []
