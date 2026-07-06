"""Seed the database with sample assets, scan profiles, and built-in rules.

Usage:
    python -m app.seed
    python -m app.seed --production   (skip demo accounts)
"""
from __future__ import annotations

import sys
import uuid
from datetime import UTC, datetime

from app.config import PRODUCTION_LIKE_ENVS, get_settings
from app.db import SessionLocal
from app.models.asset import Asset
from app.models.enums import Platform
from app.models.job import ScanProfile
from app.models.rule import ClassificationRule
from app.models.user import Role, User
from app.rules_engine.builtin_rules import BUILTIN_RULES
from app.security import hash_password


SAMPLE_ASSETS = [
    {"hostname": "rhel-app-01.corp.internal", "ip_address": "10.0.1.10", "platform": Platform.rhel, "environment": "production", "business_unit": "Application", "criticality": "high", "owner": "app-team@corp.internal"},
    {"hostname": "rhel-db-01.corp.internal", "ip_address": "10.0.1.11", "platform": Platform.rhel, "environment": "production", "business_unit": "Database", "criticality": "critical", "owner": "dba-team@corp.internal"},
    {"hostname": "sol-erp-01.corp.internal", "ip_address": "10.0.2.10", "platform": Platform.solaris, "environment": "production", "business_unit": "ERP", "criticality": "critical", "owner": "erp-team@corp.internal"},
    {"hostname": "aix-mq-01.corp.internal", "ip_address": "10.0.3.10", "platform": Platform.aix, "environment": "production", "business_unit": "Middleware", "criticality": "high", "owner": "mw-team@corp.internal"},
    {"hostname": "win-app-01.corp.internal", "ip_address": "10.0.4.10", "platform": Platform.windows, "environment": "production", "business_unit": "Application", "criticality": "high", "owner": "app-team@corp.internal"},
    {"hostname": "win-dc-01.corp.internal", "ip_address": "10.0.4.5", "platform": Platform.windows, "environment": "production", "business_unit": "Infrastructure", "criticality": "critical", "owner": "infra-team@corp.internal"},
    {"hostname": "mysql-app-01.corp.internal", "ip_address": "10.0.5.10", "platform": Platform.mysql, "environment": "production", "business_unit": "Application", "criticality": "high", "instance": "app_db"},
    {"hostname": "mssql-erp-01.corp.internal", "ip_address": "10.0.5.11", "platform": Platform.mssql, "environment": "production", "business_unit": "ERP", "criticality": "critical", "instance": "MSSQLSERVER"},
    {"hostname": "mongo-app-01.corp.internal", "ip_address": "10.0.5.12", "platform": Platform.mongodb, "environment": "production", "business_unit": "Application", "criticality": "high", "instance": "replicaset0"},
    {"hostname": "rhel-dev-01.corp.internal", "ip_address": "10.0.10.10", "platform": Platform.rhel, "environment": "development", "business_unit": "Application", "criticality": "low"},
]

SCAN_PROFILES = [
    {"name": "Unix Basic Discovery", "platforms": ["rhel", "solaris", "aix"], "mode": "safe", "description": "Collect passwd, groups, sudoers, last login. Safe mode."},
    {"name": "Unix Privilege Deep Scan", "platforms": ["rhel", "solaris", "aix"], "mode": "deep", "description": "Full privilege scan including RBAC, sudoers.d, last login age."},
    {"name": "Windows Admin Review", "platforms": ["windows"], "mode": "safe", "description": "Local groups, Administrators, Backup Operators, nested AD."},
    {"name": "MySQL Admin Review", "platforms": ["mysql"], "mode": "safe", "description": "mysql.user, SHOW GRANTS, role_edges."},
    {"name": "MSSQL Privilege Review", "platforms": ["mssql"], "mode": "deep", "description": "Server roles, database roles, db_owner, securityadmin."},
    {"name": "MongoDB Role Review", "platforms": ["mongodb"], "mode": "deep", "description": "Users, roles, custom roles, role inheritance."},
    {"name": "Full Scope Scan", "platforms": ["rhel", "solaris", "aix", "windows", "mysql", "mssql", "mongodb"], "mode": "safe", "description": "All platforms, safe mode."},
]

ROLES = ["admin", "security_analyst", "operator", "auditor", "viewer"]

DEMO_USERS = [
    {"email": "admin@local", "full_name": "Platform Admin", "password": "ChangeMe!123", "roles": ["admin"]},
    {"email": "analyst@local", "full_name": "Security Analyst", "password": "ChangeMe!123", "roles": ["security_analyst", "viewer"]},
    {"email": "auditor@local", "full_name": "Internal Auditor", "password": "ChangeMe!123", "roles": ["auditor", "viewer"]},
]


def seed(production: bool = False) -> None:
    settings = get_settings()
    if settings.env in PRODUCTION_LIKE_ENVS and settings.demo_seed_enabled:
        raise RuntimeError(
            f"DEMO_SEED_ENABLED=true is not permitted when APP_ENV={settings.env}."
        )
    allow_demo_seed = (
        settings.demo_seed_enabled
        and not production
        and settings.env in {"development", "test"}
    )

    with SessionLocal() as db:
        print("Seeding roles...")
        role_map: dict[str, Role] = {}
        for rname in ROLES:
            existing = db.query(Role).filter(Role.name == rname).first()
            if not existing:
                r = Role(name=rname, description=f"{rname} role")
                db.add(r)
                db.flush()
                role_map[rname] = r
            else:
                role_map[rname] = existing

        if allow_demo_seed:
            print("Seeding demo users...")
            for ud in DEMO_USERS:
                existing = db.query(User).filter(User.email == ud["email"]).first()
                if not existing:
                    u = User(
                        email=ud["email"],
                        full_name=ud["full_name"],
                        password_hash=hash_password(ud["password"]),
                        must_change_password=True,
                    )
                    u.roles = [role_map[r] for r in ud["roles"]]
                    db.add(u)

            print("Seeding sample assets...")
            for ad in SAMPLE_ASSETS:
                asset_data = dict(ad)
                instance = asset_data.pop("instance", None)
                existing = db.query(Asset).filter(Asset.hostname == asset_data["hostname"]).first()
                if not existing:
                    db.add(Asset(**asset_data, instance=instance))

        print("Seeding scan profiles...")
        for sp in SCAN_PROFILES:
            existing = db.query(ScanProfile).filter(ScanProfile.name == sp["name"]).first()
            if not existing:
                db.add(ScanProfile(
                    name=sp["name"],
                    description=sp.get("description"),
                    platforms=sp["platforms"],
                    mode=sp["mode"],
                ))

        print("Seeding built-in classification rules...")
        for rd in BUILTIN_RULES:
            existing = db.query(ClassificationRule).filter(ClassificationRule.rule_key == rd["rule_key"]).first()
            if not existing:
                db.add(ClassificationRule(**rd))

        db.commit()
        print("Seed complete.")


if __name__ == "__main__":
    production = "--production" in sys.argv
    seed(production=production)
