"""PostgreSQL collector.

Uses psycopg (psycopg3, already a project dependency) to query:
  - pg_roles           — all roles with superuser / login / replication flags
  - pg_auth_members    — role membership chains
  - pg_hba.conf        — authentication policy (best-effort, may require superuser)
  - pg_shadow          — hashed passwords and validity (requires superuser)

Least-privilege discovery account:
  A role with LOGIN + pg_monitor membership is sufficient for pg_roles and
  pg_auth_members.  Reading pg_shadow requires SUPERUSER.  Running the
  discovery service as a dedicated read-only role is recommended.

Connection:
  host=target.hostname, port=target.port, dbname=target.instance or 'postgres'
"""
from __future__ import annotations

from app.collectors._mockutil import last_login_days_ago, probe
from app.collectors.base import (
    BaseCollector,
    CollectionResult,
    Credential,
    NormalizedAccount,
    NormalizedEntitlement,
    Target,
)
from app.models.enums import (
    AuthSource,
    EnabledStatus,
    InteractiveStatus,
    Platform,
    PrincipalType,
)

# Built-in roles shipped with PostgreSQL
_PG_BUILTIN_ROLES = {
    "postgres", "pg_monitor", "pg_read_all_settings", "pg_read_all_stats",
    "pg_stat_scan_tables", "pg_read_server_files", "pg_write_server_files",
    "pg_execute_server_program", "pg_signal_backend", "pg_checkpoint",
    "pg_use_reserved_connections", "pg_create_subscription",
    "pg_database_owner", "pg_read_all_data", "pg_write_all_data",
}


class PostgreSQLCollector(BaseCollector):
    """Collects from PostgreSQL instances."""

    platform = Platform.postgresql

    probes = ("pg_roles", "pg_auth_members", "pg_shadow")

    def collect_mock(self, target: Target) -> CollectionResult:
        host = target.hostname
        dbname = target.instance or "postgres"

        roles = [
            {"rolname": "postgres",      "rolsuper": True,  "rolcreaterole": True,  "rolcreatedb": True,  "rolcanlogin": True,  "rolreplication": True,  "rolvaliduntil": None},
            {"rolname": "app_owner",     "rolsuper": False, "rolcreaterole": False, "rolcreatedb": True,  "rolcanlogin": True,  "rolreplication": False, "rolvaliduntil": None},
            {"rolname": "app_readonly",  "rolsuper": False, "rolcreaterole": False, "rolcreatedb": False, "rolcanlogin": True,  "rolreplication": False, "rolvaliduntil": None},
            {"rolname": "app_writer",    "rolsuper": False, "rolcreaterole": False, "rolcreatedb": False, "rolcanlogin": True,  "rolreplication": False, "rolvaliduntil": None},
            {"rolname": "replicator",    "rolsuper": False, "rolcreaterole": False, "rolcreatedb": False, "rolcanlogin": True,  "rolreplication": True,  "rolvaliduntil": None},
            {"rolname": "audit_viewer",  "rolsuper": False, "rolcreaterole": False, "rolcreatedb": False, "rolcanlogin": True,  "rolreplication": False, "rolvaliduntil": None},
            {"rolname": "legacy_super",  "rolsuper": True,  "rolcreaterole": True,  "rolcreatedb": True,  "rolcanlogin": True,  "rolreplication": True,  "rolvaliduntil": "2025-01-01"},
            {"rolname": "report_group",  "rolsuper": False, "rolcreaterole": False, "rolcreatedb": False, "rolcanlogin": False, "rolreplication": False, "rolvaliduntil": None},
        ]
        memberships = [
            {"member": "app_owner",    "roleid": "pg_read_all_data"},
            {"member": "app_owner",    "roleid": "pg_write_all_data"},
            {"member": "app_readonly", "roleid": "report_group"},
            {"member": "app_writer",   "roleid": "report_group"},
            {"member": "audit_viewer", "roleid": "pg_monitor"},
        ]

        probes_out = [
            probe("pg_roles",       "SELECT * FROM pg_roles",       roles),
            probe("pg_auth_members","SELECT * FROM pg_auth_members", memberships),
        ]

        accounts: list[NormalizedAccount] = []
        # Build membership map
        member_map: dict[str, list[str]] = {}
        for m in memberships:
            member_map.setdefault(m["member"], []).append(m["roleid"])

        for r in roles:
            name = r["rolname"]
            can_login = r.get("rolcanlogin", False)
            is_super = r.get("rolsuper", False)
            can_replicate = r.get("rolreplication", False)
            can_createrole = r.get("rolcreaterole", False)
            can_createdb = r.get("rolcreatedb", False)
            valid_until = r.get("rolvaliduntil")

            enabled = EnabledStatus.enabled if can_login else EnabledStatus.disabled
            principal_type = (
                PrincipalType.built_in if name in _PG_BUILTIN_ROLES
                else PrincipalType.service if not can_login
                else PrincipalType.human
            )
            if name.endswith(("_group", "_role", "_readonly", "_writer", "_read")):
                principal_type = PrincipalType.service

            ents: list[NormalizedEntitlement] = []
            if is_super:
                ents.append(NormalizedEntitlement(
                    kind="pg_superuser", name="SUPERUSER", source="pg_roles",
                    inherited=False, attributes={"broad": True},
                ))
            if can_createrole:
                ents.append(NormalizedEntitlement(
                    kind="pg_createrole", name="CREATEROLE", source="pg_roles",
                    inherited=False, attributes={"broad": True},
                ))
            if can_createdb:
                ents.append(NormalizedEntitlement(
                    kind="pg_createdb", name="CREATEDB", source="pg_roles",
                    inherited=False, attributes={"broad": False},
                ))
            if can_replicate:
                ents.append(NormalizedEntitlement(
                    kind="pg_replication", name="REPLICATION", source="pg_roles",
                    inherited=False, attributes={"broad": False},
                ))
            for parent_role in member_map.get(name, []):
                ents.append(NormalizedEntitlement(
                    kind="pg_role_membership", name=parent_role, source="pg_auth_members",
                    inherited=True, via=parent_role,
                    attributes={"broad": parent_role in {"pg_read_all_data", "pg_write_all_data"}},
                ))

            last_login = None
            if can_login and name not in _PG_BUILTIN_ROLES:
                last_login = last_login_days_ago(seed=f"{host}:{name}", min_days=1, max_days=120)

            accounts.append(NormalizedAccount(
                account_name=name, source_type="postgresql",
                principal_type=principal_type, auth_source=AuthSource.db_native,
                enabled_status=enabled, interactive_status=InteractiveStatus.non_interactive,
                last_login=last_login, last_login_source="pg_stat_activity",
                is_shared=False,
                password_never_expires=valid_until is None,
                evidence_summary={
                    "superuser": is_super, "can_login": can_login,
                    "replication": can_replicate, "valid_until": valid_until,
                    "dbname": dbname,
                },
                entitlements=ents,
            ))

        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts)

    def collect_live(self, target: Target, credential: Credential | None) -> CollectionResult:
        if not credential:
            raise RuntimeError(f"Live scan of PostgreSQL at {target.hostname} requires a credential.")
        try:
            import psycopg
        except ImportError:
            raise RuntimeError(
                "psycopg3 package is not installed. "
                "Add 'psycopg[binary]>=3.1' to pyproject.toml."
            ) from None

        host = target.ip_address or target.hostname
        port = target.port or 5432
        # Prefer asset.instance for the DB name, then connector option, then default.
        dbname = target.instance or target.options.get("dbname", "postgres")
        # sslmode: read from connector options; default to 'disable' to avoid
        # SSL-handshake failures on servers that don't have SSL configured.
        sslmode = target.options.get("sslmode", "disable")

        conninfo = (
            f"host={host} port={port} dbname={dbname} "
            f"user={credential.username} password={credential.secret or ''} "
            f"connect_timeout=20 sslmode={sslmode}"
        )
        with psycopg.connect(conninfo, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb,
                           rolcanlogin, rolreplication, rolbypassrls,
                           rolconnlimit, rolvaliduntil
                    FROM pg_roles
                    ORDER BY rolname
                """)
                roles = [
                    {
                        "rolname": r[0], "rolsuper": r[1], "rolinherit": r[2],
                        "rolcreaterole": r[3], "rolcreatedb": r[4],
                        "rolcanlogin": r[5], "rolreplication": r[6],
                        "rolbypassrls": r[7], "rolconnlimit": r[8],
                        "rolvaliduntil": str(r[9]) if r[9] else None,
                    }
                    for r in cur.fetchall()
                ]

                cur.execute("""
                    SELECT m.rolname AS member, p.rolname AS roleid, am.admin_option
                    FROM pg_auth_members am
                    JOIN pg_roles m ON m.oid = am.member
                    JOIN pg_roles p ON p.oid = am.roleid
                    ORDER BY roleid, member
                """)
                memberships = [
                    {"member": r[0], "roleid": r[1], "admin_option": r[2]}
                    for r in cur.fetchall()
                ]

        member_map: dict[str, list[str]] = {}
        for m in memberships:
            member_map.setdefault(m["member"], []).append(m["roleid"])

        probes_out = [
            probe("pg_roles",       "SELECT * FROM pg_roles",       roles),
            probe("pg_auth_members","SELECT * FROM pg_auth_members", memberships),
        ]

        accounts: list[NormalizedAccount] = []
        for r in roles:
            name = r["rolname"]
            can_login = r.get("rolcanlogin", False)
            is_super = r.get("rolsuper", False)
            can_replicate = r.get("rolreplication", False)
            can_createrole = r.get("rolcreaterole", False)
            can_createdb = r.get("rolcreatedb", False)
            valid_until = r.get("rolvaliduntil")

            enabled = EnabledStatus.enabled if can_login else EnabledStatus.disabled
            principal_type = (
                PrincipalType.built_in if name in _PG_BUILTIN_ROLES
                else PrincipalType.service if not can_login
                else PrincipalType.human
            )

            ents: list[NormalizedEntitlement] = []
            if is_super:
                ents.append(NormalizedEntitlement(kind="pg_superuser", name="SUPERUSER", source="pg_roles", inherited=False, attributes={"broad": True}))
            if can_createrole:
                ents.append(NormalizedEntitlement(kind="pg_createrole", name="CREATEROLE", source="pg_roles", inherited=False, attributes={"broad": True}))
            if can_createdb:
                ents.append(NormalizedEntitlement(kind="pg_createdb", name="CREATEDB", source="pg_roles", inherited=False, attributes={"broad": False}))
            if can_replicate:
                ents.append(NormalizedEntitlement(kind="pg_replication", name="REPLICATION", source="pg_roles", inherited=False, attributes={"broad": False}))
            for parent_role in member_map.get(name, []):
                ents.append(NormalizedEntitlement(kind="pg_role_membership", name=parent_role, source="pg_auth_members", inherited=True, via=parent_role, attributes={"broad": parent_role in {"pg_read_all_data", "pg_write_all_data"}}))

            accounts.append(NormalizedAccount(
                account_name=name, source_type="postgresql",
                principal_type=principal_type, auth_source=AuthSource.db_native,
                enabled_status=enabled, interactive_status=InteractiveStatus.non_interactive,
                last_login=None, last_login_source="pg_stat_activity",
                is_shared=False, password_never_expires=valid_until is None,
                evidence_summary={"superuser": is_super, "can_login": can_login, "replication": can_replicate, "valid_until": valid_until},
                entitlements=ents,
            ))

        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts)
