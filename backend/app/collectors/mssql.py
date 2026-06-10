"""Microsoft SQL Server collector.

Queries sys.server_principals, sys.server_role_members, sys.database_principals,
sys.database_role_members for every database, and captures both fixed server
roles and fixed database roles that carry elevated privilege.
"""
from __future__ import annotations

from app.collectors._mockutil import last_login_days_ago, probe
from app.collectors.base import (
    BaseCollector,
    CollectionResult,
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

HIGH_RISK_SERVER_ROLES = {
    "sysadmin",
    "securityadmin",
    "serveradmin",
    "dbcreator",
    "bulkadmin",
    "processadmin",
    "setupadmin",
    "diskadmin",
}

HIGH_RISK_DB_ROLES = {
    "db_owner",
    "db_securityadmin",
    "db_ddladmin",
    "db_backupoperator",
    "db_datareader",
    "db_datawriter",
}


class MSSQLCollector(BaseCollector):
    platform = Platform.mssql
    probes = ("server_logins", "server_roles", "server_role_members", "databases", "db_users_roles")

    def collect_mock(self, target: Target) -> CollectionResult:
        server_logins = [
            {"name": "sa", "type": "SQL_LOGIN", "is_disabled": False, "default_db": "master"},
            {"name": "CORP\\sqladmin", "type": "WINDOWS_LOGIN", "is_disabled": False, "default_db": "master"},
            {"name": "app_user", "type": "SQL_LOGIN", "is_disabled": False, "default_db": "AppDB"},
            {"name": "monitoring", "type": "SQL_LOGIN", "is_disabled": False, "default_db": "master"},
            {"name": "legacy_login", "type": "SQL_LOGIN", "is_disabled": True, "default_db": "master"},
            {"name": "CORP\\svc_backup", "type": "WINDOWS_LOGIN", "is_disabled": False, "default_db": "master"},
        ]
        server_role_members = {
            "sysadmin": ["sa", "CORP\\sqladmin"],
            "securityadmin": ["CORP\\sqladmin", "monitoring"],
            "bulkadmin": ["CORP\\svc_backup"],
        }
        databases = ["master", "AppDB", "ReportingDB"]
        db_roles = {
            "AppDB": {
                "db_owner": ["app_user", "CORP\\sqladmin"],
                "db_datareader": ["monitoring", "app_user"],
                "db_datawriter": ["app_user"],
                "db_securityadmin": ["app_user"],
            },
            "ReportingDB": {
                "db_datareader": ["monitoring", "CORP\\sqladmin"],
                "db_owner": ["CORP\\sqladmin"],
            },
        }

        probes_out = [
            probe(
                "server_logins",
                "SELECT name, type_desc AS type, is_disabled, default_database_name FROM sys.server_principals WHERE type IN ('S','U','G')",
                server_logins,
            ),
            probe(
                "server_role_members",
                "SELECT r.name AS role, m.name AS member FROM sys.server_role_members rm JOIN sys.server_principals r ON r.principal_id=rm.role_principal_id JOIN sys.server_principals m ON m.principal_id=rm.member_principal_id",
                server_role_members,
            ),
            probe(
                "databases",
                "SELECT name FROM sys.databases WHERE state_desc='ONLINE'",
                databases,
            ),
            probe(
                "db_users_roles",
                "USE [<db>]; SELECT r.name AS role, m.name AS member FROM sys.database_role_members drm JOIN sys.database_principals r ON r.principal_id=drm.role_principal_id JOIN sys.database_principals m ON m.principal_id=drm.member_principal_id",
                db_roles,
            ),
        ]

        accounts: list[NormalizedAccount] = []
        for login in server_logins:
            name = login["name"]
            ents: list[NormalizedEntitlement] = []
            # Server roles
            for role, members in server_role_members.items():
                if name in members:
                    ents.append(
                        NormalizedEntitlement(
                            kind="mssql_server_role",
                            name=role,
                            scope="server",
                            source="sys.server_role_members",
                            attributes={"high_risk": role in HIGH_RISK_SERVER_ROLES},
                        )
                    )
            # DB roles
            for db, roles in db_roles.items():
                for role, members in roles.items():
                    if name in members:
                        ents.append(
                            NormalizedEntitlement(
                                kind="mssql_db_role",
                                name=role,
                                scope=db,
                                source="sys.database_role_members",
                                attributes={"high_risk": role in HIGH_RISK_DB_ROLES},
                            )
                        )

            auth = AuthSource.ad if "\\" in name else AuthSource.db_native
            accounts.append(
                NormalizedAccount(
                    account_name=name,
                    source_type="mssql_login",
                    principal_type=(
                        PrincipalType.built_in
                        if name == "sa"
                        else PrincipalType.service
                        if "svc" in name.lower() or name in ("monitoring",)
                        else PrincipalType.human
                    ),
                    auth_source=auth,
                    enabled_status=EnabledStatus.disabled if login["is_disabled"] else EnabledStatus.enabled,
                    interactive_status=InteractiveStatus.interactive,
                    last_login=last_login_days_ago(f"{target.hostname}:{name}"),
                    last_login_source="sys.dm_exec_sessions / sys.server_principals.last_login_date",
                    evidence_summary={
                        "login_type": login["type"],
                        "default_db": login["default_db"],
                    },
                    entitlements=ents,
                )
            )
        policies = []
        if target.options.get("collect_password_policy"):
            policies = MSSQLCollector._collect_policy_mock(target, server_logins)
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts, password_policies=policies)

    def collect_live(self, target: Target, credential: "Credential | None") -> CollectionResult:
        if not credential:
            raise RuntimeError(f"Live MSSQL scan of {target.hostname} requires a credential.")
        import pymssql
        from datetime import timezone as _tz
        port = target.port or 1433
        server = f"{target.ip_address or target.hostname}:{port}"
        conn = pymssql.connect(
            server=server,
            user=credential.username,
            password=credential.secret or "",
            database="master",
            timeout=20,
            login_timeout=20,
        )
        policies: list = []
        try:
            cur = conn.cursor(as_dict=True)

            # ── Server principals with SQL-login policy flags (LEFT JOIN) ─────
            # last_login_date: available since SQL Server 2005; NULL = never logged in.
            # is_policy_checked / is_expiration_checked: only populated for SQL logins
            # (type 'S'); Windows logins inherit the domain policy → COALESCE to 1.
            cur.execute(
                "SELECT sp.name, sp.type_desc, sp.is_disabled, sp.default_database_name, "
                "sp.last_login_date, "
                "COALESCE(sl.is_policy_checked,     1) AS is_policy_checked, "
                "COALESCE(sl.is_expiration_checked, 1) AS is_expiration_checked "
                "FROM sys.server_principals sp "
                "LEFT JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id "
                "WHERE sp.type IN ('S','U','G') AND sp.name NOT LIKE '##%'"
            )
            logins = list(cur.fetchall())

            # ── Server role memberships ───────────────────────────────────────
            cur.execute(
                "SELECT r.name AS role_name, m.name AS member_name "
                "FROM sys.server_role_members rm "
                "JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id "
                "JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id"
            )
            role_members = list(cur.fetchall())
            role_map: dict[str, list[str]] = {}
            for rm in role_members:
                role_map.setdefault(rm["member_name"], []).append(rm["role_name"])

            # ── Password policy (collected while connection is still open) ────
            if target.options.get("collect_password_policy"):
                policies = MSSQLCollector._collect_policy_live(cur, target, role_map)
        finally:
            conn.close()

        # ── Build accounts ────────────────────────────────────────────────────
        probes_out = [
            probe(
                "server_principals",
                "sys.server_principals LEFT JOIN sys.sql_logins",
                [dict(lo) for lo in logins],
            )
        ]
        accounts: list[NormalizedAccount] = []
        for login in logins:
            name: str = login["name"]
            type_desc: str = login.get("type_desc") or ""
            roles = role_map.get(name, [])
            ents = [
                NormalizedEntitlement(
                    kind="mssql_server_role",
                    name=r,
                    source="sys.server_role_members",
                    attributes={"high_risk": r in HIGH_RISK_SERVER_ROLES},
                )
                for r in roles
            ]

            # last_login_date comes back as a naive datetime from pymssql — make UTC-aware
            raw_dt = login.get("last_login_date")
            last_login = None
            if raw_dt is not None:
                try:
                    last_login = raw_dt.replace(tzinfo=_tz.utc) if raw_dt.tzinfo is None else raw_dt
                except (AttributeError, TypeError):
                    last_login = None

            # password_never_expires: CHECK_EXPIRATION=OFF on a SQL login means the
            # password never expires.  Windows logins use the domain policy (not applicable).
            is_sql_login = type_desc.upper() in ("SQL_LOGIN", "S")
            pwd_never_expires = (
                not bool(login.get("is_expiration_checked", 1)) if is_sql_login else False
            )

            auth = (
                AuthSource.ad if type_desc.upper().startswith("WINDOWS")
                else AuthSource.db_native
            )
            pt = (
                PrincipalType.built_in if name.lower() == "sa"
                else PrincipalType.service if (
                    "svc" in name.lower()
                    or type_desc.upper().startswith("WINDOWS")
                )
                else PrincipalType.human
            )

            accounts.append(
                NormalizedAccount(
                    account_name=name,
                    source_type="mssql_login",
                    principal_type=pt,
                    auth_source=auth,
                    enabled_status=(
                        EnabledStatus.disabled if login.get("is_disabled")
                        else EnabledStatus.enabled
                    ),
                    interactive_status=InteractiveStatus.non_interactive,
                    last_login=last_login,
                    last_login_source="sys.server_principals.last_login_date",
                    is_shared=False,
                    password_never_expires=pwd_never_expires,
                    evidence_summary={
                        "login_type": type_desc,
                        "default_db": login.get("default_database_name", ""),
                        "server_roles": roles,
                        "is_policy_checked": bool(login.get("is_policy_checked", 1)),
                        "is_expiration_checked": bool(login.get("is_expiration_checked", 1)),
                    },
                    entitlements=ents,
                )
            )
        return CollectionResult(
            platform=self.platform,
            probes=probes_out,
            accounts=accounts,
            password_policies=policies,
        )

    @staticmethod
    def _collect_policy_live(
        cur: object,
        target: "Target",
        role_map: "dict[str, list[str]]",
    ) -> "list[NormalizedPasswordPolicy]":
        """Live MSSQL password policy collection.

        Runs two probes (each best-effort):
          1. sys.sql_logins  — per-login CHECK_POLICY / CHECK_EXPIRATION flags.
             These are the authoritative MSSQL findings; SQL Server defers actual
             complexity/length rules to the Windows OS password policy.
          2. xp_loginconfig  — instance-level authentication config; may surface
             lockout threshold and duration when called under sysadmin context.

        Returns a single NormalizedPasswordPolicy with account_exceptions for
        every SQL login that has CHECK_POLICY=OFF or CHECK_EXPIRATION=OFF.
        """
        from app.collectors.base import NormalizedPasswordPolicy, NormalizedPolicyException

        _HIGH_PRIV: frozenset[str] = frozenset({
            "sysadmin", "securityadmin", "serveradmin",
        })

        # ── Probe 1: per-login policy flags ───────────────────────────────────
        sql_logins: list[dict] = []
        try:
            cur.execute(  # type: ignore[attr-defined]
                "SELECT sl.name, sl.is_policy_checked, sl.is_expiration_checked, "
                "sp.is_disabled "
                "FROM sys.sql_logins sl "
                "JOIN sys.server_principals sp ON sl.principal_id = sp.principal_id "
                "WHERE sp.name NOT LIKE '##%'"
            )
            sql_logins = list(cur.fetchall())  # type: ignore[attr-defined]
        except Exception:
            pass  # insufficient permissions or very old SQL Server version

        # ── Probe 2: instance-level config via xp_loginconfig (best-effort) ──
        # Requires sysadmin or CONTROL SERVER; silently skipped otherwise.
        # Returns rows: { "name": "<key>", "config_value": "<value>" }
        win_policy: dict[str, str] = {}
        try:
            cur.execute("EXEC xp_loginconfig")  # type: ignore[attr-defined]
            for row in cur.fetchall():  # type: ignore[attr-defined]
                key = (row.get("name") or "").strip().lower()
                val = row.get("config_value")
                if key and val is not None:
                    win_policy[key] = str(val).strip()
        except Exception:
            pass

        # ── Build account exceptions ──────────────────────────────────────────
        account_exceptions: list = []
        logins_policy_off: list[str] = []
        logins_expiration_off: list[str] = []

        for row in sql_logins:
            name: str = row["name"]
            policy_checked = bool(row.get("is_policy_checked", 1))
            expiry_checked = bool(row.get("is_expiration_checked", 1))
            is_disabled = bool(row.get("is_disabled", 0))
            is_privileged = bool(role_map.get(name, []) and
                                 any(r in _HIGH_PRIV for r in role_map[name]))

            if not policy_checked:
                # CHECK_POLICY=OFF — Windows password policy entirely bypassed.
                # This is the more severe finding; it implies expiration is also off.
                logins_policy_off.append(name)
                account_exceptions.append(NormalizedPolicyException(
                    account_name=name,
                    exception_type="check_policy_off",
                    evidence={
                        "is_policy_checked": False,
                        "is_expiration_checked": expiry_checked,
                        "is_privileged": is_privileged,
                        "is_disabled": is_disabled,
                        "source": "sys.sql_logins",
                    },
                ))
            elif not expiry_checked:
                # CHECK_EXPIRATION=OFF — password never rotated / never expires.
                logins_expiration_off.append(name)
                account_exceptions.append(NormalizedPolicyException(
                    account_name=name,
                    exception_type="check_expiration_off",
                    evidence={
                        "is_policy_checked": True,
                        "is_expiration_checked": False,
                        "is_privileged": is_privileged,
                        "is_disabled": is_disabled,
                        "source": "sys.sql_logins",
                    },
                ))

        # ── Parse Windows-level values from xp_loginconfig ───────────────────
        def _int(key: str) -> "int | None":
            try:
                return int(win_policy[key]) if key in win_policy else None
            except (ValueError, TypeError):
                return None

        lockout_thr = _int("lockout threshold")
        lockout_dur = _int("lockout duration")   # minutes

        return [
            NormalizedPasswordPolicy(
                policy_source="database_native",
                policy_scope="database",
                policy_name="SQL Server Password Policy",
                is_effective_policy=True,
                # SQL Server defers complexity, length and history to the Windows OS
                # password policy when CHECK_POLICY=ON.  Those values are not stored
                # in any SQL Server system view — collect them from the host via secedit.
                min_password_length=None,
                complexity_enabled=None,
                password_history_count=None,
                max_password_age_days=None,
                lockout_threshold=lockout_thr,
                lockout_duration_minutes=lockout_dur,
                evidence_summary={
                    "source": "sys.sql_logins (is_policy_checked, is_expiration_checked)",
                    "host": target.hostname,
                    "total_sql_logins": len(sql_logins),
                    "logins_with_policy_off": logins_policy_off,
                    "logins_with_expiration_off": logins_expiration_off,
                    "instance_config": win_policy,
                    "note": (
                        "Complexity, min-length and history settings are enforced by the "
                        "Windows OS policy when CHECK_POLICY=ON.  Scan the host OS for "
                        "those values (secedit /export /cfg)."
                    ),
                },
                confidence_score=90,
                account_exceptions=account_exceptions,
            )
        ]

    @staticmethod
    def _collect_policy_mock(
        target: Target, server_logins: list[dict]
    ) -> "list[NormalizedPasswordPolicy]":
        """Return SQL Server policy data for a mock scan.

        Simulates a server where 'sa' has CHECK_EXPIRATION=OFF and
        'legacy_login' has both CHECK_POLICY=OFF and CHECK_EXPIRATION=OFF —
        both very common real-world findings.
        """
        from app.collectors.base import NormalizedPasswordPolicy, NormalizedPolicyException

        sql_logins = [l for l in server_logins if l.get("type") == "SQL_LOGIN"]
        account_exceptions = [
            # sa: sysadmin login with expiration disabled — very common oversight
            NormalizedPolicyException(
                account_name="sa",
                exception_type="check_expiration_off",
                evidence={
                    "is_policy_checked": True,
                    "is_expiration_checked": False,
                    "is_privileged": True,
                    "source": "sys.sql_logins",
                },
            ),
            # legacy_login: policy entirely off (disabled account, but still dangerous)
            NormalizedPolicyException(
                account_name="legacy_login",
                exception_type="check_policy_off",
                evidence={
                    "is_policy_checked": False,
                    "is_expiration_checked": False,
                    "is_disabled": True,
                    "source": "sys.sql_logins",
                },
            ),
        ]

        return [
            NormalizedPasswordPolicy(
                policy_source="database_native",
                policy_scope="database",
                policy_name="SQL Server Password Policy",
                is_effective_policy=True,
                # SQL Server defers to Windows OS password policy for complexity/length
                min_password_length=None,
                complexity_enabled=None,
                lockout_threshold=None,
                evidence_summary={
                    "source": "sys.sql_logins (is_policy_checked, is_expiration_checked)",
                    "host": target.hostname,
                    "total_sql_logins": len(sql_logins),
                    "logins_with_policy_off": ["legacy_login"],
                    "logins_with_expiration_off": ["sa", "legacy_login"],
                },
                confidence_score=90,
                account_exceptions=account_exceptions,
            )
        ]
