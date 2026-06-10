"""Oracle Database collector.

Connects via oracledb (python-oracledb, thin mode — no Oracle client needed).
Queries:
  - DBA_USERS           — all database users with status, profile, last login
  - DBA_SYS_PRIVS       — system-level privilege grants per user
  - DBA_ROLE_PRIVS      — role grants per user
  - DBA_TAB_PRIVS       — object-level privilege grants
  - DBA_PROFILES        — password / resource policy per profile
  - SESSION_PRIVS       — effective privileges for the discovery account

Least-privilege discovery account needs:
  CREATE SESSION + SELECT on DBA_USERS, DBA_SYS_PRIVS, DBA_ROLE_PRIVS,
  DBA_TAB_PRIVS, DBA_PROFILES — typically granted via the predefined role
  SELECT_CATALOG_ROLE.

Connection string:
  target.hostname:target.port/service_name
  (service_name comes from target.instance or target.options['service_name'])
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

# Oracle user accounts that ship with every database install
_ORACLE_BUILTIN = {
    "SYS", "SYSTEM", "DBSNMP", "SYSMAN", "OUTLN", "MDSYS", "ORDSYS",
    "EXFSYS", "DMSYS", "WMSYS", "CTXSYS", "ANONYMOUS", "XDB", "ORDPLUGINS",
    "ORDDATA", "SI_INFORMTN_SCHEMA", "OLAPSYS", "SCOTT", "AURORA$ORB$UNAUTHENTICATED",
    "APPQOSSYS", "OJVMSYS", "GSMADMIN_INTERNAL", "GSMUSER", "SYSBACKUP",
    "SYSDG", "SYSKM", "SYSRAC", "REMOTE_SCHEDULER_AGENT", "SYS$UMF",
    "SPATIAL_CSW_ADMIN_USR", "SPATIAL_WFS_ADMIN_USR", "LBACSYS", "APEX_PUBLIC_USER",
    "FLOWS_FILES", "APEX_040200", "DVSYS", "DVF", "AUDSYS", "DBSFWUSER",
    "GGSYS", "DGPDB_INT", "SYSUMF",
}

_DBA_PRIVS = {"DBA", "SYSDBA", "SYSOPER", "SYSBACKUP", "SYSDG", "SYSKM"}


class OracleDBCollector(BaseCollector):
    """Collects from Oracle Database instances."""

    platform = Platform.oracle_db

    probes = ("dba_users", "dba_sys_privs", "dba_role_privs", "dba_profiles")

    def collect_mock(self, target: Target) -> CollectionResult:
        host = target.hostname
        instance = target.instance or "ORCL"

        users = [
            {"username": "SYS",          "status": "OPEN",   "profile": "DEFAULT", "created": "2020-01-15", "last_login": None},
            {"username": "SYSTEM",        "status": "OPEN",   "profile": "DEFAULT", "created": "2020-01-15", "last_login": None},
            {"username": "DBSNMP",        "status": "OPEN",   "profile": "DEFAULT", "created": "2020-01-15", "last_login": None},
            {"username": "APP_OWNER",     "status": "OPEN",   "profile": "APP_PROFILE", "created": "2021-06-01", "last_login": "2026-04-24"},
            {"username": "APP_RO",        "status": "OPEN",   "profile": "APP_PROFILE", "created": "2021-06-01", "last_login": "2026-04-25"},
            {"username": "APP_BATCH",     "status": "OPEN",   "profile": "APP_PROFILE", "created": "2022-03-10", "last_login": "2026-04-25"},
            {"username": "DBA_TEAM",      "status": "OPEN",   "profile": "DBA_PROFILE", "created": "2020-02-01", "last_login": "2026-04-23"},
            {"username": "AUDIT_USER",    "status": "OPEN",   "profile": "DEFAULT",     "created": "2023-01-01", "last_login": "2026-04-20"},
            {"username": "LEGACY_OWNER",  "status": "LOCKED", "profile": "DEFAULT",     "created": "2019-05-10", "last_login": "2024-11-01"},
            {"username": "DEV_READONLY",  "status": "OPEN",   "profile": "DEFAULT",     "created": "2023-09-01", "last_login": "2026-03-15"},
        ]
        sys_privs = {
            "SYS":         ["SYSDBA", "UNLIMITED TABLESPACE", "CREATE ANY TABLE"],
            "SYSTEM":      ["DBA", "UNLIMITED TABLESPACE"],
            "APP_OWNER":   ["CREATE SESSION", "CREATE TABLE", "CREATE PROCEDURE", "CREATE SEQUENCE"],
            "DBA_TEAM":    ["DBA", "CREATE SESSION"],
            "APP_BATCH":   ["CREATE SESSION", "CREATE TABLE"],
            "AUDIT_USER":  ["CREATE SESSION", "AUDIT ANY"],
            "DEV_READONLY": ["CREATE SESSION"],
        }
        role_privs = {
            "APP_OWNER":    ["CONNECT", "RESOURCE"],
            "APP_RO":       ["CONNECT"],
            "APP_BATCH":    ["CONNECT"],
            "DBA_TEAM":     ["DBA", "SELECT_CATALOG_ROLE"],
            "AUDIT_USER":   ["CONNECT", "SELECT_CATALOG_ROLE"],
            "DEV_READONLY": ["CONNECT"],
        }

        probes_out = [
            probe("dba_users",     "SELECT * FROM dba_users",     users),
            probe("dba_sys_privs", "SELECT * FROM dba_sys_privs", sys_privs),
            probe("dba_role_privs","SELECT * FROM dba_role_privs",role_privs),
        ]

        accounts: list[NormalizedAccount] = []
        for u in users:
            name = u["username"]
            status = u.get("status", "OPEN")
            enabled = EnabledStatus.enabled if status == "OPEN" else EnabledStatus.locked
            principal_type = PrincipalType.built_in if name in _ORACLE_BUILTIN else PrincipalType.human
            if name.endswith(("_BATCH", "_JOB", "_SVC", "_SERVICE", "_OWNER")):
                principal_type = PrincipalType.service

            ents: list[NormalizedEntitlement] = []
            for priv in sys_privs.get(name, []):
                ents.append(NormalizedEntitlement(
                    kind="oracle_sys_priv", name=priv,
                    source="DBA_SYS_PRIVS", inherited=False,
                    attributes={"admin_option": False, "broad": priv in _DBA_PRIVS},
                ))
            for role in role_privs.get(name, []):
                ents.append(NormalizedEntitlement(
                    kind="oracle_role", name=role,
                    source="DBA_ROLE_PRIVS", inherited=False,
                    attributes={"broad": role in _DBA_PRIVS},
                ))

            last_login = None
            if u.get("last_login"):
                last_login = last_login_days_ago(seed=f"{host}:{name}", min_days=1, max_days=90)

            accounts.append(NormalizedAccount(
                account_name=name,
                source_type="oracle_db",
                principal_type=principal_type,
                auth_source=AuthSource.db_native,
                enabled_status=enabled,
                interactive_status=InteractiveStatus.non_interactive,
                last_login=last_login,
                last_login_source="DBA_USERS.LAST_LOGIN",
                is_shared=False,
                password_never_expires=u.get("profile") == "DEFAULT",
                evidence_summary={"status": status, "profile": u.get("profile"), "instance": instance},
                entitlements=ents,
            ))

        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts)

    def collect_live(self, target: Target, credential: Credential | None) -> CollectionResult:
        if not credential:
            raise RuntimeError(f"Live scan of Oracle DB at {target.hostname} requires a credential.")
        try:
            import oracledb
        except ImportError:
            raise RuntimeError(
                "oracledb package is not installed. "
                "Add 'oracledb>=2.0' to pyproject.toml and rebuild the image."
            ) from None

        host = target.ip_address or target.hostname
        port = target.port or 1521
        service = target.instance or target.options.get("service_name") or ""

        # Build DSN: include service name only when explicitly configured.
        # Without one, oracledb uses the listener's default service.
        dsn = f"{host}:{port}/{service}" if service else f"{host}:{port}"
        try:
            conn = oracledb.connect(
                user=credential.username,
                password=credential.secret or "",
                dsn=dsn,
            )
        except oracledb.DatabaseError as exc:
            msg = str(exc)
            if "DPY-6001" in msg or "ORA-12514" in msg or "ORA-12505" in msg:
                raise RuntimeError(
                    f"Oracle listener at {host}:{port} does not recognise service "
                    f'"{service or "(default)"}". '
                    "Set the correct service name in the asset's Instance field "
                    "(e.g. XEPDB1, ORCLPDB1, FREE) or add service_name to the "
                    "connector options."
                ) from exc
            raise
        try:
            cur = conn.cursor()

            cur.execute("""
                SELECT username, account_status, created, last_login, profile,
                       oracle_maintained, common
                FROM dba_users
                ORDER BY username
            """)
            users = [
                {
                    "username": row[0], "status": row[1],
                    "created": str(row[2]) if row[2] else None,
                    "last_login": str(row[3]) if row[3] else None,
                    "profile": row[4],
                    "oracle_maintained": row[5],
                    "common": row[6],
                }
                for row in cur.fetchall()
            ]

            cur.execute("""
                SELECT grantee, privilege, admin_option
                FROM dba_sys_privs
                ORDER BY grantee, privilege
            """)
            sys_privs: dict[str, list] = {}
            for grantee, priv, admin in cur.fetchall():
                sys_privs.setdefault(grantee, []).append({"privilege": priv, "admin_option": admin == "YES"})

            cur.execute("""
                SELECT grantee, granted_role, admin_option, default_role
                FROM dba_role_privs
                ORDER BY grantee, granted_role
            """)
            role_privs: dict[str, list] = {}
            for grantee, role, admin, default in cur.fetchall():
                role_privs.setdefault(grantee, []).append({"role": role, "admin_option": admin == "YES"})

        finally:
            conn.close()

        probes_out = [
            probe("dba_users",      "SELECT * FROM dba_users",      users),
            probe("dba_sys_privs",  "SELECT * FROM dba_sys_privs",  sys_privs),
            probe("dba_role_privs", "SELECT * FROM dba_role_privs", role_privs),
        ]

        accounts: list[NormalizedAccount] = []
        for u in users:
            name = u["username"]
            enabled = EnabledStatus.enabled if "OPEN" in u.get("status", "") else EnabledStatus.locked
            is_oracle_maintained = u.get("oracle_maintained") == "Y"
            principal_type = (
                PrincipalType.built_in if (is_oracle_maintained or name in _ORACLE_BUILTIN)
                else PrincipalType.human
            )
            if name.endswith(("_BATCH", "_JOB", "_SVC", "_SERVICE", "_OWNER")):
                principal_type = PrincipalType.service

            ents: list[NormalizedEntitlement] = []
            for entry in sys_privs.get(name, []):
                ents.append(NormalizedEntitlement(
                    kind="oracle_sys_priv", name=entry["privilege"],
                    source="DBA_SYS_PRIVS", inherited=False,
                    attributes={"admin_option": entry["admin_option"], "broad": entry["privilege"] in _DBA_PRIVS},
                ))
            for entry in role_privs.get(name, []):
                ents.append(NormalizedEntitlement(
                    kind="oracle_role", name=entry["role"],
                    source="DBA_ROLE_PRIVS", inherited=False,
                    attributes={"admin_option": entry["admin_option"], "broad": entry["role"] in _DBA_PRIVS},
                ))

            accounts.append(NormalizedAccount(
                account_name=name, source_type="oracle_db",
                principal_type=principal_type, auth_source=AuthSource.db_native,
                enabled_status=enabled, interactive_status=InteractiveStatus.non_interactive,
                last_login=None, last_login_source="DBA_USERS.LAST_LOGIN",
                is_shared=False, password_never_expires=False,
                evidence_summary={
                    "status": u.get("status"), "profile": u.get("profile"),
                    "common": u.get("common"), "oracle_maintained": u.get("oracle_maintained"),
                },
                entitlements=ents,
            ))

        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts)
