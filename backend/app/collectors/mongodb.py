"""MongoDB collector.

Issues `db.getUsers()` per database and resolves role inheritance one level
deep. Admin-critical roles (root, userAdminAnyDatabase, clusterAdmin,
dbAdminAnyDatabase, dbOwner, backup, restore) are surfaced explicitly.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.collectors._mockutil import probe
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

ADMIN_CRITICAL_ROLES = {
    "root",
    "userAdminAnyDatabase",
    "clusterAdmin",
    "dbAdminAnyDatabase",
    "dbOwner",
    "backup",
    "restore",
    "readWriteAnyDatabase",
    "hostManager",
    "clusterManager",
    "clusterMonitor",
}


def _classify_mongo_principal(username: str) -> PrincipalType:
    name = username.lower()
    if name in {"admin", "root"}:
        return PrincipalType.built_in
    if "svc" in name or "monitor" in name:
        return PrincipalType.service
    if "generic" in name or name in {"shared"}:
        return PrincipalType.shared
    if "app" in name:
        return PrincipalType.application
    return PrincipalType.human


class MongoCollector(BaseCollector):
    platform = Platform.mongodb
    probes = ("list_users", "get_roles", "list_databases")

    @staticmethod
    def _interactive_status_for_principal(principal_type: PrincipalType) -> InteractiveStatus:
        if principal_type in {PrincipalType.human, PrincipalType.shared}:
            return InteractiveStatus.interactive
        return InteractiveStatus.non_interactive

    @staticmethod
    def _coerce_lab_login_event(value: object) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed

    def collect_mock(self, target: Target) -> CollectionResult:
        all_users = {
            "admin": [
                {
                    "user": "admin",
                    "db": "admin",
                    "roles": [{"role": "root", "db": "admin"}],
                    "customData": {},
                },
                {
                    "user": "backup_svc",
                    "db": "admin",
                    "roles": [
                        {"role": "backup", "db": "admin"},
                        {"role": "restore", "db": "admin"},
                    ],
                    "customData": {"team": "ops"},
                },
                {
                    "user": "monapp",
                    "db": "admin",
                    "roles": [{"role": "clusterMonitor", "db": "admin"}],
                    "customData": {},
                },
                {
                    "user": "userAdmin",
                    "db": "admin",
                    "roles": [{"role": "userAdminAnyDatabase", "db": "admin"}],
                    "customData": {},
                },
                {
                    "user": "adt_mongo_interactive",
                    "db": "admin",
                    "roles": [{"role": "readWrite", "db": "admin"}],
                    "customData": {"team": "lab"},
                },
                {
                    "user": "adt_mongo_root_admin",
                    "db": "admin",
                    "roles": [{"role": "root", "db": "admin"}],
                    "customData": {"team": "lab"},
                },
                {
                    "user": "adt_mongo_generic",
                    "db": "admin",
                    "roles": [{"role": "readWrite", "db": "admin"}],
                    "customData": {"team": "lab"},
                },
            ],
            "appdb": [
                {
                    "user": "app_rw",
                    "db": "appdb",
                    "roles": [{"role": "readWrite", "db": "appdb"}],
                    "customData": {},
                },
                {
                    "user": "app_admin",
                    "db": "appdb",
                    "roles": [{"role": "dbOwner", "db": "appdb"}],
                    "customData": {},
                },
            ],
        }
        custom_roles = {
            "admin": [
                {
                    "role": "appDeployer",
                    "db": "admin",
                    "privileges": [
                        {"resource": {"db": "appdb", "collection": ""}, "actions": ["find", "insert", "update", "remove", "createIndex", "dropCollection"]},
                    ],
                    "roles": [{"role": "readWrite", "db": "appdb"}],
                }
            ]
        }

        probes_out = [
            probe("list_users", "db.adminCommand({usersInfo:1,showPrivileges:true})", all_users),
            probe("get_roles", "db.adminCommand({rolesInfo:1,showPrivileges:true})", custom_roles),
            probe(
                "list_databases",
                "db.adminCommand('listDatabases')",
                [{"name": "admin"}, {"name": "appdb"}],
            ),
        ]

        accounts: list[NormalizedAccount] = []
        for db_name, users in all_users.items():
            for u in users:
                uname = u["user"]
                auth_db = u["db"]
                ents: list[NormalizedEntitlement] = []
                for r in u.get("roles", []):
                    rname, rdb = r["role"], r["db"]
                    is_critical = rname in ADMIN_CRITICAL_ROLES
                    ents.append(
                        NormalizedEntitlement(
                            kind="mongo_role",
                            name=rname,
                            scope=rdb,
                            source=f"db.getUsers() on {auth_db}",
                            attributes={"admin_critical": is_critical, "any_db": rdb == "admin" and is_critical},
                        )
                    )
                    # Walk one level of custom role inheritance.
                    for cr in custom_roles.get(rdb, []):
                        if cr["role"] == rname:
                            for ir in cr.get("roles", []):
                                ents.append(
                                    NormalizedEntitlement(
                                        kind="mongo_role",
                                        name=ir["role"],
                                        scope=ir["db"],
                                        source=f"custom_role:{rname}@{rdb}",
                                        inherited=True,
                                        via=f"custom role {rname}",
                                        attributes={"admin_critical": ir["role"] in ADMIN_CRITICAL_ROLES},
                                    )
                                )
                principal_type = _classify_mongo_principal(uname)
                accounts.append(
                    NormalizedAccount(
                        account_name=f"{uname}@{auth_db}",
                        source_type="mongo_account",
                        principal_type=principal_type,
                        auth_source=AuthSource.db_native,
                        enabled_status=EnabledStatus.enabled,
                        interactive_status=MongoCollector._interactive_status_for_principal(principal_type),
                        evidence_summary={"auth_db": auth_db, "custom_data": u.get("customData", {})},
                        entitlements=ents,
                    )
                )
        policies = []
        if target.options.get("collect_password_policy"):
            policies = MongoCollector._collect_policy_mock(target)
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts, password_policies=policies)

    def collect_live(self, target: Target, credential: "Credential | None") -> CollectionResult:
        if not credential:
            raise RuntimeError(f"Live MongoDB scan of {target.hostname} requires a credential.")
        from pymongo import MongoClient
        from urllib.parse import quote_plus
        port = target.port or 27017
        host = target.ip_address or target.hostname
        uri = f"mongodb://{quote_plus(credential.username)}:{quote_plus(credential.secret or '')}@{host}:{port}/admin?authSource=admin&connectTimeoutMS=20000&serverSelectionTimeoutMS=20000"
        client = MongoClient(uri)
        raw_auth_mechs: list[str] = []
        raw_ldap_enabled: bool = False
        raw_policy_error: str | None = None
        lab_login_events: dict[str, datetime] = {}
        try:
            users_info = client.admin.command({"usersInfo": {"forAllDBs": True}, "showCredentials": False, "showPrivileges": False})
            users = users_info.get("users", [])

            try:
                for event in client["adpct_lab_app"]["adpct_lab_account_login_events"].find(
                    {}, {"_id": 0, "account_name": 1, "last_login_at": 1}
                ):
                    login_at = MongoCollector._coerce_lab_login_event(event.get("last_login_at"))
                    if login_at:
                        lab_login_events[str(event.get("account_name"))] = login_at
            except Exception:
                lab_login_events = {}

            if target.options.get("collect_password_policy"):
                # Auth mechanisms (available on all editions)
                try:
                    result = client.admin.command({"getParameter": 1, "authenticationMechanisms": 1})
                    raw_auth_mechs = result.get("authenticationMechanisms", [])
                except Exception as exc:
                    raw_policy_error = f"getParameter authenticationMechanisms: {exc}"

                # LDAP (enterprise only; silently absent on Community)
                try:
                    ldap_result = client.admin.command({"getParameter": 1, "ldapTransportSecurity": 1})
                    raw_ldap_enabled = "ldapTransportSecurity" in ldap_result
                except Exception:
                    pass
        finally:
            client.close()

        probes_out = [probe("usersInfo", "db.adminCommand({usersInfo:{forAllDBs:true}})", [str(u.get("user")) for u in users])]
        accounts = []
        admin_critical_names = {"root", "userAdminAnyDatabase", "dbAdminAnyDatabase", "clusterAdmin", "readWriteAnyDatabase"}
        for u in users:
            username = u.get("user", "")
            auth_db = u.get("db", "admin")
            roles = u.get("roles", [])
            ents = [
                NormalizedEntitlement(
                    kind="mongo_role", name=r.get("role", ""), scope=r.get("db", ""),
                    source="usersInfo",
                    attributes={
                        "admin_critical": r.get("role", "") in admin_critical_names,
                        "any_db": r.get("db", "") == "admin",
                    },
                )
                for r in roles
            ]
            principal_type = _classify_mongo_principal(username)
            account_name = f"{username}@{auth_db}"
            last_login = lab_login_events.get(account_name)
            accounts.append(NormalizedAccount(
                account_name=account_name, source_type="mongodb",
                principal_type=principal_type,
                auth_source=AuthSource.db_native,
                enabled_status=EnabledStatus.enabled,
                interactive_status=MongoCollector._interactive_status_for_principal(principal_type),
                last_login=last_login,
                last_login_source="adpct_lab_app.adpct_lab_account_login_events" if last_login else None,
                never_logged_in=False if last_login else None,
                is_shared=False, password_never_expires=False,
                evidence_summary={"auth_db": auth_db, "roles": [r.get("role") for r in roles]},
                entitlements=ents,
            ))

        policies = []
        if target.options.get("collect_password_policy"):
            policies = MongoCollector._collect_policy_live(raw_auth_mechs, raw_ldap_enabled, raw_policy_error, target)
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts, password_policies=policies)

    @staticmethod
    def _collect_policy_live(
        auth_mechs: list[str],
        ldap_enabled: bool,
        collection_error: str | None,
        target: "Target",
    ) -> "list[NormalizedPasswordPolicy]":
        """Build a NormalizedPasswordPolicy from live getParameter output.

        MongoDB has no native password complexity or expiration engine.
        Policy findings are:
          - Which authentication mechanisms are active (SCRAM-SHA-1 is weak)
          - Whether LDAP (external) auth is configured (enterprise feature)

        The external_policy_enforced flag is set when LDAP is present,
        meaning the actual password rules live outside the database.
        """
        from app.collectors.base import NormalizedPasswordPolicy

        scram1_enabled  = "SCRAM-SHA-1" in auth_mechs
        scram256_enabled = "SCRAM-SHA-256" in auth_mechs
        # SCRAM-SHA-1 still enabled alongside SHA-256 is a weak-auth finding.
        weak_auth = scram1_enabled and len(auth_mechs) > 0

        return [NormalizedPasswordPolicy(
            policy_source="database_native",
            policy_scope="database",
            policy_name="MongoDB Authentication",
            is_effective_policy=True,
            # No native password complexity or expiration — always None.
            min_password_length=None,
            complexity_enabled=None,
            max_password_age_days=None,
            external_policy_enforced=ldap_enabled,
            requires_external_review=ldap_enabled,
            collection_error=collection_error,
            evidence_summary={
                "authenticationMechanisms": auth_mechs,
                "SCRAM-SHA-1_enabled": scram1_enabled,
                "SCRAM-SHA-256_enabled": scram256_enabled,
                "LDAP_enabled": ldap_enabled,
                "weak_auth_finding": weak_auth,
                "source": "db.adminCommand({getParameter:1,authenticationMechanisms:1})",
                "host": target.hostname,
            },
            confidence_score=85 if not collection_error else 40,
        )]

    @staticmethod
    def _collect_policy_mock(target: Target) -> "list[NormalizedPasswordPolicy]":
        """Return MongoDB authentication policy for a mock scan.

        Simulates a MongoDB instance using SCRAM-SHA-256 with external auth
        enabled — visibility into the actual password policy is limited and
        requires a manual review of the external IdP.
        """
        from app.collectors.base import NormalizedPasswordPolicy
        return [
            NormalizedPasswordPolicy(
                policy_source="database_native",
                policy_scope="database",
                policy_name="MongoDB Authentication",
                is_effective_policy=True,
                external_policy_enforced=True,
                requires_external_review=True,
                evidence_summary={
                    "auth_mechanism": {"value": "SCRAM-SHA-256"},
                    "auth_source": "admin",
                    "source": "db.adminCommand({getParameter:1, authenticationMechanisms:1})",
                    "host": target.hostname,
                },
                confidence_score=20,
            )
        ]
