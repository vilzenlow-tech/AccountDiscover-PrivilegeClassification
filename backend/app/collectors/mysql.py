"""MySQL collector.

Queries `mysql.user`, `information_schema`, `SHOW GRANTS FOR user@host`,
and (if supported) `mysql.role_edges`. Does not read or derive passwords.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

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


GLOBAL_ADMIN_PRIVS = {"ALL PRIVILEGES", "SUPER", "GRANT OPTION", "CREATE USER"}


def _classify_mysql_principal(username: str) -> PrincipalType:
    name = username.lower()
    if name == "root":
        return PrincipalType.built_in
    if "svc" in name or name.endswith("_service"):
        return PrincipalType.service
    if "generic" in name or name in {"shared"}:
        return PrincipalType.shared
    if "app" in name:
        return PrincipalType.application
    return PrincipalType.human


class MySQLCollector(BaseCollector):
    platform = Platform.mysql
    probes = ("mysql_users", "mysql_grants", "mysql_roles", "mysql_locked")

    @staticmethod
    def _interactive_status_for_principal(principal_type: PrincipalType) -> InteractiveStatus:
        if principal_type in {PrincipalType.human, PrincipalType.shared}:
            return InteractiveStatus.interactive
        return InteractiveStatus.non_interactive

    @staticmethod
    def _password_expiry_metadata(
        password_expired: str | None,
        password_lifetime: int | str | None,
        password_last_changed: datetime | None,
    ) -> dict:
        lifetime_days: int | None
        try:
            lifetime_days = int(password_lifetime) if password_lifetime is not None else None
        except (TypeError, ValueError):
            lifetime_days = None

        is_expired = password_expired == "Y"
        never_expires = lifetime_days == 0
        expires_at = None
        if is_expired:
            expires_at = password_last_changed
        elif password_last_changed and lifetime_days and lifetime_days > 0:
            expires_at = password_last_changed + timedelta(days=lifetime_days)

        return {
            "password_expired": is_expired,
            "password_lifetime_days": lifetime_days,
            "password_never_expires": never_expires,
            "password_last_changed": password_last_changed,
            "password_expires_at": expires_at,
        }

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

    @staticmethod
    def _coerce_lab_account_metadata(row: dict) -> tuple[PrincipalType | None, InteractiveStatus | None]:
        principal_type = None
        interactive_status = None
        try:
            principal_type = PrincipalType(str(row.get("principal_type") or ""))
        except ValueError:
            pass
        try:
            interactive_status = InteractiveStatus(str(row.get("interactive_status") or ""))
        except ValueError:
            pass
        return principal_type, interactive_status

    @staticmethod
    def _json_safe_rows(rows: list[dict]) -> list[dict]:
        safe_rows = []
        for row in rows:
            safe_rows.append(
                {
                    key: value.isoformat() if isinstance(value, datetime) else value
                    for key, value in row.items()
                }
            )
        return safe_rows

    def collect_mock(self, target: Target) -> CollectionResult:
        users = [
            {"user": "root", "host": "localhost", "plugin": "caching_sha2_password", "locked": False},
            {"user": "root", "host": "%", "plugin": "caching_sha2_password", "locked": False},
            {"user": "app_rw", "host": "%", "plugin": "mysql_native_password", "locked": False},
            {"user": "readonly", "host": "%", "plugin": "caching_sha2_password", "locked": False},
            {"user": "backup_svc", "host": "10.0.8.%", "plugin": "caching_sha2_password", "locked": False},
            {"user": "legacy_admin", "host": "%", "plugin": "caching_sha2_password", "locked": True},
        ]
        grants = {
            "'root'@'localhost'": [
                "GRANT ALL PRIVILEGES ON *.* TO `root`@`localhost` WITH GRANT OPTION",
                "GRANT PROXY ON ''@'' TO `root`@`localhost` WITH GRANT OPTION",
            ],
            "'root'@'%'": ["GRANT ALL PRIVILEGES ON *.* TO `root`@`%` WITH GRANT OPTION"],
            "'app_rw'@'%'": [
                "GRANT SELECT, INSERT, UPDATE, DELETE ON `app`.* TO `app_rw`@`%`",
                "GRANT SELECT ON `reporting`.* TO `app_rw`@`%`",
            ],
            "'readonly'@'%'": ["GRANT SELECT ON *.* TO `readonly`@`%`"],
            "'backup_svc'@'10.0.8.%'": [
                "GRANT SELECT, RELOAD, LOCK TABLES, REPLICATION CLIENT, SHOW VIEW, EVENT, TRIGGER ON *.* TO `backup_svc`@`10.0.8.%`"
            ],
            "'legacy_admin'@'%'": ["GRANT SUPER, GRANT OPTION ON *.* TO `legacy_admin`@`%`"],
        }
        roles = {
            "role_app_admin": ["app_rw"],
        }

        probes_out = [
            probe(
                "mysql_users",
                "SELECT user, host, plugin, account_locked FROM mysql.user",
                users,
            ),
            probe("mysql_grants", "SHOW GRANTS FOR <user>@<host>", grants),
            probe(
                "mysql_roles",
                "SELECT FROM_USER, TO_USER FROM mysql.role_edges",
                roles,
            ),
            probe(
                "mysql_locked",
                "SELECT user, host, account_locked FROM mysql.user",
                {u["user"] + "@" + u["host"]: u["locked"] for u in users},
            ),
        ]

        accounts: list[NormalizedAccount] = []
        for u in users:
            key = f"'{u['user']}'@'{u['host']}'"
            ulist = grants.get(key, [])
            ents: list[NormalizedEntitlement] = []
            is_global_admin = False
            for g in ulist:
                privs_part, rest = g.split(" ON ", 1)
                privs = privs_part.replace("GRANT ", "").strip()
                on_part, _ = rest.split(" TO ", 1)
                scope = on_part.strip()
                has_with_grant = " WITH GRANT OPTION" in g
                if scope == "*.*" and any(p.strip() in GLOBAL_ADMIN_PRIVS for p in privs.split(",")):
                    is_global_admin = True
                ents.append(
                    NormalizedEntitlement(
                        kind="mysql_grant",
                        name=privs,
                        scope=scope,
                        source="SHOW GRANTS",
                        attributes={"with_grant_option": has_with_grant, "global_admin": is_global_admin},
                    )
                )
            for role, members in roles.items():
                if u["user"] in members:
                    ents.append(
                        NormalizedEntitlement(
                            kind="mysql_role",
                            name=role,
                            source="mysql.role_edges",
                            inherited=True,
                            via=f"role {role}",
                        )
                    )
            accounts.append(
                NormalizedAccount(
                    account_name=f"{u['user']}@{u['host']}",
                    source_type="mysql_account",
                    principal_type=_classify_mysql_principal(u["user"]),
                    auth_source=AuthSource.db_native,
                    enabled_status=EnabledStatus.locked if u["locked"] else EnabledStatus.enabled,
                    interactive_status=InteractiveStatus.interactive,
                    evidence_summary={
                        "host": u["host"],
                        "plugin": u["plugin"],
                        "global_admin": is_global_admin,
                    },
                    entitlements=ents,
                )
            )
        policies = []
        if target.options.get("collect_password_policy"):
            policies = MySQLCollector._collect_policy_mock(target)
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts, password_policies=policies)

    def collect_live(self, target: Target, credential: "Credential | None") -> CollectionResult:
        if not credential:
            raise RuntimeError(f"Live MySQL scan of {target.hostname} requires a credential.")
        import pymysql
        port = target.port or 3306
        conn = pymysql.connect(
            host=target.ip_address or target.hostname, port=port,
            user=credential.username, password=credential.secret or "",
            db="mysql", connect_timeout=20, cursorclass=pymysql.cursors.DictCursor,
        )
        raw_vp_vars: dict[str, str] = {}
        raw_lifetime: str | None = None
        raw_history: str | None = None
        lab_login_events: dict[str, datetime] = {}
        lab_account_metadata: dict[str, tuple[PrincipalType | None, InteractiveStatus | None]] = {}
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT User, Host, account_locked, plugin, password_expired, "
                    "password_lifetime, password_last_changed FROM mysql.user"
                )
                users = cur.fetchall()
                grants_map: dict[str, list[str]] = {}
                for u in users:
                    try:
                        cur.execute(f"SHOW GRANTS FOR '{u['User']}'@'{u['Host']}'")
                        grants_map[f"{u['User']}@{u['Host']}"] = [r[list(r.keys())[0]] for r in cur.fetchall()]
                    except Exception:
                        grants_map[f"{u['User']}@{u['Host']}"] = []

                if target.options.get("collect_password_policy"):
                    # validate_password component/plugin variables
                    try:
                        cur.execute("SHOW VARIABLES LIKE 'validate_password%'")
                        for row in cur.fetchall():
                            raw_vp_vars[row["Variable_name"]] = row["Value"]
                    except Exception:
                        pass
                    # Global password lifetime (days; 0 = never expires)
                    try:
                        cur.execute("SHOW VARIABLES LIKE 'default_password_lifetime'")
                        r = cur.fetchone()
                        if r:
                            raw_lifetime = r["Value"]
                    except Exception:
                        pass
                    # Password reuse history count
                    try:
                        cur.execute("SHOW VARIABLES LIKE 'password_history'")
                        r = cur.fetchone()
                        if r:
                            raw_history = r["Value"]
                    except Exception:
                        pass

                try:
                    cur.execute(
                        "SELECT account_name, last_login_at "
                        "FROM adpct_lab_app.adpct_lab_account_login_events"
                    )
                    for row in cur.fetchall():
                        login_at = MySQLCollector._coerce_lab_login_event(row.get("last_login_at"))
                        if login_at:
                            lab_login_events[str(row.get("account_name"))] = login_at
                except Exception:
                    lab_login_events = {}

                try:
                    cur.execute(
                        "SELECT account_name, principal_type, interactive_status "
                        "FROM adpct_lab_app.adpct_lab_account_metadata"
                    )
                    for row in cur.fetchall():
                        lab_account_metadata[str(row.get("account_name"))] = MySQLCollector._coerce_lab_account_metadata(row)
                except Exception:
                    lab_account_metadata = {}
        finally:
            conn.close()

        probes_out = [
            probe(
                "mysql_users",
                "SELECT from mysql.user + SHOW GRANTS",
                MySQLCollector._json_safe_rows([dict(u) for u in users]),
            )
        ]
        accounts = []
        for u in users:
            key = f"{u['User']}@{u['Host']}"
            metadata_principal_type, metadata_interactive_status = lab_account_metadata.get(key, (None, None))
            principal_type = metadata_principal_type or _classify_mysql_principal(u["User"])
            user_grants = grants_map.get(key, [])
            is_global_admin = (
                any("ALL PRIVILEGES" in g and "*.*" in g for g in user_grants)
                or any(priv in " ".join(user_grants) for priv in ("SUPER", "GRANT OPTION"))
            )
            ents = [
                NormalizedEntitlement(kind="mysql_grant", name=g, source="SHOW GRANTS",
                                      attributes={"global_admin": is_global_admin})
                for g in user_grants
            ]
            locked = u.get("account_locked", "N") == "Y"
            account_name = f"{u['User']}@{u['Host']}"
            expiry = MySQLCollector._password_expiry_metadata(
                u.get("password_expired"),
                u.get("password_lifetime"),
                u.get("password_last_changed"),
            )
            last_login = lab_login_events.get(account_name)
            accounts.append(NormalizedAccount(
                account_name=account_name, source_type="mysql_local",
                principal_type=principal_type,
                auth_source=AuthSource.db_native,
                enabled_status=EnabledStatus.locked if locked else EnabledStatus.enabled,
                interactive_status=metadata_interactive_status or MySQLCollector._interactive_status_for_principal(principal_type),
                last_login=last_login,
                last_login_source="adpct_lab_app.adpct_lab_account_login_events" if last_login else None,
                never_logged_in=False if last_login else None,
                is_shared=False,
                password_never_expires=expiry["password_never_expires"],
                password_last_changed=expiry["password_last_changed"],
                password_expires_at=expiry["password_expires_at"],
                evidence_summary={"host": u["Host"], "plugin": u.get("plugin", ""),
                                  "global_admin": is_global_admin,
                                  "password_expired": expiry["password_expired"],
                                  "password_lifetime_days": expiry["password_lifetime_days"]},
                entitlements=ents,
            ))
        policies = []
        if target.options.get("collect_password_policy"):
            policies = MySQLCollector._collect_policy_live(raw_vp_vars, raw_lifetime, raw_history, target)
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts, password_policies=policies)

    @staticmethod
    def _collect_policy_live(
        vp_vars: dict[str, str],
        raw_lifetime: str | None,
        raw_history: str | None,
        target: "Target",
    ) -> "list[NormalizedPasswordPolicy]":
        """Build a NormalizedPasswordPolicy from live SHOW VARIABLES output.

        MySQL's validate_password component (8.0+) / plugin (5.7) exposes all
        settings via SHOW VARIABLES LIKE 'validate_password%'.  An empty result
        means the component/plugin is not installed — itself a finding.
        """
        from app.collectors.base import NormalizedPasswordPolicy

        def _int(val: str | None) -> int | None:
            try:
                return int(val) if val is not None else None
            except (ValueError, TypeError):
                return None

        installed = bool(vp_vars)
        lifetime_days = _int(raw_lifetime)
        history_count = _int(raw_history)

        if not installed:
            return [NormalizedPasswordPolicy(
                policy_source="database_native",
                policy_scope="database",
                policy_name="validate_password",
                is_effective_policy=True,
                min_password_length=None,
                complexity_enabled=None,
                max_password_age_days=lifetime_days if lifetime_days and lifetime_days > 0 else None,
                password_history_count=history_count if history_count and history_count > 0 else None,
                evidence_summary={
                    "validate_password_component": {"value": "NOT_INSTALLED"},
                    "default_password_lifetime": raw_lifetime,
                    "password_history": raw_history,
                    "source": "SHOW VARIABLES LIKE 'validate_password%'",
                    "host": target.hostname,
                },
                confidence_score=90,
            )]

        # Component is installed — parse settings.
        # MySQL 8.0 uses dot-notation keys; 5.7 uses underscores.
        def _v(key8: str, key57: str) -> str | None:
            return vp_vars.get(key8) or vp_vars.get(key57)

        policy_level = _v("validate_password.policy", "validate_password_policy") or "MEDIUM"
        min_len      = _int(_v("validate_password.length", "validate_password_length"))
        mixed_case   = _int(_v("validate_password.mixed_case_count", "validate_password_mixed_case_count"))
        digits       = _int(_v("validate_password.number_count", "validate_password_number_count"))
        specials     = _int(_v("validate_password.special_char_count", "validate_password_special_char_count"))
        dict_file    = _v("validate_password.dictionary_file", "validate_password_dictionary_file")
        check_user   = _v("validate_password.check_user_name", "validate_password_check_user_name")

        return [NormalizedPasswordPolicy(
            policy_source="database_native",
            policy_scope="database",
            policy_name="validate_password",
            is_effective_policy=True,
            min_password_length=min_len,
            complexity_enabled=policy_level in ("MEDIUM", "STRONG"),
            max_password_age_days=lifetime_days if lifetime_days and lifetime_days > 0 else None,
            password_history_count=history_count if history_count and history_count > 0 else None,
            min_uppercase=mixed_case,
            min_lowercase=mixed_case,
            min_digits=digits,
            min_special_chars=specials,
            dictionary_check_enabled=bool(dict_file),
            evidence_summary={
                "validate_password_component": {"value": "INSTALLED"},
                "validate_password.policy": policy_level,
                "validate_password.length": _v("validate_password.length", "validate_password_length"),
                "validate_password.check_user_name": check_user,
                "default_password_lifetime": raw_lifetime,
                "password_history": raw_history,
                "all_vars": vp_vars,
                "source": "SHOW VARIABLES LIKE 'validate_password%'",
                "host": target.hostname,
            },
            confidence_score=95,
        )]

    @staticmethod
    def _collect_policy_mock(target: Target) -> "list[NormalizedPasswordPolicy]":
        """Return MySQL validate_password policy for a mock scan.

        Simulates validate_password component NOT installed — a very common
        finding on default MySQL installations.  Triggers PWPOL-014 HIGH.
        """
        from app.collectors.base import NormalizedPasswordPolicy
        return [
            NormalizedPasswordPolicy(
                policy_source="database_native",
                policy_scope="database",
                policy_name="validate_password",
                is_effective_policy=True,
                min_password_length=None,
                complexity_enabled=None,
                evidence_summary={
                    "validate_password_component": {"value": "NOT_INSTALLED"},
                    "source": "SHOW VARIABLES LIKE 'validate_password%'",
                    "host": target.hostname,
                },
                confidence_score=60,
            )
        ]
