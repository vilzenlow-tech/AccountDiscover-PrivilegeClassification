"""Redis collector.

Uses the redis-py package (already a project dependency as 'redis>=5.0') to
query Redis access control and server info.

Redis ACL system (Redis 6+):
  - ACL LIST   — returns all defined ACL users with flags, key patterns, commands
  - ACL WHOAMI — identifies current user
  - INFO server — server version, uptime, mode
  - CONFIG GET requirepass — legacy single-password auth (Redis <6)

For Redis < 6 (no ACL support) the collector falls back to reporting a single
synthetic 'default' user with the legacy password status.

Least-privilege discovery account:
  A Redis ACL user with the 'allkeys' pattern and at minimum:
    +acl|list +acl|whoami +info +config|get
  or simply: the default user with requirepass set (single-password auth).

Connection:
  host=target.hostname, port=target.port (default 6379)
  password from credential.secret
"""
from __future__ import annotations

from app.collectors._mockutil import probe
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


class RedisCollector(BaseCollector):
    """Collects ACL users and access patterns from Redis instances."""

    platform = Platform.redis

    probes = ("acl_list", "acl_whoami", "info_server", "config_requirepass")

    def collect_mock(self, target: Target) -> CollectionResult:
        acl_list = [
            "user default on nopass ~* &* +@all",
            "user admin on #<sha256hash> ~* &* +@all",
            "user app_writer on #<sha256hash> ~app:* &* +@write +@read -@dangerous",
            "user app_reader on #<sha256hash> ~app:* &* +@read -@write -@dangerous",
            "user monitor on #<sha256hash> ~* &* +info +client|list -@write -@dangerous",
            "user legacy_noauth off nopass ~* &* +@all",
        ]
        server_info = {
            "redis_version": "7.2.4",
            "redis_mode": "standalone",
            "os": "Linux 5.15.0 x86_64",
            "uptime_in_seconds": "864000",
            "connected_clients": "8",
        }

        probes_out = [
            probe("acl_list",          "ACL LIST",              acl_list),
            probe("acl_whoami",        "ACL WHOAMI",            "monitor"),
            probe("info_server",       "INFO server",           server_info),
            probe("config_requirepass","CONFIG GET requirepass", {}),
        ]

        accounts = _parse_acl_list(acl_list, source=target.hostname)
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts)

    def collect_live(self, target: Target, credential: Credential | None) -> CollectionResult:
        try:
            import redis as redis_lib
        except ImportError:
            raise RuntimeError(
                "redis package is not installed. "
                "Add 'redis>=5.0' to pyproject.toml."
            ) from None

        host = target.ip_address or target.hostname
        port = target.port or 6379
        password = credential.secret if credential else None
        username = credential.username if credential and credential.auth_method != "password" else None

        r = redis_lib.Redis(
            host=host, port=port,
            username=username, password=password,
            socket_timeout=20, decode_responses=True,
        )
        try:
            server_info = r.info("server")
            redis_version = server_info.get("redis_version", "0.0.0")
            major = int(redis_version.split(".")[0])

            if major >= 6:
                # ACL system available
                acl_list_raw = r.acl_list()
                acl_whoami = r.acl_whoami()
            else:
                # Legacy single-password mode; synthesise a 'default' user entry
                acl_list_raw = ["user default on nopass ~* +@all"]
                acl_whoami = "default"

            try:
                config_pass = r.config_get("requirepass")
            except Exception:
                config_pass = {}

        finally:
            r.close()

        probes_out = [
            probe("acl_list",          "ACL LIST",              acl_list_raw),
            probe("acl_whoami",        "ACL WHOAMI",            acl_whoami),
            probe("info_server",       "INFO server",           server_info),
            probe("config_requirepass","CONFIG GET requirepass", config_pass),
        ]

        accounts = _parse_acl_list(acl_list_raw, source=target.hostname)
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts)


def _parse_acl_list(acl_list: list[str], source: str) -> list[NormalizedAccount]:
    """Parse Redis ACL LIST output into NormalizedAccount objects.

    ACL LIST format (Redis 6+):
        user <name> <status:on|off> [nopass|#<hash>] [~<key-pattern>]
        [&<channel-pattern>] [+<cmd>|-<cmd>|+@<cat>|-@<cat>] ...
    """
    accounts: list[NormalizedAccount] = []

    for line in acl_list:
        parts = line.split()
        if len(parts) < 3 or parts[0] != "user":
            continue
        name = parts[1]
        status = parts[2]  # "on" or "off"
        flags = parts[3:]

        enabled = EnabledStatus.enabled if status == "on" else EnabledStatus.disabled
        principal_type = PrincipalType.built_in if name == "default" else PrincipalType.service

        no_password = "nopass" in flags
        has_hash = any(f.startswith("#") for f in flags)
        key_patterns = [f for f in flags if f.startswith("~")]
        cmd_rules = [f for f in flags if f.startswith("+") or f.startswith("-")]
        broad_access = "+@all" in cmd_rules or ("+@all" in flags)
        all_keys = "~*" in key_patterns or not key_patterns

        ents: list[NormalizedEntitlement] = []
        for rule in cmd_rules:
            ents.append(NormalizedEntitlement(
                kind="redis_acl_command", name=rule,
                source="ACL LIST", inherited=False,
                attributes={"broad": rule in ("+@all", "+@write")},
            ))
        for pattern in key_patterns:
            ents.append(NormalizedEntitlement(
                kind="redis_acl_key_pattern", name=pattern,
                source="ACL LIST", inherited=False,
                attributes={"broad": pattern == "~*"},
            ))

        accounts.append(NormalizedAccount(
            account_name=name,
            source_type="redis",
            principal_type=principal_type,
            auth_source=AuthSource.db_native,
            enabled_status=enabled,
            interactive_status=InteractiveStatus.non_interactive,
            last_login=None,
            last_login_source=None,
            is_shared=(name == "default"),
            password_never_expires=no_password,
            evidence_summary={
                "no_password": no_password,
                "has_hash": has_hash,
                "all_keys": all_keys,
                "broad_access": broad_access,
                "command_rules": cmd_rules,
                "key_patterns": key_patterns,
            },
            entitlements=ents,
        ))

    return accounts
