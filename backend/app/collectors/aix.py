"""AIX collector.

Reads `/etc/passwd`, `/etc/security/user`, AIX RBAC authorizations
(`lsauth`), roles (`lsrole`), and audit flags where available.
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


class AIXCollector(BaseCollector):
    platform = Platform.aix
    probes = ("lsuser", "lsgroup", "lsrole", "lsauth", "chuser_account_locked", "last")

    def collect_mock(self, target: Target) -> CollectionResult:
        lsuser = {
            "root": {"id": 0, "groups": "system,security", "login": "true", "account_locked": "false", "rlogin": "true"},
            "db2inst1": {"id": 205, "groups": "dba,db2grp1", "login": "true", "account_locked": "false", "rlogin": "true"},
            "sapadm": {"id": 206, "groups": "sapsys", "login": "true", "account_locked": "false", "rlogin": "true"},
            "monapp": {"id": 207, "groups": "staff", "login": "true", "account_locked": "false", "rlogin": "true"},
            "ljones": {"id": 1200, "groups": "staff", "login": "true", "account_locked": "false", "rlogin": "true"},
        }
        # user -> roles assigned
        lsrole_user = {
            "root": ["SecPolicy", "SysConfig"],
            "db2inst1": ["SysConfig"],
            "sapadm": [],
            "monapp": ["FSAdmin"],
            "ljones": [],
        }
        # role -> authorizations
        roles = {
            "SecPolicy": ["aix.security.*", "aix.system.config"],
            "SysConfig": ["aix.system.config", "aix.fs.manage"],
            "FSAdmin": ["aix.fs.manage.mount", "aix.fs.manage.umount"],
            "Monitor": ["aix.system.stat.ro"],
        }
        last_raw = {
            "root": "wtmp begins Mar  1; last login: Tue Apr 22 10:00 2026 on /dev/pts/0",
            "db2inst1": "last login: Tue Apr 22 08:00 2026",
            "sapadm": "last login: Thu Apr 17 02:00 2026",
            "monapp": "wtmp begins Mar  1; still logged in Tue Apr 22 09:55 2026",
            "ljones": "Never logged in",
        }

        probes_out = [
            probe("lsuser", "lsuser -a id groups account_locked login rlogin ALL", lsuser),
            probe("lsgroup", "lsgroup ALL", {"system": {"users": "root"}, "dba": {"users": "db2inst1"}}),
            probe("lsrole", "lsrole ALL; for u in $(lsuser -a roles ALL) ...", {"roles": roles, "assignment": lsrole_user}),
            probe("lsauth", "lsauth -f ALL", {"aix.security.*": {}, "aix.system.config": {}}),
            probe("chuser_account_locked", "lsuser -f account_locked ALL", {u: v["account_locked"] for u, v in lsuser.items()}),
            probe("last", "last | head -200", last_raw),
        ]

        accounts: list[NormalizedAccount] = []
        for name, attrs in lsuser.items():
            uid_i = int(attrs["id"])
            ents: list[NormalizedEntitlement] = []
            if uid_i == 0:
                ents.append(NormalizedEntitlement(kind="unix_uid0", name="root", source="/etc/passwd"))
            for g in attrs["groups"].split(","):
                ents.append(NormalizedEntitlement(kind="unix_group", name=g, source="/etc/group"))
            for role in lsrole_user.get(name, []):
                auths = roles.get(role, [])
                broad = any("aix.*" in a or a == "aix.security.*" for a in auths)
                ents.append(
                    NormalizedEntitlement(
                        kind="aix_rbac_role",
                        name=role,
                        source="lsrole",
                        attributes={"authorizations": auths, "broad": broad},
                    )
                )
                for a in auths:
                    ents.append(
                        NormalizedEntitlement(
                            kind="aix_rbac_authorization",
                            name=a,
                            source=f"role:{role}",
                            inherited=True,
                            via=f"role {role}",
                        )
                    )

            enabled = EnabledStatus.locked if attrs["account_locked"] == "true" else EnabledStatus.enabled
            interactive = (
                InteractiveStatus.interactive
                if attrs["login"] == "true" and attrs["rlogin"] == "true"
                else InteractiveStatus.non_interactive
            )
            last_login = None
            if "Never" not in last_raw.get(name, ""):
                last_login = last_login_days_ago(f"{target.hostname}:{name}")

            accounts.append(
                NormalizedAccount(
                    account_name=name,
                    source_type="aix_local",
                    principal_type=PrincipalType.built_in if name == "root" else PrincipalType.human,
                    auth_source=AuthSource.local,
                    enabled_status=enabled,
                    interactive_status=interactive,
                    last_login=last_login,
                    last_login_source="last",
                    evidence_summary={
                        "uid": uid_i,
                        "rbac_roles": lsrole_user.get(name, []),
                        "login": attrs["login"],
                        "rlogin": attrs["rlogin"],
                    },
                    entitlements=ents,
                )
            )
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts)

    def collect_live(self, target: Target, credential: "Credential | None") -> CollectionResult:
        if not credential:
            raise RuntimeError(f"Live scan of {target.hostname} requires a credential.")
        from app.collectors._ssh import SSHRunner
        port = target.port or 22
        expected_fp = target.options.get("ssh_host_fingerprint")
        with SSHRunner(hostname=target.ip_address or target.hostname, port=port,
                       username=credential.username,
                       password=credential.secret if credential.auth_method != "key" else None,
                       pkey_str=credential.secret if credential.auth_method == "key" else None,
                       expected_fingerprint=expected_fp or None) as ssh:
            observed_fp = ssh.observed_fingerprint
            lsuser_raw = ssh.run("lsuser -a id account_locked groups roles ALL 2>/dev/null || true").splitlines()
            lsgroup_raw = ssh.run("lsgroup -a users ALL 2>/dev/null || true").splitlines()
        probes_out = [probe("lsuser", "lsuser ALL", lsuser_raw)]
        accounts = []
        for line in lsuser_raw:
            if not line.strip() or ":" not in line:
                continue
            name = line.split()[0]
            attrs: dict[str, str] = {}
            for token in line.split()[1:]:
                if "=" in token:
                    k, v = token.split("=", 1)
                    attrs[k] = v
            uid_i = int(attrs.get("id", 0))
            locked = attrs.get("account_locked", "false").lower() in ("true", "1", "yes")
            roles = [r for r in attrs.get("roles", "").split(",") if r]
            enabled = EnabledStatus.locked if locked else EnabledStatus.enabled
            interactive = InteractiveStatus.interactive
            ents = []
            if uid_i == 0:
                ents.append(NormalizedEntitlement(kind="unix_uid0", name="root", source="lsuser", inherited=False, attributes={"uid": 0}))
            for role in roles:
                ents.append(NormalizedEntitlement(kind="aix_rbac_role", name=role, source="lsuser", inherited=False, attributes={"broad": "admin" in role.lower()}))
            principal_type = PrincipalType.built_in if name == "root" else (PrincipalType.system if uid_i < 200 else PrincipalType.human)
            accounts.append(NormalizedAccount(account_name=name, source_type="aix_local", principal_type=principal_type, auth_source=AuthSource.local, enabled_status=enabled, interactive_status=interactive, last_login=None, is_shared=False, password_never_expires=False, evidence_summary={"uid": uid_i, "locked": locked, "roles": roles}, entitlements=ents))
        return CollectionResult(
            platform=self.platform,
            probes=probes_out,
            accounts=accounts,
            observed_ssh_fingerprint=observed_fp,
        )
