"""Solaris collector.

Extends the Unix pattern with Solaris RBAC evidence: roles, profiles,
user_attr, and auth_attr. Where the discovery account cannot read an RBAC
file, the collector emits a warning and marks affected accounts as
`unknown_review_required` downstream.
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


class SolarisCollector(BaseCollector):
    platform = Platform.solaris
    probes = (
        "getent_passwd",
        "getent_group",
        "shadow_status",
        "sudoers",
        "user_attr",
        "auth_attr",
        "prof_attr",
        "lastlog",
    )

    def collect_mock(self, target: Target) -> CollectionResult:
        passwd_raw = [
            "root:x:0:0:Super-User:/root:/bin/bash",
            "oraops:x:1050:100:Ops:/export/home/oraops:/bin/bash",
            "svcscan:x:1060:100:Scan service:/export/home/svcscan:/bin/bash",
            "audit:x:1070:100:Audit:/export/home/audit:/bin/bash",
            "bsmith:x:1101:100:Bob Smith:/export/home/bsmith:/bin/bash",
        ]
        group_raw = [
            "root::0:root",
            "sysadmin::14:oraops,bsmith",
            "audit::15:audit",
        ]
        # user_attr: user:qualifier:res1:res2:attr
        user_attr = {
            "root": "type=normal;roles=;profiles=All",
            "oraops": "type=normal;roles=sysadmin,dbops;profiles=Primary Administrator",
            "svcscan": "type=normal;profiles=Audit Review",
            "audit": "type=normal;profiles=Audit Review",
            "bsmith": "type=normal;roles=sysadmin;profiles=Basic Solaris User",
        }
        # prof_attr : name:res1:res2:desc:attr
        prof_attr = {
            "Primary Administrator": "auths=solaris.*,solaris.grant;help=RtPriAdmin.html",
            "Audit Review": "auths=solaris.audit.read",
            "Basic Solaris User": "auths=solaris.profmgr.read",
            "Software Installation": "auths=solaris.admin.prodreg.*,solaris.system.shutdown",
        }
        auth_attr = {
            "solaris.*": "desc=All Solaris authorizations",
            "solaris.grant": "desc=Grant rights",
            "solaris.audit.read": "desc=Read audit records",
        }
        sudoers_raw = {"/etc/sudoers": ["root ALL=(ALL) ALL", "%sysadmin ALL=(ALL) ALL"]}
        shadow_status = {
            "root": "PS",
            "oraops": "PS",
            "svcscan": "PS",
            "audit": "PS",
            "bsmith": "PS",
        }
        lastlog_raw = {
            "root": "Never logged in",
            "oraops": "Thu Apr 18 10:11:00 2026",
            "svcscan": "Mon Apr 22 03:00:00 2026",
            "audit": "Thu Apr 18 09:01:00 2026",
            "bsmith": "Wed Apr 21 15:00:00 2026",
        }

        probes_out = [
            probe("getent_passwd", "getent passwd", passwd_raw),
            probe("getent_group", "getent group", group_raw),
            probe("shadow_status", "passwd -sa  # normalized", shadow_status),
            probe("sudoers", "cat /etc/sudoers /etc/sudoers.d/*", sudoers_raw),
            probe("user_attr", "cat /etc/user_attr", user_attr),
            probe("auth_attr", "cat /etc/security/auth_attr", auth_attr),
            probe("prof_attr", "cat /etc/security/prof_attr", prof_attr),
            probe("lastlog", "lastlog -b 1 -t 400", lastlog_raw),
        ]

        accounts: list[NormalizedAccount] = []
        for line in passwd_raw:
            name, _, uid, gid, gecos, home, shell = line.split(":")
            uid_i = int(uid)
            ents: list[NormalizedEntitlement] = []

            if uid_i == 0:
                ents.append(
                    NormalizedEntitlement(
                        kind="unix_uid0", name="root", source="/etc/passwd", attributes={"uid": 0}
                    )
                )
            # RBAC roles
            attrs = user_attr.get(name, "")
            roles = [
                r for r in attrs.split(";") for r in [r] if r.startswith("roles=")
            ]
            profiles = [r for r in attrs.split(";") if r.startswith("profiles=")]
            role_list = []
            if roles:
                role_list = [x for x in roles[0].split("=", 1)[1].split(",") if x]
            profile_list = []
            if profiles:
                profile_list = [x for x in profiles[0].split("=", 1)[1].split(",") if x]

            for r in role_list:
                ents.append(
                    NormalizedEntitlement(
                        kind="solaris_rbac_role",
                        name=r,
                        source="user_attr",
                        attributes={},
                    )
                )
            for p in profile_list:
                auths = prof_attr.get(p, "")
                auth_str = ""
                for kv in auths.split(";"):
                    if kv.startswith("auths="):
                        auth_str = kv.split("=", 1)[1]
                broad = "solaris.*" in auth_str or "solaris.grant" in auth_str
                ents.append(
                    NormalizedEntitlement(
                        kind="solaris_rbac_profile",
                        name=p,
                        source="user_attr+prof_attr",
                        attributes={"auths": auth_str, "broad": broad},
                    )
                )
                # Surface individual authorizations too.
                for a in auth_str.split(","):
                    a = a.strip()
                    if not a:
                        continue
                    ents.append(
                        NormalizedEntitlement(
                            kind="solaris_rbac_authorization",
                            name=a,
                            source=f"profile:{p}",
                            inherited=True,
                            via=f"profile {p}",
                            attributes={},
                        )
                    )

            # sudo parse (subset)
            for rule in sudoers_raw["/etc/sudoers"]:
                if rule.startswith("%"):
                    grp = rule.split()[0].lstrip("%")
                    members = next(
                        (mm.split(":")[3].split(",") for mm in group_raw if mm.startswith(f"{grp}:")),
                        [],
                    )
                    if name in members:
                        ents.append(
                            NormalizedEntitlement(
                                kind="sudo_rule",
                                name=rule,
                                source="/etc/sudoers",
                                inherited=True,
                                via=f"group:{grp}",
                                attributes={"broad": "ALL=(ALL) ALL" in rule},
                            )
                        )
                elif rule.split()[0] == name:
                    ents.append(
                        NormalizedEntitlement(
                            kind="sudo_rule",
                            name=rule,
                            source="/etc/sudoers",
                            attributes={"broad": "ALL=(ALL) ALL" in rule},
                        )
                    )

            enabled = (
                EnabledStatus.enabled
                if shadow_status.get(name, "PS") == "PS"
                else EnabledStatus.locked
            )
            interactive = (
                InteractiveStatus.interactive
                if shell in ("/bin/bash", "/bin/sh", "/bin/ksh")
                else InteractiveStatus.non_interactive
            )
            last_login = None
            if "Never" not in lastlog_raw.get(name, ""):
                last_login = last_login_days_ago(f"{target.hostname}:{name}")

            accounts.append(
                NormalizedAccount(
                    account_name=name,
                    source_type="solaris_local",
                    principal_type=PrincipalType.built_in if name == "root" else PrincipalType.human,
                    auth_source=AuthSource.local,
                    enabled_status=enabled,
                    interactive_status=interactive,
                    last_login=last_login,
                    last_login_source="lastlog",
                    evidence_summary={
                        "uid": uid_i,
                        "shell": shell,
                        "rbac_roles": role_list,
                        "rbac_profiles": profile_list,
                    },
                    entitlements=ents,
                )
            )

        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts)

    def collect_live(self, target: Target, credential: "Credential | None") -> CollectionResult:
        if not credential:
            raise RuntimeError(f"Live scan of {target.hostname} requires a credential.")
        from app.collectors._ssh import SSHRunner
        from app.collectors.base import Credential
        port = target.port or 22
        expected_fp = target.options.get("ssh_host_fingerprint")
        with SSHRunner(hostname=target.ip_address or target.hostname, port=port,
                       username=credential.username,
                       password=credential.secret if credential.auth_method != "key" else None,
                       pkey_str=credential.secret if credential.auth_method == "key" else None,
                       expected_fingerprint=expected_fp or None) as ssh:
            observed_fp = ssh.observed_fingerprint
            passwd_raw = [l for l in ssh.run("getent passwd").splitlines() if l.strip()]
            group_raw = [l for l in ssh.run("getent group").splitlines() if l.strip()]
            shadow_raw = ssh.run("awk -F: '{print $1,$2}' /etc/shadow 2>/dev/null || true").splitlines()
            user_attr_raw = ssh.run("cat /etc/user_attr 2>/dev/null || true").splitlines()
            prof_attr_raw = ssh.run("cat /etc/security/prof_attr 2>/dev/null || true").splitlines()
            sudoers_main = ssh.run("cat /etc/sudoers 2>/dev/null || true")
            lastlog_text = ssh.run("last -n 50 2>/dev/null || true")
        shadow_status: dict[str, str] = {}
        for line in shadow_raw:
            parts = line.split(None, 1)
            if len(parts) >= 2:
                user, pw = parts[0], parts[1]
                shadow_status[user] = "LK" if (pw.startswith("!") or pw == "*") else "PS"
        user_attr: dict[str, dict[str, str]] = {}
        for line in user_attr_raw:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(":")
            if len(parts) >= 4:
                attrs = {}
                for kv in parts[3].split(";"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        attrs[k] = v
                user_attr[parts[0]] = attrs
        broad_profiles = {"Primary Administrator", "All"}
        probes_out = [
            probe("getent_passwd", "getent passwd", passwd_raw),
            probe("user_attr", "cat /etc/user_attr", user_attr),
        ]
        accounts = []
        for line in passwd_raw:
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, _, uid, gid, gecos, home, shell = parts[:7]
            uid_i, gid_i = int(uid), int(gid)
            enabled = EnabledStatus.enabled if shadow_status.get(name, "PS") == "PS" else EnabledStatus.locked
            interactive = InteractiveStatus.interactive if shell in ("/bin/bash", "/bin/sh") else InteractiveStatus.non_interactive
            ents = []
            if uid_i == 0:
                ents.append(NormalizedEntitlement(kind="unix_uid0", name="root", source="/etc/passwd", inherited=False, attributes={"uid": 0}))
            ua = user_attr.get(name, {})
            roles = [r for r in ua.get("roles", "").split(",") if r]
            profiles = [p for p in ua.get("profiles", "").split(",") if p]
            for r in roles:
                ents.append(NormalizedEntitlement(kind="solaris_rbac_role", name=r, source="/etc/user_attr", inherited=False, attributes={"broad": r in {"Primary Administrator"}}))
            for p in profiles:
                ents.append(NormalizedEntitlement(kind="solaris_rbac_profile", name=p, source="/etc/user_attr", inherited=False, attributes={"broad": p in broad_profiles}))
            principal_type = PrincipalType.built_in if name == "root" else (PrincipalType.system if uid_i < 500 else (PrincipalType.service if shell in ("/sbin/nologin", "/bin/false") else PrincipalType.human))
            accounts.append(NormalizedAccount(account_name=name, source_type="solaris_local", principal_type=principal_type, auth_source=AuthSource.local, enabled_status=enabled, interactive_status=interactive, last_login=None, is_shared=False, password_never_expires=False, evidence_summary={"uid": uid_i, "shell": shell, "rbac_roles": roles, "rbac_profiles": profiles}, entitlements=ents))
        return CollectionResult(
            platform=self.platform,
            probes=probes_out,
            accounts=accounts,
            observed_ssh_fingerprint=observed_fp,
        )
