"""CentOS collector (SSH-based, RHEL-compatible).

CentOS is binary-compatible with RHEL; the account structure, sudoers
paths, shadow file format, and commands are identical.  The only
differences are in system account names and package defaults.
"""
from __future__ import annotations

from app.collectors._linux_ssh import LinuxSSHCollector
from app.collectors._mockutil import last_login_days_ago, probe
from app.collectors.base import (
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


class CentOSCollector(LinuxSSHCollector):
    """Collects from CentOS hosts via SSH.

    Identical live-collection logic to RHEL (inherited from LinuxSSHCollector).
    Mock data reflects typical CentOS server account layout.
    """

    platform = Platform.centos
    _source_type = "centos_local"

    probes = (
        "getent_passwd",
        "getent_group",
        "shadow_status",
        "sudoers",
        "lastlog",
    )

    def collect_mock(self, target: Target) -> CollectionResult:
        host = target.hostname
        passwd_raw = [
            "root:x:0:0:root:/root:/bin/bash",
            "bin:x:1:1:bin:/bin:/sbin/nologin",
            "daemon:x:2:2:daemon:/sbin:/sbin/nologin",
            "adm:x:3:4:adm:/var/adm:/sbin/nologin",
            "lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin",
            "sync:x:5:0:sync:/sbin:/bin/sync",
            "halt:x:7:0:halt:/sbin:/sbin/halt",
            "ntp:x:38:38::/etc/ntp:/sbin/nologin",
            "apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin",
            "centos:x:1000:1000:CentOS Stream:/home/centos:/bin/bash",
            "svc_app:x:1001:1001:Application Service:/home/svc_app:/bin/bash",
            "svc_backup:x:1002:1002:Backup Service:/home/svc_backup:/bin/bash",
            "dba:x:1003:1003:DBA User:/home/dba:/bin/bash",
            "awong:x:1004:1004:Alex Wong:/home/awong:/bin/bash",
        ]
        group_raw = [
            "root:x:0:root",
            "wheel:x:10:centos,dba",
            "apache:x:48:",
            "svc_app:x:1001:",
            "svc_backup:x:1002:",
            "dba:x:1003:",
        ]
        shadow_status = {
            "root": "PS", "bin": "LK", "daemon": "LK", "adm": "LK",
            "lp": "LK", "sync": "LK", "halt": "LK", "ntp": "LK",
            "apache": "LK", "centos": "PS", "svc_app": "PS",
            "svc_backup": "PS", "dba": "PS", "awong": "PS",
        }
        # Simulated shadow max_days (field 5): 99999 = password never expires.
        # Service and system accounts default to never-expires on many CentOS builds.
        # dba and svc_backup have this set by an admin — a realistic finding.
        shadow_never_expires = {
            "root": False, "bin": False, "daemon": False, "adm": False,
            "lp": False, "sync": False, "halt": False, "ntp": False,
            "apache": False, "centos": False,
            "svc_app": True,      # service account — password never expires
            "svc_backup": True,   # service account — password never expires
            "dba": True,          # DBA set their own account to never expire
            "awong": False,
        }
        sudoers_raw = {
            "/etc/sudoers": [
                "Defaults   requiretty",
                "%wheel  ALL=(ALL)       ALL",
            ],
            "/etc/sudoers.d/svc_backup": [
                "svc_backup ALL=(root) NOPASSWD: /usr/bin/tar, /usr/bin/rsync"
            ],
        }
        lastlog_raw = {
            "centos": "Fri Apr 25 07:00:11 +0000 2026 from 10.10.1.5",
            "dba": "Thu Apr 24 20:18:05 +0000 2026 from 10.10.2.3",
            "svc_app": "Thu Apr 24 00:01:00 +0000 2026 from 10.10.3.1",
            "awong": "Tue Apr 22 15:45:33 +0000 2026 from 10.10.1.22",
        }

        probes_out = [
            probe("getent_passwd", "getent passwd", passwd_raw),
            probe("getent_group", "getent group", group_raw),
            probe("shadow_status", "awk -F: '{print $1,$2,$5}' /etc/shadow", shadow_status),
            probe("sudoers", "cat /etc/sudoers + sudoers.d", sudoers_raw),
            probe("lastlog", "lastlog", lastlog_raw),
        ]

        accounts: list[NormalizedAccount] = []
        for line in passwd_raw:
            name, _, uid, gid, gecos, home, shell = line.split(":")
            uid_i, gid_i = int(uid), int(gid)
            principal_type = self._classify_principal(name, shell, uid_i)
            enabled = EnabledStatus.enabled if shadow_status.get(name, "PS") == "PS" else EnabledStatus.locked
            interactive = InteractiveStatus.interactive if shell in ("/bin/bash", "/bin/sh") else InteractiveStatus.non_interactive
            ents: list[NormalizedEntitlement] = []
            if uid_i == 0:
                ents.append(NormalizedEntitlement(kind="unix_uid0", name="root", source="/etc/passwd", inherited=False, attributes={"uid": 0}))
            for g in group_raw:
                gname, _, _gid, members_raw = g.split(":")
                if name in [m for m in members_raw.split(",") if m]:
                    ents.append(NormalizedEntitlement(kind="unix_group", name=gname, source="/etc/group", attributes={"gid": int(_gid)}))
            sudo_broad = False
            for path, rules in sudoers_raw.items():
                for rule in rules:
                    if rule.startswith(("Defaults", "#")):
                        continue
                    if rule.startswith("%"):
                        grp = rule.split()[0].lstrip("%")
                        is_member = any(gname == grp and name in members_raw.split(",") for gname, _, _gid, members_raw in (g.split(":") for g in group_raw))
                        if not is_member:
                            continue
                        via = f"group:{grp}"
                    elif rule.split()[0] != name:
                        continue
                    else:
                        via = "direct"
                    is_broad = "ALL=(ALL)" in rule or "NOPASSWD: ALL" in rule
                    if is_broad:
                        sudo_broad = True
                    ents.append(NormalizedEntitlement(kind="sudo_rule", name=rule.strip(), scope="ALL" if "ALL" in rule else "limited", source=path, inherited=via != "direct", via=via, attributes={"broad": is_broad, "nopasswd": "NOPASSWD" in rule}))
            last_login = None
            if lastlog_raw.get(name):
                last_login = last_login_days_ago(seed=f"{host}:{name}", min_days=1, max_days=200)
            pw_never_expires = shadow_never_expires.get(name, False)
            accounts.append(NormalizedAccount(
                account_name=name, source_type=self._source_type, principal_type=principal_type,
                auth_source=AuthSource.local, enabled_status=enabled, interactive_status=interactive,
                last_login=last_login, last_login_source="lastlog", is_shared=False,
                password_never_expires=pw_never_expires,
                evidence_summary={
                    "uid": uid_i, "gid": gid_i, "shell": shell,
                    "shadow_status": shadow_status.get(name, "??"),
                    "shadow_max_days_never_expires": pw_never_expires,
                    "sudo_broad": sudo_broad,
                },
                entitlements=ents,
            ))

        policies = []
        if target.options.get("collect_password_policy"):
            policies = CentOSCollector._collect_policy_mock(target)
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts, password_policies=policies)

    @staticmethod
    def _collect_policy_mock(target: Target) -> "list":
        """Re-use RHEL policy mock data for CentOS (identical PAM stack)."""
        from app.collectors.rhel import RHELCollector
        return RHELCollector._collect_policy_mock(target)
