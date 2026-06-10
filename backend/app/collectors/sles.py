"""SUSE Linux Enterprise Server (SLES) collector (SSH-based).

SLES uses the same account infrastructure as other Linux distributions
(getent, shadow, sudoers) but ships with a different default set of
system accounts (wwwrun, at, man, games, etc. reflecting the SUSE defaults).
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


class SLESCollector(LinuxSSHCollector):
    """Collects from SUSE Linux Enterprise Server hosts via SSH."""

    platform = Platform.sles
    _source_type = "sles_local"

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
            "bin:x:1:1:bin:/bin:/usr/sbin/nologin",
            "daemon:x:2:2:Daemon:/sbin:/usr/sbin/nologin",
            "lp:x:4:7:Printing daemon:/var/spool/lpd:/usr/sbin/nologin",
            "mail:x:8:12:Mailer daemon:/var/spool/clientmqueue:/usr/sbin/nologin",
            "wwwrun:x:30:8:WWW daemon apache:/var/lib/wwwrun:/usr/sbin/nologin",
            "at:x:25:25:Batch jobs daemon:/var/spool/atjobs:/usr/sbin/nologin",
            "nobody:x:65534:65533:nobody:/var/lib/nobody:/usr/sbin/nologin",
            "sles:x:1000:100:SLES Admin:/home/sles:/bin/bash",
            "svc_sapconn:x:1001:1001:SAP Connector:/home/svc_sapconn:/bin/bash",
            "svc_haagent:x:1002:1002:HA Agent:/home/svc_haagent:/bin/bash",
            "sap_admin:x:1003:1003:SAP Administrator:/home/sap_admin:/bin/bash",
            "mrichter:x:1004:1004:Michael Richter:/home/mrichter:/bin/bash",
        ]
        group_raw = [
            "root:x:0:root",
            "bin:x:1:daemon",
            "wheel:x:10:sles,sap_admin",
            "trusted:x:42:sles",
            "svc_sapconn:x:1001:",
            "svc_haagent:x:1002:",
            "sap_admin:x:1003:",
        ]
        shadow_status = {
            "root": "PS", "bin": "LK", "daemon": "LK", "lp": "LK",
            "mail": "LK", "wwwrun": "LK", "at": "LK", "nobody": "LK",
            "sles": "PS", "svc_sapconn": "PS", "svc_haagent": "PS",
            "sap_admin": "PS", "mrichter": "PS",
        }
        shadow_never_expires = {
            "root": False, "bin": False, "daemon": False, "lp": False,
            "mail": False, "wwwrun": False, "at": False, "nobody": False,
            "sles": False,
            "svc_sapconn": True,   # SAP connector service account — password never expires
            "svc_haagent": True,   # HA agent service account — password never expires
            "sap_admin": False,
            "mrichter": False,
        }
        sudoers_raw = {
            "/etc/sudoers": [
                "Defaults    env_reset",
                "%wheel ALL=(ALL) ALL",
            ],
            "/etc/sudoers.d/sap_admin": [
                "sap_admin ALL=(ALL) NOPASSWD: /usr/sap/*/exe/startdb, /usr/sap/*/exe/stopdb"
            ],
        }
        lastlog_raw = {
            "sles": "Fri Apr 25 06:55:00 +0000 2026 from 192.168.10.5",
            "sap_admin": "Thu Apr 24 18:22:14 +0000 2026 from 10.20.1.5",
            "svc_sapconn": "Thu Apr 24 00:05:00 +0000 2026 from 10.20.2.1",
            "mrichter": "Wed Apr 23 13:10:44 +0000 2026 from 192.168.10.15",
        }

        probes_out = [
            probe("getent_passwd", "getent passwd", passwd_raw),
            probe("getent_group", "getent group", group_raw),
            probe("shadow_status", "awk -F: '{print $1,$2}' /etc/shadow", shadow_status),
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
            policies = SLESCollector._collect_policy_mock(target)
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts, password_policies=policies)

    @staticmethod
    def _collect_policy_mock(target: Target) -> "list":
        """Re-use RHEL policy mock data for SLES (identical PAM stack)."""
        from app.collectors.rhel import RHELCollector
        return RHELCollector._collect_policy_mock(target)
