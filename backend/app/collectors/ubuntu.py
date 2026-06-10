"""Ubuntu Server collector (SSH-based)."""
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


class UbuntuCollector(LinuxSSHCollector):
    """Collects from Ubuntu Server hosts via SSH.

    Ubuntu-specific notes:
    - Default admin user is typically the provisioned user with sudo access via /etc/sudoers.d/
    - System accounts start at UID 1000+ for human users (different from RHEL's 500+)
    - Uses 'shadow' group for /etc/shadow read access
    - adduser creates accounts with /bin/bash shell
    """

    platform = Platform.ubuntu
    _source_type = "ubuntu_local"

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
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
            "messagebus:x:103:106::/nonexistent:/usr/sbin/nologin",
            "syslog:x:104:110::/home/syslog:/usr/sbin/nologin",
            "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin",
            "ubuntu:x:1000:1000:Ubuntu,,,:/home/ubuntu:/bin/bash",
            "svc_deploy:x:1001:1001:Deploy Service,,,:/home/svc_deploy:/bin/bash",
            "svc_monitor:x:1002:1002:Monitoring Service,,,:/home/svc_monitor:/bin/bash",
            "dbadmin:x:1003:1003:DB Admin,,,:/home/dbadmin:/bin/bash",
            "jsmith:x:1004:1004:John Smith,,,:/home/jsmith:/bin/bash",
        ]
        group_raw = [
            "root:x:0:",
            "sudo:x:27:ubuntu,dbadmin",
            "adm:x:4:syslog,ubuntu",
            "svc_deploy:x:1001:",
            "svc_monitor:x:1002:",
            "dbadmin:x:1003:",
        ]
        shadow_status = {
            "root": "LK",  # root login typically locked on Ubuntu
            "daemon": "LK", "bin": "LK", "sys": "LK",
            "messagebus": "LK", "syslog": "LK", "systemd-network": "LK",
            "ubuntu": "PS", "svc_deploy": "PS", "svc_monitor": "PS",
            "dbadmin": "PS", "jsmith": "PS",
        }
        shadow_never_expires = {
            "root": False, "daemon": False, "bin": False, "sys": False,
            "messagebus": False, "syslog": False, "systemd-network": False,
            "ubuntu": False,
            "svc_deploy": True,    # deploy service account — password never expires
            "svc_monitor": True,   # monitor service account — password never expires
            "dbadmin": False,
            "jsmith": False,
        }
        sudoers_raw = {
            "/etc/sudoers": [
                "Defaults    env_reset",
                "Defaults    mail_badpass",
                "%sudo   ALL=(ALL:ALL) ALL",
            ],
            "/etc/sudoers.d/ubuntu": ["ubuntu ALL=(ALL) NOPASSWD: ALL"],
            "/etc/sudoers.d/dbadmin": ["dbadmin ALL=(ALL) /usr/bin/mysql, /usr/bin/pg_dump"],
        }
        lastlog_raw = {
            "ubuntu": "Thu Apr 24 09:15:00 +0000 2026 from 192.168.1.10",
            "svc_deploy": "Thu Apr 24 02:00:01 +0000 2026 from 10.0.2.15",
            "dbadmin": "Wed Apr 23 14:30:10 +0000 2026 from 10.0.1.5",
            "jsmith": "Mon Apr 21 08:45:22 +0000 2026 from 10.0.1.12",
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
            interactive = InteractiveStatus.interactive if shell in ("/bin/bash", "/bin/sh", "/usr/bin/bash") else InteractiveStatus.non_interactive
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
                    is_broad = "ALL=(ALL" in rule or "NOPASSWD: ALL" in rule
                    if is_broad:
                        sudo_broad = True
                    ents.append(NormalizedEntitlement(kind="sudo_rule", name=rule.strip(), scope="ALL" if "ALL" in rule else "limited", source=path, inherited=via != "direct", via=via, attributes={"broad": is_broad, "nopasswd": "NOPASSWD" in rule}))
            last_login = None
            last_text = lastlog_raw.get(name, "")
            if last_text:
                last_login = last_login_days_ago(seed=f"{host}:{name}", min_days=1, max_days=180)
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
            policies = UbuntuCollector._collect_policy_mock(target)
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts, password_policies=policies)

    @staticmethod
    def _collect_policy_mock(target: Target) -> "list":
        """Re-use RHEL policy mock data for Ubuntu (identical PAM stack)."""
        from app.collectors.rhel import RHELCollector
        return RHELCollector._collect_policy_mock(target)

    @staticmethod
    def _classify_principal(name: str, shell: str, uid: int) -> PrincipalType:
        if uid == 0 or name == "root":
            return PrincipalType.built_in
        if uid < 1000:
            return PrincipalType.system
        if shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/dev/null"):
            return PrincipalType.service
        if name.startswith("svc_") or name.endswith("_svc"):
            return PrincipalType.service
        return PrincipalType.human
