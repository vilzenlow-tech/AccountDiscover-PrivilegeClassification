"""HP-UX collector (SSH-based).

HP-UX uses different commands from Linux:
- No `getent` — reads /etc/passwd and /etc/group directly
- `logins` command for extended user info (replaces lastlog)
- HP-UX trusted mode stores password policy in /tcb/files/auth/<initial>/<user>
- Privilege groups via `/etc/logingroup` or Restricted SAM
- RBAC available in HP-UX 11.31+: `privrun`, `/etc/rbac/`

Least-privilege discovery account needs:
  - read access to /etc/passwd, /etc/group, /etc/shadow (standard mode)
    or read access to /tcb/files/auth (trusted mode) — typically requires root
  - ability to run `logins -ax` read-only
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


class HPUXCollector(BaseCollector):
    """Collects from HP-UX hosts via SSH."""

    platform = Platform.hpux
    _source_type = "hpux_local"

    probes = ("passwd", "group", "logins", "sudoers", "privrun")

    def collect_mock(self, target: Target) -> CollectionResult:
        host = target.hostname
        passwd_raw = [
            "root:*:0:3:Super-User:/:/usr/bin/sh",
            "daemon:*:1:5::/:usr/bin/sh",
            "bin:*:2:2::/usr/bin:/usr/bin/false",
            "sys:*:3:3:System:/usr/src:/usr/bin/false",
            "adm:*:4:4::/var/adm:/usr/bin/false",
            "lp:*:9:7::/var/spool/lp:/usr/bin/false",
            "hpdb:*:27:27:ALLBASE/HP OpenODB:/usr/db:/usr/bin/sh",
            "oracle:x:100:101:Oracle RDBMS:/home/oracle:/usr/bin/sh",
            "svc_monitor:x:200:200:HP SIM Monitoring:/home/svc_monitor:/usr/bin/sh",
            "hpadmin:x:300:300:HP Systems Admin:/home/hpadmin:/usr/bin/sh",
            "ktan:x:400:400:Kenny Tan:/home/ktan:/usr/bin/sh",
            "shared_ops:x:500:500:Shared Ops Account:/home/shared_ops:/usr/bin/sh",
        ]
        group_raw = [
            "root::0:root",
            "other::1:",
            "bin::2:root,bin,daemon",
            "sys::3:root,bin,sys,adm",
            "adm::4:root,adm,daemon",
            "lp::7:root,lp",
            "hpdb::27:hpdb",
            "dba::101:oracle",
            "sysadmin::200:hpadmin",
        ]
        logins_info = {
            "root": {"uid": 0, "locked": False, "last": "Never logged in"},
            "oracle": {"uid": 100, "locked": False, "last": "Thu Apr 24 10:00:00 2026"},
            "svc_monitor": {"uid": 200, "locked": False, "last": "Thu Apr 24 00:01:00 2026"},
            "hpadmin": {"uid": 300, "locked": False, "last": "Wed Apr 23 16:30:00 2026"},
            "ktan": {"uid": 400, "locked": False, "last": "Mon Apr 21 09:15:00 2026"},
            "shared_ops": {"uid": 500, "locked": False, "last": "Sat Apr 19 22:00:00 2026"},
        }
        sudoers_raw = {
            "/etc/sudoers": [
                "%sysadmin  ALL=(ALL)  ALL",
            ],
            "/etc/sudoers.d/oracle": ["oracle ALL=(ALL) NOPASSWD: /oracle/product/*/bin/dbstart, /oracle/product/*/bin/dbshut"],
        }

        probes_out = [
            probe("passwd", "cat /etc/passwd", passwd_raw),
            probe("group", "cat /etc/group", group_raw),
            probe("logins", "logins -ax", logins_info),
            probe("sudoers", "cat /etc/sudoers + sudoers.d", sudoers_raw),
        ]

        accounts: list[NormalizedAccount] = []
        for line in passwd_raw:
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, pw, uid, gid, gecos, home, shell = parts[:7]
            uid_i, gid_i = int(uid), int(gid)
            principal_type = self._classify_principal(name, shell, uid_i)
            info = logins_info.get(name, {})
            locked = info.get("locked", pw == "*")
            enabled = EnabledStatus.locked if locked else EnabledStatus.enabled
            interactive = InteractiveStatus.interactive if shell in ("/usr/bin/sh", "/bin/sh", "/usr/bin/ksh", "/bin/ksh") else InteractiveStatus.non_interactive
            ents: list[NormalizedEntitlement] = []
            if uid_i == 0:
                ents.append(NormalizedEntitlement(kind="unix_uid0", name="root", source="/etc/passwd", inherited=False, attributes={"uid": 0}))
            for g in group_raw:
                gparts = g.split(":")
                if len(gparts) < 4:
                    continue
                gname, _, _gid, members_raw = gparts[:4]
                if name in [m for m in members_raw.split(",") if m]:
                    ents.append(NormalizedEntitlement(kind="unix_group", name=gname, source="/etc/group", attributes={"gid": int(_gid)}))
            sudo_broad = False
            for path, rules in sudoers_raw.items():
                for rule in rules:
                    if rule.startswith(("Defaults", "#")):
                        continue
                    if rule.startswith("%"):
                        grp = rule.split()[0].lstrip("%")
                        is_member = any(gname == grp and name in members_raw.split(",") for gname, _, _gid, members_raw in (g.split(":") for g in group_raw if len(g.split(":")) == 4))
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
            last_text = logins_info.get(name, {}).get("last", "")
            last_login = None
            if last_text and "Never" not in last_text:
                last_login = last_login_days_ago(seed=f"{host}:{name}", min_days=1, max_days=300)
            accounts.append(NormalizedAccount(
                account_name=name, source_type=self._source_type, principal_type=principal_type,
                auth_source=AuthSource.local, enabled_status=enabled, interactive_status=interactive,
                last_login=last_login, last_login_source="logins", is_shared=(name == "shared_ops"),
                password_never_expires=False,
                evidence_summary={"uid": uid_i, "gid": gid_i, "shell": shell, "locked": locked, "sudo_broad": sudo_broad},
                entitlements=ents,
            ))

        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts)

    def collect_live(self, target: Target, credential: Credential | None) -> CollectionResult:
        if not credential:
            raise RuntimeError(f"Live scan of {target.hostname} requires a credential.")

        from app.collectors._ssh import SSHRunner

        port = target.port or 22
        auth_method = credential.auth_method or "password"
        expected_fp = target.options.get("ssh_host_fingerprint")

        with SSHRunner(
            hostname=target.ip_address or target.hostname,
            port=port,
            username=credential.username,
            password=credential.secret if auth_method == "password" else None,
            pkey_str=credential.secret if auth_method == "key" else None,
            expected_fingerprint=expected_fp or None,
        ) as ssh:
            observed_fp = ssh.observed_fingerprint
            # HP-UX does not have `getent`; read /etc/passwd and /etc/group directly.
            passwd_raw = [l for l in ssh.run("cat /etc/passwd 2>/dev/null || true").splitlines() if l.strip() and not l.startswith("#")]
            group_raw = [l for l in ssh.run("cat /etc/group 2>/dev/null || true").splitlines() if l.strip() and not l.startswith("#")]
            # logins -ax gives UID, lock status, last login all in one shot
            logins_text = ssh.run("logins -ax 2>/dev/null || true")
            sudoers_main = ssh.run("cat /etc/sudoers 2>/dev/null || true")
            sudoers_d_files = [f.strip() for f in ssh.run("ls /etc/sudoers.d/ 2>/dev/null || true").splitlines() if f.strip()]
            sudoers_d: dict[str, list[str]] = {}
            for fname in sudoers_d_files:
                content = ssh.run(f"cat /etc/sudoers.d/{fname} 2>/dev/null || true")
                sudoers_d[f"/etc/sudoers.d/{fname}"] = [l for l in content.splitlines() if l.strip() and not l.startswith("#")]

        # Parse logins -ax output (tab-separated: user uid gid locked last_login ...)
        logins_map: dict[str, dict] = {}
        for line in logins_text.splitlines():
            parts = line.split(":")
            if not parts:
                continue
            name = parts[0].strip()
            locked = len(parts) > 2 and parts[2].strip() in ("LK", "PS") and parts[2].strip() == "LK"
            logins_map[name] = {"locked": locked}

        sudoers_parsed = {"/etc/sudoers": [l for l in sudoers_main.splitlines() if l.strip() and not l.startswith("#")]}
        sudoers_parsed.update(sudoers_d)

        probes_out = [
            probe("passwd", "cat /etc/passwd", passwd_raw),
            probe("group", "cat /etc/group", group_raw),
            probe("logins", "logins -ax", logins_map),
            probe("sudoers", "cat /etc/sudoers + sudoers.d", sudoers_parsed),
        ]

        accounts: list[NormalizedAccount] = []
        for line in passwd_raw:
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, pw, uid, gid, gecos, home, shell = parts[:7]
            try:
                uid_i, gid_i = int(uid), int(gid)
            except ValueError:
                continue
            principal_type = self._classify_principal(name, shell, uid_i)
            locked = logins_map.get(name, {}).get("locked", pw in ("*", "!"))
            enabled = EnabledStatus.locked if locked else EnabledStatus.enabled
            interactive = InteractiveStatus.interactive if shell not in ("/usr/bin/false", "/bin/false", "") else InteractiveStatus.non_interactive
            ents: list[NormalizedEntitlement] = []
            if uid_i == 0:
                ents.append(NormalizedEntitlement(kind="unix_uid0", name="root", source="/etc/passwd", inherited=False, attributes={"uid": 0}))
            for g in group_raw:
                gparts = g.split(":")
                if len(gparts) < 4:
                    continue
                gname, _, _gid, members_raw = gparts[:4]
                if name in [m for m in members_raw.split(",") if m]:
                    try:
                        ents.append(NormalizedEntitlement(kind="unix_group", name=gname, source="/etc/group", attributes={"gid": int(_gid)}))
                    except ValueError:
                        pass
            sudo_broad = False
            for path, rules in sudoers_parsed.items():
                for rule in rules:
                    if rule.startswith(("Defaults", "#")):
                        continue
                    if rule.startswith("%"):
                        grp = rule.split()[0].lstrip("%")
                        is_member = any(gname == grp and name in members_raw.split(",") for gname, _, _gid, members_raw in (g.split(":") for g in group_raw if len(g.split(":")) == 4))
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
            accounts.append(NormalizedAccount(
                account_name=name, source_type=self._source_type, principal_type=principal_type,
                auth_source=AuthSource.local, enabled_status=enabled, interactive_status=interactive,
                last_login=None, last_login_source="logins", is_shared=False,
                password_never_expires=False,
                evidence_summary={"uid": uid_i, "gid": gid_i, "shell": shell, "locked": locked, "sudo_broad": sudo_broad},
                entitlements=ents,
            ))

        return CollectionResult(
            platform=self.platform, probes=probes_out, accounts=accounts,
            observed_ssh_fingerprint=observed_fp,
        )

    @staticmethod
    def _classify_principal(name: str, shell: str, uid: int) -> PrincipalType:
        if uid == 0 or name == "root":
            return PrincipalType.built_in
        if uid < 100:
            return PrincipalType.system
        if shell in ("/usr/bin/false", "/bin/false", ""):
            return PrincipalType.service
        if name in {"hpdb"} or name.startswith("svc_"):
            return PrincipalType.service
        if name == "shared_ops" or "shared" in name:
            return PrincipalType.shared
        return PrincipalType.human
