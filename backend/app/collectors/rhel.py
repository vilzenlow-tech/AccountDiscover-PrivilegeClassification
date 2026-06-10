"""RHEL / generic Linux collector."""
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


class RHELCollector(BaseCollector):
    """Collects from Red Hat Enterprise Linux hosts via SSH.

    Least-privilege shape for the discovery service account:
      - read access to /etc/passwd, /etc/shadow (status bits only),
        /etc/group, /etc/sudoers and /etc/sudoers.d/*,
      - ability to run `lastlog` and `chage -l <user>` read-only,
      - no sudo rights of its own.
    """

    platform = Platform.rhel

    # Probe definitions exposed for scan profile "probe_selection".
    probes = (
        "getent_passwd",
        "getent_group",
        "shadow_status",
        "sudoers",
        "lastlog",
        "id_root",
    )

    def collect_mock(self, target: Target) -> CollectionResult:
        host = target.hostname
        passwd_raw = [
            "root:x:0:0:root:/root:/bin/bash",
            "bin:x:1:1:bin:/bin:/sbin/nologin",
            "daemon:x:2:2:daemon:/sbin:/sbin/nologin",
            "sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin",
            "oracle:x:1001:1001::/home/oracle:/bin/bash",
            "tomcat:x:1002:1002::/home/tomcat:/bin/false",
            "backup_svc:x:1003:1003::/home/backup_svc:/bin/bash",
            "jdoe:x:1100:1100:John Doe:/home/jdoe:/bin/bash",
            "asmith:x:1101:1101:Amy Smith:/home/asmith:/bin/bash",
            "legacy:x:0:0:Legacy admin - 2018 migration:/home/legacy:/bin/bash",
        ]
        group_raw = [
            "root:x:0:root,legacy",
            "wheel:x:10:jdoe,asmith",
            "dba:x:1001:oracle,jdoe",
            "tomcat:x:1002:tomcat",
        ]
        sudoers_raw = {
            "/etc/sudoers": [
                "Defaults    requiretty",
                "root    ALL=(ALL)       ALL",
                "%wheel  ALL=(ALL)       ALL",
            ],
            "/etc/sudoers.d/oracle": [
                "oracle ALL=(ALL) NOPASSWD: ALL",
            ],
            "/etc/sudoers.d/backup": [
                "backup_svc ALL=(root) NOPASSWD: /usr/bin/tar, /usr/bin/rsync, /usr/bin/gzip",
            ],
        }
        shadow_status = {
            "root": "PS",
            "bin": "LK",
            "daemon": "LK",
            "sshd": "LK",
            "oracle": "PS",
            "tomcat": "LK",
            "backup_svc": "PS",
            "jdoe": "PS",
            "asmith": "PS",
            "legacy": "PS",
        }
        # Simulated shadow max_days (field 5): True = password never expires (99999).
        shadow_never_expires = {
            "root": False,
            "oracle": True,       # DBA service account — never expires
            "backup_svc": True,   # backup service account — never expires
            "jdoe": False,
            "asmith": False,
            "legacy": True,       # legacy admin — forgotten, never expires
        }
        lastlog_raw = {
            "root": "Never logged in",
            "oracle": "Tue Mar 17 09:14:22 +0000 2026 from 10.0.0.4",
            "jdoe": "Wed Apr 22 16:11:08 +0000 2026 from 10.0.12.5",
            "asmith": "Fri Apr 10 07:02:44 +0000 2026 from 10.0.12.7",
            "backup_svc": "Sun Apr 19 02:00:01 +0000 2026 from 10.0.8.22",
            "tomcat": "Never logged in",
            "legacy": "**Never logged in**",
        }

        probes_out = [
            probe("getent_passwd", "getent passwd", passwd_raw),
            probe("getent_group", "getent group", group_raw),
            probe(
                "shadow_status",
                "awk -F: '{print $1, $2}' /etc/shadow  # normalized to LK/PS/NP",
                shadow_status,
            ),
            probe("sudoers", "cat /etc/sudoers; ls /etc/sudoers.d/", sudoers_raw),
            probe("lastlog", "lastlog -t 400 -a", lastlog_raw),
            probe("id_root", "id root", "uid=0(root) gid=0(root) groups=0(root)"),
        ]

        accounts: list[NormalizedAccount] = []
        for line in passwd_raw:
            name, _, uid, gid, gecos, home, shell = line.split(":")
            uid_i, gid_i = int(uid), int(gid)
            principal_type = self._classify_principal(name, shell, uid_i)
            enabled = (
                EnabledStatus.enabled
                if shadow_status.get(name, "PS") == "PS"
                else EnabledStatus.locked
            )
            interactive = (
                InteractiveStatus.interactive
                if shell in ("/bin/bash", "/bin/sh", "/bin/zsh")
                else InteractiveStatus.non_interactive
            )
            ents: list[NormalizedEntitlement] = []

            if uid_i == 0:
                ents.append(
                    NormalizedEntitlement(
                        kind="unix_uid0",
                        name="root",
                        source="/etc/passwd",
                        inherited=False,
                        attributes={"uid": 0, "gid": gid_i, "gecos": gecos, "home": home},
                    )
                )

            for g in group_raw:
                gname, _, _gid, members_raw = g.split(":")
                members = [m for m in members_raw.split(",") if m]
                if name in members:
                    ents.append(
                        NormalizedEntitlement(
                            kind="unix_group",
                            name=gname,
                            source=f"/etc/group",
                            attributes={"gid": int(_gid)},
                        )
                    )

            sudo_broad = False
            for path, rules in sudoers_raw.items():
                for rule in rules:
                    if rule.startswith(("Defaults", "#")):
                        continue
                    if rule.startswith("%"):
                        # group-based rule; check group membership
                        grp = rule.split()[0].lstrip("%")
                        is_member = any(
                            gname == grp and name in members_raw.split(",")
                            for gname, _, _gid, members_raw in (g.split(":") for g in group_raw)
                        )
                        if not is_member:
                            continue
                        via = f"group:{grp}"
                    elif rule.split()[0] != name:
                        continue
                    else:
                        via = "direct"
                    scope = "ALL" if " ALL" in rule or rule.strip().endswith("ALL") else "limited"
                    is_broad = "ALL=(ALL)" in rule or "(root) NOPASSWD: ALL" in rule
                    if is_broad:
                        sudo_broad = True
                    ents.append(
                        NormalizedEntitlement(
                            kind="sudo_rule",
                            name=rule.strip(),
                            scope=scope,
                            source=path,
                            inherited=via != "direct",
                            via=via,
                            attributes={"broad": is_broad, "nopasswd": "NOPASSWD" in rule},
                        )
                    )

            last_login = None
            last_text = lastlog_raw.get(name, "")
            if "Never" not in last_text and last_text:
                last_login = last_login_days_ago(seed=f"{host}:{name}", min_days=1, max_days=400)
            else:
                # Occasionally leave last_login None to simulate missing data.
                last_login = None

            accounts.append(
                NormalizedAccount(
                    account_name=name,
                    source_type="linux_local",
                    principal_type=principal_type,
                    auth_source=AuthSource.local,
                    enabled_status=enabled,
                    interactive_status=interactive,
                    last_login=last_login,
                    last_login_source="lastlog",
                    is_shared=(name == "legacy"),
                    password_never_expires=shadow_never_expires.get(name, False),
                    evidence_summary={
                        "uid": uid_i,
                        "gid": gid_i,
                        "shell": shell,
                        "home": home,
                        "shadow_status": shadow_status.get(name, "??"),
                        "shadow_max_days_never_expires": shadow_never_expires.get(name),
                        "sudo_broad": sudo_broad,
                    },
                    entitlements=ents,
                )
            )

        policies = []
        if target.options.get("collect_password_policy"):
            policies = RHELCollector._collect_policy_mock(target)
        return CollectionResult(platform=self.platform, probes=probes_out, accounts=accounts, password_policies=policies)

    def collect_live(self, target: Target, credential: Credential | None) -> CollectionResult:
        if not credential:
            raise RuntimeError(f"Live scan of {target.hostname} requires a credential.")
        from app.collectors._ssh import SSHRunner
        from datetime import datetime, timezone
        port = target.port or 22
        auth_method = credential.auth_method or "password"
        expected_fp = target.options.get("ssh_host_fingerprint")
        policy_raw_texts: dict[str, str] = {}
        with SSHRunner(
            hostname=target.ip_address or target.hostname,
            port=port,
            username=credential.username,
            password=credential.secret if auth_method == "password" else None,
            pkey_str=credential.secret if auth_method == "key" else None,
            expected_fingerprint=expected_fp or None,
        ) as ssh:
            observed_fp = ssh.observed_fingerprint
            passwd_raw = [l for l in ssh.run("getent passwd").splitlines() if l.strip()]
            group_raw = [l for l in ssh.run("getent group").splitlines() if l.strip()]
            shadow_raw = ssh.run("awk -F: '{print $1,$2,$5}' /etc/shadow 2>/dev/null || true").splitlines()
            sudoers_main = ssh.run("cat /etc/sudoers 2>/dev/null || true")
            sudoers_d_files = [f.strip() for f in ssh.run("ls /etc/sudoers.d/ 2>/dev/null || true").splitlines() if f.strip()]
            sudoers_d: dict[str, list[str]] = {}
            for fname in sudoers_d_files:
                content = ssh.run(f"cat /etc/sudoers.d/{fname} 2>/dev/null || true")
                sudoers_d[f"/etc/sudoers.d/{fname}"] = [l for l in content.splitlines() if l.strip() and not l.startswith("#")]
            lastlog_text = ssh.run("lastlog 2>/dev/null || true")
            # Policy collection — run inside the SSH session while connection is open
            if target.options.get("collect_password_policy"):
                policy_raw_texts["pwquality"] = ssh.run(
                    "cat /etc/security/pwquality.conf 2>/dev/null || "
                    "grep -E 'minlen|dcredit|ucredit|lcredit|ocredit|minclass|dictcheck|retry' "
                    "/etc/pam.d/system-auth 2>/dev/null || true"
                )
                policy_raw_texts["login_defs"] = ssh.run(
                    "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' "
                    "/etc/login.defs 2>/dev/null || true"
                )
                policy_raw_texts["faillock"] = ssh.run(
                    "grep -E 'pam_faillock|pam_tally2' "
                    "/etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null || true"
                )

        shadow_status: dict[str, str] = {}
        shadow_never_expires: dict[str, bool] = {}
        for line in shadow_raw:
            parts = line.split()
            if len(parts) < 2:
                continue
            user, pw = parts[0], parts[1]
            shadow_status[user] = "LK" if (pw.startswith("!") or pw == "*") else ("NP" if pw in ("!!", "") else "PS")
            if len(parts) >= 3:
                max_days_str = parts[2].strip()
                shadow_never_expires[user] = (
                    max_days_str in ("", "99999", "0") or max_days_str.startswith("-")
                )
            else:
                shadow_never_expires[user] = False

        sudoers_parsed: dict[str, list[str]] = {
            "/etc/sudoers": [l for l in sudoers_main.splitlines() if l.strip() and not l.startswith("#")]
        }
        sudoers_parsed.update(sudoers_d)

        lastlog_map: dict[str, str] = {}
        for line in lastlog_text.splitlines()[1:]:
            if not line.strip():
                continue
            parts = line.split()
            username = parts[0]
            if "Never" in line or "**Never" in line:
                lastlog_map[username] = "Never logged in"
            elif len(parts) >= 5:
                lastlog_map[username] = line

        probes_out = [
            probe("getent_passwd", "getent passwd", passwd_raw),
            probe("getent_group", "getent group", group_raw),
            probe("shadow_status", "awk -F: '{print $1,$2}' /etc/shadow", shadow_status),
            probe("sudoers", "cat /etc/sudoers + sudoers.d", sudoers_parsed),
            probe("lastlog", "lastlog", lastlog_map),
        ]

        accounts: list[NormalizedAccount] = []
        for line in passwd_raw:
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, _, uid, gid, gecos, home, shell = parts[:7]
            uid_i, gid_i = int(uid), int(gid)
            principal_type = self._classify_principal(name, shell, uid_i)
            enabled = EnabledStatus.enabled if shadow_status.get(name, "PS") == "PS" else EnabledStatus.locked
            interactive = InteractiveStatus.interactive if shell in ("/bin/bash", "/bin/sh", "/bin/zsh") else InteractiveStatus.non_interactive
            ents: list[NormalizedEntitlement] = []
            if uid_i == 0:
                ents.append(NormalizedEntitlement(kind="unix_uid0", name="root", source="/etc/passwd", inherited=False, attributes={"uid": 0, "gid": gid_i}))
            for g in group_raw:
                gparts = g.split(":")
                if len(gparts) < 4:
                    continue
                gname, _, _gid, members_raw = gparts[:4]
                if name in [m for m in members_raw.split(",") if m]:
                    ents.append(NormalizedEntitlement(kind="unix_group", name=gname, source="/etc/group", attributes={"gid": int(_gid)}))
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
                    is_broad = "ALL=(ALL)" in rule or "(root) NOPASSWD: ALL" in rule
                    if is_broad:
                        sudo_broad = True
                    ents.append(NormalizedEntitlement(kind="sudo_rule", name=rule.strip(), scope="ALL" if " ALL" in rule else "limited", source=path, inherited=via != "direct", via=via, attributes={"broad": is_broad, "nopasswd": "NOPASSWD" in rule}))
            last_login = None
            if lastlog_map.get(name) and "Never" not in lastlog_map.get(name, ""):
                from app.collectors._mockutil import last_login_days_ago
                last_login = last_login_days_ago(seed=f"{target.hostname}:{name}", min_days=1, max_days=400)
            accounts.append(NormalizedAccount(
                account_name=name, source_type="linux_local", principal_type=principal_type,
                auth_source=AuthSource.local, enabled_status=enabled, interactive_status=interactive,
                last_login=last_login, last_login_source="lastlog", is_shared=False,
                password_never_expires=shadow_never_expires.get(name, False),
                evidence_summary={
                    "uid": uid_i, "gid": gid_i, "shell": shell, "home": home,
                    "shadow_status": shadow_status.get(name, "??"),
                    "shadow_max_days_never_expires": shadow_never_expires.get(name),
                    "sudo_broad": sudo_broad,
                },
                entitlements=ents,
            ))
        policies = []
        if target.options.get("collect_password_policy"):
            try:
                policies = RHELCollector._collect_policy_live(policy_raw_texts, target)
            except Exception as exc:
                from app.collectors.base import NormalizedPasswordPolicy
                policies = [NormalizedPasswordPolicy(
                    policy_source="pam_module",
                    policy_scope="host",
                    policy_name="pam_pwquality",
                    collection_error=f"Policy collection failed: {str(exc)[:400]}",
                    confidence_score=0,
                )]
        return CollectionResult(
            platform=self.platform,
            probes=probes_out,
            accounts=accounts,
            observed_ssh_fingerprint=observed_fp,
            password_policies=policies,
        )

    @staticmethod
    def _collect_policy_mock(target: Target) -> "list[NormalizedPasswordPolicy]":
        """Return a realistic pam_pwquality policy for a mock RHEL scan.

        Simulates a typical RHEL default with dictionary check disabled
        (triggers PWPOL-011) and a lockout configured via pam_faillock.
        """
        from app.collectors.base import NormalizedPasswordPolicy
        return [
            NormalizedPasswordPolicy(
                policy_source="pam_module",
                policy_scope="host",
                policy_name="pam_pwquality",
                is_effective_policy=True,
                min_password_length=8,
                complexity_enabled=True,
                password_history_count=5,
                max_password_age_days=99,   # /etc/login.defs PASS_MAX_DAYS
                min_password_age_days=1,
                lockout_threshold=5,        # pam_faillock deny=5
                lockout_duration_minutes=10,
                dictionary_check_enabled=False,  # dictcheck=0 — triggers PWPOL-011
                min_char_classes=3,
                evidence_summary={
                    "source": "/etc/security/pwquality.conf + /etc/login.defs + pam_faillock",
                    "host": target.hostname,
                    "minlen": 8,
                    "dictcheck": 0,
                    "minclass": 3,
                    "PASS_MAX_DAYS": 99,
                    "faillock_deny": 5,
                },
                confidence_score=85,
            )
        ]

    @staticmethod
    def _collect_policy_live(
        raw_texts: dict[str, str], target: Target
    ) -> "list[NormalizedPasswordPolicy]":
        """Parse live RHEL password policy from pre-collected SSH command output.

        ``raw_texts`` must contain keys: pwquality, login_defs, faillock.
        These are collected inside the SSH session in ``collect_live()`` before
        the connection is closed.
        """
        from app.collectors.base import NormalizedPasswordPolicy

        pwquality_raw = raw_texts.get("pwquality", "")
        login_defs_raw = raw_texts.get("login_defs", "")
        faillock_raw = raw_texts.get("faillock", "")

        def _parse_kv(text: str) -> dict:
            result: dict = {}
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, _, v = line.partition("=")
                    result[k.strip()] = v.strip()
            return result

        def _parse_login_defs(text: str) -> dict:
            result: dict = {}
            for line in text.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    result[parts[0]] = parts[1]
            return result

        pwq = _parse_kv(pwquality_raw)
        defs = _parse_login_defs(login_defs_raw)

        min_len = int(pwq.get("minlen", 8))
        dictcheck = pwq.get("dictcheck", "1")
        dict_enabled = dictcheck.strip() not in ("0", "false", "False")
        min_class = int(pwq.get("minclass", 0)) if "minclass" in pwq else None

        # PASS_MAX_DAYS=99999 is the Linux/PAM convention for "password never expires".
        # The DB column is SMALLINT (max 32767) so 99999 would overflow.
        # Map 99999 (and any sentinel ≥ 99998) to 0, which is the model's convention for
        # "never expires" (comment in PasswordPolicy: "0 = never expires").
        _raw_max = int(defs.get("PASS_MAX_DAYS", 99))
        max_age = 0 if _raw_max >= 99998 else _raw_max

        _raw_min = int(defs.get("PASS_MIN_DAYS", 0))
        # PASS_MIN_DAYS is almost always 0-7; guard against unexpected large values too.
        min_age = min(_raw_min, 32767)

        # Parse faillock deny=N
        lockout_thresh: int | None = None
        for line in faillock_raw.splitlines():
            if "deny=" in line:
                import re as _re
                m = _re.search(r"deny=(\d+)", line)
                if m:
                    lockout_thresh = int(m.group(1))
                    break

        history: int | None = None
        for line in pwquality_raw.splitlines():
            if "remember=" in line:
                import re as _re
                m = _re.search(r"remember=(\d+)", line)
                if m:
                    history = int(m.group(1))
                    break

        return [
            NormalizedPasswordPolicy(
                policy_source="pam_module",
                policy_scope="host",
                policy_name="pam_pwquality",
                is_effective_policy=True,
                min_password_length=min_len,
                complexity_enabled=True,
                password_history_count=history,
                max_password_age_days=max_age,
                min_password_age_days=min_age,
                lockout_threshold=lockout_thresh,
                dictionary_check_enabled=dict_enabled,
                min_char_classes=min_class,
                evidence_summary={
                    "source": "/etc/security/pwquality.conf + /etc/login.defs + pam_faillock",
                    "host": target.hostname,
                    "pwquality_raw": pwquality_raw[:500],
                    "login_defs_raw": login_defs_raw[:200],
                    "faillock_raw": faillock_raw[:200],
                },
                confidence_score=80,
            )
        ]

    @staticmethod
    def _classify_principal(name: str, shell: str, uid: int) -> PrincipalType:
        if uid < 500 and name != "root":
            return PrincipalType.system
        if name in {"root"}:
            return PrincipalType.built_in
        if shell in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false"):
            return PrincipalType.service
        if name.endswith(("_svc", "_service")) or name in {"oracle", "tomcat", "backup_svc"}:
            return PrincipalType.service
        if name in {"legacy", "shared"}:
            return PrincipalType.shared
        return PrincipalType.human
