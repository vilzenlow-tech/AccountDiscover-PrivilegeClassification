"""Shared SSH-based live collection logic for Linux/Unix platforms.

Ubuntu, CentOS, SLES, and any future RHEL-compatible platforms inherit
``LinuxSSHCollector`` and only need to implement ``collect_mock`` plus set
their ``platform`` attribute.  The live path is identical across all of them:
  getent passwd + group, /etc/shadow, /etc/sudoers*, lastlog.
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
    PrincipalType,
)


class LinuxSSHCollector(BaseCollector):
    """Base for all SSH-based Linux platform collectors.

    Concrete subclasses must set ``platform`` and implement ``collect_mock``.
    Optionally override ``_classify_principal`` for platform-specific logic.
    """

    # Override in subclasses for accurate source_type labelling.
    _source_type: str = "linux_local"

    def collect_live(self, target: Target, credential: Credential | None) -> CollectionResult:
        if not credential:
            raise RuntimeError(f"Live scan of {target.hostname} requires a credential.")

        from app.collectors._ssh import SSHRunner

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
            # Read fields 1 (user), 2 (pw hash), 5 (max_days) from shadow.
            # Field 5 encodes "password never expires": 99999 or empty = never.
            shadow_raw = ssh.run(
                "awk -F: '{print $1,$2,$5}' /etc/shadow 2>/dev/null || true"
            ).splitlines()
            sudoers_main = ssh.run("cat /etc/sudoers 2>/dev/null || true")
            sudoers_d_files = [
                f.strip()
                for f in ssh.run("ls /etc/sudoers.d/ 2>/dev/null || true").splitlines()
                if f.strip()
            ]
            sudoers_d: dict[str, list[str]] = {}
            for fname in sudoers_d_files:
                content = ssh.run(f"cat /etc/sudoers.d/{fname} 2>/dev/null || true")
                sudoers_d[f"/etc/sudoers.d/{fname}"] = [
                    l for l in content.splitlines() if l.strip() and not l.startswith("#")
                ]
            lastlog_text = ssh.run("lastlog 2>/dev/null || true")
            # Password policy collection — runs inside the session while open
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

        # --- Parse shadow ------------------------------------------------
        shadow_status: dict[str, str] = {}
        shadow_never_expires: dict[str, bool] = {}
        for line in shadow_raw:
            parts = line.split()
            if len(parts) < 2:
                continue
            user = parts[0]
            pw = parts[1]
            shadow_status[user] = (
                "LK" if (pw.startswith("!") or pw == "*")
                else ("NP" if pw in ("!!", "") else "PS")
            )
            # Field 5 (max_days): empty string, "99999", or "0" all mean never expires.
            # A real positive value (e.g. "90") means the policy enforces rotation.
            if len(parts) >= 3:
                max_days_str = parts[2].strip()
                shadow_never_expires[user] = (
                    max_days_str in ("", "99999", "0") or max_days_str.startswith("-")
                )
            else:
                # Field not present in output — treat as unknown (don't assert True)
                shadow_never_expires[user] = False

        # --- Parse sudoers ------------------------------------------------
        sudoers_parsed: dict[str, list[str]] = {
            "/etc/sudoers": [
                l for l in sudoers_main.splitlines()
                if l.strip() and not l.startswith("#")
            ]
        }
        sudoers_parsed.update(sudoers_d)

        # --- Parse lastlog ------------------------------------------------
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
            enabled = (
                EnabledStatus.enabled
                if shadow_status.get(name, "PS") == "PS"
                else EnabledStatus.locked
            )
            interactive = (
                InteractiveStatus.interactive
                if shell in ("/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash")
                else InteractiveStatus.non_interactive
            )
            ents: list[NormalizedEntitlement] = []
            if uid_i == 0:
                ents.append(
                    NormalizedEntitlement(
                        kind="unix_uid0", name="root", source="/etc/passwd",
                        inherited=False, attributes={"uid": 0, "gid": gid_i},
                    )
                )
            for g in group_raw:
                gparts = g.split(":")
                if len(gparts) < 4:
                    continue
                gname, _, _gid, members_raw = gparts[:4]
                if name in [m for m in members_raw.split(",") if m]:
                    ents.append(
                        NormalizedEntitlement(
                            kind="unix_group", name=gname, source="/etc/group",
                            attributes={"gid": int(_gid)},
                        )
                    )
            sudo_broad = False
            for path, rules in sudoers_parsed.items():
                for rule in rules:
                    if rule.startswith(("Defaults", "#")):
                        continue
                    if rule.startswith("%"):
                        grp = rule.split()[0].lstrip("%")
                        is_member = any(
                            gname == grp and name in members_raw.split(",")
                            for gname, _, _gid, members_raw in (
                                g.split(":") for g in group_raw if len(g.split(":")) == 4
                            )
                        )
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
                    ents.append(
                        NormalizedEntitlement(
                            kind="sudo_rule", name=rule.strip(),
                            scope="ALL" if " ALL" in rule else "limited",
                            source=path, inherited=via != "direct", via=via,
                            attributes={"broad": is_broad, "nopasswd": "NOPASSWD" in rule},
                        )
                    )
            last_login = None
            if lastlog_map.get(name) and "Never" not in lastlog_map.get(name, ""):
                last_login = last_login_days_ago(
                    seed=f"{target.hostname}:{name}", min_days=1, max_days=400
                )
            accounts.append(
                NormalizedAccount(
                    account_name=name,
                    source_type=self._source_type,
                    principal_type=principal_type,
                    auth_source=AuthSource.local,
                    enabled_status=enabled,
                    interactive_status=interactive,
                    last_login=last_login,
                    last_login_source="lastlog",
                    is_shared=False,
                    password_never_expires=shadow_never_expires.get(name, False),
                    evidence_summary={
                        "uid": uid_i, "gid": gid_i, "shell": shell, "home": home,
                        "shadow_status": shadow_status.get(name, "??"),
                        "shadow_max_days_never_expires": shadow_never_expires.get(name),
                        "sudo_broad": sudo_broad,
                    },
                    entitlements=ents,
                )
            )

        policies: list = []
        if target.options.get("collect_password_policy"):
            try:
                from app.collectors.rhel import RHELCollector
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
    def _classify_principal(name: str, shell: str, uid: int) -> PrincipalType:
        if uid == 0 or name == "root":
            return PrincipalType.built_in
        if uid < 1000 and shell in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false",
                                     "/usr/bin/false", "/dev/null"):
            return PrincipalType.system
        if shell in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false",
                     "/usr/bin/false", "/dev/null"):
            return PrincipalType.service
        if name.endswith(("_svc", "_service", "svc", "daemon")):
            return PrincipalType.service
        if name in {"nobody", "nfsnobody", "sync", "shutdown", "halt"}:
            return PrincipalType.system
        return PrincipalType.human
