"""Password Policy Rules Engine.

Evaluates a PasswordPolicy (and related AccountPolicyExceptions) against a
built-in set of rules and returns a list of PasswordPolicyFinding objects
ready to be persisted.

Rules catalogue
---------------
PWPOL-001  Minimum password length critically short (< 8)         CRITICAL
PWPOL-002  Minimum password length below baseline (< 12)          HIGH
PWPOL-003  Password complexity disabled                            HIGH
PWPOL-004  No password history configured (count == 0)            MEDIUM
PWPOL-005  Password history too short (< 5)                       LOW
PWPOL-006  No account lockout threshold configured                 HIGH
PWPOL-007  Lockout threshold too permissive (> 10 attempts)       MEDIUM
PWPOL-008  Password max age disabled at policy level              MEDIUM
PWPOL-009  Reversible encryption enabled                          CRITICAL
PWPOL-010  No lockout configured on a domain controller           CRITICAL
PWPOL-011  PAM dictionary check disabled                          MEDIUM
PWPOL-012  SQL login with CHECK_POLICY OFF  (exception-level)     HIGH
PWPOL-013  SQL login with CHECK_EXPIRATION OFF (exception-level)  MEDIUM
PWPOL-014  MySQL validate_password component not enabled          HIGH
PWPOL-015  MongoDB local auth with no visible policy control      MEDIUM
PWPOL-016  Privileged account not under stricter FGPP             HIGH
PWPOL-017  Fine-grained policy not applied to privileged groups   HIGH
PWPOL-018  Password not required flag set (exception-level)       CRITICAL
PWPOL-019  Password never expires for privileged account          HIGH
PWPOL-020  External policy enforced — review required             INFO
PWPOL-021  Inconsistent lockout — unlock requires admin           INFO
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.models.enums import (
    Platform,
    PolicyFindingReviewState,
    PolicyFindingSeverity,
    PolicySource,
)
from app.models.password_policy import (
    AccountPolicyException,
    PasswordPolicy,
    PasswordPolicyFinding,
)

# Recommended baseline values used in comparison and finding descriptions
BASELINE_MIN_LENGTH = 12
BASELINE_HISTORY_COUNT = 5
BASELINE_MAX_AGE_DAYS = 90
BASELINE_LOCKOUT_THRESHOLD = 5
_CRITICAL_MIN_LENGTH = 8


def _finding(
    policy: PasswordPolicy,
    rule_key: str,
    severity: PolicyFindingSeverity,
    title: str,
    description: str,
    recommendation: str,
    affected_scope: str | None = None,
    evidence: dict[str, Any] | None = None,
    account_id: Any = None,
    exception_id: Any = None,
    is_exception: bool = False,
) -> PasswordPolicyFinding:
    return PasswordPolicyFinding(
        asset_id=policy.asset_id,
        account_id=account_id,
        policy_id=policy.id,
        exception_id=exception_id,
        rule_key=rule_key,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation,
        affected_scope=affected_scope or _default_scope(policy),
        evidence=evidence or {},
        is_exception_finding=is_exception,
        review_state=PolicyFindingReviewState.open,
        discovered_at=datetime.now(UTC),
    )


def _default_scope(policy: PasswordPolicy) -> str:
    if policy.policy_scope.value == "domain":
        return "All domain users"
    if policy.policy_scope.value == "host":
        return f"All local accounts on {policy.asset_id}"
    if policy.policy_scope.value in ("database", "database_login"):
        return "Database logins"
    if policy.policy_scope.value == "group":
        name = (policy.applies_to or {}).get("name", "")
        return f"Group: {name}" if name else "Targeted group"
    return "Asset-level"


# ── Core policy rules ─────────────────────────────────────────────────────────

def _check_min_length(policy: PasswordPolicy) -> list[PasswordPolicyFinding]:
    findings: list[PasswordPolicyFinding] = []
    ml = policy.min_password_length
    if ml is None:
        return findings  # not collected — cannot evaluate
    if ml < _CRITICAL_MIN_LENGTH:
        findings.append(_finding(
            policy, "PWPOL-001",
            PolicyFindingSeverity.critical,
            "Minimum password length critically short",
            f"The minimum password length is set to {ml} characters, which is far below the "
            f"recommended baseline of {BASELINE_MIN_LENGTH}. Passwords this short are highly "
            "susceptible to brute-force and dictionary attacks.",
            f"Increase the minimum password length to at least {BASELINE_MIN_LENGTH} characters. "
            "Consider 15+ for privileged accounts.",
            evidence={"min_password_length": ml, "baseline": BASELINE_MIN_LENGTH},
        ))
    elif ml < BASELINE_MIN_LENGTH:
        findings.append(_finding(
            policy, "PWPOL-002",
            PolicyFindingSeverity.high,
            "Minimum password length below recommended baseline",
            f"The minimum password length ({ml} characters) is below the recommended "
            f"baseline of {BASELINE_MIN_LENGTH}.",
            f"Increase the minimum password length to at least {BASELINE_MIN_LENGTH} characters.",
            evidence={"min_password_length": ml, "baseline": BASELINE_MIN_LENGTH},
        ))
    return findings


def _check_complexity(policy: PasswordPolicy) -> list[PasswordPolicyFinding]:
    if policy.complexity_enabled is False:
        return [_finding(
            policy, "PWPOL-003",
            PolicyFindingSeverity.high,
            "Password complexity requirements disabled",
            "Password complexity is disabled, meaning users are not required to include "
            "uppercase letters, lowercase letters, digits, or special characters. This "
            "significantly reduces the effective password entropy.",
            "Enable password complexity requirements. For Windows, enable 'Password must meet "
            "complexity requirements' in the password policy. For Linux, configure pam_pwquality "
            "with appropriate minclass or specific character-class minimums.",
            evidence={"complexity_enabled": False},
        )]
    return []


def _check_history(policy: PasswordPolicy) -> list[PasswordPolicyFinding]:
    findings: list[PasswordPolicyFinding] = []
    h = policy.password_history_count
    if h is None:
        return findings
    if h == 0:
        findings.append(_finding(
            policy, "PWPOL-004",
            PolicyFindingSeverity.medium,
            "No password history configured",
            "Password history is set to 0, meaning users can immediately reuse any previous "
            "password, negating the benefit of forced password changes.",
            f"Set password history to at least {BASELINE_HISTORY_COUNT} (recommended: 10–24) to "
            "prevent immediate password reuse.",
            evidence={"password_history_count": 0, "baseline": BASELINE_HISTORY_COUNT},
        ))
    elif h < BASELINE_HISTORY_COUNT:
        findings.append(_finding(
            policy, "PWPOL-005",
            PolicyFindingSeverity.low,
            "Password history count too low",
            f"Password history is set to {h}. Users can cycle through passwords "
            f"in fewer changes than the recommended {BASELINE_HISTORY_COUNT}.",
            f"Increase password history to at least {BASELINE_HISTORY_COUNT}.",
            evidence={"password_history_count": h, "baseline": BASELINE_HISTORY_COUNT},
        ))
    return findings


def _check_lockout(policy: PasswordPolicy) -> list[PasswordPolicyFinding]:
    findings: list[PasswordPolicyFinding] = []
    lt = policy.lockout_threshold
    if lt is None:
        return findings

    # Domain controllers without lockout are especially dangerous
    is_dc_context = (
        policy.policy_scope.value == "domain"
        and policy.policy_source in (PolicySource.domain_policy, PolicySource.fine_grained_ad)
    )
    if lt == 0:
        sev = PolicyFindingSeverity.critical if is_dc_context else PolicyFindingSeverity.high
        findings.append(_finding(
            policy, "PWPOL-010" if is_dc_context else "PWPOL-006",
            sev,
            "No account lockout threshold configured",
            "The account lockout threshold is set to 0 (disabled), meaning accounts will never "
            "be locked out after failed authentication attempts. This allows unlimited brute-force "
            "attempts against any account.",
            f"Set the lockout threshold to {BASELINE_LOCKOUT_THRESHOLD}–10 failed attempts. "
            "Configure a lockout duration or 'unlock by administrator only' for privileged accounts.",
            evidence={"lockout_threshold": 0},
        ))
    elif lt > 10:
        findings.append(_finding(
            policy, "PWPOL-007",
            PolicyFindingSeverity.medium,
            f"Account lockout threshold too permissive ({lt} attempts)",
            f"The lockout threshold is {lt} attempts, which is above the recommended maximum "
            "of 10. A high threshold allows many brute-force attempts before lockout.",
            f"Reduce the lockout threshold to {BASELINE_LOCKOUT_THRESHOLD}–10 attempts.",
            evidence={"lockout_threshold": lt, "baseline": BASELINE_LOCKOUT_THRESHOLD},
        ))
    return findings


def _check_max_age(policy: PasswordPolicy) -> list[PasswordPolicyFinding]:
    findings: list[PasswordPolicyFinding] = []
    ma = policy.max_password_age_days
    if ma is None:
        return findings
    if ma == 0:
        findings.append(_finding(
            policy, "PWPOL-008",
            PolicyFindingSeverity.medium,
            "Password expiration disabled at policy level",
            "The maximum password age is set to 0 (never expires). Without password rotation, "
            "compromised credentials can be used indefinitely.",
            f"Set a maximum password age of {BASELINE_MAX_AGE_DAYS} days for standard accounts. "
            "For privileged accounts, consider 60–90 days or enforce MFA instead.",
            evidence={"max_password_age_days": 0},
        ))
    return findings


def _check_reversible_encryption(policy: PasswordPolicy) -> list[PasswordPolicyFinding]:
    if policy.reversible_encryption_enabled is True:
        return [_finding(
            policy, "PWPOL-009",
            PolicyFindingSeverity.critical,
            "Reversible encryption for passwords is enabled",
            "Store passwords using reversible encryption is enabled, which is functionally "
            "equivalent to storing passwords in plaintext. This severely violates the principle "
            "of password confidentiality.",
            "Disable reversible encryption immediately. It is only required for legacy CHAP "
            "authentication, which should be replaced with modern authentication protocols.",
            evidence={"reversible_encryption_enabled": True},
        )]
    return []


def _check_pam_dictionary(policy: PasswordPolicy) -> list[PasswordPolicyFinding]:
    if (
        policy.platform in (Platform.rhel, Platform.centos, Platform.ubuntu,
                             Platform.sles, Platform.aix, Platform.solaris, Platform.hpux)
        and policy.policy_source == PolicySource.pam_module
        and policy.dictionary_check_enabled is False
    ):
        return [_finding(
            policy, "PWPOL-011",
            PolicyFindingSeverity.medium,
            "PAM dictionary check (pam_pwquality/cracklib) disabled",
            "The PAM dictionary check is disabled, meaning users can set passwords that appear "
            "in common password dictionaries or are based on the username.",
            "Enable the 'dictcheck' option in pam_pwquality.conf, or enable cracklib checking "
            "in the PAM configuration.",
            evidence={"dictionary_check_enabled": False,
                      "policy_source": policy.policy_source.value},
        )]
    return []


def _check_mysql_validate_password(policy: PasswordPolicy) -> list[PasswordPolicyFinding]:
    """MySQL: check if validate_password component is absent."""
    if (
        policy.platform == Platform.mysql
        and policy.policy_source == PolicySource.database_native
    ):
        ev = policy.evidence_summary or {}
        component_enabled = ev.get("validate_password_component", {})
        if isinstance(component_enabled, dict):
            val = component_enabled.get("value")
        else:
            val = component_enabled
        if val is False or val == "NOT_INSTALLED":
            return [_finding(
                policy, "PWPOL-014",
                PolicyFindingSeverity.high,
                "MySQL validate_password component is not installed/enabled",
                "The MySQL validate_password component is not enabled. Without it, there are no "
                "enforced password strength requirements — any password length or complexity is "
                "accepted at the database level.",
                "Install and enable the validate_password component: "
                "INSTALL COMPONENT 'file://component_validate_password'; "
                "Then configure validate_password.policy=STRONG and set minimum length.",
                evidence={"validate_password_component": val},
            )]
    return []


def _check_mongodb_external(policy: PasswordPolicy) -> list[PasswordPolicyFinding]:
    """MongoDB: surface external-auth finding when policy visibility is limited."""
    if (
        policy.platform == Platform.mongodb
        and policy.external_policy_enforced is True
        and policy.requires_external_review is True
    ):
        return [_finding(
            policy, "PWPOL-015",
            PolicyFindingSeverity.medium,
            "MongoDB: password policy enforced externally — review required",
            "This MongoDB instance uses external authentication (LDAP, Kerberos, or x.509). "
            "Password policy settings are not visible locally and are governed by the external "
            "identity provider. The effective policy cannot be verified from this host.",
            "Review the password policy in the external identity provider (LDAP/AD/IdP) to "
            "confirm it meets your security baseline. Document the policy source in your CMDB.",
            evidence={
                "external_policy_enforced": True,
                "auth_mechanism": (policy.evidence_summary or {}).get("auth_mechanism", {})
                    .get("value", "external"),
            },
        )]
    return []


# ── Exception-level rules ─────────────────────────────────────────────────────

def evaluate_exceptions(
    policy: PasswordPolicy,
    exceptions: list[AccountPolicyException],
) -> list[PasswordPolicyFinding]:
    """Generate findings for per-account exceptions on this policy."""
    findings: list[PasswordPolicyFinding] = []
    for exc in exceptions:
        f = _evaluate_single_exception(policy, exc)
        if f:
            findings.append(f)
    return findings


def _evaluate_single_exception(
    policy: PasswordPolicy,
    exc: AccountPolicyException,
) -> PasswordPolicyFinding | None:
    etype = exc.exception_type
    ev = exc.evidence or {}

    if etype == "password_not_required":
        return PasswordPolicyFinding(
            asset_id=policy.asset_id,
            account_id=exc.account_id,
            policy_id=policy.id,
            exception_id=exc.id,
            rule_key="PWPOL-018",
            severity=PolicyFindingSeverity.critical,
            title="Account has 'password not required' flag set",
            description=(
                f"The account is flagged as not requiring a password. "
                "This allows authentication without any credential, creating an "
                "unauthenticated access vector."
            ),
            recommendation=(
                "Remove the PASSWD_NOTREQD flag immediately. Assign a strong password "
                "or disable the account if it is not actively needed."
            ),
            affected_scope=f"Account: {exc.account_id}",
            evidence=ev,
            is_exception_finding=True,
            review_state=PolicyFindingReviewState.open,
            discovered_at=datetime.now(UTC),
        )

    if etype == "password_never_expires":
        # Escalate to HIGH if the account is privileged (check evidence)
        is_privileged = ev.get("is_privileged", False)
        sev = PolicyFindingSeverity.high if is_privileged else PolicyFindingSeverity.medium
        rule = "PWPOL-019" if is_privileged else "PWPOL-008"
        return PasswordPolicyFinding(
            asset_id=policy.asset_id,
            account_id=exc.account_id,
            policy_id=policy.id,
            exception_id=exc.id,
            rule_key=rule,
            severity=sev,
            title=(
                "Privileged account has password set to never expire"
                if is_privileged
                else "Account has password set to never expire"
            ),
            description=(
                "The PASSWORD_NEVER_EXPIRES flag is set on this account. Passwords that "
                "never expire remain valid indefinitely, increasing the window of exposure "
                "if the credential is compromised."
                + (" This account has elevated privileges, increasing the risk." if is_privileged else "")
            ),
            recommendation=(
                "Remove the 'password never expires' flag and enforce the domain/local "
                "max password age policy. For service accounts, use group Managed Service "
                "Accounts (gMSA) which auto-rotate passwords."
            ),
            affected_scope=f"Account: {exc.account_id}",
            evidence=ev,
            is_exception_finding=True,
            review_state=PolicyFindingReviewState.open,
            discovered_at=datetime.now(UTC),
        )

    if etype == "check_policy_off":
        return PasswordPolicyFinding(
            asset_id=policy.asset_id,
            account_id=exc.account_id,
            policy_id=policy.id,
            exception_id=exc.id,
            rule_key="PWPOL-012",
            severity=PolicyFindingSeverity.high,
            title="SQL Server login has CHECK_POLICY = OFF",
            description=(
                "This SQL Server login has CHECK_POLICY = OFF, meaning the Windows password "
                "policy (complexity, history, lockout) is NOT enforced for this login. "
                "The login can be set to any password regardless of domain/local policy."
            ),
            recommendation=(
                "Enable CHECK_POLICY and CHECK_EXPIRATION for all SQL logins: "
                "ALTER LOGIN [login_name] WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON;"
            ),
            affected_scope=f"SQL Login: {exc.account_id}",
            evidence=ev,
            is_exception_finding=True,
            review_state=PolicyFindingReviewState.open,
            discovered_at=datetime.now(UTC),
        )

    if etype == "check_expiration_off":
        return PasswordPolicyFinding(
            asset_id=policy.asset_id,
            account_id=exc.account_id,
            policy_id=policy.id,
            exception_id=exc.id,
            rule_key="PWPOL-013",
            severity=PolicyFindingSeverity.medium,
            title="SQL Server login has CHECK_EXPIRATION = OFF",
            description=(
                "This SQL Server login has CHECK_EXPIRATION = OFF. Even if CHECK_POLICY is "
                "ON, the login password will never expire. Credentials can remain unchanged "
                "indefinitely."
            ),
            recommendation=(
                "Enable CHECK_EXPIRATION: ALTER LOGIN [login_name] WITH CHECK_EXPIRATION = ON;"
            ),
            affected_scope=f"SQL Login: {exc.account_id}",
            evidence=ev,
            is_exception_finding=True,
            review_state=PolicyFindingReviewState.open,
            discovered_at=datetime.now(UTC),
        )

    if etype == "privileged_account_weak_policy":
        return PasswordPolicyFinding(
            asset_id=policy.asset_id,
            account_id=exc.account_id,
            policy_id=policy.id,
            exception_id=exc.id,
            rule_key="PWPOL-016",
            severity=PolicyFindingSeverity.high,
            title="Privileged account governed by weaker-than-expected password policy",
            description=(
                "This privileged account is governed by a weaker password policy than expected. "
                f"Effective policy: {exc.effective_policy_source or 'unknown'}. "
                f"Expected policy: {exc.expected_policy_source or 'stricter policy'}. "
                "Privileged accounts represent the highest-risk targets and should be under "
                "the strictest password controls."
            ),
            recommendation=(
                "Ensure all privileged accounts are members of a group targeted by an AD "
                "Fine-Grained Password Policy (PSO) with stronger settings than the default "
                "domain policy."
            ),
            affected_scope=f"Privileged account: {exc.account_id}",
            evidence=ev,
            is_exception_finding=True,
            review_state=PolicyFindingReviewState.open,
            discovered_at=datetime.now(UTC),
        )

    if etype == "fgpp_not_applied":
        return PasswordPolicyFinding(
            asset_id=policy.asset_id,
            account_id=exc.account_id,
            policy_id=policy.id,
            exception_id=exc.id,
            rule_key="PWPOL-017",
            severity=PolicyFindingSeverity.high,
            title="Fine-Grained Password Policy not applied to privileged group",
            description=(
                "The privileged group is not targeted by an AD Fine-Grained Password Policy "
                "(PSO). All members fall back to the Default Domain Policy, which may not be "
                "strict enough for high-privilege accounts."
            ),
            recommendation=(
                "Create a PSO with elevated requirements (min length ≥ 15, history ≥ 24, "
                "lockout threshold ≤ 5, lockout duration = 0/admin unlock) and apply it to "
                "the privileged group."
            ),
            affected_scope=f"Group / account: {exc.account_id}",
            evidence=ev,
            is_exception_finding=True,
            review_state=PolicyFindingReviewState.open,
            discovered_at=datetime.now(UTC),
        )

    if etype == "under_external_policy":
        return PasswordPolicyFinding(
            asset_id=policy.asset_id,
            account_id=exc.account_id,
            policy_id=policy.id,
            exception_id=exc.id,
            rule_key="PWPOL-020",
            severity=PolicyFindingSeverity.info,
            title="Account governed by external identity provider — policy not locally visible",
            description=(
                "This account is authenticated via an external IdP (LDAP, Kerberos, SAML, "
                "or OIDC). Password policy settings are enforced by the external system and "
                "cannot be directly inspected from this host."
            ),
            recommendation=(
                "Verify the external IdP's password policy meets your security baseline. "
                "Document the policy source and review periodically."
            ),
            affected_scope=f"Account: {exc.account_id}",
            evidence=ev,
            is_exception_finding=True,
            review_state=PolicyFindingReviewState.open,
            discovered_at=datetime.now(UTC),
        )

    return None  # unrecognised exception type — no finding generated


# ── Public entry point ────────────────────────────────────────────────────────

def evaluate_policy(
    policy: PasswordPolicy,
    exceptions: list[AccountPolicyException] | None = None,
) -> list[PasswordPolicyFinding]:
    """Run all rules against *policy* and any associated *exceptions*.

    Returns a flat list of PasswordPolicyFinding objects (not persisted yet).
    The caller is responsible for deleting stale findings and saving the new
    ones in a single transaction.
    """
    findings: list[PasswordPolicyFinding] = []

    # Policy-level rules
    findings += _check_min_length(policy)
    findings += _check_complexity(policy)
    findings += _check_history(policy)
    findings += _check_lockout(policy)
    findings += _check_max_age(policy)
    findings += _check_reversible_encryption(policy)
    findings += _check_pam_dictionary(policy)
    findings += _check_mysql_validate_password(policy)
    findings += _check_mongodb_external(policy)

    # Exception-level rules
    if exceptions:
        findings += evaluate_exceptions(policy, exceptions)

    return findings
