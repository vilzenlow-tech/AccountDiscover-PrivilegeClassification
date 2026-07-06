# Password Policy Guide

Version date: 2026-06-28

## What Password Policy Visibility Means

Password policy visibility is the amount of password and lockout policy evidence the collector can read from a host or database. Unknown fields mean not collected or not visible, not compliant.

Policy evidence is stored in:

- `password_policies`
- `account_policy_exceptions`
- `password_policy_findings`

## Configured vs Effective Policy

A configured policy is any policy source discovered on an asset, such as local policy, domain policy, PAM settings, or database-native policy.

An effective policy is the policy marked `is_effective_policy=true`, meaning it applies to most accounts or is the collector's best determination.

Some platforms can have multiple policies, such as Windows domain policy plus fine-grained password policies.

## Fields Collected

Core fields:

- Minimum password length.
- Complexity enabled.
- Password history count.
- Minimum password age.
- Maximum password age.
- Reversible encryption enabled.
- Lockout threshold.
- Lockout duration.
- Reset lockout counter after minutes.

Unix/PAM fields:

- Dictionary check enabled.
- Minimum character classes.
- Minimum uppercase/lowercase/digits/special characters.

External/federated fields:

- External policy enforced.
- Requires external review.

## Minimum Password Length

The rules engine flags:

- Critical if minimum length is below 8.
- High if below the baseline of 12.

## Password Complexity

Complexity disabled is flagged high severity.

## Password History

No password history is medium severity. A history count below baseline is low severity.

## Password Age

Maximum age of 0 means passwords never expire at policy level and is flagged medium severity. Account-level password-never-expires flags are tracked as exceptions and findings.

## Lockout Threshold and Duration

Lockout threshold of 0 means no lockout and is high severity, or critical for domain-controller/domain-style policy contexts. Thresholds above 10 are medium severity.

Lockout duration and reset counter are collected where visible and included in comparison/export data.

## Platform-Specific Limitations

Windows:

- Local policy via secedit is implemented.
- Domain policy and fine-grained policy are best effort and depend on RSAT/domain permissions.

Linux/Unix:

- PAM and login_defs visibility depends on file permissions and distro layout.
- AIX/Solaris/HP-UX policy visibility may be partial.

Databases:

- MSSQL policy flags are visible for SQL logins where metadata allows.
- MySQL validate_password settings depend on version/component state.
- MongoDB local password policy visibility is limited; external auth often requires manual IdP review.
- Oracle profiles require DBA view permissions.

## Reviewing Password Policy Findings

1. Open Password Policy.
2. Review summary counts.
3. Filter findings by severity, rule key, platform, review state, asset, account, or exception status.
4. Open related asset/account context.
5. Record review state: open, acknowledged, risk_accepted, remediated, or false_positive.
6. Rerun scan after remediation.

## Account Policy Exceptions

Exceptions represent per-account deviations such as:

- `password_never_expires`
- `password_not_required`
- `check_policy_off`
- `check_expiration_off`
- `lockout_exempt`
- `under_weaker_policy`
- `privileged_account_weak_policy`
- `under_external_policy`
- `unknown_effective_policy`
- `service_account_exception`
- `fgpp_not_applied`

## Export Password Policy Report

Implemented exports:

- `GET /api/v1/password-policy/export/csv`
- `GET /api/v1/password-policy/export/excel`

Excel export includes sheets for policies, open findings, and account exceptions. Export actions are audit logged.
