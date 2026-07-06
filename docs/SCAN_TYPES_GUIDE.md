# Scan Types Guide

Version date: 2026-06-28

## Important Implementation Note

The API stores `scan_type` on the discovery job and uses it for credential validation and password-policy collection decisions. Current backend target execution still runs the selected platform collector; the scan type does not yet narrow individual probes as much as the labels imply. Treat scan type as an intent and validation/profile selector, not a fully separate collector pipeline.

## Basic Discovery Scan Without Credential

Purpose: lightweight discovery where no credential is supplied.

When to use:

- Development/mock mode.
- Connectivity-style checks where unauthenticated discovery is acceptable.
- Low-impact inventory experiments.

Required input:

- Target scope.
- Platform selector.
- Credential mode `none`.

Credential requirement: none.

Connector requirement: none for validation, but live collectors may still require credentials and fail.

Supported platforms: accepted by API for all platforms, but practical live support depends on collector behavior.

Output generated:

- Discovery job and target rows.
- Any accounts a collector can return without credentials.
- Findings only if accounts are collected.

Limitations:

- Most OS and database collectors require credentials for meaningful account inventory.
- Not a network scanner.

Common failures:

- Collector raises credential-required error.
- No accounts discovered.

## Credentialed Account Discovery Scan

Purpose: collect accounts, entitlements, and evidence using stored credentials.

When to use:

- Normal account inventory.
- Server/database onboarding.
- Post-remediation validation.

Required input:

- Target scope.
- Platform selector.
- Credential mode `asset` or `connector`.
- Active connector and credential.

Credential requirement: required.

Connector requirement: required in live mode. The backend resolves an asset-specific connector, an asset tag connector ID, or the first active connector matching platform kind.

Supported platforms: backend collectors exist for Windows, Linux/Unix variants, and supported database platforms.

Output generated:

- Raw probe evidence.
- Normalized accounts.
- Entitlements.
- Privilege findings.
- Password-never-expires policy hygiene findings where detected.

Limitations:

- Collector permissions determine evidence completeness.
- Connector-agent path currently has full Windows logic only.

Common failures:

- Missing connector or credential.
- Vault secret missing.
- TCP unreachable.
- SSH host key mismatch.
- WinRM or database authentication failure.

## Privileged Account Scan

Purpose: focus operational intent on privileged account discovery and classification.

When to use:

- Local Administrators/root/DBA reviews.
- PAM onboarding reviews.
- Quarterly privileged access certification.

Required input: same as credentialed discovery.

Credential requirement: required.

Connector requirement: required in live mode.

Supported platforms: all platforms with collectors and seeded rules.

Output generated:

- Same collection data as credentialed discovery.
- Privilege finding rows and account `privilege_classification`.

Limitations:

- Current collectors still collect broader account inventory; filtering is primarily in review/export.
- PAM onboarding gap is not a first-class workflow.

Common failures: same as credentialed discovery.

## Password Policy Scan

Purpose: collect and evaluate password and lockout policy posture.

When to use:

- Password standard audits.
- Weak lockout/complexity reviews.
- Password-never-expires exception cleanup.

Required input:

- Target scope.
- Platform selector.
- Credentials.

Credential requirement: required for most platforms.

Connector requirement: required in live mode.

Supported platforms:

- Windows local/domain/fine-grained policy best effort.
- Linux/Unix PAM/login_defs/faillock style policy best effort.
- MySQL, MSSQL, MongoDB, and other database policy visibility where collectors implement it.

Output generated:

- PasswordPolicy rows.
- AccountPolicyException rows.
- PasswordPolicyFinding rows.
- CSV/Excel export data.

Evidence collected:

- Policy source, scope, effective flag, min length, complexity, history, age, lockout, reversible encryption, dictionary checks, external policy flags, and collection errors.

Limitations:

- External IdP policy may require manual review.
- Some platform settings need elevated read privileges.
- Unknown values mean not collected, not safe or compliant.

Common failures:

- Insufficient permission to read policy files/views.
- RSAT/AD cmdlets missing for Windows domain policy.
- Database metadata visibility restricted.

## Interactive/Non-Interactive Classification Scan

Purpose: classify whether accounts can log on interactively or are service/batch/network-only.

When to use:

- Service account controls.
- Windows RDP/local logon review.
- Human versus non-human account review.

Required input: target scope, platform selector, credentials.

Credential requirement: required.

Connector requirement: required in live mode.

Supported platforms:

- Windows has detailed evidence-based logic using User Rights Assignment and Event 4624 history.
- Non-Windows platforms use shell/principal heuristics or database principal type.

Output generated:

- `interactive_status`.
- Windows-specific confidence, detection method, allowed logon flags, last observed logon type, and review reason.

Limitations:

- Event log retention and collector rights affect confidence.
- Domain group/user evidence may be partial without domain tooling.

Common failures:

- WinRM access denied.
- Security log access denied.
- User rights export unavailable.

## Full Discovery Scan

Purpose: collect account inventory, privilege classification, password policy, and interactive classification together.

When to use:

- Baseline scans.
- Monthly governance refresh.
- Post-deployment validation.

Required input: target scope, platform selector, credentials.

Credential requirement: required.

Connector requirement: required in live mode.

Supported platforms: all backend collector platforms, subject to target permissions and library availability.

Output generated:

- Accounts, entitlements, raw evidence, privilege findings, password policy rows/findings, scan target stats, and exports.

Limitations:

- Highest runtime and widest permission requirements.
- Agent-based full discovery is currently Windows-focused.

Common failures:

- Any credential, network, collector, or policy collection failure described above.
