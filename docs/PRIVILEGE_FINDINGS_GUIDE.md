# Privilege Findings Guide

Version date: 2026-06-28

## What Is a Privilege Finding

A privilege finding is a persisted match between a normalized account and a classification rule. Findings are written to `privilege_findings` during scan processing or connector-agent result ingestion.

Each finding records:

- Job or connector-agent job.
- Account.
- Rule ID, rule key, and rule version.
- Classification.
- Confidence and risk score.
- Whether it is the winning match.
- Direct versus inherited evidence.
- Inheritance path.
- Explanation.
- Matched evidence.
- Evaluation timestamp.

The API now enriches each finding with reviewer-facing context from the linked
account and asset:

- Account name and normalized account name.
- Asset hostname, IP address, platform, environment, and application tag when
  available.
- Account source, account type, enabled status, interactive status, last login,
  activity status, owner, shared-account flag, and password-never-expires flag.
- PAM-managed status when the collector or asset tags provide that evidence.
- Latest review state, reviewer, comment, and review timestamp.

## Classification Categories

`full_admin`: unrestricted control of the asset, such as root/UID 0, Windows local Administrators, or database root/sysadmin equivalents.

`admin_equivalent`: effectively administrative access through broad sudo, RBAC, security admin roles, or equivalent broad authority.

`operator_high_impact`: operator roles with serious impact, such as backup or server operator style permissions.

`delegated_admin`: admin within a narrower scope, such as database owner or scoped role.

`privileged_service`: service/non-human account carrying privileged access.

`sensitive_non_admin`: non-admin but sensitive access, such as remote login groups or broad read access.

`dormant_privileged`: privileged account whose last-login evidence exceeds dormancy threshold or indicates inactivity.

`unknown_review_required`: evidence is incomplete or ambiguous and must be reviewed.

`non_privileged`: no enabled privilege rule matched.

## Direct vs Inherited Privilege

Direct privilege means the account itself has the entitlement.

Inherited privilege means the privilege comes through a group, role, nested group, custom role, or other membership path. The `inheritance_path` field records the path when available.

## Evidence Summary

Evidence can include:

- Unix UID/GID, group membership, sudo rule, sudoers file path.
- Windows group membership, PrincipalSource, SID, service/task run-as, user rights, Event 4624 logon types.
- Database roles, grants, server roles, profile/policy flags.
- Raw probe references to command/query outputs.

## Privilege Path

The path is shown through finding `inheritance_path` and matched evidence. Example patterns:

- `group:wheel`
- `CORP\Domain Admins -> Administrators`
- `custom role appDeployer -> readWrite@appdb`

## Severity and Risk

The code uses `PRIVILEGE_SEVERITY` to rank classes:

- full_admin: 100
- admin_equivalent: 90
- dormant_privileged: 85
- operator_high_impact: 80
- privileged_service: 75
- delegated_admin: 70
- sensitive_non_admin: 50
- unknown_review_required: 40
- non_privileged: 10

Rule risk modifiers adjust account risk score, capped at 100.

## Review State

Privilege finding review states are append-only rows:

- `unreviewed`
- `acknowledged`
- `risk_accepted`
- `remediated`
- `false_positive`

Admins, security analysts, and auditors can record review state through `/api/v1/findings/review`.

Every review update writes an audit event with the actor, finding ID, target
state, and timestamp. The latest review state is returned on `/api/v1/findings`
and `/api/v1/findings/{finding_id}` for table display and filtering.

## Remediation State

There is no separate remediation workflow beyond review state and comments. Use `remediated` when evidence has been corrected and verified by a follow-up scan.

## Search, Filters, and Sorting

The Privilege Findings page uses server-side search and filters. This avoids
loading all findings into the browser when datasets grow.

By default, the page and export endpoint only show real privileged/review
findings:

- Rows linked to `collection_mode = mock` accounts are excluded.
- `non_privileged` classifications are excluded.
- `unknown_review_required` remains visible because it is an evidence gap that
  requires analyst review, not fake data.

Supported API filters include:

- `search`: case-insensitive multi-keyword search across account name, asset,
  IP address, platform, classification, rule key, explanation, privilege path,
  owner, database instance, scan ID, and matched evidence.
- `severity`: `critical`, `high`, `medium`, `low`, or `review_required`.
- `platform`, `environment`, `application_tag`, `classification`, `direct`,
  `enabled_status`, `interactive_status`, `pam_managed`, `owner`,
  `review_state`, `dormant_privileged`, `service_account`, `shared_account`,
  `no_owner`, `password_never_expires`, and `unresolved_privilege_path`.
- `is_winning`: defaults to the page's winning-findings-only behavior.
- `real_only`: defaults to `true` to hide mock-sourced rows.
- `privileged_only`: defaults to `true` to hide `non_privileged` rows.
- `sort`: `risk_score`, `severity`, `confidence`, `account`, `asset`,
  `platform`, `classification`, `last_login`, or `last_discovered`.
- `direction`: `asc` or `desc`.
- `limit` and `offset`: paginated result retrieval, capped server-side.

The frontend exposes:

- Search with clear/reset behavior.
- Quick filters for critical findings, high risk, unmanaged PAM, dormant
  privileged, interactive privileged, service privileged, shared privileged,
  no owner, inherited privilege, and unknown review.
- Advanced filters for severity, platform, classification, review status,
  direct/inherited, PAM status, enabled status, interactive status, owner,
  sort order, direction, and page size.
- Pagination controls and visible result counts.
- A detail panel with privilege explanation, classification help, privilege
  path, evidence JSON, reviewer state, and review actions.

## RBAC and Audit Controls

Backend authorization is the control boundary.

- Listing and viewing privilege findings requires `privileged_findings:read`.
- Exporting privilege findings requires both `privileged_findings:read` and
  `reports:export`.
- Updating review state requires the existing review roles.
- Unauthorized attempts are audited by the auth dependency.
- Export actions write a `finding.exported` audit event with filter context and
  exported row count.

The frontend also hides the Privileged Findings navigation item from roles that
do not have findings access, but this is only a usability layer.

## PAM Onboarding Gap

There is still no dedicated PAM onboarding workflow table. The page displays
PAM managed/unmanaged status only when evidence includes `pam_managed`,
`managed_by_pam`, `pam_onboarded`, or equivalent asset tag evidence. If no
evidence exists, the UI shows PAM status as unknown.

## Export Findings

Privilege findings can be exported from `/api/v1/findings/export/csv`.

The export:

- Respects search, severity, platform, classification, direct/inherited,
  PAM-managed, owner, and winning-only filters.
- Enforces backend RBAC.
- Logs export activity.
- Includes account, asset, severity, classification, confidence, risk score,
  privilege path, PAM status, owner, interactive status, enabled status, last
  login, review state, rule key, and explanation.

Excel and PDF finding exports are not implemented yet.

## Remaining Gaps

The following items need additional schema and workflow work before they can be
considered production-complete:

- Dedicated remediation status separate from review state.
- Owner assignment workflow from the finding page.
- Exception request, approval, rejection, and expiry workflow for privilege
  findings.
- Selected-row export from the frontend.
- Raw evidence permission separation beyond matched evidence summaries.
- Full audit-history timeline in the finding detail panel.
- PDF summary report generation.
