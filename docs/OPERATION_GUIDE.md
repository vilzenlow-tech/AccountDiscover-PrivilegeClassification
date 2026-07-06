# Operation Guide

Version date: 2026-06-28

## Daily Operating Model

1. Log in with an active local user account.
2. Check Dashboard for API status, last successful scan, privileged counts, and open alerts.
3. Review failed or partial scans before trusting coverage metrics.
4. Review new privileged accounts, dormant privileged accounts, password-policy findings, and audit logs.
5. Export account or policy evidence when required for governance review.

## Login and Password Change

- Open `/login`, enter email and password.
- The frontend stores JWTs in `sessionStorage`.
- If `must_change_password` is true, the user is redirected to `/change-password`.
- Password changes require the current password and a new password passing backend strength checks.

Password strength implemented by backend:

- Minimum 12 characters.
- Uppercase, lowercase, digit, and special character required.
- Password must not contain username or email local-part.

## Dashboard

The dashboard reads `/api/v1/dashboard/metrics` and shows asset, account, privileged, dormant, shared, unknown-review, last-scan, open-alert, platform, and classification metrics.

If metrics fail, treat the API as offline or unhealthy and check backend logs.

## Asset Management

Operators with admin or security analyst role can:

- Create, update, toggle, and bulk import assets.
- Download an Excel import template.
- Import CSV assets with columns: `hostname`, `platform`, `ip_address`, `port`, `environment`, `owner`, `business_unit`, `criticality`, `connector_name`.
- Create and manage asset groups.
- Assign tags/applications to assets.

Deleting assets is admin-only.

## Connector and Credential Management

Protocol connectors map assets/platforms to connection kinds and credential metadata.

Implemented connector kinds include SSH, WinRM/WMI, MySQL, MSSQL, MongoDB, Oracle, PostgreSQL, and Redis. Credentials store username, auth method, vault backend, and vault reference; secret material is never returned by API responses.

Use connector test to validate:

- Connector is active.
- Connector kind matches the asset platform.
- Linked credential exists and vault secret resolves.
- Target TCP port is reachable.

## Scan Management

Use Scans -> New scan to select:

- Scan intent.
- Platform coverage.
- Targeting method.
- Credential source.
- Optional name and note.

Implemented target methods:

- All enabled assets.
- Platform-filtered all enabled assets.
- Selected assets from inventory.
- Assets by tag/application.
- Assets by environment.
- Assets by connector.
- Bulk hostname/IP matching existing inventory rows.

Range and CIDR expansion are not implemented. Import or create assets first.

## Scan Progress and Failure Handling

Scan jobs have job-level status and target-level rows. Target errors include `error_bucket` and `error_detail`.

Common procedure:

1. Open the scan detail page.
2. Review target statuses.
3. Fix connector, credential, vault secret, network, or platform mismatch.
4. Use retry failed targets.

Cancel is supported for pending, queued, or running jobs, but already queued Celery target tasks may need worker-level completion before all effects stop.

## Account Review

Use Accounts to filter by platform, classification, enabled status, interactive status, source type, activity status, privilege-only, shared-only, search, or asset.

Open Account Detail to review:

- Account identity and platform.
- Privilege classification, confidence, and risk score.
- Entitlements.
- Last-login and activity evidence.
- Raw evidence references.
- Windows interactive classification fields when available.

## Privilege Finding Review

Use Findings to filter privilege findings by job, account, classification, winning status, or connector-agent job. Admin, security analyst, and auditor roles can record review state.

Review states:

- `unreviewed`
- `acknowledged`
- `risk_accepted`
- `remediated`
- `false_positive`

## Password Policy Review

Use Password Policy to review:

- Policy summary.
- Policy snapshots.
- Policy findings.
- Account policy exceptions.
- Cross-asset comparison.
- CSV or Excel exports.

Policy collection is enabled by password-policy scans, full-discovery scans, or scan profiles with `collect_password_policy=true`.

## Reports and Exports

Implemented server-side exports:

- `/exports/accounts/csv`
- `/exports/accounts/excel`
- `/exports/housekeeping/csv`
- `/password-policy/export/csv`
- `/password-policy/export/excel`

Exports are audit logged and capped to 50,000 account rows per request for account exports.

## Audit Log Review

Admins and auditors can review `/audit`. Filters include action and actor email.

The audit log is append-only through application behavior. There is no code-enforced retention, WORM storage, or cryptographic signing.

## User Management

Admins can create users, update users, enable/disable users, assign roles, reset passwords, and list roles/permissions.

Available seeded roles:

- `admin`
- `security_analyst`
- `operator`
- `auditor`
- `viewer`

## Scheduled Scans

Settings supports scan profiles and schedules. Schedules use cron expressions evaluated in GMT+8. Enabled schedules are checked every 30 seconds.

Limitation: `requires_approval=true` schedules are not routed to an approval workflow; the scheduler advances them without launching a scan.

## Troubleshooting Quick Checks

- Login failed: validate user active state, password, lockout count, backend logs.
- Permission denied: compare user role to backend route dependency.
- Scan not starting: check Celery worker, Redis, target scope, and credential validation error.
- Credential missing: verify connector has active credential and vault secret exists.
- Connector offline: check heartbeat recency, token, TLS/proxy, and agent logs.
- No accounts discovered: check collector mode, permissions, target platform, and whether agent platform scanner is implemented.
