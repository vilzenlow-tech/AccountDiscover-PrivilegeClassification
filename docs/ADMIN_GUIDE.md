# Admin Guide

This guide is for administrators who operate the tool, manage users, maintain inventory, configure discovery, and review audit-sensitive workflows.

## Admin Responsibilities

Administrators normally manage:

- Users, roles, activation, lockout recovery, and password resets.
- Assets, asset groups, tags, connectors, and credentials.
- Scan profiles, scan schedules, and scan execution.
- Connector-agent enrollment and approval.
- Rule seeding and custom rules.
- Export access and audit log review.

## First Run

The seeded demo administrator is available only when demo seeding is enabled in development or test mode. Production-like environments should use explicit seeding and strong secrets.

If a first-run account has `must_change_password=true`, sign in and complete the password change before using the rest of the application.

## User Management

User management endpoints are under `/api/v1/users`, `/api/v1/roles`, and `/api/v1/permissions`.

Common tasks:

- Create a user.
- Assign one of the seeded roles.
- Activate or deactivate a user.
- Reset a password.
- Change a user's role.
- Confirm available permissions.

Security notes:

- Password reset creates a temporary password state and should force a change.
- Ten failed login attempts disable the user.
- Admin actions are audit logged.
- There is no SSO or external identity provider integration in the current code.

## Role Selection

Use the smallest practical role:

- `admin`: full administrative operation.
- `security_analyst`: security investigation and scan operation.
- `operator`: operational scan execution and inventory support.
- `auditor`: read-heavy access and review/export workflows.
- `viewer`: read-only dashboard and inventory viewing.

See `docs/RBAC_GUIDE.md` for the effective matrix and current limitations.

## Inventory Administration

Assets are the scan targets. A scan cannot directly expand arbitrary CIDR ranges today; import or create assets first, then select by asset, tag, connector, environment, platform, or all enabled assets.

Recommended asset fields:

- Hostname or address.
- Platform.
- Environment.
- Owner.
- Connector.
- Tags that describe scope, location, criticality, or Windows server/desktop role.

CSV import and template download are available through the assets API and UI.

## Tags And Groups

Use tags for dynamic operational targeting:

- Environment slices such as `prod`, `uat`, or `lab`.
- Ownership slices such as application or support team.
- Windows role hints such as `windows_role=server`.
- Compliance scopes.

Tags can be assigned to individual assets or in bulk. Tags cannot be deleted while still assigned.

Asset groups are another grouping mechanism for scan scope. Use them when a stable named set is easier than tag filters.

## Connectors

Connectors describe how the backend reaches targets. Connector kind must match the target platform family.

Recommended flow:

1. Create connector.
2. Assign credential.
3. Attach connector to assets.
4. Use connector test before running scans.
5. Launch a small scan before broad production scope.

Connector test checks kind/platform compatibility, credential/vault availability, and basic reachability. In mock mode, connector test returns synthetic success.

## Credentials And Vaults

Credential metadata is stored in the database. Secret material is not returned by the API.

Current vault behavior:

- Local vault is implemented with Fernet encryption.
- Persistent local vault encryption should use the Docker secret at `/run/secrets/vault_fernet_key`, an env key file, or `VAULT_LOCAL_FERNET_KEY`.
- If no persistent key is configured, an ephemeral key may be generated and stored secrets will not survive restarts.
- External vault providers are placeholders and raise `NotImplementedError`.

Administrative controls:

- Keep credentials least-privileged.
- Rotate credentials outside the tool, then update stored secret material.
- Disable or delete stale credentials.
- Confirm scan service accounts have only the permissions needed for their platforms.

## Scan Profiles

Scan profiles define repeatable discovery behavior:

- Scan type.
- Platforms.
- Target scope.
- Timeout and retry settings.
- Policy collection flags.
- Optional concurrency and throttle fields.

Important limitation: concurrency and throttle fields exist in profile/config data, but target fan-out is primarily controlled by Celery dispatch. Do not rely on these fields alone for hard production rate limiting.

## Scan Launch

Available scan types:

- Basic Discovery.
- Credentialed Discovery.
- Privileged Accounts.
- Password Policy.
- Interactive Classification.
- Full Discovery.

Credentialed scan types require a valid credential unless the scan uses credential mode `none` or mock mode is active. Password policy scan type forces password policy collection.

Common launch scopes:

- All enabled assets.
- Platform.
- Selected assets.
- Tag.
- Environment.
- Connector.
- Bulk hostname/IP match against existing assets.

## Scan Scheduling

Schedules use cron expressions and GMT+8 semantics in the scheduler service.

Operational notes:

- Scheduler checks due schedules roughly every 30 seconds.
- Schedules marked `requires_approval` are skipped and advanced; no approval queue is implemented.
- Confirm worker and beat services are running.

## Connector Agent Administration

Connector-agent administration includes:

- Generate enrollment token.
- Approve pending agent when required.
- Enable, disable, revoke, or rotate token.
- Update settings.
- Dispatch agent jobs.
- Review heartbeats, logs, and result uploads.

Current implementation uses bearer token authentication. mTLS/certificate enrollment fields are not implemented as a security boundary.

The standalone connector agent has real Windows WinRM scanning logic. Non-Windows job execution in the standalone agent is currently placeholder behavior.

## Finding Review

Findings are produced by the scan service and rules engine. Review states are append-only records:

- `unreviewed`
- `acknowledged`
- `risk_accepted`
- `remediated`
- `false_positive`

Use comments to record the reason for a state change. Use follow-up scans to verify remediation.

## Password Policy Administration

Password policy data can be collected from supported platforms and manually upserted through the API.

Admin tasks:

- Review policy summary.
- Review policy findings.
- Create account exceptions.
- Compare policies.
- Export CSV or Excel reports.

See `docs/PASSWORD_POLICY_GUIDE.md` for limitations and field definitions.

## Exports

Implemented export areas:

- Account CSV.
- Account Excel.
- Housekeeping CSV.
- Password policy CSV.
- Password policy Excel.

Account exports support `only_privileged=true` and cap output at 50,000 rows. Export operations are audit logged.

## Audit Review

Audit logs can be reviewed through `/api/v1/audit`.

Implemented audit coverage includes authentication, permission failures, user actions, inventory changes, scans, findings, password policy actions, exports, and connector-agent operations.

Limitations:

- No configured retention policy.
- No WORM storage.
- No cryptographic signing.
- No built-in SIEM forwarding.

## Production Readiness Checklist

Before production:

- Set `APP_ENV=production`.
- Use a strong `APP_SECRET_KEY`.
- Disable demo mode and demo seeding.
- Use `COLLECTOR_MODE=live`.
- Configure TLS certificates under nginx.
- Configure persistent local vault encryption or implement an external vault provider.
- Confirm CORS origins.
- Confirm backup and restore for PostgreSQL and vault data.
- Define data retention for audit logs, raw evidence, scan results, connector logs, and exports.
- Review route RBAC and frontend RBAC drift.
- Correct the stale Makefile backend `npm` commands.
