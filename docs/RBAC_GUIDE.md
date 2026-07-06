# RBAC Guide

Version date: 2026-06-28

## Roles

Seeded backend roles:

- `admin`
- `security_analyst`
- `operator`
- `auditor`
- `viewer`

The user-facing request mentions "Security Operator" and "Auditor/Reviewer". In the actual code, the closest implemented roles are `security_analyst`, `operator`, and `auditor`.

## Backend Permissions

Permission constants include:

- User and role: `users:create`, `users:read`, `users:update`, `users:disable`, `users:reset_password`, `roles:manage`
- Assets/tags: `assets:read`, `assets:manage`, `tags:read`, `tags:manage`
- Scans: `scans:launch`, `scans:schedule`, `scans:cancel`, `scans:retry`, `scans:read`
- Accounts/findings: `accounts:read`, `findings:read`, `findings:review`, `privileged_findings:read`
- Connectors/credentials: `connectors:read`, `connectors:manage`, `credentials:read_metadata`, `credentials:manage`, `credentials:use`
- Reports/audit/settings: `reports:export`, `audit:read`, `settings:manage`

## Default Role-Permission Matrix

| Permission area | admin | security_analyst | operator | auditor | viewer |
|---|---:|---:|---:|---:|---:|
| User management | Yes | No | No | No | No |
| Role management | Yes | No | No | No | No |
| Asset read | Yes | Yes | Yes | Yes | Yes |
| Asset manage | Yes | No in permission map, but some routes allow security_analyst | No | No | No |
| Tag read | Yes | Yes | Yes | Yes | Yes |
| Tag manage | Yes | No in permission map, but routes allow security_analyst | No | No | No |
| Launch scans | Yes | Yes | Yes in permission map, but route allows admin/security_analyst only | No | No |
| Schedule scans | Yes | Yes | No | No | No |
| Cancel/retry scans | Yes | Yes | No retry/cancel in route | No | No |
| Read scans/accounts | Yes | Yes | Yes | Yes | Viewer limited |
| Review findings | Yes | Yes | No | Privilege finding review route allows auditor | No |
| Connector manage | Yes | No in permission map, but routes allow security_analyst | No | No | No |
| Credential manage/use | Yes | Yes | Use only | No | No |
| Export reports | Yes | Yes | No | Yes | No |
| Audit read | Yes | No | No | Yes | No |
| Settings manage | Yes | No | No | No | No |

Important: the code has a mixed enforcement style. Some routes use `require_permissions`, but many use `require_roles`. The route behavior is the effective behavior.

## What Admin Can Do

Admin can manage users, roles, assets, tags, scans, scan profiles, schedules, connectors, credentials, connector agents, findings, policies, exports, audit logs, and destructive deletes where implemented.

## What Security Analyst Can Do

Security analysts can launch and manage scans, manage many operational assets/tags/connectors/credentials through role-based routes, review findings, use credentials for scans, and export account reports. They cannot manage users or delete admin-only objects.

## What Operator Can Do

The permission map gives operators read access, scan launch, credential use, and connector read. In actual scan routes, launch is limited to admin/security_analyst, so operator launch should be verified before relying on it.

## What Auditor/Reviewer Can Do

Auditors can read assets/accounts/scans/findings, read audit logs, export reports, and record privilege/password-policy review states where routes allow auditor.

## What Viewer Can Do

Viewer has minimal read access in the permission map. Frontend navigation shows limited items based on its own UX permission map.

## User Management Procedures

Add user:

1. Open User Management.
2. Create user with username, email, display name, role, temporary password, active state, and must-change-password flag.

Assign role:

1. Edit the user.
2. Select the implemented role.
3. Save.

Disable user:

1. Open user status action.
2. Set `is_active=false`.

Reset password:

1. Use reset-password action.
2. Supply temporary password that passes strength checks.
3. Optionally force password change.

## Enforcement Boundaries

Backend enforcement:

- JWT token is decoded.
- User must exist and be active.
- `must_change_password` blocks most endpoints.
- Role or permission dependency checks route access.

Frontend enforcement:

- Navigation and some buttons are hidden based on `frontend/src/app/rbac.ts`.
- This is UX-only and not a security boundary.

## Limitations

- No SSO group mapping.
- No custom role editor beyond seeded roles and role rows.
- Mixed role/permission enforcement can cause matrix drift.
- Frontend permission names differ from backend permission names.
- No per-object ABAC checks for asset ownership, tag scope, or environment scope.
