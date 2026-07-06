# Security Settings Guide

Version date: 2026-06-28

## Authentication Settings

Implemented authentication is local email/password with bcrypt hashes and JWT access/refresh tokens.

Environment variables:

- `APP_SECRET_KEY`
- `APP_JWT_ALG`
- `APP_ACCESS_TOKEN_TTL_MIN`
- `APP_REFRESH_TOKEN_TTL_MIN`
- `APP_RATE_LIMIT_LOGIN_PER_MIN`

Note: `APP_RATE_LIMIT_LOGIN_PER_MIN` is defined in settings, but no route-level rate limiter is implemented. Login lockout is implemented by failed attempt count.

## Password Policy for Tool Login

Backend password strength rules:

- Minimum 12 characters.
- Uppercase required.
- Lowercase required.
- Digit required.
- Special character required.
- Must not contain username.
- Must not contain email local-part.

User lockout:

- Failed login attempts increment `failed_login_attempts`.
- At 10 consecutive failures, `is_active` is set false.
- Successful login resets the counter.

## Session and Token Settings

- Access token type: JWT with `sub`, `roles`, `type=access`, `exp`, and `iat`.
- Refresh token type: JWT with `type=refresh`.
- Frontend storage: `sessionStorage`.
- Refresh behavior: frontend retries once on 401 using `/auth/refresh`.

No token revocation list, JTI tracking, or per-session management is implemented.

## RBAC Roles and Permissions

Backend roles:

- `admin`
- `security_analyst`
- `operator`
- `auditor`
- `viewer`

Backend permission constants exist in `backend/app/security.py`. Some routes use role checks directly, and some use permission checks. Backend checks are authoritative; frontend checks are UX-only.

## User Management

Implemented:

- List, create, update, enable/disable users.
- Reset passwords.
- Assign roles.
- List roles and permissions.
- Audit user create/update/status/password reset actions.

Admin reset password is implemented at `/api/v1/users/{user_id}/reset-password`.

## Scan Launch Permission Controls

Current scan launch, cancel, and retry endpoints use role checks:

- `admin`
- `security_analyst`

The permission names `scans:launch`, `scans:cancel`, and `scans:retry` exist but are not used consistently by all scan routes.

## Export Permission Controls

Account and housekeeping exports require one of:

- `admin`
- `security_analyst`
- `auditor`

Password-policy exports currently require any authenticated principal through `get_current_principal`; tighten this if exports are considered sensitive in production.

## Connector Management Permission Controls

Protocol connectors:

- Create/update/test: `admin` or `security_analyst`.
- Delete: `admin`.

Connector agents:

- Admin actions such as enrollment token generation, approval, revoke, rotate token: `admin`.
- Manager actions such as update, enable/disable, settings, dispatch jobs: `admin` or `security_analyst`.
- List/detail/log views mostly require authenticated user.

## Credential Management Permission Controls

Credential list/create/update require `admin` or `security_analyst`. Delete requires `admin`.

Secrets are not returned in API responses.

## Vault Settings

Environment variables:

- `VAULT_PROVIDER`
- `VAULT_LOCAL_FERNET_KEY`
- `VAULT_LOCAL_FERNET_KEY_FILE`
- Docker secret `/run/secrets/vault_fernet_key`

Implemented provider:

- `local`: Fernet-encrypted JSON store.

Stub providers:

- `cyberark`
- `hashicorp`
- `azure`
- `aws`

Production should not rely on local vault unless risk accepted and key management is hardened.

## Production Mode Controls

Startup validation blocks unsafe production-like settings:

- `DEMO_MODE=true` is not allowed for UAT, staging, or production.
- `COLLECTOR_MODE=mock` is not allowed for UAT, staging, or production.
- Weak `APP_SECRET_KEY` is rejected in production.
- `DEMO_SEED_ENABLED=true` is rejected in production.

## Demo and Mock Mode Controls

- `DEMO_MODE`: UI/status flag and startup guard.
- `DEMO_SEED_ENABLED`: allows seeded demo users/assets only in development/test.
- `COLLECTOR_MODE=mock`: uses deterministic mock collectors and is blocked in production-like environments.

## TLS and HTTPS

nginx terminates TLS on port 443 and redirects port 80 to HTTPS. The nginx config enables TLS 1.2/1.3 and HSTS.

FastAPI also adds security headers:

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `X-XSS-Protection`
- `Permissions-Policy`
- `Content-Security-Policy`
- `Cache-Control`
- `Pragma`

## CORS

FastAPI CORS origins come from `APP_CORS_ORIGINS`. Methods and headers are broadly allowed for configured origins.

## Audit Logging

Implemented audit events include login success/failure, unauthorized permission attempts, user changes, asset/connector/credential/tag changes, scans, findings, password policy actions, exports, and connector-agent operations.

Limitations:

- No code-level retention policy.
- No WORM or cryptographic signing.
- No external SIEM forwarding.

## Data Retention

No general retention or purge policy is implemented for accounts, raw evidence, audit logs, connector logs, or scan results. Define operational retention before production use.
