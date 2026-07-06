# Troubleshooting

This guide covers common failures for the current FastAPI, Celery, Vite, PostgreSQL, Redis, nginx, and connector-agent implementation.

## First Checks

Check the stack:

```bash
docker compose ps
docker compose logs --tail=200 backend
docker compose logs --tail=200 worker
docker compose logs --tail=200 beat
docker compose logs --tail=200 frontend
docker compose logs --tail=200 nginx
```

Check application health through nginx:

```bash
curl -k https://localhost/health
curl -k https://localhost/api/v1/status
```

The backend container runs:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The frontend container runs Vite on port 5173 and nginx proxies the application on ports 80 and 443.

## Login Fails

Symptoms:

- `401 Unauthorized`
- User reports lockout after repeated failures.
- First-run admin cannot log in.

Checks:

- Verify the user exists and is active.
- Verify `must_change_password` state; users forced to change password can use only auth endpoints until complete.
- Login attempts are counted; after 10 failed attempts, the account is disabled.
- Demo users are seeded only when demo seeding is enabled in development or test mode.
- In production-like environments, `DEMO_MODE`, `DEMO_SEED_ENABLED`, and weak secret keys are blocked by startup validation.

Useful logs:

```bash
docker compose logs --tail=200 backend | rg "login|auth|permission|unauthorized"
```

## Password Change Fails

Passwords must:

- Be at least 12 characters.
- Include uppercase, lowercase, digit, and special character.
- Not contain the username or email local part.

If a reset password is issued by an admin, the user should log in and complete the forced password change flow.

## API Returns 403

The backend is the security boundary. Frontend menus and buttons are only convenience controls.

Checks:

- Confirm the user's backend role.
- Compare the route dependency in `backend/app/api/v1`.
- Remember that some routes enforce roles directly while others enforce named permissions.
- If the frontend shows a control but the backend denies it, trust the backend result.

## Frontend Shows Stale Or Empty Data

Checks:

- Confirm `/api/v1` requests are reaching nginx and backend.
- Confirm the access token exists in `sessionStorage`.
- Refresh tokens are attempted once after a 401; repeated 401 responses normally mean the session is invalid.
- Check browser console and nginx/backend logs.

Useful commands:

```bash
docker compose logs --tail=200 nginx
docker compose logs --tail=200 frontend
docker compose logs --tail=200 backend
```

## Backend Will Not Start

Common causes:

- PostgreSQL or Redis not healthy.
- `.env` missing required values.
- Production-like mode with `COLLECTOR_MODE=mock`, `DEMO_MODE=true`, weak `APP_SECRET_KEY`, or demo seeding enabled.
- Missing local vault key when a persistent local vault is expected.

Check:

```bash
docker compose logs --tail=200 backend
docker compose logs --tail=200 postgres
docker compose logs --tail=200 redis
```

## Database Migration Issues

Alembic reads `APP_DATABASE_URL` from backend settings.

Inside the backend container:

```bash
alembic current
alembic upgrade head
```

If metadata import errors occur, inspect model imports in `backend/app/models` and `backend/app/alembic/env.py`.

## Makefile Commands Fail

The current `Makefile` still runs backend commands through `npm`, but the active backend is Python FastAPI.

Stale targets:

```bash
make test
make lint
make build
```

Use direct commands until the Makefile is corrected:

```bash
docker compose exec backend pytest
docker compose exec backend ruff check app tests
docker compose exec frontend npm run build
docker compose exec frontend npm run lint
```

## Scan Stays Queued

Checks:

- Worker container is running.
- Redis is healthy.
- Celery worker can import `app.workers.celery_app`.
- The job has targets after scope resolution.

Commands:

```bash
docker compose ps worker redis
docker compose logs --tail=200 worker
docker compose logs --tail=200 backend | rg "scan|job|celery|dispatch"
```

## Scan Has No Targets

Common causes:

- Asset is disabled.
- Scan scope selects a tag, connector, environment, or platform with no matching enabled assets.
- Windows server/desktop filters depend on asset tag values such as `windows_role`, `windows_kind`, `windows_type`, or `os_role`.
- Bulk hostname/IP input matches existing inventory only; it does not expand raw IP ranges or CIDR blocks.

## Credentialed Scan Rejected

Credentialed scan types require usable credentials unless mock mode is active or the request explicitly uses credential mode `none`.

Check:

- Asset connector is assigned and active.
- Connector has a default credential or the scan request supplies one.
- Credential is active.
- Local vault secret exists for local vault credentials.
- External vault providers are currently stubs and are not usable until implemented.

## Collector Connection Fails

Linux and Unix collectors:

- Verify SSH reachability.
- Verify account permission for `/etc/passwd`, group data, sudoers/RBAC files, and optional shadow/policy files.
- Verify SSH host key behavior; the implementation uses trust-on-first-use host key storage.

Windows collectors:

- Verify WinRM reachability on 5985 or 5986.
- Verify credentials can run the required PowerShell commands.
- Verify event log access for interactive classification.

Database collectors:

- Verify network port, TLS requirements, and database role permissions.
- Verify Python driver dependencies are installed in the backend image.

## Password Policy Findings Missing

Checks:

- Scan profile or scan request must collect password policy.
- Password policy scan type forces policy collection.
- Platform collector must support the relevant policy fields.
- Some database platforms expose limited policy detail; unknown fields may produce weaker or fewer findings.

## Connector Agent Does Not Enroll

Checks:

- Enrollment token is valid and not expired.
- `CONSOLE_URL` points to the console API.
- TLS trust is valid, or `VERIFY_TLS=false` is used only in development.
- Pending agents may need admin approval.

Useful agent-side commands:

```bash
journalctl -u adpct-agent
```

Console-side:

```bash
docker compose logs --tail=200 backend | rg "connector-agent|enroll|heartbeat"
```

## Connector Agent Stops Heartbeating

The console classifies agents by last heartbeat:

- Online: recent heartbeat.
- Stale: heartbeat older than about 120 seconds.
- Offline: heartbeat older than about 600 seconds.

Checks:

- Agent service is running.
- Agent token was not rotated, revoked, disabled, or rejected.
- Proxy and firewall allow outbound HTTPS to the console.

## Exports Fail

Checks:

- User role has export access.
- Account exports are limited to 50,000 rows.
- Large exports may take time because they are generated synchronously.
- Password policy exports are separate from account exports.

## Evidence Or Raw Results Missing

Live collector results are expected to carry raw evidence references. The scan service raises an error if live account records are returned without raw evidence references. Mock mode is more permissive because fixture data is synthetic.

## When To Re-Run A Scan

Re-run a scan after:

- Changing credentials.
- Changing asset platform, connector, environment, or tags.
- Updating rules.
- Reviewing a finding as remediated and needing fresh evidence.
- Enabling password policy collection.
