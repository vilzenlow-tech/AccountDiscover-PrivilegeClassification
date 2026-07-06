# Developer Guide

This guide helps developers understand the current repository, run the application, add features, and avoid stale assumptions.

## Repository Reality Check

The active deployed backend is Python FastAPI under `backend/app`.

The repository also contains a NestJS tree under `backend/src` and Node metadata under `backend/package.json`. That tree is not the active backend in `docker-compose.yml`.

Current active services:

- `backend`: FastAPI served by Uvicorn.
- `worker`: Celery worker.
- `beat`: Celery beat.
- `frontend`: React, Vite, TypeScript.
- `postgres`: PostgreSQL 16.
- `redis`: Redis 7.
- `nginx`: TLS termination and reverse proxy.

## Local Stack

Start the stack:

```bash
docker compose up -d --build
```

Follow logs:

```bash
docker compose logs -f --tail=200
```

Stop and remove volumes:

```bash
docker compose down -v
```

Application URLs:

- nginx: `https://localhost`
- frontend direct dev server: `http://localhost:5173`
- backend internal container port: `8000`

## Backend Development

Backend source:

```text
backend/app
```

Core directories:

- `api/v1`: FastAPI route modules.
- `collectors`: platform collectors.
- `models`: SQLAlchemy models and enums.
- `schemas`: Pydantic request and response models.
- `services`: scan, vault, scheduler, audit, and related domain services.
- `rules_engine`: classification rule evaluation.
- `workers`: Celery application and tasks.
- `alembic`: database migrations.
- `tests`: pytest suite.

Run tests in the backend container:

```bash
docker compose exec backend pytest
```

Run lint:

```bash
docker compose exec backend ruff check app tests
```

Run a specific test:

```bash
docker compose exec backend pytest tests/test_api.py -q
```

Integration tests that require lab targets are marked `integration`.

## Frontend Development

Frontend source:

```text
frontend/src
```

Core directories:

- `api`: RTK Query API slice, types, and download helpers.
- `app`: store and frontend RBAC helpers.
- `components`: shell and UI components.
- `pages`: routed screens.
- `store`: auth state.

Run build:

```bash
docker compose exec frontend npm run build
```

Run lint:

```bash
docker compose exec frontend npm run lint
```

Run Vite directly through the compose service:

```bash
docker compose exec frontend npm run dev -- --host 0.0.0.0
```

## Makefile Warning

The current `Makefile` is stale for backend tasks:

- `make test` runs `docker compose exec backend npm test`.
- `make lint` runs `docker compose exec backend npm run lint`.
- `make build` runs `docker compose exec backend npm run build`.

Those commands target the inactive Node/NestJS backend metadata, not the active FastAPI backend. Use direct backend Python commands until the Makefile is updated.

## Configuration

Settings are defined in:

```text
backend/app/config.py
```

Common variables:

- `APP_ENV`
- `APP_DATABASE_URL`
- `APP_REDIS_URL`
- `APP_SECRET_KEY`
- `APP_CORS_ORIGINS`
- `COLLECTOR_MODE`
- `DEMO_MODE`
- `DEMO_SEED_ENABLED`
- `VAULT_LOCAL_FERNET_KEY`

Startup validation blocks unsafe combinations in production-like environments.

## Database Changes

Models live in `backend/app/models`. Alembic imports model metadata in `backend/alembic/env.py`.

Migration commands:

```bash
docker compose exec backend alembic revision --autogenerate -m "describe change"
docker compose exec backend alembic upgrade head
```

When adding a model:

1. Add SQLAlchemy model.
2. Add Pydantic schemas.
3. Import the model so Alembic metadata sees it.
4. Generate and review migration.
5. Add route/service tests.

## API Route Pattern

Routes are included in `backend/app/main.py` with `/api/v1`.

Typical route implementation:

- Define an `APIRouter`.
- Use Pydantic schemas for input and output.
- Use `get_db` for session boundaries.
- Use `get_current_principal`, `require_roles`, or `require_permissions` for access control.
- Log meaningful administrative actions through the audit service.
- Validate input at route boundaries.

## RBAC Development

Backend enforcement is in:

```text
backend/app/security.py
```

Frontend display rules are in:

```text
frontend/src/app/rbac.ts
```

Keep them aligned, but treat backend checks as authoritative. Some backend routes use roles directly and others use named permissions, so route review is required when changing access behavior.

## Collector Development

Collectors live in:

```text
backend/app/collectors
```

Collector expectations:

- Support mock mode through deterministic fixtures where practical.
- Return normalized account records.
- Preserve raw evidence references in live mode.
- Keep platform-specific parsing isolated.
- Avoid returning secrets.
- Raise clear errors for unreachable targets or insufficient privileges.

Register collectors in:

```text
backend/app/collectors/__init__.py
```

## Scan Flow

High-level flow:

1. API validates scan request and resolves target scope.
2. API creates a discovery job.
3. Celery dispatches one target task per target.
4. Collector gathers raw platform evidence.
5. Scan service stores raw results and normalized accounts.
6. Rules engine classifies privilege and creates findings.
7. Optional password policy collection and policy findings run.
8. Job is finalized when all target tasks are terminal.

Important files:

- `backend/app/api/v1/scans.py`
- `backend/app/services/scan_service.py`
- `backend/app/workers/tasks.py`
- `backend/app/rules_engine`

## Connector Agent Development

Console APIs are in:

```text
backend/app/api/v1/connector_agents.py
```

Standalone agent source is in:

```text
connector-agent/adpct_agent
```

Current state:

- Enrollment token flow is implemented.
- Heartbeats, config pull, pending jobs, job status, result chunks, and logs are implemented.
- Result chunks are gzip/base64 with checksums.
- Completed result processing ingests connector results into backend account data.
- Standalone agent has substantive Windows WinRM scan logic.
- Non-Windows standalone agent scan behavior is placeholder.
- mTLS/certificate fields are metadata only today.

## Frontend API Development

The frontend uses RTK Query:

```text
frontend/src/api/apiSlice.ts
```

Guidelines:

- Keep response types in `frontend/src/api/types.ts`.
- Add endpoints to the existing API slice.
- Use route-level components under `frontend/src/pages`.
- Use backend route behavior as source of truth.
- Do not rely on frontend RBAC for security.

## Test Expectations

For backend changes:

- Add or update pytest coverage.
- Include negative permission and validation tests when touching routes.
- Include parser fixtures when changing collectors.

For frontend changes:

- Run TypeScript build.
- Run lint.
- Manually verify key routes if changing navigation, auth, or scan launch.

For docs-only changes:

- Validate file presence and line counts.
- Verify docs reference current code paths and active services.

## Known Development Gaps

- Stale Makefile backend commands.
- Stale architecture claims in older docs that describe NestJS as active.
- External vault providers are placeholders.
- Connector-agent non-Windows scanning is placeholder.
- CIDR/IP range expansion is not implemented.
- Schedule approval workflow is not implemented.
- Audit retention, signing, WORM storage, and SIEM forwarding are not implemented.
- Frontend RBAC names differ from backend permission names.
