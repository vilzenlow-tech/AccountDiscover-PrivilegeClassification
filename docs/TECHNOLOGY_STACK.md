# Technology Stack

Version date: 2026-06-28

## Active Deployed Stack

Current `docker-compose.yml` and `backend/Dockerfile` run the Python backend:

| Layer | Implemented stack |
|---|---|
| Frontend | React 19, TypeScript, Vite, Redux Toolkit, RTK Query, React Router |
| UI libraries | Flowbite React, Tailwind CSS |
| Backend | Python 3.11, FastAPI, Uvicorn, Pydantic v2 |
| ORM/database | SQLAlchemy 2, Alembic, PostgreSQL 16 |
| Queue/workers | Celery 5 with Redis broker/backend |
| Scheduler | APScheduler inside FastAPI lifespan; Celery beat container also exists |
| Auth | Local email/password, bcrypt, JWT via python-jose |
| RBAC | Backend roles/permissions in `backend/app/security.py`; frontend UX gating in `frontend/src/app/rbac.ts` |
| API style | REST JSON under `/api/v1`; streaming CSV/Excel exports |
| Credential vault | Local Fernet encrypted store implemented; CyberArk, HashiCorp, Azure, AWS are stubs |
| Collectors | Python modules using Paramiko, pywinrm, PyMySQL, pymssql, pymongo, oracledb, psycopg, redis |
| Connector agent | Standalone Python package using requests, urllib3, psutil, pywinrm |
| Reverse proxy | nginx 1.27-alpine, TLS termination, HTTP to HTTPS redirect |
| Tests | pytest for backend and connector agent; frontend build/lint scripts |

## Deployment Files

- `docker-compose.yml`: postgres, redis, backend, worker, beat, frontend, nginx.
- `backend/Dockerfile`: Python image installing `pyproject.toml` dependencies and running Uvicorn.
- `frontend/Dockerfile`: Node image running Vite dev server.
- `nginx/nginx.conf`: TLS reverse proxy to backend and frontend, security headers.
- `.env.example`: application, database, Redis, collector, vault, and frontend settings.

## Legacy or Inactive Stack

The repository contains `backend/src`, `backend/package.json`, and NestJS/Mongoose dependencies. This is not the active deployed backend in the current Docker configuration. Treat it as legacy/inactive unless deployment files are changed.

## Important Mismatches

- `docs/GAPS_ASSESSMENT_2026-06-27.md` says Docker runs the NestJS backend. Current deployment files run FastAPI, so that assessment is stale.
- `Makefile` still runs backend `npm` commands for test/lint/build. Current backend validation should use Python commands such as `pytest` and `ruff`, not backend `npm`.
- Root `README.md` mentions PostgreSQL 15+ and seven target platforms, but the current code now includes PostgreSQL 16 in Docker and more platform enum values than the older seven-platform wording.
- `CONNECTOR_FRAMEWORK.md` describes mTLS certificates, encrypted queues, and diagnostic upload endpoints. Current code implements token auth and log upload, not mTLS or a durable encrypted offline queue.

## Key Dependencies

Backend:

- `fastapi`, `uvicorn[standard]`, `pydantic`, `pydantic-settings`
- `SQLAlchemy`, `alembic`, `psycopg[binary]`
- `bcrypt`, `python-jose[cryptography]`, `cryptography`
- `celery`, `redis`, `APScheduler`
- `openpyxl`, `pandas`, `jinja2`, `structlog`, `httpx`, `tenacity`
- Collector libraries: `paramiko`, `pymysql`, `pymssql`, `pymongo`, `oracledb`, `pywinrm`
- Optional AI assistant dependency: `anthropic`

Frontend:

- `react`, `react-dom`, `react-router-dom`
- `@reduxjs/toolkit`, `react-redux`
- `flowbite`, `flowbite-react`
- `vite`, `typescript`, `tailwindcss`, `eslint`

Connector agent:

- `requests`, `urllib3`, `psutil`, `cryptography`, `pywinrm`

## Testing Frameworks

- Backend and connector agent: pytest.
- Frontend: TypeScript build and ESLint scripts.
- Existing backend tests cover API behavior, rules, connectors, connector agents, password policy, schedules, Unix parsers, and lab database account discovery.

## Build and Run Commands

Current practical commands:

```bash
docker compose up -d --build
docker compose logs -f --tail=200
docker compose exec backend pytest -q
docker compose exec frontend npm run build
```

The Makefile should be updated before relying on `make test`, `make lint`, or `make build`.
