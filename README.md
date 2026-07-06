# Account Discovery and Privilege Classification Tool (ADPCT)

Internal enterprise platform for discovering accounts across Unix (RHEL, Solaris,
AIX), Windows servers, and databases (MySQL, MS SQL Server, MongoDB), then
classifying each account's privilege level with deterministic, explainable rules
and full evidence.

The tool is designed for **IT Security, IAM/PAM, GRC, and Audit** teams to
answer questions such as:

- Who has `root`, `sudo ALL`, `sysadmin`, `db_owner`, `root@mongo`, Domain
  Admin, or Backup Operator on which asset?
- Which privileged accounts are shared, dormant, or not yet onboarded into PAM?
- What changed between two scans? Did anything become privileged overnight?
- For any classification decision: what command, what output, what rule, what
  inherited path?

## Documentation

| Document | Description |
|---|---|
| [README.md](README.md) | This file — project overview and quick start |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Full architecture, threat model, and limitations |
| [CONNECTOR_FRAMEWORK.md](CONNECTOR_FRAMEWORK.md) | Connector/Agent framework design — communication model, security, job lifecycle |
| [connector-agent/AGENT_INSTALL.md](connector-agent/AGENT_INSTALL.md) | Connector Agent installation, OS support, enrollment, and operations guide |

---

## Status

This repository contains the **first working version** of the platform:

- Full backend (FastAPI + SQLAlchemy + PostgreSQL + Celery).
- Canonical account model + deterministic rules engine with built-in rules.
- Modular collectors for all seven target platforms with a **mock mode** for
  offline development and CI.
- Encrypted credential vault service with adapters ready for CyberArk, HashiCorp
  Vault, Azure Key Vault, and AWS Secrets Manager.
- Scan orchestration (on-demand, scheduled, bulk, profiled), delta detection,
  alerts, and a live job dashboard.
- React + TypeScript enterprise UI for assets, connectors, scans, accounts,
  findings, rules, exceptions, exports, and audit.
- Seed data, sample rules, unit tests for the rules engine, and integration
  tests for the API.

## High-level architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for full detail. Key choices:

- **Read-only by default.** Collectors issue only inspection commands/queries.
  No password reset, no privilege grant, no write statements are allowed.
- **Evidence first.** Every finding links to the raw command/query that
  produced it, the normalized evidence, the rule that matched, and a
  human-readable explanation.
- **Deterministic rules.** Privilege classification is rule-based, not
  AI-based. Rules live in the database (or YAML) and are editable without code
  changes.
- **Modular collectors.** Each platform has its own collector module
  implementing a common interface so new platforms can be added without
  touching the rules engine or UI.
- **Separation of secrets.** Credentials are never in application code, logs,
  exports, or API responses. They are retrieved at scan launch time from the
  configured vault.

## Project layout

```
account-discovery-tool/
├── README.md                     # this file
├── ARCHITECTURE.md               # architecture, threat model, limitations
├── CONNECTOR_FRAMEWORK.md        # connector/agent framework design
├── docker-compose.yml            # Postgres, Redis, backend, worker, frontend
├── .env.example                  # copy to .env before running
├── Makefile                      # common developer commands
├── backend/                      # FastAPI + SQLAlchemy + Celery
│   ├── pyproject.toml
│   ├── alembic.ini
│   ├── alembic/                  # database migrations
│   ├── app/
│   │   ├── main.py               # FastAPI entrypoint
│   │   ├── config.py             # settings (env-driven)
│   │   ├── db.py                 # engine, session factory
│   │   ├── db_types.py           # portable JSONB/UUID TypeDecorators (PG + SQLite)
│   │   ├── security.py           # hashing, JWT, RBAC
│   │   ├── models/               # SQLAlchemy ORM models
│   │   ├── schemas/              # Pydantic DTOs
│   │   ├── api/v1/               # REST routers
│   │   │   └── connector_agents.py  # 20 connector-agent endpoints
│   │   ├── collectors/           # per-platform collector modules
│   │   ├── rules_engine/         # deterministic classification engine
│   │   ├── services/             # scan, delta, export, vault, audit
│   │   ├── workers/              # Celery tasks + scheduler
│   │   └── seed.py               # sample data and rules
│   └── tests/                    # pytest (44 tests — API + connector agents)
├── connector-agent/              # remote connector agent (Python daemon)
│   ├── AGENT_INSTALL.md          # installation, OS support, enrollment guide
│   ├── requirements.txt          # requests, urllib3, psutil, cryptography
│   └── adpct_agent/
│       ├── main.py               # entry point — enrollment + polling loop
│       ├── client.py             # outbound-only HTTPS client
│       ├── config.py             # config loader (env vars + agent.json cache)
│       └── executor.py           # job execution engine + result upload
└── frontend/                     # React + TypeScript (Vite)
    ├── package.json
    ├── tsconfig.json
    ├── index.html
    └── src/
        ├── App.tsx
        ├── api/                  # typed API client
        ├── components/
        ├── pages/                # dashboard, accounts, assets, scans,
        │                         # connectors, connector-agent management
        └── lib/                  # auth, theme, utils
```

## Quick start (development, mock mode)

Prerequisites: Docker, Docker Compose, Python 3.11+, Node 20+.

```bash
cp .env.example .env
make up                # starts Postgres, Redis, backend, worker, frontend
make seed              # inserts sample assets, rules, and a demo user
# open http://localhost:5173
# login: admin@local / ChangeMe!123   (force password change on first login)
```

By default the platform runs in `COLLECTOR_MODE=mock`, which wires all
collectors to their mock implementations. No real hosts or databases are
contacted. Flip `COLLECTOR_MODE=live` in `.env` to enable real SSH/WinRM/DB
connections (see [ARCHITECTURE.md](ARCHITECTURE.md) for prerequisites).

## Lab database seeding

The RHEL lab host at `192.168.7.130` can also seed controlled MySQL and
MongoDB simulation accounts. The script connects to the host over SSH, uses the
local `mysql` and `mongosh`/`mongo` clients, and generates throwaway database
passwords on the host without printing or saving them.

```bash
export RHEL_TEST_HOST=192.168.7.130
export RHEL_TEST_USERNAME=root
export RHEL_TEST_PASSWORD=

python3 scripts/lab_seed_databases.py
```

To live-scan those database accounts, provide read-capable database credentials
through local environment variables, then run:

```bash
export MYSQL_TEST_HOST=192.168.7.130
export MYSQL_TEST_USERNAME=
export MYSQL_TEST_PASSWORD=

export MONGO_TEST_HOST=192.168.7.130
export MONGO_TEST_USERNAME=
export MONGO_TEST_PASSWORD=

COLLECTOR_MODE=live backend/.venv/bin/python -m pytest backend/tests/test_lab_database_accounts.py -m integration -q
```

Cleanup removes only `adt_mysql_*` and `adt_mongo_*` lab users plus the
`adpct_lab_app` database:

```bash
python3 scripts/lab_cleanup_databases.py
```

Safety guard: database seeding and cleanup are allowed by default only for
`192.168.7.130`. For an explicitly approved non-production test host, set
`ALLOW_NON_LAB_TARGET=true` or pass `--allow-non-lab-target`.

## Setup instructions (production outline)

1. Provision a managed PostgreSQL instance with TLS, a Redis/Valkey instance,
   and internal-only DNS for the application.
2. Provision an internal secrets vault (CyberArk / HashiCorp Vault / Azure Key
   Vault / AWS Secrets Manager) and create a least-privilege role for ADPCT.
3. Set `VAULT_PROVIDER` in `.env` and provide the adapter configuration. Do not
   fall back to the local encrypted store in production.
4. Create discovery service accounts per platform with read-only privileges
   (see `docs/least_privilege.md` in each collector module docstring).
5. Deploy the backend behind an internal reverse proxy with mTLS (or SSO).
6. Run `alembic upgrade head` and `python -m app.seed --production`.
7. Configure scheduled scans, scan profiles, blackout windows, and alert
   destinations through the UI.

## Security assumptions

See the "Security assumptions" section of
[ARCHITECTURE.md](ARCHITECTURE.md#security-assumptions). Highlights:

- The application runs on trusted internal infrastructure.
- TLS terminates at the reverse proxy; the backend is only reachable through
  it.
- The Postgres instance is not shared with any untrusted workload and is
  encrypted at rest.
- All discovery credentials are short-lived and originate from the configured
  vault; local fallback is dev-only.
- Operators, analysts, and auditors are authenticated; RBAC is enforced on
  every endpoint.

## Known limitations

- Windows collection requires WinRM/HTTPS; the collector includes both pywinrm
  and a PowerShell-over-SSH fallback but assumes the target is joined to a
  reachable domain for nested group resolution.
- Solaris RBAC and AIX RBAC evidence collection depends on the remote account
  being able to read `/etc/security/*` files; where this is not permitted, the
  account is marked `unknown_review_required` with an explanatory finding.
- MongoDB custom-role inherited privilege graphs are walked one level deep in
  the first version; deeper walks are scheduled for v1.1.
- PAM vault integration ships with adapter stubs and contract tests but not
  production-grade client code for every vendor. The local encrypted store is
  fully implemented and acceptable for pilot.
- No agentless privilege change detection between scans (i.e., we do not tail
  auth logs); deltas are derived from scan-to-scan comparison.

## Future enhancements

- Add LDAP/AD group expansion service and cache.
- Add Kubernetes RBAC collector, Okta/Entra collector, and network device
  collectors (Cisco, Palo Alto).
- Add ML-assisted dormancy detection and anomaly scoring on top of (not in
  place of) the deterministic rules engine.
- Add SCIM and ServiceNow CMDB sync for asset ownership.
- Add SIEM forwarding for audit and finding events.
- Add SSO (SAML / OIDC) with group-mapped RBAC.
- Add signed, append-only audit log with external attestation.

## License

Internal use only. Not for redistribution.
