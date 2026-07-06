# ADPCT — Account Discovery & Privilege Classification Tool
## Read-Only Gap Assessment

**Date:** 2026-06-27
**Mode:** Read-only assessment. No code, config, schema, UI, API, or files were modified. All findings are grounded in the currently *wired/deployed* application (the stack that `docker-compose.yml` actually runs), with the decommissioned Python backend noted for contrast.

---

## A. Executive Summary

The application is **mid-migration** and the deployed state is a **functional regression** against its own documented design. The repository contains two backends:

1. **`backend/app` (Python / FastAPI / SQLAlchemy / Celery)** — the original, feature-complete platform described in `README.md`: per-platform collectors for all targets, scan profiles, connector/credential routing, scheduler, exports, rules engine, audit. **This backend is no longer wired into `docker-compose.yml` or the `Dockerfile` — it is not deployed.**
2. **`backend/src` (NestJS / MongoDB / Mongoose)** — the *currently deployed* backend. It implements **only** auth and accounts, plus a **mock "scan"** that upserts hardcoded lab data. (`docker-compose.yml`, `backend/src/app.module.ts`)

As a result, the **core promise of the product — choosing a scan type and platform and actually discovering accounts — does not exist in the running application.** There is a single button, "Launch full scan," that ignores all input and writes a fixed set of demo accounts (`backend/src/domain/accounts/accounts.service.ts:91`, `frontend/src/App.tsx`).

Most of the console (Connectors, Findings, Rules, Exceptions, Tags, Agents, Policies, Settings, Audit) is rendered from **static mock data** (`frontend/src/mockData.ts`), not the backend. RBAC roles exist on the user model but are **never enforced** (`backend/src/domain/auth/auth.guard.ts`). There is no real collector, connector, scheduler, validation, or server-side export in the deployed app.

**Production readiness: NOT READY.** The deployed build is a demo/UI shell. The mature capability exists in the Python backend but has been disconnected. The central decision the team faces is whether to **re-wire the Python backend** or **port its capabilities into NestJS** — either way, the scan-type/platform/scope/connector/RBAC functionality must be rebuilt or reconnected before this can be called an account-discovery tool.

---

## B. Gaps Report

> Severity reflects impact on the *deployed* application.

### GAP-01 — Deployed backend implements none of the discovery engine
- **Module:** Backend / deployment
- **Category:** backend / workflow / scan logic
- **Severity:** Critical
- **Current:** `docker-compose.yml` runs `node:lts-slim` -> NestJS (`backend/src`), which wires only `AuthModule` + `AccountsModule` (`app.module.ts`). The Python backend with all collectors/scan logic is not built or started.
- **Expected:** The deployed backend should expose scan orchestration, collectors, connectors, scheduler, exports, rules, audit, etc.
- **Evidence:** `command: ["sh","-c","npm install && npm run build && npm start"]` in `docker-compose.yml`; only two modules imported in `app.module.ts:36`.
- **Impact:** The product cannot perform its primary function. Anything demoed is illusory.
- **Remediation:** Decide on the target backend. Either (a) restore the FastAPI service in compose/Dockerfile, or (b) port collectors/orchestration into NestJS. Until then, treat the NestJS app as a prototype.
- **Priority:** P0 · **Effort:** Large · **Dependencies:** architecture decision · **Owner:** Backend/Architecture lead

### GAP-02 — No scan-type selection
- **Module:** Scans (UI + API)
- **Category:** scan logic / UI / workflow
- **Severity:** Critical
- **Current:** Only one action exists: "Launch full scan." `ScansController.launch()` takes **no parameters** and calls `launchFullScan()` (`accounts.controller.ts`, `accounts.service.ts:91`). The frontend POSTs `{ all_enabled: true, note: ... }` which the controller silently ignores (`App.tsx`).
- **Expected:** User selects basic (uncredentialed) / credentialed / password-policy / privileged / interactive-classification / full discovery.
- **Evidence:** No DTO, no `scan_type` field anywhere in `backend/src`.
- **Impact:** Cannot tailor discovery; all "scans" are identical mock writes.
- **Remediation:** Introduce a scan-type enum + DTO; enforce end-to-end (UI -> API -> orchestrator -> collector -> result/export).
- **Priority:** P0 · **Effort:** Large · **Dependencies:** GAP-01 · **Owner:** Backend + Frontend

### GAP-03 — No platform selection (the named example issue)
- **Module:** Scans (UI + API)
- **Category:** scan logic / UI
- **Severity:** Critical
- **Current:** No way to choose Windows-only, RHEL-only, selected platforms, etc. `launchFullScan()` hardcodes coverage of 5 platforms and always marks Solaris/AIX/Oracle/MSSQL as "target not configured" (`accounts.service.ts:96-105`).
- **Expected:** Select any single platform, a subset, or all; selection enforced through collection and reporting.
- **Evidence:** Hardcoded `platformCoverage` array; no platform parameter accepted.
- **Impact:** The exact capability the customer asked for is absent. (See Section C.)
- **Remediation:** Platform multi-select in UI; platform filter in scan DTO; collector routing per platform.
- **Priority:** P0 · **Effort:** Large · **Dependencies:** GAP-01, GAP-02 · **Owner:** Backend + Frontend

### GAP-04 — No scan scope selection
- **Module:** Scans
- **Category:** workflow / scan logic
- **Severity:** Critical
- **Current:** No single-asset, selected-assets, hostname/IP, tag-based, app-based, environment-based, connector-based, or platform-based scoping. Scope is a fixed string.
- **Expected:** Full scope picker (single / selected / bulk / tag / app / env / platform / connector).
- **Evidence:** `scope_description` is a constant in `launchFullScan()`.
- **Impact:** Cannot target real estates; no operational control.
- **Remediation:** Scope model + selectors; validate non-empty scope.
- **Priority:** P0 · **Effort:** Large · **Dependencies:** GAP-01 · **Owner:** Backend + Frontend

### GAP-05 — Scans are in-memory and fake
- **Module:** Scans
- **Category:** backend / data model
- **Severity:** Critical
- **Current:** `private readonly scans: ScanRecord[] = []` (`accounts.service.ts`). Scans are not persisted (lost on restart), not shared across replicas, always `status: completed`, `progress: 100`. No actual collection runs — it upserts hardcoded accounts.
- **Expected:** Persisted scan jobs with real lifecycle (queued -> running -> completed/failed), per-target status, durable history.
- **Evidence:** In-memory array; `status: 'completed' as const`.
- **Impact:** No real discovery, no audit trail, no progress, data loss on restart.
- **Remediation:** Persist Scan/Job entities (Mongo collection + Bull queue, which is imported but unused) and run real collectors.
- **Priority:** P0 · **Effort:** Large · **Dependencies:** GAP-01 · **Owner:** Backend

### GAP-06 — No collector routing in deployed backend
- **Module:** Collectors
- **Category:** scan logic / backend
- **Severity:** Critical
- **Current:** NestJS has **zero collectors**. The Python backend has a full `COLLECTOR_REGISTRY` for all platforms (`backend/app/collectors/__init__.py:27`) and per-platform connector-kind mapping (`backend/app/services/scan_service.py:39`) — but it is not deployed.
- **Expected:** Platform -> correct collector routing; unsupported platforms shown explicitly, not silently skipped.
- **Evidence:** No collector code under `backend/src`.
- **Impact:** No account data can be collected from any real target.
- **Remediation:** Re-wire Python collectors or port the registry pattern to NestJS.
- **Priority:** P0 · **Effort:** Large · **Dependencies:** GAP-01 · **Owner:** Backend

### GAP-07 — No scan validation / prerequisite checks
- **Module:** Scans
- **Category:** workflow / scan logic
- **Severity:** High
- **Current:** No validation of scan type, platform, asset/platform match, scope non-empty, connector availability, credential requirement/availability, or launch permission. `launch()` always succeeds.
- **Expected:** Pre-flight validation with clear error messaging (Python `_resolve_credential` shows the intended pattern — connector/credential/vault checks — at `scan_service.py:60`).
- **Impact:** Invalid scans "succeed" silently; no operator feedback.
- **Remediation:** Validation layer in API + inline UI errors.
- **Priority:** P1 · **Effort:** Medium · **Dependencies:** GAP-02..06 · **Owner:** Backend + Frontend

### GAP-08 — RBAC roles defined but never enforced
- **Module:** Auth / governance
- **Category:** security
- **Severity:** Critical
- **Current:** Users have `roles: ['admin','operator']` (`user.schema.ts`), and tokens carry roles, but `AuthGuard` only checks the bearer token is valid — **no role check** (`auth.guard.ts`). No `@Roles` decorator/guard exists. Any authenticated user can call any endpoint. Frontend does not gate by role either.
- **Expected:** Role-based authorization for who can launch scans, export, manage credentials/connectors/tags, schedule, and view privileged findings.
- **Evidence:** `canActivate` returns true for any valid token.
- **Impact:** Privilege-escalation / least-privilege violation in a security product — unacceptable for GRC/audit use.
- **Remediation:** Roles guard + decorators on every sensitive route; reflect in UI.
- **Priority:** P0 · **Effort:** Medium · **Dependencies:** none · **Owner:** Security/Backend

### GAP-09 — No real audit logging
- **Module:** Audit
- **Category:** security / governance
- **Severity:** High
- **Current:** Audit Log page renders 3 static mock rows (`mockData.ts` `audit`). No sensitive action (login, scan launch, export, credential access) is recorded by the deployed backend. (Python backend has `services/audit.py`, not deployed.)
- **Expected:** Immutable, timestamped audit of all sensitive actions with actor identity.
- **Impact:** No evidence trail — fails the tool's own GRC/ITAC purpose.
- **Remediation:** Audit service + persistence; surface real entries.
- **Priority:** P1 · **Effort:** Medium · **Dependencies:** GAP-01 · **Owner:** Backend

### GAP-10 — Connector / Agent workflow is non-functional (mock)
- **Module:** Connectors / Agents
- **Category:** connector
- **Severity:** Critical
- **Current:** Connectors and Agents pages are static mock tables (`App.tsx` `StaticWorkspace`, `mockData.ts`). No connector selection for scans, no scope/profile restriction, no status/heartbeat, no offline handling, no port-443 result ingestion. (Design exists in `CONNECTOR_FRAMEWORK.md` and `backend/app/services/connector_result_ingestion.py`, not deployed.)
- **Expected:** Selectable, status-aware connectors with scope/profile enforcement and graceful offline failure.
- **Impact:** Cannot scan segmented networks; no agent governance.
- **Remediation:** Implement/connect connector domain + agent enrollment & status.
- **Priority:** P1 · **Effort:** Large · **Dependencies:** GAP-01 · **Owner:** Backend + Frontend

### GAP-11 — No scheduled scans
- **Module:** Scheduler
- **Category:** scheduler
- **Severity:** High
- **Current:** No scheduling in deployed app. `@nestjs/bull` and Redis are configured but **unused** (`app.module.ts`). No frequency, next-run, or last-run. (Python `services/scheduler.py` + Celery beat exist, not deployed.)
- **Expected:** Schedule e.g. "Windows Server privileged scan every Sunday 02:00" with type/platform/scope/connector/credential mode and run history.
- **Impact:** No recurring discovery; manual only.
- **Remediation:** Scheduler on Bull/cron; schedule CRUD UI.
- **Priority:** P1 · **Effort:** Large · **Dependencies:** GAP-02..06 · **Owner:** Backend

### GAP-12 — Reporting/export is client-side only and unfiltered server-side
- **Module:** Export
- **Category:** export / reporting
- **Severity:** High
- **Current:** Only export is a **client-side CSV** of the in-memory accounts list, columns fixed (`AccountTriageWorkbench.tsx:72`). It reflects the workbench's client filters but cannot do platform-only / scan-type-only / failed-scan / password-policy / evidence-backed reports, and is capped by the `limit=200` fetch. (Python `api/v1/exports.py` exists, not deployed.)
- **Expected:** Server-side exports honoring selected platform/type/tags/assets, plus failed-scan, privileged, password-policy, full-inventory, and evidence-backed reports.
- **Impact:** Reports incomplete and not authoritative for audit.
- **Remediation:** Server-side export endpoints with filter parity.
- **Priority:** P1 · **Effort:** Medium · **Dependencies:** GAP-01 · **Owner:** Backend + Frontend

### GAP-13 — Tag / application-based workflow is mock-only
- **Module:** Tags
- **Category:** workflow / data model
- **Severity:** Medium
- **Current:** Tags page is static mock (`mockData.ts`). Cannot assign tags to assets, scan by tag (e.g. "CoreBanking"), filter/export/dashboard by tag. Accounts have no tag field in the deployed schema (`account.schema.ts`).
- **Expected:** Full tag lifecycle integrated with scan scoping, filtering, export, dashboard.
- **Impact:** No application-centric governance.
- **Remediation:** Tag model + asset/account associations + tag-scoped scans/reports.
- **Priority:** P2 · **Effort:** Medium · **Dependencies:** GAP-01, GAP-04 · **Owner:** Backend + Frontend

### GAP-14 — Findings / Rules / Exceptions / Password-Policy are mock-only
- **Module:** Findings, Rules, Exceptions, Policies
- **Category:** scan logic / backend
- **Severity:** High
- **Current:** All four are static `StaticWorkspace` pages from `mockData.ts`. No rules engine, no password-policy evaluation, no exceptions workflow in the deployed backend. (Python `rules_engine/`, `services/password_policy_rules.py` exist, not deployed.)
- **Expected:** Deterministic classification rules, password-policy findings, exception approvals with expiry — all live.
- **Impact:** "Privilege classification" — the product's namesake — is not actually computed in the deployed app (privilege values are hardcoded in mock data).
- **Remediation:** Connect/port rules + policy engines.
- **Priority:** P1 · **Effort:** Large · **Dependencies:** GAP-01 · **Owner:** Backend

### GAP-15 — Real-time gateway is a stub
- **Module:** Realtime
- **Category:** backend / UX
- **Severity:** Medium
- **Current:** `DiscoveryGateway` only handles `discovery:subscribe`; it never emits progress/events, and nothing publishes to it (`discovery.gateway.ts`). Frontend never subscribes.
- **Expected:** Live scan progress / per-target status pushed to UI.
- **Impact:** No live progress; scans appear instantly "complete."
- **Remediation:** Emit job events; subscribe in Scans UI.
- **Priority:** P2 · **Effort:** Medium · **Dependencies:** GAP-05 · **Owner:** Backend + Frontend

### GAP-16 — UI/UX: scan form, validation, states missing
- **Module:** Frontend (Scans, global)
- **Category:** UI
- **Severity:** High
- **Current:** Scans page = one button + a read-only table (`App.tsx` `LiveScans`). No scan-creation form, no type/platform/scope/connector/credential fields, no progress, no per-target rows, no retry. Several nav items (Connectors, Findings, Rules, etc.) link to mock pages, implying functionality that isn't there. Error display is a bare `String(err)` ("API request failed with 500"); no success toasts; tables show generic "empty" text without cause.
- **Expected:** Guided scan wizard; meaningful empty/loading/error/success states; retry; per-target results.
- **Impact:** Misleading UX; operators cannot drive real workflows.
- **Remediation:** Build scan wizard + state handling once backend exists.
- **Priority:** P1 · **Effort:** Large · **Dependencies:** GAP-02..06 · **Owner:** Frontend

### GAP-17 — Scan result display lacks required fields
- **Module:** Scans results
- **Category:** UI / data model
- **Severity:** High
- **Current:** Result row shows scope/status/progress/trigger/created/success/failed/skipped/platforms/evidence-string, but values are mock; no scan type, connector used, credentialed-vs-unauthenticated flag, per-target list, or skip/failure reasons.
- **Expected:** Full result detail incl. scan type, platform, asset, connector, auth mode, per-target status with reasons, discovered/privileged counts, policy findings, evidence summary.
- **Impact:** Results not actionable or auditable.
- **Remediation:** Extend scan/result model + detail view.
- **Priority:** P1 · **Effort:** Medium · **Dependencies:** GAP-05 · **Owner:** Backend + Frontend

### GAP-18 — Orphaned/dead legacy code referencing missing modules
- **Module:** Frontend hygiene
- **Category:** data model / maintainability
- **Severity:** Low
- **Current:** `frontend/src/api/client.ts` and `endpoints.ts` import `axios`, `qs`, `react-hot-toast`, `@/lib/auth` — none of which exist in `package.json` or `src/lib` (empty). Legacy pages (`Scans.tsx`, `Connectors.tsx`, `Assets.tsx`, `AccountDetail.tsx`, `AssetDetail.tsx`) import the dead `@/api/endpoints`. They survive only because `tsconfig.json` `include` is narrowed to App/main/store, and they aren't imported by `App.tsx`.
- **Expected:** Either reconnect these to the real API or remove them.
- **Impact:** Confusion, false sense of capability, build fragility if `include` changes.
- **Remediation:** Remove or reintegrate dead files (later, not now).
- **Priority:** P3 · **Effort:** Small · **Dependencies:** none · **Owner:** Frontend

### GAP-19 — Documentation contradicts deployed reality
- **Module:** Docs
- **Category:** governance
- **Severity:** Medium
- **Current:** `README.md` describes FastAPI/PostgreSQL/Celery with full collectors/scheduler/vault as "first working version," while the deployed app is NestJS/MongoDB with only auth+accounts+mock scan. The in-app Help page even lists a *different* "allowed stack" (NestJS) (`App.tsx` `Help`).
- **Expected:** Docs reflect the actual deployed architecture and current capability honestly.
- **Impact:** Stakeholders may believe capabilities exist that don't; risk in audit/sign-off.
- **Remediation:** Reconcile docs to deployed state after architecture decision.
- **Priority:** P2 · **Effort:** Small · **Dependencies:** GAP-01 · **Owner:** Architecture/Docs

### GAP-20 — Default admin auto-seed with weak fallback secrets
- **Module:** Auth
- **Category:** security
- **Severity:** Medium
- **Current:** On boot, an admin is seeded with `ADMIN_PASSWORD` defaulting to `ChangeMe!123`, and the token-signing `AUTH_SECRET` defaults to `dev-only-change-this-auth-secret` (`auth.service.ts`). Hand-rolled HMAC token format (not standard JWT) with no rotation/JTI. `mustChangePassword` is set, but there's no lockout/rate-limiting on login.
- **Expected:** Fail-closed on missing secrets in non-dev; enforce strong secrets; consider vetted JWT lib; brute-force protection.
- **Impact:** Weak defaults could ship to staging/prod (note: the Python side already had a "refuse mock collector in staging/prod" guard per git log — equivalent guardrails are absent here).
- **Remediation:** Require secrets via env validation; add login throttling.
- **Priority:** P1 · **Effort:** Small · **Dependencies:** none · **Owner:** Security

---

## C. Scan-Type & Platform Selection Assessment

Assessed against the **deployed (NestJS) application** — the only thing that actually runs. The single "Launch full scan" button accepts no parameters and writes a fixed mock dataset.

| Capability | Status | Note |
|---|---|---|
| Windows-only scan | **Not Supported** | No platform selector |
| Windows Server-only scan | **Not Supported** | Server vs Desktop not separately selectable |
| Windows Desktop-only scan | **Not Supported** | — |
| RHEL-only scan | **Not Supported** | — |
| Solaris-only scan | **Not Supported** | Always "target not configured" |
| AIX-only scan | **Not Supported** | Always "target not configured" |
| Oracle-only scan | **Not Supported** | Always "target not configured" |
| MSSQL-only scan | **Not Supported** | Always "target not configured" |
| MySQL-only scan | **Not Supported** | — |
| MongoDB-only scan | **Not Supported** | — |
| Selected-platform scan | **Not Supported** | No multi-select |
| All-platform scan | **Partially Supported** | One button covers a *fixed* 5 platforms via mock upsert; 4 always skipped; no real collection occurs |

**Scan types** (basic uncredentialed / credentialed / password-policy / privileged / interactive-classification / full): **Not Supported** in the deployed app (no type parameter exists).

> For contrast, the **decommissioned Python backend** supports platform->collector routing and credentialed/connector-based scanning for all listed platforms (`collectors/__init__.py`, `scan_service.py`). The capability exists in the codebase but is **not deployed**.

---

## D. Remediation Plan

### Phase 0 (decision gate, precedes everything)
- **Objective:** Choose the target backend — (A) re-wire the Python/FastAPI service, or (B) port capabilities into NestJS.
- **Tasks:** Architecture decision (ADR); update `docker-compose.yml`/`Dockerfile` accordingly; reconcile docs (GAP-19).
- **Outcome:** A single, real backend powering the app.
- **Validation:** App boots with a backend that exposes scans/collectors/connectors endpoints.

> Recommendation: **Option A (re-wire Python backend)** unless there is a hard mandate for the NestJS stack — it already implements every Critical gap below. Option B means rebuilding all of it.

### Phase 1 — Critical production blockers
- **Objective:** Make discovery real and access-controlled.
- **Tasks:** GAP-01, GAP-02, GAP-03, GAP-04, GAP-05, GAP-06, GAP-08, GAP-20.
- **Modules:** backend orchestration, collectors, auth, scans UI.
- **Outcome:** User can run a real, scoped, typed, platform-targeted scan; only authorized roles can launch.
- **Dependencies:** Phase 0.
- **Validation:** Platform-specific + scan-type + RBAC tests (Section E).

### Phase 2 — High-priority workflow & logic
- **Objective:** Complete the operational scan lifecycle.
- **Tasks:** GAP-07, GAP-10, GAP-11, GAP-14, GAP-17, GAP-16.
- **Outcome:** Validated, connector-routed, schedulable scans with real classification and per-target results.
- **Dependencies:** Phase 1.
- **Validation:** Connector-based, scheduled, invalid-selection tests.

### Phase 3 — Reporting, UX & governance
- **Objective:** Make output authoritative and auditable.
- **Tasks:** GAP-09, GAP-12, GAP-13, GAP-15.
- **Outcome:** Filter-parity exports, evidence-backed reports, tag-scoped operations, audit trail.
- **Dependencies:** Phase 2.
- **Validation:** Export-filter + tag-scope + audit tests.

### Phase 4 — Hardening & optimization
- **Objective:** Production polish.
- **Tasks:** GAP-18, GAP-19, login throttling/lockout, secrets management review, performance/pagination on large estates, replica-safe job state.
- **Outcome:** Clean, documented, hardened build.
- **Validation:** Security regression + load tests.

---

## E. Test Plan (to validate fixes later)

**Platform-specific scan tests** — For each of Windows Server, Windows Desktop, RHEL, Solaris, AIX, Oracle, MSSQL, MySQL, MongoDB: launch a single-platform scan and assert only that platform's collector runs and only matching accounts appear in results/export.

**Scan-type selection tests** — For each type (uncredentialed/credentialed/password-policy/privileged/interactive/full): assert the collector behavior and result fields match the type (e.g., uncredentialed yields no privilege detail; password-policy yields policy findings).

**Invalid-selection tests** — Empty scope -> rejected; platform/asset mismatch -> rejected; credentialed scan with no credential -> rejected with clear message; unsupported platform -> shown as unsupported, not silently skipped.

**Connector-based scan tests** — Scan via a selected connector; connector offline -> job fails gracefully with status; connector restricted to scope/profile -> out-of-scope target refused.

**Tag-based scan tests** — Tag assets "CoreBanking," scan by tag, assert only tagged assets scanned, filtered, and exported.

**Scheduled scan tests** — Create "Windows Server privileged scan, Sundays 02:00"; verify next-run computed, run executes at time, last-run result recorded.

**Export filter tests** — Apply UI filters (platform/type/tags/assets), export, assert exported rows == filtered set (parity); verify failed-scan, privileged, password-policy, full-inventory, evidence-backed report variants.

**RBAC / security tests** — operator cannot manage credentials/connectors/users; non-privileged role cannot view privileged findings or launch scans; export gated; all sensitive actions appear in audit log; tokens fail-closed without secrets; login throttled after N failures.

---

## F. Final Recommendation

- **Production readiness:** **Not production-ready.** The deployed application is a UI shell with a mock backend; it does not perform account discovery, privilege classification, scanning by type/platform/scope, connector routing, scheduling, real export, or RBAC.

- **Top 5 to fix first:**
  1. **GAP-01** — Deploy a real backend (Phase 0 decision; recommend re-wiring the existing Python backend).
  2. **GAP-08** — Enforce RBAC (roles guard) — critical for a security tool.
  3. **GAP-03 / GAP-02** — Platform selection and scan-type selection (the customer's named requirement).
  4. **GAP-05 / GAP-06** — Persisted real scans + collector routing (actual discovery).
  5. **GAP-12 / GAP-09** — Authoritative server-side exports + real audit logging (audit/GRC fitness).

- **Suggested next action:** Hold a short architecture decision meeting on Option A (re-wire FastAPI) vs Option B (port to NestJS), record it as an ADR, then execute Phase 1. Re-wiring the existing Python backend is the fastest path to closing all Critical gaps because that capability already exists in-repo.

- **Are code changes required later?** **Yes — substantial.** Closing the Critical/High gaps requires real backend wiring, new scan/platform/scope/connector/scheduler logic (or reconnection of the Python implementation), RBAC enforcement, server-side exports, audit logging, and a redesigned scan UI.

---

*Assessment-only deliverable. No application code, configuration, schema, UI, or API was modified in producing this report.*
