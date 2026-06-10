# ADPCT Architecture

## 1. High-level architecture

```
                    +---------------------------+
                    |      Enterprise SSO       |
                    |   (future: SAML / OIDC)   |
                    +-------------+-------------+
                                  |
                           (session / JWT)
                                  |
+---------------------+   +-------v--------+   +---------------------+
|  React + TS UI      <--->   FastAPI API   <--->   PostgreSQL 15+    |
|  (Vite)             |   | (FastAPI+Uvicorn|   | (assets, accounts, |
|  dashboard, assets, |   |   + Pydantic v2 |   |  findings, rules,  |
|  accounts, scans,   |   |   + SQLAlchemy  |   |  evidence refs,    |
|  rules, findings,   |   |   + Alembic)    |   |  audit log, users) |
|  audit, exports     |   +---+---------+---+   +---------------------+
+---------------------+       |         |
                              |         |
                       (task) |         | (vault client)
                              v         v
                      +-----------+  +---------------------------+
                      |  Celery   |  |  Credential Vault Service |
                      |  workers  |  |  - CyberArk adapter       |
                      |  + beat   |  |  - HashiCorp Vault adapter|
                      +---+-------+  |  - Azure Key Vault adapter|
                          |          |  - AWS Secrets adapter    |
                          |          |  - local encrypted store  |
                          |          +---------------------------+
                          |
           +--------------+--------------+
           |              |              |
           v              v              v
     +----------+   +----------+   +----------+
     | Unix SSH |   | WinRM /  |   | DB native|
     | collector|   | PS / WMI |   | drivers  |
     | (RHEL,   |   | collector|   | MySQL,   |
     | Solaris, |   | (Windows)|   | MSSQL,   |
     | AIX)     |   |          |   | Mongo    |
     +----+-----+   +----+-----+   +----+-----+
          |              |              |
          v              v              v
     +--------------------------------------+
     |        Target infrastructure         |
     |   (read-only, least-privileged)      |
     +--------------------------------------+
```

### Components

- **API / web layer (FastAPI):** RESTful, JWT-secured, RBAC-gated, all inputs
  validated with Pydantic v2. Serves both the React UI and external clients.
- **Persistence (PostgreSQL 15+):** Authoritative store for every domain
  entity. All raw evidence blobs are stored either in-row (JSONB) or linked to
  object storage by URI.
- **Background workers (Celery + beat, alternative APScheduler):** Execute
  discovery jobs, rule evaluation, delta computation, export generation, and
  scheduled scans. Workers are horizontally scalable.
- **Collectors:** Pluggable modules, one per platform. Each implements a
  `BaseCollector` interface and returns a uniform `CollectionResult`.
- **Rules engine:** Deterministic evaluator operating over normalized evidence.
  Rules are stored in PostgreSQL; YAML import/export is supported for GitOps
  workflows.
- **Credential vault service:** Abstracts credential retrieval behind a small
  interface. External vault adapters are preferred; the encrypted local store
  is an explicit fallback for pilots and air-gapped labs.
- **Frontend (React + TS, Vite):** Purely a consumer of the REST API. No
  secrets cross the browser. All sensitive fields are masked server-side.

## 2. Data flow: one scan

1. An analyst (or scheduler) launches a scan of a scope (an asset, a group, a
   profile target list, or "all enabled").
2. The API validates authorization, writes a `discovery_job` row, and enqueues
   one `run_collection` task per (asset, collector) tuple.
3. Each worker task:
   a. Resolves the credential via the vault service (scoped by asset, group,
      profile).
   b. Opens a read-only connection (SSH/WinRM/DB driver).
   c. Runs each evidence probe in the collector's probe list.
   d. Persists `discovery_results_raw` rows (one per probe) with exact command
      and raw output reference.
   e. Normalizes evidence into `accounts_normalized` and `account_entitlements`
      rows.
   f. Emits a per-asset `job_run` record with timing, status, and error
      buckets.
4. When all per-target tasks reach a terminal state, the orchestrator fires
   `evaluate_rules` for the job, which:
   a. Iterates every account in the job.
   b. Runs the rules engine against the account's normalized evidence plus any
      group/role transitive state.
   c. Writes `privilege_findings` rows with the matched rule, classification,
      confidence, direct-vs-inherited path, and an explanation string.
5. `compute_delta` compares this job's findings to the latest baseline for the
   same scope and writes `deltas` plus `notifications`.
6. The API exposes all of the above to the UI for review, filtering, export,
   and exception management.

## 3. Canonical account model

See also `backend/app/models/account.py` and `backend/app/schemas/account.py`.

| Field                 | Type                | Notes                                           |
| --------------------- | ------------------- | ----------------------------------------------- |
| account_id            | UUID (pk)           | stable within the platform                      |
| asset_id              | UUID (fk)           |                                                 |
| platform              | enum                | rhel/solaris/aix/windows/mysql/mssql/mongodb    |
| source_type           | enum                | local, ad, ldap, db-native, os-integrated, ... |
| account_name          | text                | as seen on the platform                         |
| principal_type        | enum                | human/service/shared/built-in/system/app/unknown|
| auth_source           | enum                | local/ad/ldap/db-native/os-integrated/unknown   |
| enabled_status        | enum                | enabled/disabled/locked/unknown                 |
| interactive_status    | enum                | interactive/non-interactive/unknown             |
| last_login            | timestamp, nullable | nullable if unavailable                         |
| last_login_source     | text                | which evidence produced last_login              |
| privilege_classification | enum             | see taxonomy below                              |
| privilege_confidence  | smallint 0-100      | rules engine score                              |
| risk_score            | smallint 0-100      | rules engine + modifiers (dormant, shared, ...) |
| owner                 | text, nullable      | business owner (from CMDB or manual)            |
| evidence_summary      | jsonb               | compact, UI-renderable                          |
| raw_evidence_refs     | jsonb               | pointers to `discovery_results_raw` rows        |
| discovered_at         | timestamp           |                                                 |
| updated_at            | timestamp           |                                                 |

Entitlements (groups, roles, sudoers, grants) are first-class rows linked to
the account, so the rules engine and UI can cite them individually.

## 4. Privilege classification taxonomy

| Classification              | Meaning                                                                             |
| --------------------------- | ------------------------------------------------------------------------------------ |
| full_admin                  | Unrestricted control of the asset (root, sysadmin, Local Administrators, mongo root) |
| admin_equivalent            | Effectively admin: broad sudo, securityadmin, userAdminAnyDatabase                   |
| operator_high_impact        | Operator-level but with serious blast radius (Backup Operators, db_backupoperator)   |
| delegated_admin             | Admin within a specific scope (db_owner on one DB, OU-scoped AD delegation)          |
| privileged_service          | Service/non-human account that carries any of the above privileges                   |
| sensitive_non_admin         | Not admin, but carries sensitive access (db_datareader on PII DB, read-all SELECT)   |
| dormant_privileged          | Any privileged class above, not used within the dormancy threshold                   |
| non_privileged              | Baseline end-user                                                                    |
| unknown_review_required     | Evidence incomplete or ambiguous; must not silently default to non_privileged        |

Risk score is computed on top of the classification and adjusted for modifiers
such as `shared`, `dormant`, `password_never_expires`, `mfa_not_enforced`,
`no_owner_assigned`, etc.

## 5. Rules engine

A **deterministic**, **explainable** engine:

- Rules are DB rows (or loaded from YAML) with `platform`, `when` predicate,
  `classify_as`, `confidence`, `risk_modifier`, and `explanation_template`.
- Predicates are small, declarative expressions over normalized evidence
  (`account.groups contains 'Administrators'`, `sudoers.any(broad=true)`,
  `server_roles contains 'sysadmin'`). This avoids running arbitrary code from
  rule definitions.
- Each account evaluation returns **all matching rules**, ranked; the
  highest-severity classification wins, but every match is recorded as a
  finding row so the UI can show "also matched rule X".
- Rules can be suppressed per-asset or per-account through the exception
  system, which itself is audit-logged and expirable.
- Historical evaluations are preserved (`privilege_findings` is append-only by
  design; no UPDATE).

## 6. Evidence and auditability

Every finding in the UI can be expanded to show:

- The exact command or query executed (`getent passwd`, `SHOW GRANTS FOR 'x'@'%'`,
  `Get-LocalGroupMember -Group Administrators`, ...).
- The raw output excerpt (bounded; full blob is stored in
  `discovery_results_raw`).
- The normalized parsed structure.
- The rule id, version, and explanation template rendered with the matched
  values.
- Whether privilege was direct or inherited, and the inheritance path (e.g.
  `user joe -> group db_admins -> role db_owner on db sales`).
- Reviewer state (`unreviewed | acknowledged | risk_accepted | remediated`).

## 7. Bulk onboarding and bulk scanning

- Targets can be imported via CSV/Excel or pasted from the UI with
  deduplication, validation, and platform-guessing hints.
- Scan profiles encode what to collect, timeouts, retry counts, concurrency,
  and credential-selection rules.
- Scans support retries, partial success, resume-failed-only, throttling, and
  blackout windows.

## 8. Security assumptions

- The application is deployed on trusted internal infrastructure, fronted by a
  reverse proxy that terminates TLS and enforces network zoning.
- Operators accessing the application authenticate with strong local credentials
  (v1) or SSO (v2).
- Discovery credentials are **never** in environment variables, config files,
  logs, exports, or API responses. They originate from a vault.
- Postgres is encrypted at rest, network-isolated, and not shared with any
  untrusted workload.
- Backups are encrypted and access-controlled.
- Rate limiting is applied to all auth endpoints.
- All privileged actions (login, scan create, config change, export, rule
  change, exception approval) are written to an append-only audit log.
- The application does not store target account passwords, does not attempt
  authentication with anything except the discovery credential, and does not
  attempt any state-changing action on the target.

## 9. Threat model highlights

| Threat                                        | Mitigation                                                                 |
| --------------------------------------------- | ---------------------------------------------------------------------------- |
| Credential theft from the app                 | Vault-only retrieval, just-in-time, short-lived; no plaintext at rest       |
| Compromised worker exfiltrates data           | Workers have DB write access only to result tables; no secret store access  |
| Malicious rule submission                     | Rule predicates are declarative, not code; RBAC-guarded; audited            |
| Prompt-injection-style data from targets      | Evidence is stored as raw text; rendering sanitizes HTML; rules operate on  |
|                                               | structured parsed fields, not raw strings                                   |
| Excessive network fan-out / DoS of targets    | Scan profile throttling, concurrency limits, blackout windows               |
| Analyst abuse of export                       | Role-based masking, export audit log, per-row provenance                    |
| Tampering with findings                       | Finding rows are append-only; reviewers create new reviewer-state rows      |

## 10. Known limitations

Listed in `README.md`.
