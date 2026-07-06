# Account Discovery and Privilege Classification Tool - Overview

Version date: 2026-06-28

## Purpose

This application is an Account Discovery and Privilege Classification Tool used to discover accounts from servers and databases, classify privileged/admin accounts, review evidence, support audit/governance, and assist remediation.

Primary users:

- IT Security and IAM teams reviewing privileged access.
- PAM teams identifying onboarding gaps and high-risk service accounts.
- System and database administrators validating local and database accounts.
- Auditors and application support teams reviewing evidence and operator actions.
- Developers maintaining collectors, APIs, and rules.

## Implemented Capabilities

- React/Vite frontend protected by local login and JWT session handling.
- FastAPI backend with SQLAlchemy models, Alembic migrations, PostgreSQL, Redis, Celery workers, and APScheduler.
- Asset inventory with CSV import, asset groups, discovery enablement, platform metadata, and connector assignment.
- Managed tags/applications with asset assignment and bulk assignment.
- Protocol connectors for SSH, WinRM/WMI, and database protocols, linked to credential metadata.
- Local encrypted credential vault provider using Fernet; external vault providers are stubs.
- On-demand scans for selected assets, groups, all enabled assets, and frontend inventory-matched hostname/IP lists.
- Scan types: `basic_discovery`, `credentialed_discovery`, `privileged_accounts`, `password_policy`, `interactive_classification`, `full_discovery`.
- Platform selectors for Windows, Windows Server/Desktop via asset tags, RHEL, Solaris, AIX, Oracle, MSSQL, MySQL, MongoDB, and all platform enum values accepted by API.
- Backend collector registry for RHEL, CentOS, Ubuntu, SLES, Solaris, AIX, HP-UX, Windows, MySQL, MSSQL, MongoDB, Oracle DB, PostgreSQL, and Redis.
- Privilege classification rules engine with seeded built-in rules and persisted privilege findings.
- Password policy snapshots, findings, exceptions, comparison, review state, and CSV/Excel exports.
- Account, finding, audit, report/export, user management, scan profile, and schedule APIs.
- Connector-agent framework for enrollment, approval, heartbeat, config pull, job polling, status updates, chunked result upload, and log upload.
- Standalone Python connector agent with implemented Windows WinRM scanner.

## Partially Implemented Capabilities

- Scheduled scans exist, but approval-required schedules are skipped and advanced; no approval queue is implemented.
- Connector-agent scope settings are stored and pulled by agents, but only local executor policy checks are implemented in the standalone agent.
- Connector-agent non-Windows scans return zero-account success placeholders rather than full collectors.
- Windows Server/Desktop selection relies on asset tag values such as `windows_role=server` or `windows_type=desktop`; there is no separate platform enum.
- Scan profile concurrency, retry, throttle, and mode fields are stored, but current Celery fan-out does not fully enforce profile concurrency/throttle settings.
- Password policy visibility varies by platform and target permissions; many collectors return partial policy data when commands or metadata are unavailable.

## Planned or Not Implemented

- Direct IP range or CIDR expansion at scan launch is not implemented. Targets must exist as assets first.
- SSO/SAML/OIDC is not implemented. Authentication is local email/password with JWT.
- CyberArk, HashiCorp Vault, Azure Key Vault, and AWS Secrets Manager adapters are not wired; they raise `NotImplementedError`.
- mTLS for connector agents is modeled but not implemented; agent auth uses bearer tokens plus `X-Connector-ID`.
- Tamper-evident audit storage and SIEM forwarding are not implemented.
- PAM onboarding gap workflow is not a first-class implemented module; it can be inferred from classifications and exports only.

## Supported Platforms

Implemented backend platform enum values:

- Windows: `windows`
- Linux/Unix: `rhel`, `centos`, `ubuntu`, `sles`, `solaris`, `aix`, `hpux`
- Databases: `mysql`, `mssql`, `mongodb`, `oracle_db`, `postgresql`, `redis`

Requested platform names map as follows: Windows Server/Desktop are selectors over `windows` assets, Oracle means `oracle_db`, and RHEL is one Linux collector family.

## Supported Account Types

- Local OS users, built-in users, system users, service accounts, shared accounts, human users, application accounts, and unknown principals.
- Windows local, domain, built-in, gMSA, computer, service, system, and unresolved SID principals where collector evidence allows.
- Database-native users, logins, roles, ACL users, and role memberships.

## Production Readiness Notes

The FastAPI backend is the active deployed stack in current `docker-compose.yml`. It has meaningful production hardening controls, including startup checks that block mock collectors and demo mode in production-like environments, security headers, JWT/RBAC enforcement, and audit logging.

Production readiness gaps remain:

- External vault providers need real client implementations before production use.
- Initial admin creation and secret management need a controlled operational runbook.
- Makefile backend commands are stale and still call `npm`.
- Existing root-level README/architecture docs contain some stale statements and should be superseded by these dated docs.
- Connector-agent installation exists as source code, not packaged installers.
- No data retention policy is enforced in code.

## High-Level Workflow

1. Configure application environment, database, Redis, TLS reverse proxy, and vault key/provider.
2. Seed roles, scan profiles, and built-in classification rules.
3. Create users and assign roles.
4. Create credentials and protocol connectors.
5. Add assets, assign tags/applications, and link connectors where needed.
6. Launch or schedule scans.
7. Workers collect evidence, normalize accounts and entitlements, and evaluate privilege and password-policy findings.
8. Analysts review accounts, findings, policy exceptions, target failures, and evidence.
9. Operators export reports and auditors review audit logs.
