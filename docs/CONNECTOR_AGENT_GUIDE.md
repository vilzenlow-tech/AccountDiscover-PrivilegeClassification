# Connector and Agent Guide

Version date: 2026-06-28

## Two Connector Concepts

This codebase has two related but different concepts:

1. Protocol connectors: console records that describe how to reach assets by SSH, WinRM, or database protocol and which credential metadata to use.
2. Connector agents: standalone Python agents deployed in remote or segmented networks. They call the console outbound, poll jobs, execute local scans, and upload results.

## Protocol Connectors

Implemented:

- CRUD API under `/api/v1/connectors`.
- Connector kinds: `ssh`, `winrm`, `wmi`, `mysql`, `mssql`, `mongodb`, `oracle`, `postgresql`, `redis`.
- Connector options for protocol settings such as WinRM scheme/transport or database names/SSL options.
- Active/inactive state.
- Linked credential metadata.
- Test connection endpoint that checks connector kind, credential/vault secret resolution, and TCP reachability.

Used when:

- Backend workers scan assets directly from the central environment.
- Assets need platform-specific credentials and protocol options.

## Connector Agents

Implemented:

- Enrollment token generation.
- Agent self-enrollment using one-time registration token.
- Manual approval or auto-approve.
- Bearer token plus `X-Connector-ID` authentication.
- Heartbeat tracking and online/stale/offline computation.
- Console-managed settings.
- Job dispatch, polling, status update, cancellation, result chunk upload, result ingestion, and log upload.
- Token rotation and revocation.
- Standalone Python agent main loop.
- Windows WinRM scan execution in the standalone agent.

Partially implemented:

- Allowed scan profiles, modes, environments, and tags are stored in settings and partially enforced by the standalone executor.
- Offline queue fields exist in settings, but the current agent does not implement a durable encrypted result queue.
- Non-Windows agent target scanning returns success with zero accounts rather than real collection.
- Token rotation command handling in the agent loop is noted but not fully implemented.

Planned or not implemented:

- mTLS/certificate authentication.
- Packaged installers.
- Signed job payloads beyond checksum.
- Durable encrypted offline result queue.
- Agent auto-upgrade.
- Diagnostic upload endpoint separate from logs.

## Why Use an Agent

Use a connector agent when the central console cannot directly reach target assets due to network segmentation, remote sites, DMZs, or cloud/VPC isolation. The agent needs outbound HTTPS access to the console and local network access to targets.

## Communication Model

The agent initiates all console communication:

- `POST /api/v1/connector-agents/enroll`
- `GET /api/v1/connector-agents/enroll/status`
- `POST /api/v1/connector-agents/{id}/heartbeat`
- `GET /api/v1/connector-agents/{id}/config`
- `GET /api/v1/connector-agents/{id}/jobs/pending`
- `PATCH /api/v1/connector-agents/{id}/jobs/{job_id}/status`
- `POST /api/v1/connector-agents/{id}/results`
- `POST /api/v1/connector-agents/{id}/logs`

The code and docs describe outbound TCP 443 behavior. In development, the configured `CONSOLE_URL` may use another HTTPS endpoint or local port, but production should use HTTPS on 443 through nginx or an enterprise reverse proxy.

## Enrollment and Authentication

1. Admin generates an enrollment token.
2. Agent starts with `CONSOLE_URL` and `REGISTRATION_TOKEN`.
3. Agent posts host metadata and token to enroll.
4. Console creates a pending or approved agent.
5. If auto-approved, the agent receives a bearer token immediately.
6. If manual approval is required, the agent polls enrollment status until approved.
7. Runtime calls require `Authorization: Bearer <token>` and `X-Connector-ID: <uuid>`.

Plaintext runtime tokens are returned only when issued or rotated. Token hashes are stored server-side as SHA-256 hashes.

## Heartbeat

The agent heartbeat includes:

- Agent timestamp and version.
- Status.
- Active jobs.
- Queued results count.
- Optional CPU, memory, disk, and error count.
- Additional OS/Python payload.

Console marks agents online, stale, or offline based on heartbeat recency.

## Job Polling and Result Upload

Console-side jobs are created under an agent. The agent polls pending jobs, verifies payload checksum, enforces local policy, accepts the job, executes targets, uploads compressed base64 result chunks, and updates status.

Completed result ingestion can create normalized accounts and privilege findings from uploaded agent account data.

## Connector Scope Assignment

ConnectorAgentSettings stores:

- Allowed scan profiles.
- Allowed scan modes.
- Allowed environments.
- Allowed and denied tags.
- Max targets per job.

Current enforcement is strongest inside the standalone agent for scan mode, profile, and max target count. Environment/tag enforcement should be verified before relying on it as a production control.

## Offline Behavior

Implemented:

- HTTP retry adapter and exponential backoff for enrollment/heartbeat errors.
- Status goes stale/offline when heartbeats stop.

Not implemented:

- Durable encrypted offline result queue despite settings fields and older design docs.

## Troubleshooting Connector Issues

- Pending approval: approve the agent or use auto-approve token for trusted automation.
- Heartbeat missing: check `CONSOLE_URL`, TLS trust, proxy, bearer token, `X-Connector-ID`, and firewall egress.
- Job not picked up: verify agent enabled, not revoked, local policy allows the job, and max concurrent jobs not reached.
- Result rejected: check chunk checksum, gzip JSON payload, and job ID.
- Windows scan failed: verify pywinrm, WinRM service, port 5985/5986, transport, certificate validation, and credential.
- Non-Windows agent scan returns no accounts: current standalone agent lacks real non-Windows scanner implementations.
