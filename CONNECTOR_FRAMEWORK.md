# Connector/Agent Framework Architecture

## 1. Overview

The Connector/Agent Framework enables secure, distributed scanning across segmented or remote environments. Each connector:
- **Initiates outbound HTTPS connections** to the console (port 443 only)
- **Never receives inbound connections** from the console
- **Polls for jobs** from the console
- **Executes scans locally** with console-provided configuration
- **Uploads results securely** back to the console

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    CENTRAL CONSOLE                          │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐ │
│  │  Web UI      │  │  REST APIs   │  │  Job Queue/Queue  │ │
│  │  Dashboard   │  │  &           │  │  Results Store    │ │
│  │              │  │  WebSocket   │  │                   │ │
│  └──────────────┘  └──────────────┘  └───────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                    ↑
                    │ OUTBOUND ONLY
                    │ HTTPS/TLS 443
                    │
        ┌───────────┴──────────┬──────────────┬─────────────┐
        │                      │              │             │
┌─────────────────┐  ┌──────────────────┐  ┌────────────────┐
│   CONNECTOR 1   │  │  CONNECTOR 2     │  │  CONNECTOR N   │
│                 │  │                  │  │                │
│ ┌─────────────┐ │  │ ┌──────────────┐ │  │ ┌────────────┐ │
│ │Job Executor │ │  │ │Job Executor  │ │  │ │Job Executor│ │
│ │             │ │  │ │              │ │  │ │            │ │
│ │SSH/WinRM    │ │  │ │SSH/WinRM     │ │  │ │SSH/WinRM   │ │
│ │Scanner      │ │  │ │Scanner       │ │  │ │Scanner     │ │
│ └─────────────┘ │  │ └──────────────┘ │  │ └────────────┘ │
│                 │  │                  │  │                │
│ ┌─────────────┐ │  │ ┌──────────────┐ │  │ ┌────────────┐ │
│ │Config Cache │ │  │ │Config Cache  │ │  │ │Config Cache│ │
│ │Result Queue │ │  │ │Result Queue  │ │  │ │Result Queue│ │
│ └─────────────┘ │  │ └──────────────┘ │  │ └────────────┘ │
└─────────────────┘  └──────────────────┘  └────────────────┘
```

## 2. Connector Lifecycle

```
1. INSTALLATION & ENROLLMENT
   - Generate registration token in console
   - Deploy connector agent
   - Agent registers with enrollment token → receives connector_id + cert
   
2. HEARTBEAT & CONFIG SYNC
   - Agent polls heartbeat endpoint every N seconds (configurable, default 30s)
   - Console sends heartbeat + pending settings
   - Agent caches config locally (encrypted)
   
3. JOB POLLING
   - Agent polls job endpoint every M seconds (configurable, default 10s)
   - Console returns pending jobs for this connector
   - Agent validates job signature and scope
   
4. JOB EXECUTION
   - Agent executes job according to config and scope
   - Uploads progress updates (optional)
   - Uploads results on completion
   
5. RESULT UPLOAD
   - Agent uploads results in chunks if large
   - Results encrypted before transmission
   - Console acknowledges receipt → agent cleans local copy
   
6. OFFLINE RESILIENCE
   - If console unreachable, agent queues results locally
   - Automatic retry with exponential backoff
   - Safe deduplication on reconnection
   
7. REVOCATION/DISABLE
   - Console revokes certificate/token
   - Agent detects revocation on next heartbeat
   - Agent stops accepting jobs, attempts clean shutdown
```

## 3. Communication Model

### Outbound HTTPS Only (Port 443)

```
CONNECTOR → CONSOLE (TCP 443, HTTPS)

All traffic initiated by connector:
- Heartbeat polling      (GET /api/v1/connectors/{id}/heartbeat)
- Config pull            (GET /api/v1/connectors/{id}/config)
- Job pull               (GET /api/v1/connectors/{id}/jobs)
- Job status update      (PATCH /api/v1/connectors/{id}/jobs/{job_id})
- Result upload          (POST /api/v1/connectors/{id}/results)
- Log upload             (POST /api/v1/connectors/{id}/logs)
- Diagnostic upload      (POST /api/v1/connectors/{id}/diagnostics)
```

### TLS Security

```
Mutual TLS (mTLS):
- Console: trusted CA certificate (self-signed or enterprise CA)
- Connector: client certificate (issued at enrollment)
- Connector validates console certificate pinning (optional but recommended)
- All traffic encrypted with TLS 1.3+

OR Token-Based + TLS:
- Console: standard HTTPS certificate
- Connector: bearer token (rotated periodically)
- Token stored encrypted locally
- Console validates token signature
```

## 4. Security Model

### Connector Identity
- **Unique connector_id**: UUID generated at enrollment
- **Certificate-based**: Client certificate for mTLS (preferred)
- **Token-based**: JWT token with expiry and rotation
- **Scope tags**: Asset tags and environments connector can access

### Data Protection
- **In transit**: TLS 1.3+, AEAD cipher suites (AES-GCM-256)
- **At rest (connector)**: Encrypted config cache, encrypted result queue
- **Sensitive data**: Credentials never stored on connector, retrieved from vault at scan time
- **Audit**: All connector actions logged to console audit log

### Local Security (Connector)
```
File Structure:
/opt/connector/
├── bin/                    # Binary/executable
├── config/
│   ├── connector.conf      # Encrypted config cache
│   ├── cert.pem            # Client certificate
│   └── ca-bundle.pem       # Console CA certificate (pinned)
├── cache/
│   ├── .encrypted_results  # Encrypted pending results
│   └── .encrypted_queue    # Encrypted job queue
├── logs/
│   ├── connector.log       # Sanitized logs
│   └── audit.log           # Local audit trail
└── var/
    └── run/                # Runtime state, lock files

Permissions:
- All config files: 600 (owner read/write only)
- Binary: 755 (owner rwx, others rx)
- Logs: 640 (owner rw, group r)
```

## 5. Connector Registration Flow

```
STEP 1: GENERATE TOKEN (Console Admin)
  Console → Generate registration token
  Token: uuid, expires_in: 3600, scope: scope_id
  Displayed once to admin
  
STEP 2: DEPLOY CONNECTOR
  Admin downloads agent binary
  Admin sets env: CONSOLE_URL, REGISTRATION_TOKEN
  Agent starts
  
STEP 3: SELF-REGISTER (Agent)
  Agent → POST /api/v1/connectors/enroll
  {
    "registration_token": "token",
    "hostname": "system-hostname",
    "platform": "linux|windows|macos",
    "version": "1.0.0",
    "location": "office-1"
  }
  
STEP 4: APPROVE & ISSUE CERT (Console)
  Admin reviews enrollment request
  Console issues client certificate
  Console stores connector metadata
  
STEP 5: AGENT RECEIVES CERT & ID
  Agent → GET /api/v1/connectors/enroll/status?token=token
  Response:
  {
    "connector_id": "uuid",
    "certificate": "-----BEGIN CERT-----...",
    "ca_certificate": "-----BEGIN CERT-----...",
    "console_fingerprint": "sha256:...",
    "status": "approved"
  }
  
STEP 6: AGENT CONFIGURED & READY
  Agent caches certificate + CA
  Agent starts polling heartbeat/jobs
  Console shows connector as "online"
```

## 6. Job Execution Model

### Job Types

```
1. BASIC DISCOVERY
   No credentials required
   Scan network, OS info, basic service discovery
   
2. CREDENTIALED DISCOVERY
   Requires credential_id (pre-stored in console vault)
   Agent retrieves credential at scan time (request with scope)
   Full privilege discovery
   
3. BULK JOB
   Multiple assets/targets in single job
   Agent executes serially or with concurrency limit
   
4. SCHEDULED JOB
   Recurring based on cron expression
   Console marks as ready, agent polls and executes
   
5. ON-DEMAND JOB
   Ad hoc, triggered from console UI
   User selects assets, click "Launch Scan"
   Agent polls and picks up immediately
```

### Job State Machine

```
PENDING       → Agent polls, picks up job
ACCEPTED      → Agent validated scope, accepted execution
RUNNING       → Agent executing scan
PARTIAL_SUCCESS → Some targets failed, some succeeded
SUCCESS       → All targets completed successfully
FAILED        → Job failed, error logged
CANCELLED     → Console or agent cancelled
TIMED_OUT     → Job exceeded max_timeout
```

### Result Format

```json
{
  "job_id": "uuid",
  "connector_id": "uuid",
  "status": "success|partial_success|failed",
  "started_at": "2026-04-26T21:00:00Z",
  "completed_at": "2026-04-26T21:15:30Z",
  "duration_ms": 930000,
  
  "summary": {
    "total_targets": 10,
    "successful": 9,
    "failed": 1,
    "skipped": 0
  },
  
  "target_results": [
    {
      "asset_id": "uuid",
      "hostname": "server-01.internal",
      "status": "success",
      "discovered_accounts": 45,
      "discovered_entitlements": 280,
      "error": null
    }
  ],
  
  "evidence": {
    "raw_output": "...",
    "parsed_data": {...}
  },
  
  "connector_version": "1.0.0",
  "execution_summary": {
    "total_scan_time_ms": 930000,
    "avg_target_time_ms": 93000
  }
}
```

## 7. Connector Configuration

```json
{
  "connector_id": "uuid",
  "console_url": "https://console.internal:443",
  "console_fingerprint": "sha256:...",
  
  "polling": {
    "heartbeat_interval_seconds": 30,
    "job_poll_interval_seconds": 10,
    "config_refresh_interval_seconds": 3600
  },
  
  "retry": {
    "max_retries": 5,
    "backoff_base_seconds": 2,
    "backoff_max_seconds": 300
  },
  
  "execution": {
    "job_timeout_seconds": 3600,
    "max_concurrent_jobs": 2,
    "result_chunk_size_mb": 50
  },
  
  "security": {
    "certificate_path": "/opt/connector/config/cert.pem",
    "ca_certificate_path": "/opt/connector/config/ca-bundle.pem",
    "local_encryption_key": "kms:vault-path/connector-key",
    "verify_console_certificate": true,
    "verify_console_fingerprint": true
  },
  
  "storage": {
    "encrypted_queue_max_mb": 500,
    "result_retention_hours": 72,
    "log_retention_days": 30
  },
  
  "proxy": {
    "enabled": false,
    "url": "http://proxy.internal:3128",
    "username": "connector",
    "password": "vault:...",
    "no_proxy": "localhost,127.0.0.1,.internal"
  },
  
  "logging": {
    "level": "info",
    "format": "json",
    "sanitize_secrets": true
  },
  
  "scope": {
    "allowed_tags": ["production", "linux"],
    "allowed_environments": ["prod", "staging"],
    "denied_tags": ["do-not-scan"],
    "max_targets_per_job": 100
  },
  
  "allowed_scan_profiles": ["fast", "standard"],
  "enabled": true
}
```

## 8. Result Upload & Deduplication

```
UPLOAD FLOW:
1. Agent completes job
2. Agent encrypts result locally
3. Agent chunks result (if > chunk_size)
4. Agent → POST /api/v1/connectors/{id}/results
   {
     "job_id": "uuid",
     "chunk_index": 0,
     "chunk_count": 3,
     "data": "encrypted_base64_data",
     "checksum": "sha256:..."
   }
5. Console receives chunk, verifies checksum
6. Console → 202 Accepted (or 206 Partial Content)
7. Agent retries if necessary, exponential backoff
8. Console acknowledges final chunk → 200 OK
9. Agent deletes local result copy

DEDUPLICATION (on reconnection):
- Each result has unique job_id + checksum
- Console checks if result already received
- If duplicate detected, console returns 202 (already processed)
- Agent can safely retry without concern
```

## 9. Health & Monitoring

```json
{
  "connector_id": "uuid",
  "hostname": "connector-1.internal",
  "status": "online|offline|disabled|error",
  "version": "1.0.0",
  "platform": "linux",
  
  "heartbeat": {
    "last_seen": "2026-04-26T21:30:00Z",
    "next_expected": "2026-04-26T21:30:30Z",
    "stale_after_seconds": 120
  },
  
  "queue": {
    "pending_results_count": 2,
    "pending_results_size_mb": 145,
    "failed_jobs_count": 1,
    "retry_scheduled": true
  },
  
  "execution": {
    "active_jobs": 1,
    "total_jobs_processed": 456,
    "success_rate_percent": 98.5,
    "last_job_completed": "2026-04-26T21:25:00Z"
  },
  
  "certificate": {
    "expires_at": "2027-04-26T21:30:00Z",
    "expires_in_days": 365,
    "warning_issued": false
  },
  
  "resource_usage": {
    "cpu_percent": 2.5,
    "memory_mb": 128,
    "disk_free_mb": 5120
  },
  
  "recent_errors": [
    {
      "timestamp": "2026-04-26T21:20:00Z",
      "error": "credential_retrieval_failed",
      "job_id": "uuid"
    }
  ]
}
```

## 10. RBAC & Governance

```
ROLES:
- Connector Admin: Register, revoke, disable, update settings
- Connector Manager: Assign scope, tags, assign jobs
- Scan Analyst: View connector status, results (read-only)
- Auditor: View connector audit log

APPROVAL FLOWS:
- New connector registration: Requires Connector Admin approval
- Connector certificate rotation: Automatic, no approval
- Credential assignment to connector: Requires Connector Admin
- Scope/tag assignment: Requires Connector Manager
- Connector disable/revoke: Requires Connector Admin
```

## 11. Audit Logging

```
All connector actions logged:
- Enrollment: who, when, hostname, approval status
- Config changes: what changed, who changed, when
- Job dispatch: job_id, targets, when
- Job completion: status, results summary
- Certificate rotation: old expiry, new expiry
- Connector disable/revoke: reason, who
- Failed jobs: error, retry count
- Authentication failures: when, reason
```

---

## Implementation Phases

**Phase 1**: Database schema + backend APIs for registration, heartbeat, job queue
**Phase 2**: Frontend console pages for connector management
**Phase 3**: Example Python connector agent
**Phase 4**: Configuration sync, result upload, offline resilience
**Phase 5**: Advanced features (certificate rotation, vault integration, etc.)

