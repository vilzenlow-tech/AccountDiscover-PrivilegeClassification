# ADPCT Connector Agent — Installation & Operations Guide

This guide covers everything needed to install, enroll, and operate the ADPCT
Connector Agent on a remote machine.

---

## Table of Contents

1. [What is the Connector Agent?](#1-what-is-the-connector-agent)
2. [OS Support](#2-os-support)
   - [Agent Host (where the agent runs)](#agent-host-where-the-agent-runs)
   - [Scan Targets (what the agent can scan)](#scan-targets-what-the-agent-can-scan)
3. [Prerequisites](#3-prerequisites)
4. [Installation](#4-installation)
5. [Enrollment](#5-enrollment)
6. [Running the Agent](#6-running-the-agent)
   - [Foreground (dev/test)](#foreground-devtest)
   - [systemd Service (Linux production)](#systemd-service-linux-production)
   - [Windows Service (optional)](#windows-service-optional)
7. [Environment Variables Reference](#7-environment-variables-reference)
8. [Configuration File](#8-configuration-file)
9. [Connectivity Requirements](#9-connectivity-requirements)
10. [Lifecycle & Enrollment Flow](#10-lifecycle--enrollment-flow)
11. [Scanner Implementation Status](#11-scanner-implementation-status)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. What is the Connector Agent?

The Connector Agent is a lightweight Python daemon deployed in remote or
network-segmented environments. It bridges assets that the central ADPCT console
cannot reach directly.

**Key design principles:**

- **Outbound HTTPS only.** The agent initiates all connections to the console
  over port 443. It never opens a listening socket — no inbound firewall rules
  are needed.
- **Token-based identity.** Each agent receives a unique `connector_id` (UUID)
  and a rotating bearer token at enrollment. All API calls are authenticated.
- **Offline resilience.** If the console is unreachable, the agent queues
  results locally and retries with exponential backoff.
- **Read-only scanning.** Discovery collectors issue inspection-only
  commands/queries. No password resets, no privilege grants, no write
  statements.

---

## 2. OS Support

### Agent Host (where the agent runs)

The agent is written in pure Python 3.9+ with no OS-specific code. It runs on
any platform that supports Python:

| Operating System | Support | Recommended Deployment |
|---|---|---|
| **Linux** (any distro — RHEL, Ubuntu, Debian, SUSE, …) | ✅ Full | `systemd` service |
| **macOS** | ✅ Full | Dev/testing; `launchd` plist for production |
| **Windows Server / Windows 10+** | ✅ Full | Windows Service (NSSM or `sc.exe`) |

> **Linux is the recommended host OS** for production deployments because
> `systemd` provides automatic restart, journald logging, and tight filesystem
> permission control out of the box.

**Minimum requirements for the agent host:**

| Requirement | Minimum |
|---|---|
| Python | 3.9+ |
| CPU | 1 vCPU |
| RAM | 128 MB (idle); 256 MB during active scans |
| Disk | 1 GB (for local result queue and logs) |
| Network | Outbound TCP 443 to the ADPCT console |

---

### Scan Targets (what the agent can scan)

The agent dispatches to scanner workers based on the asset's `platform` field.
The following platforms are defined and will be supported:

#### Operating Systems (scanned via SSH or WinRM)

| Platform | Enum Value | Protocol | Connection Type |
|---|---|---|---|
| Red Hat Enterprise Linux | `rhel` | SSH | TCP 22 |
| CentOS / Rocky / AlmaLinux | `centos` | SSH | TCP 22 |
| Ubuntu Server | `ubuntu` | SSH | TCP 22 |
| SUSE Linux Enterprise Server | `sles` | SSH | TCP 22 |
| Oracle Solaris | `solaris` | SSH | TCP 22 |
| IBM AIX | `aix` | SSH | TCP 22 |
| HP-UX | `hpux` | SSH | TCP 22 |
| Windows Server / Windows Desktop | `windows` | WinRM / WMI | TCP 5985 / 5986 |

#### Databases (scanned via native protocol)

| Platform | Enum Value | Protocol | Default Port |
|---|---|---|---|
| MySQL / MariaDB | `mysql` | MySQL protocol | 3306 |
| Microsoft SQL Server | `mssql` | TDS (pyodbc / pymssql) | 1433 |
| MongoDB | `mongodb` | Mongo wire protocol | 27017 |
| Oracle Database | `oracle_db` | OCI / thin (cx_Oracle) | 1521 |
| PostgreSQL | `postgresql` | PG native (psycopg2) | 5432 |
| Redis | `redis` | Redis protocol (redis-py) | 6379 |

> **Note:** The connector agent itself only needs TCP 443 outbound to the
> console. The SSH/WinRM/DB connections originate from the agent host to the
> target assets, so the agent host must be able to reach them on the ports
> listed above.

---

## 3. Prerequisites

### On the ADPCT Console

- Admin account with the **Connector Admin** role
- Console accessible over HTTPS from the remote machine (port 443)

### On the Agent Host

- Python **3.9 or newer**
  ```bash
  python3 --version
  ```
- `pip` package manager
- Outbound TCP 443 to the console URL
- (Optional) `psutil` — enables CPU/memory metrics in heartbeats

---

## 4. Installation

### Step 1 — Copy the agent package

Copy the `connector-agent/` directory from the project repository to the target
machine. Any transfer method works (scp, rsync, git clone, artifact download):

```bash
# From your workstation
scp -r "connector-agent/" user@remote-host:/opt/adpct-agent/

# Or using rsync
rsync -av connector-agent/ user@remote-host:/opt/adpct-agent/
```

### Step 2 — Create a virtual environment

```bash
cd /opt/adpct-agent
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows
```

### Step 3 — Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Dependencies installed:**

| Package | Purpose |
|---|---|
| `requests` | HTTPS client for all console communication |
| `urllib3` | TLS transport, retry logic |
| `psutil` | (Optional) CPU / memory metrics in heartbeat |
| `cryptography` | Certificate handling (future mTLS support) |

### Step 4 — Set directory permissions (Linux)

```bash
# Create a dedicated non-root service user
sudo useradd -r -s /sbin/nologin -d /opt/adpct-agent adpct

# Lock down the directory
sudo chown -R adpct:adpct /opt/adpct-agent
sudo chmod 750 /opt/adpct-agent

# Config dir will be created automatically at first run with mode 700
```

---

## 5. Enrollment

Enrollment is a **one-time process** that registers the agent with the console
and issues it a unique identity and bearer token.

### Step 1 — Generate a registration token (console UI)

1. Log in to the ADPCT console as an admin
2. Navigate to **Connectors → New Connector → Generate Token**
3. Set an expiry (default 1 hour) and optionally enable **Auto-Approve**
4. Copy the token — it is displayed **only once**

> **Auto-Approve** skips the manual approval step. Use it in trusted
> environments (e.g., infrastructure-as-code deployments). For untrusted
> networks, leave it off and review the enrollment request manually.

### Step 2 — Run enrollment on the remote machine

```bash
export CONSOLE_URL=https://your-console.internal
export REGISTRATION_TOKEN=<paste-token-here>

python3 -m adpct_agent.main
```

**What happens next depends on whether Auto-Approve is enabled:**

#### Auto-Approve enabled
```
INFO  Enrolling with console at https://your-console.internal
INFO  Enrolled with auto-approve. connector_id=<uuid>
INFO  Config saved to /opt/adpct-agent/config/agent.json
INFO  Agent running. connector_id=<uuid>
```
The agent immediately starts heartbeating.

#### Manual approval required
```
INFO  Enrolling with console at https://your-console.internal
INFO  Enrollment pending admin approval (connector_id=<uuid>). Polling...
INFO  Still pending approval...
INFO  Still pending approval...
```
An admin must approve the connector in the console UI
(**Connectors → Pending → Approve**). Once approved:
```
INFO  Enrollment approved! connector_id=<uuid>
INFO  Config saved to /opt/adpct-agent/config/agent.json
INFO  Agent running. connector_id=<uuid>
```

### Step 3 — Verify in the console

After enrollment the connector appears in **Connectors** with:
- Status: `online` (heartbeating every 30 seconds)
- Hostname, IP, OS platform, and agent version populated automatically
- Ready to receive dispatched jobs

---

## 6. Running the Agent

### Foreground (dev/test)

```bash
source /opt/adpct-agent/.venv/bin/activate
export CONSOLE_URL=https://your-console.internal

python3 -m adpct_agent.main
```

Press `Ctrl+C` to trigger a graceful shutdown (drains active jobs).

---

### systemd Service (Linux production)

Create `/etc/systemd/system/adpct-agent.service`:

```ini
[Unit]
Description=ADPCT Connector Agent
Documentation=https://your-console.internal/docs/connector-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=adpct
Group=adpct
WorkingDirectory=/opt/adpct-agent
Environment=CONSOLE_URL=https://your-console.internal
Environment=ADPCT_HOME=/opt/adpct-agent
ExecStart=/opt/adpct-agent/.venv/bin/python -m adpct_agent.main
Restart=on-failure
RestartSec=15
StartLimitBurst=5
StartLimitIntervalSec=300
StandardOutput=journal
StandardError=journal
SyslogIdentifier=adpct-agent

# Harden the service
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/adpct-agent

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable adpct-agent
sudo systemctl start adpct-agent
sudo systemctl status adpct-agent

# Follow logs
sudo journalctl -u adpct-agent -f
```

> **First-time enrollment with systemd:** Run the enrollment command once
> manually as the `adpct` user (with `REGISTRATION_TOKEN` set) before enabling
> the service. Once `agent.json` is written, the service restarts without
> needing the token.
>
> ```bash
> sudo -u adpct bash -c \
>   'CONSOLE_URL=https://your-console.internal \
>    REGISTRATION_TOKEN=<token> \
>    /opt/adpct-agent/.venv/bin/python -m adpct_agent.main'
> # Ctrl+C once you see "Agent running."
> sudo systemctl start adpct-agent
> ```

---

### Windows Service (optional)

Install [NSSM](https://nssm.cc) (Non-Sucking Service Manager), then:

```powershell
# Set the home directory via env var
$env:ADPCT_HOME = "C:\adpct-agent"
$env:CONSOLE_URL = "https://your-console.internal"

# Register service
nssm install adpct-agent "C:\adpct-agent\.venv\Scripts\python.exe" "-m adpct_agent.main"
nssm set adpct-agent AppDirectory "C:\adpct-agent"
nssm set adpct-agent AppEnvironmentExtra "CONSOLE_URL=https://your-console.internal" "ADPCT_HOME=C:\adpct-agent"
nssm set adpct-agent Start SERVICE_AUTO_START
nssm start adpct-agent
```

---

## 7. Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `CONSOLE_URL` | **Always** | Base URL of the ADPCT console (no trailing slash). Example: `https://console.internal` |
| `REGISTRATION_TOKEN` | **First boot only** | One-time enrollment token generated in the console UI. Not needed after enrollment. |
| `ADPCT_HOME` | Optional | Override the agent's home directory. Default: `/opt/adpct-agent` (Linux/macOS) |
| `CONNECTOR_ID` | Optional | Override the stored connector UUID. Useful for containerised or immutable deployments. |
| `CONNECTOR_TOKEN` | Optional | Override the stored bearer token. Use this to inject the token from a secrets manager (e.g., Vault, AWS Secrets Manager) instead of reading from `agent.json`. |
| `PROXY_URL` | Optional | HTTP/HTTPS proxy for console communication. Example: `http://proxy.internal:3128` |

---

## 8. Configuration File

After enrollment the agent writes a configuration cache to:

```
$ADPCT_HOME/config/agent.json    (mode 600, owner adpct)
```

**Example `agent.json`:**

```json
{
  "console_url": "https://your-console.internal",
  "connector_id": "a1b2c3d4-...",
  "heartbeat_interval": 30,
  "job_poll_interval": 10,
  "config_refresh_interval": 3600,
  "job_timeout_seconds": 3600,
  "max_concurrent_jobs": 2,
  "result_chunk_size_mb": 50,
  "retry_max_attempts": 5,
  "retry_backoff_base": 2,
  "retry_backoff_max": 300,
  "offline_queue_max_mb": 500,
  "result_retention_hours": 72,
  "verify_tls": true,
  "console_ca_bundle": null,
  "proxy_url": null,
  "log_level": "info",
  "sanitize_secrets": true,
  "max_targets_per_job": 100
}
```

> **Security note:** The bearer token (`token`) is intentionally excluded from
> `agent.json`. In this reference implementation it is held in memory and
> reloaded from the `CONNECTOR_TOKEN` env var. In production, integrate with
> your OS keystore, HashiCorp Vault, or AWS Secrets Manager.

### Console-pushed configuration

The console can update the agent's settings remotely via the
`PATCH /api/v1/connector-agents/{id}/settings` endpoint. The agent pulls the
latest config on every `config_refresh_interval` (default 1 hour) and merges
the following sections:

| Section | Settable fields |
|---|---|
| `polling` | `heartbeat_interval_seconds`, `job_poll_interval_seconds`, `config_refresh_interval_seconds` |
| `execution` | `job_timeout_seconds`, `max_concurrent_jobs`, `result_chunk_size_mb` |
| `retry` | `max_attempts`, `backoff_base_seconds`, `backoff_max_seconds` |
| `storage` | `offline_queue_max_mb`, `result_retention_hours` |
| `logging` | `level`, `sanitize_secrets` |
| `scope` | `allowed_scan_profiles`, `allowed_scan_modes`, `max_targets_per_job` |

---

## 9. Connectivity Requirements

The agent only needs **outbound TCP 443** to the console.

```
Remote machine  ──(TCP 443 HTTPS)──>  ADPCT Console
```

No inbound ports are required on the agent host. No firewall rule changes are
needed on the console side beyond the standard HTTPS listener.

### If the agent scans assets directly

When scanner workers are implemented the agent host will also need outbound
access to the target assets on their respective service ports:

| Asset type | Outbound port needed (from agent host) |
|---|---|
| Linux / Unix / AIX / Solaris / HP-UX | TCP 22 (SSH) |
| Windows | TCP 5985 (WinRM HTTP) or TCP 5986 (WinRM HTTPS) |
| MySQL / MariaDB | TCP 3306 |
| Microsoft SQL Server | TCP 1433 |
| MongoDB | TCP 27017 |
| Oracle Database | TCP 1521 |
| PostgreSQL | TCP 5432 |
| Redis | TCP 6379 |

### Proxy support

If the agent host reaches the console via an HTTP/HTTPS proxy, set:

```bash
export PROXY_URL=http://proxy.internal:3128

# Or in agent.json / pushed from console:
# "proxy_url": "http://proxy.internal:3128"
# "no_proxy": "localhost,127.0.0.1,.internal"
```

### TLS verification

TLS verification is **on by default** (`verify_tls: true`). If the console uses
a private CA certificate, provide its path:

```bash
# In agent.json
"console_ca_bundle": "/opt/adpct-agent/config/ca-bundle.pem"
```

> Never set `verify_tls: false` in production.

---

## 10. Lifecycle & Enrollment Flow

```
STEP 1  Admin generates a registration token in the console UI
        └── Token is single-use, time-limited (default 1 h)

STEP 2  Agent starts with CONSOLE_URL + REGISTRATION_TOKEN
        └── POST /api/v1/connector-agents/enroll
            Body: hostname, IP, OS platform, OS version, agent version

STEP 3a  Auto-approve ON  →  Console returns connector_id + bearer token
STEP 3b  Auto-approve OFF →  Console returns connector_id, status=pending
                              Agent polls GET /api/v1/connector-agents/enroll/status
                              every 10 s until admin approves in the UI

STEP 4  Agent saves connector_id to agent.json
        Token held in memory (or injected via CONNECTOR_TOKEN)

STEP 5  Main polling loop begins:
        ┌──────────────────────────────────────────────────────────┐
        │  Every heartbeat_interval (default 30 s):               │
        │    POST /api/v1/connector-agents/{id}/heartbeat         │
        │    → Reports CPU, memory, disk, active jobs, version    │
        │    → Receives any console commands (stop, rotate_token) │
        │                                                          │
        │  Every config_refresh_interval (default 1 h):           │
        │    GET /api/v1/connector-agents/{id}/config             │
        │    → Merges updated settings                            │
        │                                                          │
        │  Every job_poll_interval (default 10 s):                │
        │    GET /api/v1/connector-agents/{id}/jobs/pending       │
        │    → Validates + executes each job in a thread          │
        │    → Uploads result chunks on completion                │
        │    → Streams logs to console                            │
        └──────────────────────────────────────────────────────────┘

STEP 6  Revocation / disable (from console):
        └── Agent receives 403 on next heartbeat
            Logs the reason, stops accepting jobs, shuts down
```

---

## 11. Scanner Implementation Status

| Capability | Status |
|---|---|
| Enrollment, heartbeat, config sync | ✅ Implemented |
| Job polling, status updates, cancellation | ✅ Implemented |
| Result upload (chunked, gzip, sha256 verified) | ✅ Implemented |
| Log streaming to console | ✅ Implemented |
| Token rotation | ✅ Implemented |
| Revocation detection | ✅ Implemented |
| **SSH scanner** (Linux/Unix/AIX/Solaris) | 🔲 Planned — Phase 3 |
| **WinRM / WMI scanner** (Windows) | 🔲 Planned — Phase 3 |
| **MySQL / MariaDB scanner** | 🔲 Planned — Phase 3 |
| **MSSQL scanner** | 🔲 Planned — Phase 3 |
| **MongoDB scanner** | 🔲 Planned — Phase 3 |
| **Oracle DB scanner** | 🔲 Planned — Phase 3 |
| **PostgreSQL scanner** | 🔲 Planned — Phase 3 |
| **Redis scanner** | 🔲 Planned — Phase 3 |
| Certificate-based auth (mTLS) | 🔲 Planned — Phase 5 |
| Encrypted local result queue | 🔲 Planned — Phase 4 |

> Until the platform-specific scanners are implemented, the `_scan_target()`
> method in `executor.py` returns a stub result (0 accounts discovered). The
> full communication infrastructure (enrollment, heartbeat, jobs, results, logs)
> is production-ready.

---

## 12. Troubleshooting

### Agent cannot reach the console

```
WARNING  Enrollment attempt 1 failed: ConnectionError. Retrying in 2s...
```

- Verify `CONSOLE_URL` is correct and reachable: `curl -v https://your-console.internal/api/v1/health`
- Check outbound TCP 443 firewall rules on the agent host
- If behind a proxy, set `PROXY_URL`
- If using a private CA, set `console_ca_bundle` in `agent.json`

---

### Enrollment token rejected (400)

```
ERROR  Enrollment failed: 400 Bad Request
```

- Token has expired (default 1 hour) — generate a new one in the console UI
- Token was already used — each token is single-use; generate a fresh one

---

### Agent stuck on "pending approval"

```
INFO  Still pending approval...
```

- Log in to the console as a **Connector Admin**
- Go to **Connectors → Pending** and approve the enrollment request
- The agent will detect approval within 10 seconds

---

### Heartbeat returns 403

```
WARNING  Heartbeat failed: 403 Forbidden
```

| Detail message | Cause | Action |
|---|---|---|
| `Connector has been revoked` | Admin permanently revoked the connector | Cannot recover — re-enroll with a new token |
| `Connector is disabled` | Admin temporarily disabled the connector | Re-enable in console UI |
| `Connector pending approval` | Not yet approved | Approve in console UI |

---

### Config file location

| Platform | Default path |
|---|---|
| Linux / macOS | `/opt/adpct-agent/config/agent.json` |
| Windows | `C:\adpct-agent\config\agent.json` |
| Custom | `$ADPCT_HOME/config/agent.json` |

---

### Viewing logs

```bash
# systemd
sudo journalctl -u adpct-agent -f

# Foreground
# Logs stream to stdout automatically

# Increase verbosity
export LOG_LEVEL=debug      # or set log_level: "debug" in agent.json
```

---

### Reset enrollment (start fresh)

```bash
# Stop the agent
sudo systemctl stop adpct-agent

# Delete saved config (forces re-enrollment on next start)
rm /opt/adpct-agent/config/agent.json

# Set new token and restart
sudo -u adpct bash -c \
  'CONSOLE_URL=https://your-console.internal \
   REGISTRATION_TOKEN=<new-token> \
   /opt/adpct-agent/.venv/bin/python -m adpct_agent.main'
```

---

*For architecture details see [CONNECTOR_FRAMEWORK.md](../CONNECTOR_FRAMEWORK.md).*  
*For the full project overview see [README.md](../README.md).*
