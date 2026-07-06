# Agent Installation Guide

Version date: 2026-06-28

## Implementation Status

Connector-agent source code is implemented under `connector-agent/`, and a source-based installation path exists. There are no packaged MSI/RPM/DEB installers in the repository. This guide documents the implemented source-based deployment and labels planned parts.

## Prerequisites

Agent host:

- Python 3.9 or newer.
- `pip` and virtual environment support.
- Outbound HTTPS access to the console URL, normally TCP 443.
- Local network access from the agent host to scan targets.
- A dedicated OS service account is recommended.

Console:

- Admin access to generate enrollment tokens and approve agents.
- HTTPS endpoint reachable from the agent host.

## Supported Agent Operating Systems

Implemented Python agent code is cross-platform:

- Linux: recommended production host, typically via systemd.
- Windows: supported by Python and useful for WinRM proximity, but no Windows service wrapper is included.
- macOS: usable for development/testing.

## Required Network Connectivity

- Agent to console: outbound HTTPS to `CONSOLE_URL`, normally TCP 443.
- Agent to Windows targets: WinRM TCP 5985 or 5986.
- Agent to any future SSH/database targets: target-specific ports, but current standalone agent only has substantive Windows scanner logic.

## Files Required

- `connector-agent/adpct_agent/`
- `connector-agent/requirements.txt`

Optional existing reference:

- `connector-agent/AGENT_INSTALL.md`, but it currently overstates some future capabilities such as durable offline queues and broad platform scanning.

## Installation on Linux

```bash
sudo mkdir -p /opt/adpct-agent
sudo cp -R connector-agent/* /opt/adpct-agent/
cd /opt/adpct-agent
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Recommended runtime user:

```bash
sudo useradd -r -s /usr/sbin/nologin -d /opt/adpct-agent adpct
sudo chown -R adpct:adpct /opt/adpct-agent
sudo chmod 750 /opt/adpct-agent
```

## Enrollment

On the console:

1. Generate an enrollment token using `/api/v1/connector-agents/enrollment-tokens` or the UI.
2. Choose auto-approve only for trusted automation.
3. Copy the token once.

On the agent host:

```bash
export CONSOLE_URL=https://console.example.internal
export REGISTRATION_TOKEN=<one-time-token>
cd /opt/adpct-agent
. .venv/bin/activate
python -m adpct_agent.main
```

If auto-approved, the agent stores connector ID and bearer token in `/opt/adpct-agent/config/agent.json`. If pending, approve the agent in the console and let the agent continue polling.

## Configuration

Environment variables:

| Variable | Purpose |
|---|---|
| `CONSOLE_URL` | Console base URL, for example `https://console.example.internal`. |
| `REGISTRATION_TOKEN` | One-time enrollment token for first run. |
| `CONNECTOR_ID` | Optional override for enrolled connector ID. |
| `CONNECTOR_TOKEN` | Optional override for runtime bearer token. |
| `PROXY_URL` | Optional HTTP/HTTPS proxy URL. |
| `VERIFY_TLS=false` | Disables TLS verification. Use only for development. |
| `ADPCT_HOME` | Base directory; defaults to `/opt/adpct-agent`. |

Config cache:

- Path: `/opt/adpct-agent/config/agent.json` by default.
- Mode: code sets file mode `600`.
- Content includes connector ID, token, console URL, polling intervals, execution limits, proxy, and scope settings.

Note: the config file is permission-protected but not encrypted in the current implementation.

## systemd Service Example

Create `/etc/systemd/system/adpct-agent.service`:

```ini
[Unit]
Description=ADPCT Connector Agent
After=network-online.target
Wants=network-online.target

[Service]
User=adpct
Group=adpct
WorkingDirectory=/opt/adpct-agent
Environment=CONSOLE_URL=https://console.example.internal
ExecStart=/opt/adpct-agent/.venv/bin/python -m adpct_agent.main
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Start and enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now adpct-agent
sudo systemctl status adpct-agent
```

## Start, Stop, Restart

```bash
sudo systemctl start adpct-agent
sudo systemctl stop adpct-agent
sudo systemctl restart adpct-agent
journalctl -u adpct-agent -f
```

Foreground development run:

```bash
CONSOLE_URL=https://console.example.internal python -m adpct_agent.main
```

## Verify Heartbeat

Console checks:

- Agent status moves from approved to online after heartbeat.
- `last_heartbeat_at` updates.
- Heartbeat list shows recent entries.

API checks:

- `GET /api/v1/connector-agents`
- `GET /api/v1/connector-agents/{id}/heartbeats`

## Run a Test Scan Through the Agent

1. Ensure the agent is online and enabled.
2. Dispatch a connector-agent job with a Windows target payload and credential material in the accepted job payload shape.
3. Confirm job moves accepted -> running -> success or partial_success.
4. Confirm uploaded result chunks and ingested accounts.

Current limitation: the standalone agent implements Windows scanning. Non-Windows targets are placeholders.

## Proxy Configuration

Set:

```bash
export PROXY_URL=http://proxy.example.internal:3128
```

Console-managed proxy settings are exposed in agent config, but the current `update_from_console` function does not fully apply the `proxy` section. Use environment variables for reliable proxy setup today.

## Upgrade

No auto-upgrade implementation exists. Manual upgrade:

1. Stop the service.
2. Back up `/opt/adpct-agent/config/agent.json`.
3. Replace the agent source files.
4. Reinstall dependencies if `requirements.txt` changed.
5. Start the service.

## Uninstall

```bash
sudo systemctl disable --now adpct-agent
sudo rm /etc/systemd/system/adpct-agent.service
sudo systemctl daemon-reload
sudo rm -rf /opt/adpct-agent
sudo userdel adpct
```

Revoke the connector in the console after uninstalling.

## Logs

Foreground logs go to stdout/stderr. systemd logs are available through journald:

```bash
journalctl -u adpct-agent
```

Console-side logs uploaded by the agent are available at:

- `GET /api/v1/connector-agents/{id}/logs`

## Troubleshooting

- Enrollment fails: verify token, expiry, console URL, TLS trust, and network.
- Stuck pending: admin approval required.
- Heartbeat rejected: verify connector ID/token, status not revoked/disabled, and headers.
- TLS error: install enterprise CA bundle or correct `VERIFY_TLS` only for dev.
- Proxy error: set `PROXY_URL` and verify proxy allows HTTPS to console.
- Windows scan error: install `pywinrm`, verify WinRM target port and credential.
- No accounts from non-Windows target: not implemented in standalone agent.
