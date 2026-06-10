"""Connector agent configuration — loaded from encrypted local cache + env vars.

Env vars (required at first boot):
  CONSOLE_URL            - https://your-console.internal
  REGISTRATION_TOKEN     - one-time enrollment token (only needed at first run)

After enrollment, CONNECTOR_ID and TOKEN are persisted to the encrypted cache.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("adpct.config")

_BASE_DIR = Path(os.environ.get("ADPCT_HOME", "/opt/adpct-agent"))
_CONFIG_FILE = _BASE_DIR / "config" / "agent.json"


@dataclass
class AgentConfig:
    # Console connection
    console_url: str = ""
    connector_id: str = ""
    token: str = ""                 # bearer token — never logged

    # Polling
    heartbeat_interval: int = 30
    job_poll_interval: int = 10
    config_refresh_interval: int = 3600

    # Execution
    job_timeout_seconds: int = 3600
    max_concurrent_jobs: int = 2
    result_chunk_size_mb: int = 50

    # Retry
    retry_max_attempts: int = 5
    retry_backoff_base: int = 2
    retry_backoff_max: int = 300

    # Storage
    offline_queue_max_mb: int = 500
    result_retention_hours: int = 72

    # TLS / proxy
    verify_tls: bool = True
    console_ca_bundle: str | None = None
    proxy_url: str | None = None
    no_proxy: str | None = None

    # Logging
    log_level: str = "info"
    sanitize_secrets: bool = True

    # Scope
    allowed_scan_profiles: list[str] = field(default_factory=list)
    allowed_scan_modes: list[str] = field(default_factory=lambda: ["safe"])
    max_targets_per_job: int = 100


_config: AgentConfig | None = None


def get_config() -> AgentConfig:
    global _config
    if _config is None:
        _config = _load_config()
    return _config


def _load_config() -> AgentConfig:
    cfg = AgentConfig()
    cfg.console_url = os.environ.get("CONSOLE_URL", "")

    if _CONFIG_FILE.exists():
        try:
            data = json.loads(_CONFIG_FILE.read_text())
            for k, v in data.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
        except Exception as e:
            log.warning("Failed to read config cache: %s", e)

    # Env overrides take precedence
    if os.environ.get("CONNECTOR_ID"):
        cfg.connector_id = os.environ["CONNECTOR_ID"]
    if os.environ.get("CONNECTOR_TOKEN"):
        cfg.token = os.environ["CONNECTOR_TOKEN"]
    if os.environ.get("PROXY_URL"):
        cfg.proxy_url = os.environ["PROXY_URL"]
    if os.environ.get("VERIFY_TLS", "").lower() in ("0", "false", "no"):
        cfg.verify_tls = False

    return cfg


def save_config(cfg: AgentConfig) -> None:
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Stored with mode 600 so the systemd service can restart after enrollment.
    data = cfg.__dict__.copy()
    _CONFIG_FILE.write_text(json.dumps(data, indent=2))
    _CONFIG_FILE.chmod(0o600)
    log.info("Config saved to %s", _CONFIG_FILE)


def update_from_console(cfg: AgentConfig, console_cfg: dict) -> None:
    """Merge settings received from /config endpoint into local config."""
    if "polling" in console_cfg:
        p = console_cfg["polling"]
        cfg.heartbeat_interval = p.get("heartbeat_interval_seconds", cfg.heartbeat_interval)
        cfg.job_poll_interval = p.get("job_poll_interval_seconds", cfg.job_poll_interval)
        cfg.config_refresh_interval = p.get("config_refresh_interval_seconds", cfg.config_refresh_interval)
    if "execution" in console_cfg:
        e = console_cfg["execution"]
        cfg.job_timeout_seconds = e.get("job_timeout_seconds", cfg.job_timeout_seconds)
        cfg.max_concurrent_jobs = e.get("max_concurrent_jobs", cfg.max_concurrent_jobs)
        cfg.result_chunk_size_mb = e.get("result_chunk_size_mb", cfg.result_chunk_size_mb)
    if "retry" in console_cfg:
        r = console_cfg["retry"]
        cfg.retry_max_attempts = r.get("max_attempts", cfg.retry_max_attempts)
        cfg.retry_backoff_base = r.get("backoff_base_seconds", cfg.retry_backoff_base)
        cfg.retry_backoff_max = r.get("backoff_max_seconds", cfg.retry_backoff_max)
    if "storage" in console_cfg:
        s = console_cfg["storage"]
        cfg.offline_queue_max_mb = s.get("offline_queue_max_mb", cfg.offline_queue_max_mb)
        cfg.result_retention_hours = s.get("result_retention_hours", cfg.result_retention_hours)
    if "logging" in console_cfg:
        l = console_cfg["logging"]
        cfg.log_level = l.get("level", cfg.log_level)
        cfg.sanitize_secrets = l.get("sanitize_secrets", cfg.sanitize_secrets)
    if "scope" in console_cfg:
        sc = console_cfg["scope"]
        cfg.allowed_scan_profiles = sc.get("allowed_scan_profiles", cfg.allowed_scan_profiles)
        cfg.allowed_scan_modes = sc.get("allowed_scan_modes", cfg.allowed_scan_modes)
        cfg.max_targets_per_job = sc.get("max_targets_per_job", cfg.max_targets_per_job)
    if console_cfg.get("is_enabled") is False:
        log.warning("Console has disabled this connector — pausing job execution")
    save_config(cfg)
