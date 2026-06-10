"""ADPCT Connector Agent — main entry point.

Lifecycle:
  1. Load or create config
  2. Enroll with console if not yet registered
  3. Loop:
       a. Send heartbeat
       b. Pull config (if refresh due)
       c. Poll for jobs
       d. Submit jobs to executor
       e. Upload queued logs
  4. On signal: drain active jobs, upload remaining results, exit

Usage:
  CONSOLE_URL=https://console.internal REGISTRATION_TOKEN=<token> python -m adpct_agent.main
"""
from __future__ import annotations

import logging
import os
import platform
import signal
import sys
import time
from datetime import datetime, timezone
from queue import Queue

from .client import ConsoleClient, exponential_backoff
from .config import AgentConfig, get_config, save_config, update_from_console
from .executor import JobExecutor

log = logging.getLogger("adpct.main")

_shutdown = False
_log_queue: Queue = Queue(maxsize=10000)


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=getattr(logging, level.upper(), logging.INFO),
    )


# ── Enrollment ────────────────────────────────────────────────────────────────

def ensure_enrolled(cfg: AgentConfig, client: ConsoleClient) -> bool:
    """Enroll with console if connector_id is not yet set. Returns True when ready."""
    reg_token = os.environ.get("REGISTRATION_TOKEN", "")

    if cfg.connector_id and cfg.token:
        log.info("Already enrolled as connector %s", cfg.connector_id)
        return True

    if not reg_token:
        log.error("Not enrolled and REGISTRATION_TOKEN env var not set. Cannot start.")
        return False

    log.info("Starting enrollment with console…")
    attempt = 0
    while not _shutdown:
        try:
            resp = client.enroll(reg_token)
            cfg.connector_id = str(resp["connector_id"])
            status = resp.get("status", "pending")

            if status == "pending":
                log.info("Enrollment pending admin approval (connector_id=%s). Polling…", cfg.connector_id)
                # Poll until approved
                while not _shutdown:
                    time.sleep(10)
                    check = client.check_enrollment_status(reg_token)
                    if check.get("token"):
                        cfg.token = check["token"]
                        log.info("Enrollment approved! connector_id=%s", cfg.connector_id)
                        save_config(cfg)
                        return True
                    log.info("Still pending approval…")
                return False

            if resp.get("token"):
                cfg.token = resp["token"]
                save_config(cfg)
                log.info("Enrolled with auto-approve. connector_id=%s", cfg.connector_id)
                return True

        except Exception as e:
            wait = exponential_backoff(attempt)
            log.warning("Enrollment attempt %d failed: %s. Retrying in %ds…", attempt + 1, e, wait)
            time.sleep(wait)
            attempt += 1
            if attempt > 20:
                log.error("Enrollment failed after %d attempts. Giving up.", attempt)
                return False

    return False


# ── Heartbeat ─────────────────────────────────────────────────────────────────

def _build_health(cfg: AgentConfig, executor: JobExecutor) -> dict:
    import psutil  # optional dependency
    cpu = memory_mb = disk_mb = None
    try:
        cpu = psutil.cpu_percent(interval=None)
        memory_mb = psutil.virtual_memory().used / (1024 * 1024)
        disk_mb = psutil.disk_usage("/").free / (1024 * 1024)
    except ImportError:
        pass
    return {
        "agent_timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_version": "1.0.0",
        "status": "running",
        "active_jobs": executor.active_job_count,
        "queued_results": 0,
        "cpu_percent": cpu,
        "memory_mb": memory_mb,
        "disk_free_mb": disk_mb,
        "error_count": 0,
        "payload": {
            "os_platform": platform.system(),
            "os_release": platform.release(),
            "python_version": sys.version,
        },
    }


# ── Log flusher ───────────────────────────────────────────────────────────────

def _flush_logs(client: ConsoleClient) -> None:
    entries = []
    while not _log_queue.empty() and len(entries) < 200:
        try:
            entries.append(_log_queue.get_nowait())
        except Exception:
            break
    if entries:
        try:
            client.upload_logs(entries)
        except Exception as e:
            log.debug("Log upload failed: %s", e)


# ── Main polling loop ─────────────────────────────────────────────────────────

def run_agent() -> None:
    global _shutdown

    cfg = get_config()
    _setup_logging(cfg.log_level)

    log.info("ADPCT Connector Agent v1.0.0 starting")
    log.info("Console: %s", cfg.console_url)

    client = ConsoleClient(cfg)
    executor = JobExecutor(cfg, client)

    if not ensure_enrolled(cfg, client):
        sys.exit(1)

    last_config_refresh = 0.0
    hb_errors = 0
    MAX_HB_ERRORS = 10

    def _handle_signal(sig, frame):
        global _shutdown
        log.info("Received signal %s — shutting down…", sig)
        _shutdown = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    log.info("Agent running. connector_id=%s", cfg.connector_id)

    while not _shutdown:
        loop_start = time.monotonic()

        # ── 1. Heartbeat ──────────────────────────────────────────────────
        try:
            health = _build_health(cfg, executor)
            hb_resp = client.heartbeat(health)
            hb_errors = 0

            # Check for console commands
            cmd = hb_resp.get("command")
            if cmd == "stop":
                log.warning("Console issued STOP command — shutting down")
                _shutdown = True
                break
            elif cmd == "rotate_token":
                log.info("Console requested token rotation")
                # Real implementation: call rotate-token endpoint + persist

        except Exception as e:
            hb_errors += 1
            log.warning("Heartbeat failed (%d/%d): %s", hb_errors, MAX_HB_ERRORS, e)
            if hb_errors >= MAX_HB_ERRORS:
                log.error("Too many consecutive heartbeat failures. Backing off.")
                time.sleep(min(60 * hb_errors, 600))

        # ── 2. Config refresh (every config_refresh_interval seconds) ─────
        now = time.monotonic()
        if now - last_config_refresh >= cfg.config_refresh_interval:
            try:
                config_resp = client.pull_config()
                console_cfg = config_resp.get("config", {})
                if console_cfg:
                    update_from_console(cfg, console_cfg)
                    log.info("Config refreshed from console")
                last_config_refresh = now
            except Exception as e:
                log.warning("Config pull failed: %s", e)

        # ── 3. Poll for jobs ───────────────────────────────────────────────
        if not _shutdown:
            try:
                jobs = client.poll_jobs()
                if jobs:
                    log.info("Received %d pending job(s)", len(jobs))
                for job in jobs:
                    accepted = executor.submit(job)
                    if not accepted:
                        log.warning("Job %s could not be accepted (policy or capacity)", job["id"])
            except Exception as e:
                log.warning("Job poll failed: %s", e)

        # ── 4. Upload buffered logs ────────────────────────────────────────
        _flush_logs(client)

        # ── Sleep until next heartbeat ─────────────────────────────────────
        elapsed = time.monotonic() - loop_start
        sleep_for = max(0.0, cfg.heartbeat_interval - elapsed)
        if sleep_for > 0 and not _shutdown:
            time.sleep(sleep_for)

    log.info("Agent shutdown complete.")


if __name__ == "__main__":
    run_agent()
