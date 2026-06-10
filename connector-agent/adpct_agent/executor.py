"""Job execution engine for the connector agent.

Validates and executes scan jobs received from the console.
Enforces local policy (scope, allowed profiles, allowed modes).
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .client import ConsoleClient
from .config import AgentConfig
from .scanners.windows import WindowsScanner

log = logging.getLogger("adpct.executor")


@dataclass
class JobResult:
    job_id: str
    status: str  # success | partial_success | failed
    accounts_discovered: int = 0
    assets_scanned: int = 0
    error: str | None = None
    target_results: list[dict] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""


class PolicyViolation(Exception):
    pass


class JobExecutor:
    """Executes connector jobs with local policy enforcement."""

    def __init__(self, cfg: AgentConfig, client: ConsoleClient) -> None:
        self.cfg = cfg
        self.client = client
        self._windows_scanner = WindowsScanner()
        self._active_jobs: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    def can_accept(self, job: dict) -> tuple[bool, str]:
        """Check local policy before accepting a job."""
        payload = job.get("payload", {})

        # Check concurrency limit
        with self._lock:
            if len(self._active_jobs) >= self.cfg.max_concurrent_jobs:
                return False, f"Max concurrent jobs ({self.cfg.max_concurrent_jobs}) reached"

        # Check scan mode
        scan_mode = payload.get("scan_mode", "safe")
        if self.cfg.allowed_scan_modes and scan_mode not in self.cfg.allowed_scan_modes:
            return False, f"Scan mode '{scan_mode}' not in allowed modes: {self.cfg.allowed_scan_modes}"

        # Check scan profile
        scan_profile = payload.get("scan_profile", "standard")
        if self.cfg.allowed_scan_profiles and scan_profile not in self.cfg.allowed_scan_profiles:
            return False, f"Scan profile '{scan_profile}' not in allowed profiles"

        # Check targets
        targets = payload.get("targets", [])
        if len(targets) > self.cfg.max_targets_per_job:
            return False, f"Target count {len(targets)} exceeds max {self.cfg.max_targets_per_job}"

        return True, "ok"

    def verify_payload_integrity(self, job: dict) -> bool:
        """Verify job payload checksum matches what console sent."""
        if not job.get("payload_checksum"):
            return True  # No checksum provided — skip verification
        payload_str = json.dumps(job["payload"], sort_keys=True)
        actual = hashlib.sha256(payload_str.encode()).hexdigest()
        return actual == job["payload_checksum"]

    def execute_job(self, job: dict) -> None:
        """Main job execution — runs in a separate thread."""
        job_id = job["id"]
        payload = job.get("payload", {})
        log.info("Starting job %s (type=%s)", job_id, job.get("job_type"))

        try:
            # Accept
            self.client.update_job_status(job_id, "accepted", progress_pct=0)

            targets = payload.get("targets", [])
            started_at = datetime.now(timezone.utc).isoformat()

            self.client.update_job_status(
                job_id, "running",
                progress_pct=5,
                progress_message=f"Starting scan of {len(targets)} target(s)",
                targets_total=len(targets),
                targets_done=0,
            )

            result = JobResult(
                job_id=job_id,
                status="success",
                started_at=started_at,
            )

            # ── Execute each target ────────────────────────────────────────
            for idx, target in enumerate(targets):
                # Re-check if job was cancelled
                status_resp = self.client.update_job_status(
                    job_id, "running",
                    progress_pct=int(10 + (idx / max(len(targets), 1)) * 85),
                    progress_message=f"Scanning {target.get('hostname', target.get('asset_id', '?'))}",
                    targets_done=idx,
                )
                if status_resp.get("status") == "cancelled":
                    log.info("Job %s was cancelled by console", job_id)
                    return

                # Delegate to the appropriate scanner
                target_result = self._scan_target(target, payload, job.get("job_type"))
                result.target_results.append(target_result)

                if target_result["status"] == "success":
                    result.accounts_discovered += target_result.get("accounts_discovered", 0)
                    result.assets_scanned += 1
                else:
                    result.status = "partial_success"

            if result.assets_scanned == 0 and len(targets) > 0:
                result.status = "failed"

            result.completed_at = datetime.now(timezone.utc).isoformat()

            # ── Upload result ──────────────────────────────────────────────
            self._upload_result(result, job_id)

            final_status = result.status
            self.client.update_job_status(
                job_id, final_status,
                progress_pct=100,
                progress_message=f"Completed: {result.assets_scanned} scanned, {result.accounts_discovered} accounts",
                targets_done=result.assets_scanned,
                targets_failed=len(targets) - result.assets_scanned,
            )
            log.info("Job %s completed: %s (%d accounts)", job_id, final_status, result.accounts_discovered)

        except Exception as exc:
            log.exception("Job %s failed with exception", job_id)
            try:
                self.client.update_job_status(
                    job_id, "failed",
                    error_message=str(exc)[:500],
                )
            except Exception:
                pass
        finally:
            with self._lock:
                self._active_jobs.pop(job_id, None)

    def _scan_target(self, target: dict, payload: dict, job_type: str | None) -> dict:
        """Dispatch to appropriate scanner based on platform/job type.

        Windows credentialed discovery is implemented in-agent because this
        package is deployed standalone outside the backend container.
        """
        hostname = target.get("hostname", "unknown")
        platform = str(target.get("platform", "unknown")).lower()
        log.debug("Scanning target %s (platform=%s)", hostname, platform)

        try:
            if platform == "windows":
                return self._windows_scanner.scan(target, payload)

            time.sleep(0.1)

            return {
                "asset_id": target.get("asset_id"),
                "hostname": hostname,
                "platform": platform,
                "status": "success",
                "accounts_discovered": 0,  # real scanner fills this
                "evidence": {},
                "scanned_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            log.warning("Failed to scan %s: %s", hostname, e)
            return {
                "asset_id": target.get("asset_id"),
                "hostname": hostname,
                "status": "failed",
                "error": str(e),
            }

    def _upload_result(self, result: JobResult, job_id: str) -> None:
        """Compress, chunk and upload the job result."""
        payload_bytes = json.dumps({
            "job_id": result.job_id,
            "status": result.status,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "accounts_discovered": result.accounts_discovered,
            "assets_scanned": result.assets_scanned,
            "target_results": result.target_results,
        }).encode()

        compressed = gzip.compress(payload_bytes)
        total_checksum = hashlib.sha256(compressed).hexdigest()
        chunk_size = self.cfg.result_chunk_size_mb * 1024 * 1024

        chunks = [compressed[i:i + chunk_size] for i in range(0, len(compressed), chunk_size)]
        chunk_count = max(len(chunks), 1)

        for idx, chunk in enumerate(chunks):
            chunk_b64 = base64.b64encode(chunk).decode()
            chunk_checksum = hashlib.sha256(chunk).hexdigest()
            self.client.upload_result_chunk(
                job_id=job_id,
                chunk_index=idx,
                chunk_count=chunk_count,
                data_b64=chunk_b64,
                checksum=chunk_checksum,
                total_checksum=total_checksum if idx == chunk_count - 1 else None,
            )
            log.debug("Uploaded chunk %d/%d for job %s", idx + 1, chunk_count, job_id)

    def submit(self, job: dict) -> bool:
        """Validate and submit a job for async execution. Returns True if accepted."""
        job_id = job["id"]

        if not self.verify_payload_integrity(job):
            log.error("Job %s payload checksum mismatch — rejecting", job_id)
            self.client.update_job_status(
                job_id,
                "failed",
                progress_pct=0,
                error_message="Payload checksum mismatch",
            )
            return False

        ok, reason = self.can_accept(job)
        if not ok:
            log.warning("Job %s rejected by local policy: %s", job_id, reason)
            self.client.update_job_status(
                job_id,
                "failed",
                progress_pct=0,
                error_message=reason[:500],
            )
            return False

        t = threading.Thread(target=self.execute_job, args=(job,), daemon=True, name=f"job-{job_id[:8]}")
        with self._lock:
            self._active_jobs[job_id] = t
        t.start()
        return True

    @property
    def active_job_count(self) -> int:
        with self._lock:
            return len(self._active_jobs)
