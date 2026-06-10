"""Celery tasks for scan execution."""
from __future__ import annotations

import uuid

import structlog

from app.workers.celery_app import celery
from app.db import SessionLocal

log = structlog.get_logger("adpct.worker")


@celery.task(bind=True, max_retries=3, default_retry_delay=30, name="adpct.run_target")
def run_target_task(self, job_target_id: str) -> dict:
    from app.services.scan_service import run_target, finalize_job
    from app.models.job import DiscoveryJobTarget

    tid = uuid.UUID(job_target_id)
    with SessionLocal() as db:
        try:
            run_target(db, tid)
            db.commit()
            # Check if all targets for this job are done.
            target = db.query(DiscoveryJobTarget).filter(DiscoveryJobTarget.id == tid).first()
            if target:
                from app.models.enums import JobStatus
                from app.models.job import DiscoveryJobTarget as DJT
                job_targets = db.query(DJT).filter(DJT.job_id == target.job_id).all()
                all_done = all(
                    t.status
                    in (JobStatus.success, JobStatus.failed, JobStatus.cancelled, JobStatus.timed_out)
                    for t in job_targets
                )
                if all_done:
                    finalize_job(db, target.job_id)
                    db.commit()
            return {"status": "done", "job_target_id": job_target_id}
        except Exception as exc:
            db.rollback()
            log.exception("task.error", job_target_id=job_target_id)
            raise self.retry(exc=exc)


@celery.task(name="adpct.dispatch_job")
def dispatch_job_task(job_id: str) -> dict:
    """Fan-out: enqueue one run_target_task per target in the job."""
    from app.models.job import DiscoveryJobTarget, DiscoveryJob
    from app.models.enums import JobStatus
    from datetime import UTC, datetime

    jid = uuid.UUID(job_id)
    with SessionLocal() as db:
        job = db.query(DiscoveryJob).filter(DiscoveryJob.id == jid).first()
        if not job:
            return {"error": "job_not_found"}
        job.status = JobStatus.running
        job.started_at = datetime.now(UTC)
        db.flush()
        targets = db.query(DiscoveryJobTarget).filter(DiscoveryJobTarget.job_id == jid).all()
        for t in targets:
            t.status = JobStatus.queued
        db.commit()
        for t in targets:
            run_target_task.delay(str(t.id))
    return {"status": "dispatched", "targets": len(targets)}
