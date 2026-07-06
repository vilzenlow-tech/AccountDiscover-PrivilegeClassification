"""Lightweight scheduled scan dispatcher."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from app.db import SessionLocal
from app.models.asset import Asset, AssetGroup
from app.models.job import ScheduledScan
from app.services.scan_service import create_job

SCHEDULE_TIMEZONE = timezone(timedelta(hours=8), "GMT+8")


def _next_run(cron_expr: str, *, previous: datetime | None = None) -> datetime | None:
    trigger = CronTrigger.from_crontab(cron_expr, timezone=SCHEDULE_TIMEZONE)
    now = previous.astimezone(SCHEDULE_TIMEZONE) if previous else datetime.now(SCHEDULE_TIMEZONE)
    return trigger.get_next_fire_time(previous, now)


def process_due_schedules() -> None:
    from app.workers.tasks import dispatch_job_task

    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        due = (
            db.query(ScheduledScan)
            .filter(ScheduledScan.enabled.is_(True), ScheduledScan.next_run_at.is_not(None), ScheduledScan.next_run_at <= now)
            .order_by(ScheduledScan.next_run_at.asc())
            .all()
        )

        for schedule in due:
            if schedule.requires_approval:
                schedule.last_run_at = now
                schedule.next_run_at = _next_run(schedule.cron, previous=schedule.next_run_at)
                continue

            asset_ids: set = set()
            scope = schedule.scope or {}
            for asset_id in scope.get("asset_ids", []):
                try:
                    asset_ids.add(uuid.UUID(str(asset_id)))
                except ValueError:
                    continue
            if scope.get("all_enabled"):
                for asset in db.query(Asset).filter(Asset.discovery_enabled.is_(True)).all():
                    asset_ids.add(asset.id)
            for group_id in scope.get("group_ids", []):
                group = db.query(AssetGroup).filter(AssetGroup.id == group_id).first()
                if group:
                    for asset in group.assets:
                        asset_ids.add(asset.id)

            if asset_ids:
                job = create_job(
                    db,
                    asset_ids=list(asset_ids),
                    profile_id=schedule.profile_id,
                    triggered_by="scheduler",
                    triggered_kind="scheduled",
                    note=f"Scheduled scan: {schedule.name}",
                )
                db.commit()
                dispatch_job_task.delay(str(job.id))
            schedule.last_run_at = now
            schedule.next_run_at = _next_run(schedule.cron, previous=schedule.next_run_at)
        db.commit()


def recompute_activity_statuses() -> None:
    """Nightly re-tiering: accounts age into 30/90-day buckets between scans."""
    from app.services.activity import recompute_all_activity

    with SessionLocal() as db:
        recompute_all_activity(db)


def build_scheduler() -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone=SCHEDULE_TIMEZONE)
    scheduler.add_job(process_due_schedules, "interval", seconds=30, id="scheduled-scan-dispatcher", max_instances=1, replace_existing=True)
    scheduler.add_job(
        recompute_activity_statuses,
        CronTrigger(hour=1, minute=15, timezone=SCHEDULE_TIMEZONE),
        id="activity-status-recompute",
        max_instances=1,
        replace_existing=True,
    )
    return scheduler
