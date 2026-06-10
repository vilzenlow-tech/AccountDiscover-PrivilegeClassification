"""Scan launch and monitoring endpoints."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.asset import Asset, AssetGroup
from app.models.enums import JobStatus
from app.models.job import DiscoveryJob, DiscoveryJobTarget, ScanProfile
from app.schemas.common import Page
from app.schemas.scan import DiscoveryJobOut, DiscoveryJobTargetOut, ScanLaunchRequest
from app.security import Principal, get_current_principal, require_roles
from app.services.audit import log_action
from app.services.scan_service import compute_delta, create_job

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=DiscoveryJobOut, status_code=201)
def launch_scan(
    body: ScanLaunchRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    profile = db.query(ScanProfile).filter(ScanProfile.id == body.profile_id).first() if body.profile_id else None
    target_scope = {
        "asset_ids": [str(asset_id) for asset_id in body.asset_ids],
        "group_ids": [str(group_id) for group_id in body.group_ids],
        "all_enabled": body.all_enabled,
    }
    if (
        profile
        and not target_scope["asset_ids"]
        and not target_scope["group_ids"]
        and not target_scope["all_enabled"]
    ):
        target_scope = profile.target_scope or {"all_enabled": True}

    asset_ids: list[uuid.UUID] = []
    for asset_id in target_scope.get("asset_ids", []):
        try:
            asset_ids.append(uuid.UUID(str(asset_id)))
        except ValueError:
            continue

    if target_scope.get("all_enabled"):
        asset_ids += [a.id for a in db.query(Asset).filter(Asset.discovery_enabled.is_(True)).all()]
    for gid in target_scope.get("group_ids", []):
        grp = db.query(AssetGroup).filter(AssetGroup.id == gid).first()
        if grp:
            asset_ids += [a.id for a in grp.assets]

    asset_ids = list(set(asset_ids))
    if not asset_ids:
        raise HTTPException(400, "No target assets resolved from the given scope")

    # Resolve collect_password_policy: request override > profile setting > False
    collect_policy = body.collect_password_policy
    if collect_policy is None and profile:
        collect_policy = bool(profile.collect_password_policy)
    if collect_policy is None:
        collect_policy = False

    job = create_job(
        db,
        asset_ids=asset_ids,
        profile_id=body.profile_id,
        triggered_by=p.email,
        triggered_kind="manual",
        note=body.note,
        collect_password_policy=collect_policy,
    )
    db.commit()

    from app.workers.tasks import dispatch_job_task
    dispatch_job_task.delay(str(job.id))

    log_action(db, "scan.launched", actor_id=p.id, actor_email=p.email, subject_type="job", subject_id=str(job.id))
    db.commit()
    return DiscoveryJobOut.model_validate(job)


@router.get("", response_model=Page[DiscoveryJobOut])
def list_scans(
    status: str | None = None,
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(DiscoveryJob)
    if status:
        q = q.filter(DiscoveryJob.status == status)
    total = q.count()
    items = q.order_by(DiscoveryJob.created_at.desc()).offset(offset).limit(limit).all()
    return Page(items=[DiscoveryJobOut.model_validate(j) for j in items], total=total, limit=limit, offset=offset)


@router.get("/{job_id}", response_model=DiscoveryJobOut)
def get_scan(job_id: uuid.UUID, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    j = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id).first()
    if not j:
        raise HTTPException(404, "Job not found")
    return DiscoveryJobOut.model_validate(j)


@router.get("/{job_id}/targets", response_model=list[DiscoveryJobTargetOut])
def get_scan_targets(job_id: uuid.UUID, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    targets = db.query(DiscoveryJobTarget).filter(DiscoveryJobTarget.job_id == job_id).all()
    asset_ids = list({t.asset_id for t in targets})
    assets_by_id = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()}
    out = []
    for t in targets:
        dto = DiscoveryJobTargetOut.model_validate(t)
        asset = assets_by_id.get(t.asset_id)
        if asset:
            dto.hostname = asset.hostname
            dto.ip_address = asset.ip_address
        out.append(dto)
    return out


@router.post("/{job_id}/cancel", response_model=DiscoveryJobOut)
def cancel_scan(
    job_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    j = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id).first()
    if not j:
        raise HTTPException(404, "Job not found")
    if j.status not in (JobStatus.pending, JobStatus.queued, JobStatus.running):
        raise HTTPException(400, "Job cannot be cancelled in its current state")
    j.status = JobStatus.cancelled
    j.cancelled_reason = f"Cancelled by {p.email}"
    log_action(db, "scan.cancelled", actor_id=p.id, actor_email=p.email, subject_id=str(job_id))
    db.commit()
    return DiscoveryJobOut.model_validate(j)


@router.post("/{job_id}/retry-failed", response_model=DiscoveryJobOut)
def retry_failed_targets(
    job_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    """Re-launch only the failed targets of an existing job."""
    j = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id).first()
    if not j:
        raise HTTPException(404, "Job not found")
    failed = db.query(DiscoveryJobTarget).filter(
        DiscoveryJobTarget.job_id == job_id,
        DiscoveryJobTarget.status == JobStatus.failed,
    ).all()
    for t in failed:
        t.status = JobStatus.queued
        from app.workers.tasks import run_target_task
        run_target_task.delay(str(t.id))
    j.status = JobStatus.running
    db.commit()
    return DiscoveryJobOut.model_validate(j)


@router.get("/delta/{baseline_job_id}/{current_job_id}")
def get_delta(
    baseline_job_id: uuid.UUID,
    current_job_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    from app.schemas.account import DeltaResponse
    items = compute_delta(db, baseline_job_id, current_job_id)
    summary: dict[str, int] = {}
    for d in items:
        summary[d["change"]] = summary.get(d["change"], 0) + 1
    return {"baseline_job_id": str(baseline_job_id), "current_job_id": str(current_job_id), "items": items, "summary": summary}
