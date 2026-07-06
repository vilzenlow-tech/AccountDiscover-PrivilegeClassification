"""Scan launch and monitoring endpoints."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.asset import Asset, AssetGroup
from app.models.connector import Connector, Credential as CredModel
from app.models.enums import CredentialMode, JobStatus, Platform, ScanType
from app.models.job import DiscoveryJob, DiscoveryJobTarget, ScanProfile
from app.schemas.common import Page
from app.schemas.scan import DiscoveryJobOut, DiscoveryJobTargetOut, ScanLaunchRequest
from app.security import Principal, get_current_principal, require_roles
from app.config import get_settings
from app.services.audit import log_action
from app.services.scan_service import _PLATFORM_KIND
from app.services.scan_service import compute_delta, create_job
from app.services.vault import get_vault

router = APIRouter(prefix="/scans", tags=["scans"])

_PLATFORM_SELECTORS = {
    "all",
    "windows",
    "windows_server",
    "windows_desktop",
    *(p.value for p in Platform),
}


def _dedupe(items: list[uuid.UUID]) -> list[uuid.UUID]:
    return list(dict.fromkeys(items))


def _windows_role(asset: Asset) -> str | None:
    tags = asset.tags or {}
    value = (
        tags.get("windows_role")
        or tags.get("windows_kind")
        or tags.get("windows_type")
        or tags.get("os_role")
    )
    return str(value).lower() if value else None


def _matches_platform_selector(asset: Asset, selectors: set[str]) -> bool:
    if "all" in selectors:
        return True
    if asset.platform == Platform.windows:
        role = _windows_role(asset)
        if "windows" in selectors:
            return True
        if "windows_server" in selectors and role == "server":
            return True
        if "windows_desktop" in selectors and role in {"desktop", "workstation", "client"}:
            return True
        return False
    return asset.platform.value in selectors


def _validate_live_credentials(db: Session, assets: list[Asset], credential_mode: CredentialMode) -> None:
    if get_settings().collector_mode == "mock" or credential_mode == CredentialMode.none:
        return

    missing: list[str] = []
    missing_secrets: list[str] = []
    for asset in assets:
        connector_id = asset.connector_id or (asset.tags or {}).get("connector_id")
        kind = _PLATFORM_KIND.get(asset.platform)
        conn = None
        if connector_id:
            conn = db.query(Connector).filter(Connector.id == connector_id, Connector.is_active.is_(True)).first()
        elif kind:
            conn = db.query(Connector).filter(Connector.kind == kind, Connector.is_active.is_(True)).first()
        if not conn or not conn.credential_id:
            missing.append(f"{asset.hostname} ({asset.platform.value})")
            continue

        cred = db.query(CredModel).filter(CredModel.id == conn.credential_id, CredModel.is_active.is_(True)).first()
        if not cred:
            missing.append(f"{asset.hostname} ({asset.platform.value})")
            continue

        try:
            get_vault().resolve(cred.vault_ref)
        except LookupError:
            missing_secrets.append(f"{cred.name} ({cred.vault_ref})")
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Vault resolution failed for credential '{cred.name}': {exc}",
            ) from exc

    if missing:
        raise HTTPException(
            status_code=400,
            detail=(
                "Credentialed scan requires an active connector with a linked credential for: "
                + ", ".join(missing[:10])
            ),
        )
    if missing_secrets:
        raise HTTPException(
            status_code=400,
            detail=(
                "Credentialed scan cannot start because vault secret material is missing for: "
                + ", ".join(dict.fromkeys(missing_secrets[:10]))
                + ". Restore the secret from Connectors / Agents → Credentials."
            ),
        )


@router.post("", response_model=DiscoveryJobOut, status_code=201)
def launch_scan(
    body: ScanLaunchRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    invalid_platforms = sorted(set(body.selected_platforms) - _PLATFORM_SELECTORS)
    if invalid_platforms:
        raise HTTPException(400, f"Unsupported platform selector(s): {', '.join(invalid_platforms)}")

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

    asset_ids = _dedupe(asset_ids)
    if not asset_ids:
        raise HTTPException(400, "No target assets resolved from the given scope")

    assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
    existing_asset_ids = {a.id for a in assets}
    missing_asset_ids = [str(asset_id) for asset_id in asset_ids if asset_id not in existing_asset_ids]
    if missing_asset_ids:
        raise HTTPException(400, f"Selected asset(s) not found: {', '.join(missing_asset_ids[:10])}")

    requested_platforms = set(body.selected_platforms)
    assets = [asset for asset in assets if _matches_platform_selector(asset, requested_platforms)]
    if profile and profile.platforms:
        profile_platforms = set(profile.platforms)
        assets = [asset for asset in assets if asset.platform.value in profile_platforms]
    if not assets:
        raise HTTPException(
            400,
            "No target assets match the selected platform(s), profile restrictions, and scope",
        )

    if body.scan_type in {
        ScanType.credentialed_discovery,
        ScanType.privileged_accounts,
        ScanType.password_policy,
        ScanType.interactive_classification,
        ScanType.full_discovery,
    }:
        _validate_live_credentials(db, assets, body.credential_mode)

    # Resolve collect_password_policy: request override > profile setting > False
    collect_policy = body.collect_password_policy
    if collect_policy is None and profile:
        collect_policy = bool(profile.collect_password_policy)
    if collect_policy is None:
        collect_policy = False
    if body.scan_type == ScanType.password_policy:
        collect_policy = True

    job = create_job(
        db,
        asset_ids=[a.id for a in assets],
        profile_id=body.profile_id,
        triggered_by=p.email,
        triggered_kind="manual",
        note=body.note,
        name=body.name,
        scan_type=body.scan_type,
        selected_platforms=body.selected_platforms,
        credential_mode=body.credential_mode,
        connector_id=body.connector_id,
        collect_password_policy=collect_policy,
    )
    db.commit()

    from app.workers.tasks import dispatch_job_task
    dispatch_job_task.delay(str(job.id))

    log_action(
        db,
        "scan.launched",
        actor_id=p.id,
        actor_email=p.email,
        subject_type="job",
        subject_id=str(job.id),
        context={
            "scan_type": body.scan_type.value,
            "selected_platforms": body.selected_platforms,
            "credential_mode": body.credential_mode.value,
            "target_count": len(assets),
        },
    )
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
