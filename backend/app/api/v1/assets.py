"""Asset CRUD endpoints."""
from __future__ import annotations

import io
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.asset import Asset, AssetGroup
from app.models.connector import Connector
from app.models.tag import AssetTag
from app.schemas.asset import AssetGroupIn, AssetGroupOut, AssetGroupSummary, AssetGroupUpdate, AssetIn, AssetOut, BulkImportResult
from app.schemas.common import Page
from app.schemas.tag import TagSummary
from app.security import Principal, get_current_principal, require_roles
from app.services.audit import log_action

router = APIRouter(prefix="/assets", tags=["assets"])
group_router = APIRouter(prefix="/asset-groups", tags=["asset-groups"])


def _out(asset: Asset, db: Session) -> AssetOut:
    """Build AssetOut, resolving connector_name and managed tag summaries."""
    o = AssetOut.model_validate(asset)
    if asset.connector_id:
        conn = db.query(Connector).filter(Connector.id == asset.connector_id).first()
        o.connector_name = conn.name if conn else None
    # Populate tag_summaries from the selectin-loaded tag_assignments relationship
    o.tag_summaries = [
        TagSummary(
            id=at.tag.id,
            tag_name=at.tag.tag_name,
            tag_code=at.tag.tag_code,
            color=at.tag.color,
            category=at.tag.category.value,
            assigned_at=at.assigned_at,
            assigned_by=at.assigned_by,
        )
        for at in asset.tag_assignments
    ]
    o.group_summaries = [
        AssetGroupSummary(
            id=g.id,
            name=g.name,
            description=g.description,
            asset_count=len(g.assets),
        )
        for g in asset.groups
    ]
    return o


def _group_out(group: AssetGroup) -> AssetGroupOut:
    return AssetGroupOut(
        id=group.id,
        name=group.name,
        description=group.description,
        asset_ids=[a.id for a in group.assets],
        asset_count=len(group.assets),
        created_at=group.created_at,
        updated_at=group.updated_at,
    )


@router.get("", response_model=Page[AssetOut])
def list_assets(
    platform: str | None = None,
    environment: str | None = None,
    business_unit: str | None = None,
    search: str | None = None,
    enabled: bool | None = None,
    group_id: uuid.UUID | None = None,
    tag_ids: list[uuid.UUID] | None = Query(default=None),
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(Asset)
    if platform:
        q = q.filter(Asset.platform == platform)
    if environment:
        q = q.filter(Asset.environment == environment)
    if business_unit:
        q = q.filter(Asset.business_unit == business_unit)
    if enabled is not None:
        q = q.filter(Asset.discovery_enabled == enabled)
    if search:
        q = q.filter(Asset.hostname.ilike(f"%{search}%"))
    if tag_ids:
        # Asset must have ANY of the specified tags (union, not intersection)
        q = q.filter(
            Asset.id.in_(select(AssetTag.asset_id).where(AssetTag.tag_id.in_(tag_ids)))
        )
    if group_id:
        from app.models.asset import asset_group_members
        q = q.filter(
            Asset.id.in_(
                select(asset_group_members.c.asset_id).where(asset_group_members.c.group_id == group_id)
            )
        )
    total = q.count()
    items = q.order_by(Asset.hostname).offset(offset).limit(limit).all()
    return Page(items=[_out(a, db) for a in items], total=total, limit=limit, offset=offset)


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
def create_asset(
    body: AssetIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    asset = Asset(**body.model_dump())
    db.add(asset)
    db.flush()
    log_action(db, "asset.created", actor_id=p.id, actor_email=p.email, subject_type="asset", subject_id=str(asset.id))
    db.commit()
    db.refresh(asset)
    return _out(asset, db)


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: uuid.UUID, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Asset not found")
    return _out(a, db)


@router.put("/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: uuid.UUID,
    body: AssetIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Asset not found")
    for k, v in body.model_dump().items():
        setattr(a, k, v)
    log_action(db, "asset.updated", actor_id=p.id, actor_email=p.email, subject_type="asset", subject_id=str(a.id))
    db.commit()
    db.refresh(a)
    return _out(a, db)


@router.patch("/{asset_id}/toggle", response_model=AssetOut)
def toggle_asset(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    """Flip discovery_enabled on/off."""
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Asset not found")
    a.discovery_enabled = not a.discovery_enabled
    log_action(db, "asset.toggled", actor_id=p.id, actor_email=p.email,
               subject_type="asset", subject_id=str(a.id),
               context={"discovery_enabled": a.discovery_enabled})
    db.commit()
    db.refresh(a)
    return _out(a, db)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin")),
):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Asset not found")
    db.delete(a)
    log_action(db, "asset.deleted", actor_id=p.id, actor_email=p.email, subject_type="asset", subject_id=str(asset_id))
    db.commit()


@router.post("/import/csv", response_model=BulkImportResult)
async def bulk_import_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    """Bulk-import assets from CSV.
    Columns: hostname*, platform*, ip_address, port, environment, owner, business_unit, criticality, connector_name
    """
    import csv as csv_module
    from app.models.enums import Platform

    content = await file.read()
    reader = csv_module.DictReader(io.StringIO(content.decode("utf-8-sig")))
    total = imported = duplicates = invalid = 0
    errors = []

    # Build connector name → id lookup
    connector_map = {c.name.lower(): c.id for c in db.query(Connector).all()}

    for i, row in enumerate(reader, start=2):
        total += 1
        hostname = (row.get("hostname") or "").strip()
        platform_raw = (row.get("platform") or "").strip().lower()

        if not hostname:
            invalid += 1
            errors.append({"row": i, "error": "hostname is required"})
            continue
        try:
            plat = Platform(platform_raw)
        except ValueError:
            invalid += 1
            errors.append({"row": i, "error": f"Unknown platform '{platform_raw}'. Valid: rhel, solaris, aix, windows, mysql, mssql, mongodb"})
            continue

        existing = db.query(Asset).filter(Asset.hostname == hostname, Asset.instance == None).first()
        if existing:
            # Update existing instead of skipping
            existing.ip_address = row.get("ip_address") or existing.ip_address
            existing.platform = plat
            existing.environment = row.get("environment") or existing.environment
            existing.owner = row.get("owner") or existing.owner
            existing.business_unit = row.get("business_unit") or existing.business_unit
            existing.criticality = row.get("criticality") or existing.criticality
            if row.get("port"):
                try:
                    existing.port = int(row["port"])
                except ValueError:
                    pass
            conn_name = (row.get("connector_name") or "").strip().lower()
            if conn_name and conn_name in connector_map:
                existing.connector_id = connector_map[conn_name]
            duplicates += 1
            continue

        port = None
        if row.get("port"):
            try:
                port = int(row["port"])
            except ValueError:
                pass

        conn_id = None
        conn_name = (row.get("connector_name") or "").strip().lower()
        if conn_name:
            conn_id = connector_map.get(conn_name)
            if not conn_id:
                errors.append({"row": i, "error": f"Connector '{conn_name}' not found (asset will be created without connector)"})

        db.add(Asset(
            hostname=hostname,
            ip_address=row.get("ip_address") or None,
            platform=plat,
            port=port,
            environment=row.get("environment") or None,
            owner=row.get("owner") or None,
            business_unit=row.get("business_unit") or None,
            criticality=row.get("criticality") or None,
            connector_id=conn_id,
        ))
        imported += 1

    from app.models.job import BulkImportJob
    job = BulkImportJob(
        source="csv", filename=file.filename, uploaded_by=p.email,
        total_rows=total, imported_rows=imported, duplicate_rows=duplicates,
        invalid_rows=invalid, errors=errors,
    )
    db.add(job)
    log_action(db, "asset.bulk_import", actor_id=p.id, actor_email=p.email,
               context={"filename": file.filename, "imported": imported})
    db.commit()
    return BulkImportResult(
        total_rows=total, imported_rows=imported, duplicate_rows=duplicates,
        invalid_rows=invalid, errors=errors, job_id=job.id,
    )


# Asset Groups
@group_router.get("", response_model=list[AssetGroupOut])
def list_groups(db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    groups = db.query(AssetGroup).order_by(AssetGroup.name).all()
    return [_group_out(g) for g in groups]


@group_router.post("", response_model=AssetGroupOut, status_code=201)
def create_group(body: AssetGroupIn, db: Session = Depends(get_db), p: Principal = Depends(require_roles("admin", "security_analyst"))):
    existing = db.query(AssetGroup).filter(AssetGroup.name == body.name).first()
    if existing:
        raise HTTPException(409, "Asset group name already exists")
    assets = db.query(Asset).filter(Asset.id.in_(body.asset_ids)).all()
    group = AssetGroup(name=body.name, description=body.description, assets=assets)
    db.add(group)
    log_action(db, "asset_group.created", actor_id=p.id, actor_email=p.email, subject_type="asset_group", subject_id=str(group.id))
    db.commit()
    db.refresh(group)
    return _group_out(group)


@group_router.get("/{group_id}", response_model=AssetGroupOut)
def get_group(group_id: uuid.UUID, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    group = db.query(AssetGroup).filter(AssetGroup.id == group_id).first()
    if not group:
        raise HTTPException(404, "Asset group not found")
    return _group_out(group)


@group_router.put("/{group_id}", response_model=AssetGroupOut)
def update_group(
    group_id: uuid.UUID,
    body: AssetGroupUpdate,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    group = db.query(AssetGroup).filter(AssetGroup.id == group_id).first()
    if not group:
        raise HTTPException(404, "Asset group not found")
    existing = db.query(AssetGroup).filter(AssetGroup.name == body.name, AssetGroup.id != group_id).first()
    if existing:
        raise HTTPException(409, "Asset group name already exists")
    group.name = body.name
    group.description = body.description
    group.assets = db.query(Asset).filter(Asset.id.in_(body.asset_ids)).all()
    log_action(db, "asset_group.updated", actor_id=p.id, actor_email=p.email, subject_type="asset_group", subject_id=str(group.id))
    db.commit()
    db.refresh(group)
    return _group_out(group)


@group_router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(
    group_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    group = db.query(AssetGroup).filter(AssetGroup.id == group_id).first()
    if not group:
        raise HTTPException(404, "Asset group not found")
    db.delete(group)
    log_action(db, "asset_group.deleted", actor_id=p.id, actor_email=p.email, subject_type="asset_group", subject_id=str(group_id))
    db.commit()
