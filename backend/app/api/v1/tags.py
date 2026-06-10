"""Tag management endpoints.

Provides:
  CRUD for the managed tag catalog     — GET/POST/PUT/PATCH/DELETE /tags
  Per-asset tag assignment/removal     — GET/POST/DELETE /assets/{id}/tags
  Bulk assignment/removal              — POST /assets/tags/bulk-assign|bulk-remove
"""
from __future__ import annotations

import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.asset import Asset
from app.models.tag import AssetTag, Tag
from app.schemas.common import Page
from app.schemas.tag import (
    AssetTagsAssign,
    AssetTagsRemove,
    BulkTagAssign,
    BulkTagRemove,
    TagIn,
    TagOut,
    TagStatusPatch,
    TagSummary,
)
from app.security import Principal, get_current_principal, require_roles
from app.services.audit import log_action

router = APIRouter(tags=["tags"])

# ── Roles allowed to mutate tags ─────────────────────────────────────────────
_TAG_WRITER = require_roles("admin", "security_analyst")
_TAG_ADMIN = require_roles("admin")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_tag_or_404(tag_id: uuid.UUID, db: Session) -> Tag:
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    return tag


def _usage_count(tag_id: uuid.UUID, db: Session) -> int:
    return db.query(func.count(AssetTag.id)).filter(AssetTag.tag_id == tag_id).scalar() or 0


def _tag_out(tag: Tag, db: Session) -> TagOut:
    o = TagOut.model_validate(tag)
    o.usage_count = _usage_count(tag.id, db)
    return o


def _tag_summaries(asset_id: uuid.UUID, db: Session) -> list[TagSummary]:
    rows = db.query(AssetTag).filter(AssetTag.asset_id == asset_id).all()
    return [
        TagSummary(
            id=row.tag.id,
            tag_name=row.tag.tag_name,
            tag_code=row.tag.tag_code,
            color=row.tag.color,
            category=row.tag.category.value,
            assigned_at=row.assigned_at,
            assigned_by=row.assigned_by,
        )
        for row in rows
    ]


# ── Tag CRUD ──────────────────────────────────────────────────────────────────

@router.get("/tags", response_model=Page[TagOut])
def list_tags(
    search: str | None = None,
    category: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(Tag)
    if search:
        q = q.filter(Tag.tag_name.ilike(f"%{search}%") | Tag.tag_code.ilike(f"%{search}%"))
    if category:
        q = q.filter(Tag.category == category)
    if status:
        q = q.filter(Tag.status == status)
    total = q.count()
    tags = q.order_by(Tag.tag_name).offset(offset).limit(limit).all()
    return Page(
        items=[_tag_out(t, db) for t in tags],
        total=total, limit=limit, offset=offset,
    )


@router.post("/tags", response_model=TagOut, status_code=status.HTTP_201_CREATED)
def create_tag(
    body: TagIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(_TAG_WRITER),
):
    # Duplicate name check
    if db.query(Tag).filter(Tag.tag_name == body.tag_name).first():
        raise HTTPException(status_code=409, detail=f"Tag name '{body.tag_name}' already exists")
    if body.tag_code and db.query(Tag).filter(Tag.tag_code == body.tag_code).first():
        raise HTTPException(status_code=409, detail=f"Tag code '{body.tag_code}' already exists")

    tag = Tag(
        tag_name=body.tag_name,
        tag_code=body.tag_code,
        description=body.description,
        category=body.category,
        color=body.color,
        status=body.status,
        created_by=p.email,
        updated_by=p.email,
    )
    db.add(tag)
    db.flush()
    log_action(db, "tag.create", actor_id=p.id, actor_email=p.email,
               subject_type="tag", subject_id=str(tag.id),
               context={"tag_name": tag.tag_name, "category": tag.category.value})
    db.commit()
    db.refresh(tag)
    return _tag_out(tag, db)


@router.get("/tags/{tag_id}", response_model=TagOut)
def get_tag(
    tag_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    return _tag_out(_get_tag_or_404(tag_id, db), db)


@router.put("/tags/{tag_id}", response_model=TagOut)
def update_tag(
    tag_id: uuid.UUID,
    body: TagIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(_TAG_WRITER),
):
    tag = _get_tag_or_404(tag_id, db)

    # Duplicate name/code check (excluding self)
    dup_name = db.query(Tag).filter(Tag.tag_name == body.tag_name, Tag.id != tag_id).first()
    if dup_name:
        raise HTTPException(status_code=409, detail=f"Tag name '{body.tag_name}' already exists")
    if body.tag_code:
        dup_code = db.query(Tag).filter(Tag.tag_code == body.tag_code, Tag.id != tag_id).first()
        if dup_code:
            raise HTTPException(status_code=409, detail=f"Tag code '{body.tag_code}' already exists")

    tag.tag_name = body.tag_name
    tag.tag_code = body.tag_code
    tag.description = body.description
    tag.category = body.category
    tag.color = body.color
    tag.status = body.status
    tag.updated_by = p.email
    db.flush()
    log_action(db, "tag.update", actor_id=p.id, actor_email=p.email,
               subject_type="tag", subject_id=str(tag.id),
               context={"tag_name": tag.tag_name})
    db.commit()
    db.refresh(tag)
    return _tag_out(tag, db)


@router.patch("/tags/{tag_id}/status", response_model=TagOut)
def patch_tag_status(
    tag_id: uuid.UUID,
    body: TagStatusPatch,
    db: Session = Depends(get_db),
    p: Principal = Depends(_TAG_WRITER),
):
    tag = _get_tag_or_404(tag_id, db)
    old_status = tag.status
    tag.status = body.status
    tag.updated_by = p.email
    db.flush()
    action = "tag.deactivate" if body.status.value == "inactive" else "tag.activate"
    log_action(db, action, actor_id=p.id, actor_email=p.email,
               subject_type="tag", subject_id=str(tag.id),
               context={"tag_name": tag.tag_name, "old_status": old_status.value, "new_status": body.status.value})
    db.commit()
    db.refresh(tag)
    return _tag_out(tag, db)


@router.delete("/tags/{tag_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_tag(
    tag_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(_TAG_ADMIN),
):
    tag = _get_tag_or_404(tag_id, db)
    count = _usage_count(tag_id, db)
    if count > 0:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete tag '{tag.tag_name}' — it is assigned to {count} asset(s). "
                   "Deactivate it instead, or remove it from all assets first.",
        )
    tag_name = tag.tag_name
    db.delete(tag)
    log_action(db, "tag.delete", actor_id=p.id, actor_email=p.email,
               subject_type="tag", subject_id=str(tag_id),
               context={"tag_name": tag_name})
    db.commit()


# ── Per-asset tag assignment ──────────────────────────────────────────────────

@router.get("/assets/{asset_id}/tags", response_model=List[TagSummary])
def get_asset_tags(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    if not db.query(Asset).filter(Asset.id == asset_id).first():
        raise HTTPException(status_code=404, detail="Asset not found")
    return _tag_summaries(asset_id, db)


@router.post("/assets/{asset_id}/tags", response_model=List[TagSummary])
def assign_asset_tags(
    asset_id: uuid.UUID,
    body: AssetTagsAssign,
    db: Session = Depends(get_db),
    p: Principal = Depends(_TAG_WRITER),
):
    if not db.query(Asset).filter(Asset.id == asset_id).first():
        raise HTTPException(status_code=404, detail="Asset not found")

    assigned: list[str] = []
    for tag_id in body.tag_ids:
        tag = db.query(Tag).filter(Tag.id == tag_id).first()
        if not tag:
            raise HTTPException(status_code=404, detail=f"Tag {tag_id} not found")
        if tag.status.value == "inactive":
            raise HTTPException(status_code=409, detail=f"Tag '{tag.tag_name}' is inactive and cannot be assigned")
        exists = db.query(AssetTag).filter(
            AssetTag.asset_id == asset_id, AssetTag.tag_id == tag_id
        ).first()
        if not exists:
            db.add(AssetTag(asset_id=asset_id, tag_id=tag_id, assigned_by=p.email))
            assigned.append(tag.tag_name)

    if assigned:
        log_action(db, "asset_tag.assign", actor_id=p.id, actor_email=p.email,
                   subject_type="asset", subject_id=str(asset_id),
                   context={"tags_assigned": assigned})
    db.commit()
    return _tag_summaries(asset_id, db)


@router.delete("/assets/{asset_id}/tags", status_code=status.HTTP_204_NO_CONTENT)
def remove_asset_tags(
    asset_id: uuid.UUID,
    body: AssetTagsRemove,
    db: Session = Depends(get_db),
    p: Principal = Depends(_TAG_WRITER),
):
    if not db.query(Asset).filter(Asset.id == asset_id).first():
        raise HTTPException(status_code=404, detail="Asset not found")

    removed: list[str] = []
    for tag_id in body.tag_ids:
        row = db.query(AssetTag).filter(
            AssetTag.asset_id == asset_id, AssetTag.tag_id == tag_id
        ).first()
        if row:
            tag_name = row.tag.tag_name
            db.delete(row)
            removed.append(tag_name)

    if removed:
        log_action(db, "asset_tag.remove", actor_id=p.id, actor_email=p.email,
                   subject_type="asset", subject_id=str(asset_id),
                   context={"tags_removed": removed})
    db.commit()


# ── Bulk assignment / removal ─────────────────────────────────────────────────

@router.post("/assets/tags/bulk-assign", response_model=dict)
def bulk_assign_tags(
    body: BulkTagAssign,
    db: Session = Depends(get_db),
    p: Principal = Depends(_TAG_WRITER),
):
    """Assign one or more tags to multiple assets at once."""
    # Validate all tags exist and are active
    tags = db.query(Tag).filter(Tag.id.in_(body.tag_ids)).all()
    if len(tags) != len(body.tag_ids):
        raise HTTPException(status_code=404, detail="One or more tags not found")
    inactive = [t.tag_name for t in tags if t.status.value == "inactive"]
    if inactive:
        raise HTTPException(status_code=409, detail=f"Inactive tags cannot be assigned: {', '.join(inactive)}")

    # Validate all assets exist
    asset_count = db.query(func.count(Asset.id)).filter(Asset.id.in_(body.asset_ids)).scalar() or 0
    if asset_count != len(body.asset_ids):
        raise HTTPException(status_code=404, detail="One or more assets not found")

    pairs_added = 0
    for asset_id in body.asset_ids:
        for tag_id in body.tag_ids:
            exists = db.query(AssetTag).filter(
                AssetTag.asset_id == asset_id, AssetTag.tag_id == tag_id
            ).first()
            if not exists:
                db.add(AssetTag(asset_id=asset_id, tag_id=tag_id, assigned_by=p.email))
                pairs_added += 1

    log_action(db, "asset_tag.bulk_assign", actor_id=p.id, actor_email=p.email,
               context={
                   "asset_count": len(body.asset_ids),
                   "tag_names": [t.tag_name for t in tags],
                   "pairs_added": pairs_added,
               })
    db.commit()
    return {"assets_affected": len(body.asset_ids), "tags_assigned": len(tags), "pairs_added": pairs_added}


@router.post("/assets/tags/bulk-remove", response_model=dict)
def bulk_remove_tags(
    body: BulkTagRemove,
    db: Session = Depends(get_db),
    p: Principal = Depends(_TAG_WRITER),
):
    """Remove one or more tags from multiple assets at once."""
    tags = db.query(Tag).filter(Tag.id.in_(body.tag_ids)).all()
    tag_names = [t.tag_name for t in tags]

    rows = db.query(AssetTag).filter(
        AssetTag.asset_id.in_(body.asset_ids),
        AssetTag.tag_id.in_(body.tag_ids),
    ).all()
    pairs_removed = len(rows)
    for row in rows:
        db.delete(row)

    log_action(db, "asset_tag.bulk_remove", actor_id=p.id, actor_email=p.email,
               context={
                   "asset_count": len(body.asset_ids),
                   "tag_names": tag_names,
                   "pairs_removed": pairs_removed,
               })
    db.commit()
    return {"assets_affected": len(body.asset_ids), "tags_removed": len(tag_names), "pairs_removed": pairs_removed}
