"""Connector and test-connection endpoints."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.connector import Connector, Credential
from app.schemas.common import Page
from app.schemas.connector import ConnectorIn, ConnectorOut, TestConnectionRequest, TestConnectionResult
from app.security import Principal, get_current_principal, require_roles
from app.services.audit import log_action

router = APIRouter(prefix="/connectors", tags=["connectors"])


@router.get("", response_model=Page[ConnectorOut])
def list_connectors(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(Connector)
    total = q.count()
    items = q.order_by(Connector.name).offset(offset).limit(limit).all()
    return Page(items=[ConnectorOut.model_validate(c) for c in items], total=total, limit=limit, offset=offset)


@router.post("", response_model=ConnectorOut, status_code=201)
def create_connector(
    body: ConnectorIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    conn = Connector(**body.model_dump())
    db.add(conn)
    log_action(db, "connector.created", actor_id=p.id, actor_email=p.email)
    db.commit()
    db.refresh(conn)
    return ConnectorOut.model_validate(conn)


@router.get("/{connector_id}", response_model=ConnectorOut)
def get_connector(connector_id: uuid.UUID, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    c = db.query(Connector).filter(Connector.id == connector_id).first()
    if not c:
        raise HTTPException(404, "Connector not found")
    return ConnectorOut.model_validate(c)


@router.put("/{connector_id}", response_model=ConnectorOut)
def update_connector(
    connector_id: uuid.UUID,
    body: ConnectorIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    c = db.query(Connector).filter(Connector.id == connector_id).first()
    if not c:
        raise HTTPException(404, "Connector not found")
    for k, v in body.model_dump().items():
        setattr(c, k, v)
    log_action(db, "connector.updated", actor_id=p.id, actor_email=p.email, subject_id=str(connector_id))
    db.commit()
    db.refresh(c)
    return ConnectorOut.model_validate(c)


@router.delete("/{connector_id}", status_code=204)
def delete_connector(
    connector_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin")),
):
    c = db.query(Connector).filter(Connector.id == connector_id).first()
    if not c:
        raise HTTPException(404, "Connector not found")
    db.delete(c)
    log_action(db, "connector.deleted", actor_id=p.id, actor_email=p.email, subject_id=str(connector_id))
    db.commit()


@router.post("/test", response_model=TestConnectionResult)
def test_connection(
    body: TestConnectionRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst")),
):
    from app.config import get_settings
    from app.models.asset import Asset
    import time

    asset = db.query(Asset).filter(Asset.id == body.asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")

    t0 = time.perf_counter()
    if get_settings().collector_mode == "mock":
        latency = int((time.perf_counter() - t0) * 1000) + 35
        log_action(db, "connector.test", actor_id=p.id, actor_email=p.email, subject_id=str(body.asset_id))
        db.commit()
        return TestConnectionResult(success=True, latency_ms=latency, message="Mock: connection successful", details={"mode": "mock"})

    # Live test — stub for now.
    return TestConnectionResult(success=False, latency_ms=0, message="Live test not yet supported in this build")
