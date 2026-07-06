"""Connector and test-connection endpoints."""
from __future__ import annotations

import uuid
import socket
import time

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models.asset import Asset
from app.models.connector import Connector, Credential
from app.schemas.common import Page
from app.schemas.connector import ConnectorIn, ConnectorOut, TestConnectionRequest, TestConnectionResult
from app.security import Principal, get_current_principal, require_roles
from app.services.audit import log_action
from app.services.scan_service import _PLATFORM_KIND
from app.services.vault import get_vault

router = APIRouter(prefix="/connectors", tags=["connectors"])

_DEFAULT_PORTS = {
    "ssh": 22,
    "winrm": 5985,
    "wmi": 135,
    "mysql": 3306,
    "mssql": 1433,
    "mongodb": 27017,
    "oracle": 1521,
    "postgresql": 5432,
    "redis": 6379,
}


def _validate_credential(db: Session, credential_id: uuid.UUID | None) -> None:
    if not credential_id:
        return
    cred = db.query(Credential).filter(Credential.id == credential_id, Credential.is_active.is_(True)).first()
    if not cred:
        raise HTTPException(400, "Linked credential does not exist or is inactive")


def _connector_for_test(db: Session, asset: Asset, body: TestConnectionRequest) -> Connector | None:
    if body.connector_id:
        return db.query(Connector).filter(Connector.id == body.connector_id).first()
    if asset.connector_id:
        return db.query(Connector).filter(Connector.id == asset.connector_id).first()
    kind = _PLATFORM_KIND.get(asset.platform)
    return db.query(Connector).filter(Connector.kind == kind, Connector.is_active.is_(True)).first() if kind else None


def _resolve_test_credential(db: Session, connector: Connector, override_id: uuid.UUID | None) -> Credential | None:
    credential_id = override_id or connector.credential_id
    if not credential_id:
        return None
    return db.query(Credential).filter(Credential.id == credential_id, Credential.is_active.is_(True)).first()


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
    _validate_credential(db, body.credential_id)
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
    _validate_credential(db, body.credential_id)
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
    asset = db.query(Asset).filter(Asset.id == body.asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    connector = _connector_for_test(db, asset, body)
    if not connector:
        raise HTTPException(404, "Connector not found")
    if not connector.is_active:
        return TestConnectionResult(
            success=False,
            latency_ms=0,
            message=f"Connector '{connector.name}' is inactive",
            details={"connector_id": str(connector.id), "kind": connector.kind.value},
        )

    expected_kind = _PLATFORM_KIND.get(asset.platform)
    if expected_kind and connector.kind.value != expected_kind:
        return TestConnectionResult(
            success=False,
            latency_ms=0,
            message=(
                f"Connector kind '{connector.kind.value}' does not match asset platform "
                f"'{asset.platform.value}' (expected '{expected_kind}')"
            ),
            details={"connector_id": str(connector.id), "asset_id": str(asset.id)},
        )

    t0 = time.perf_counter()
    if get_settings().collector_mode == "mock":
        latency = int((time.perf_counter() - t0) * 1000) + 35
        log_action(db, "connector.test", actor_id=p.id, actor_email=p.email, subject_id=str(body.asset_id))
        db.commit()
        return TestConnectionResult(
            success=True,
            latency_ms=latency,
            message="Mock: connector and target selection valid",
            details={"mode": "mock", "connector_id": str(connector.id), "asset_id": str(asset.id)},
        )

    credential = _resolve_test_credential(db, connector, body.credential_id)
    if not credential:
        return TestConnectionResult(
            success=False,
            latency_ms=0,
            message=f"Connector '{connector.name}' has no active credential linked",
            details={"connector_id": str(connector.id), "kind": connector.kind.value},
        )
    try:
        get_vault().resolve(credential.vault_ref)
    except LookupError:
        return TestConnectionResult(
            success=False,
            latency_ms=0,
            message=f"Secret for credential '{credential.name}' (vault_ref={credential.vault_ref!r}) not found in vault",
            details={"connector_id": str(connector.id), "credential_id": str(credential.id)},
        )
    except Exception as exc:
        return TestConnectionResult(
            success=False,
            latency_ms=0,
            message=f"Vault resolution failed for credential '{credential.name}': {exc}",
            details={"connector_id": str(connector.id), "credential_id": str(credential.id)},
        )

    host = asset.ip_address or asset.hostname
    port = asset.port or connector.default_port or _DEFAULT_PORTS.get(connector.kind.value)
    if not port:
        return TestConnectionResult(
            success=False,
            latency_ms=0,
            message=f"No port configured for connector kind '{connector.kind.value}'",
            details={"connector_id": str(connector.id), "asset_id": str(asset.id)},
        )

    try:
        with socket.create_connection((host, int(port)), timeout=5):
            latency = int((time.perf_counter() - t0) * 1000)
    except OSError as exc:
        latency = int((time.perf_counter() - t0) * 1000)
        return TestConnectionResult(
            success=False,
            latency_ms=latency,
            message=f"TCP connection to {host}:{port} failed: {exc}",
            details={"connector_id": str(connector.id), "asset_id": str(asset.id), "host": host, "port": int(port)},
        )

    log_action(db, "connector.test", actor_id=p.id, actor_email=p.email, subject_id=str(body.asset_id))
    db.commit()
    return TestConnectionResult(
        success=True,
        latency_ms=latency,
        message=f"Reachability OK and credential '{credential.name}' resolved",
        details={
            "mode": "live",
            "connector_id": str(connector.id),
            "credential_id": str(credential.id),
            "asset_id": str(asset.id),
            "host": host,
            "port": int(port),
        },
    )
