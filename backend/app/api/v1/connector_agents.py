"""Connector Agent Framework API.

Two audiences:
  1. Console UI  — CRUD, approval, revocation, job dispatch, logs view
  2. Agent       — enrollment, heartbeat, config pull, job poll, result/log upload

Agent endpoints require:
  - Authorization: Bearer <agent_token>
  - X-Connector-ID: <uuid>

Console endpoints require normal user JWT.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.connector_agent import (
    ConnectorAgent,
    ConnectorAgentHeartbeat,
    ConnectorAgentJob,
    ConnectorAgentLog,
    ConnectorAgentResult,
    ConnectorAgentResultChunk,
    ConnectorAgentSettings,
    ConnectorEnrollmentToken,
)
from app.models.enums import ConnectorAgentJobStatus, ConnectorAgentStatus
from app.schemas.common import Page
from app.schemas.connector_agent import (
    ApproveConnectorRequest,
    ConnectorAgentCreate,
    ConnectorAgentHeartbeatOut,
    ConnectorAgentJobOut,
    ConnectorAgentOut,
    ConnectorAgentSettingsIn,
    ConnectorAgentSettingsOut,
    ConnectorAgentUpdate,
    ConnectorJobOut,
    DispatchJobRequest,
    EnrollRequest,
    EnrollResponse,
    EnrollStatusResponse,
    GenerateEnrollmentTokenRequest,
    GenerateEnrollmentTokenResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    JobStatusUpdate,
    LogUploadRequest,
    ResultUploadRequest,
    ResultUploadResponse,
    RevokeConnectorRequest,
    TokenRotateResponse,
)
from app.security import Principal, get_current_principal, require_roles
from app.services.audit import log_action
from app.services.connector_result_ingestion import ingest_connector_result

router = APIRouter(tags=["connector-agents"])

# ── RBAC helpers ───────────────────────────────────────────────────────────────
_CONNECTOR_ADMIN = require_roles("admin")
_CONNECTOR_MANAGER = require_roles("admin", "security_analyst")

# Stale threshold: if last heartbeat > this, status = stale / offline
_STALE_THRESHOLD_SECONDS = 120
_OFFLINE_THRESHOLD_SECONDS = 600


def _process_completed_result(result: ConnectorAgentResult, db: Session) -> None:
    """Reassemble result chunks, decode the JSON payload and extract summary counts."""
    chunks = (
        db.query(ConnectorAgentResultChunk)
        .filter(ConnectorAgentResultChunk.result_id == result.id)
        .order_by(ConnectorAgentResultChunk.chunk_index)
        .all()
    )
    compressed = b"".join(base64.b64decode(chunk.data) for chunk in chunks)
    if result.checksum:
        actual = hashlib.sha256(compressed).hexdigest()
        if actual != result.checksum:
            raise HTTPException(status_code=400, detail="Total checksum mismatch")

    result.size_bytes = len(compressed)
    if result.content_encoding == "gzip":
        raw = gzip.decompress(compressed)
    else:
        raw = compressed

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        result.processing_error = f"Result JSON decode failed: {str(exc)[:400]}"
        result.processed_at = datetime.now(UTC)
        return

    result.payload = payload
    result.accounts_discovered = int(payload.get("accounts_discovered") or 0)
    result.assets_scanned = int(payload.get("assets_scanned") or 0)

    target_results = payload.get("target_results")
    if isinstance(target_results, list):
        if not result.accounts_discovered:
            result.accounts_discovered = sum(
                int(t.get("accounts_discovered") or 0)
                for t in target_results
                if isinstance(t, dict)
            )
        if not result.assets_scanned:
            result.assets_scanned = sum(
                1
                for t in target_results
                if isinstance(t, dict) and t.get("status") == "success"
            )

    result.processing_error = None
    result.processed_at = datetime.now(UTC)
    ingest_connector_result(db, result)

# ── Token helpers ──────────────────────────────────────────────────────────────

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _generate_token() -> tuple[str, str, str]:
    """Returns (plaintext_token, token_hash, token_prefix)."""
    token = secrets.token_urlsafe(48)
    token_hash = _hash_token(token)
    token_prefix = token[:8]
    return token, token_hash, token_prefix


def _verify_token(token: str, stored_hash: str) -> bool:
    return hmac.compare_digest(_hash_token(token), stored_hash)


def _resolve_agent_status(agent: ConnectorAgent) -> ConnectorAgentStatus:
    """Compute effective status based on heartbeat recency."""
    if not agent.is_enabled:
        return ConnectorAgentStatus.disabled
    if agent.status == ConnectorAgentStatus.revoked:
        return ConnectorAgentStatus.revoked
    if agent.status == ConnectorAgentStatus.pending:
        return ConnectorAgentStatus.pending
    if not agent.last_heartbeat_at:
        return ConnectorAgentStatus.approved
    age = (datetime.now(UTC) - agent.last_heartbeat_at).total_seconds()
    if age <= _STALE_THRESHOLD_SECONDS:
        return ConnectorAgentStatus.online
    if age <= _OFFLINE_THRESHOLD_SECONDS:
        return ConnectorAgentStatus.stale
    return ConnectorAgentStatus.offline


def _get_agent_or_404(agent_id: uuid.UUID, db: Session) -> ConnectorAgent:
    agent = db.query(ConnectorAgent).filter(ConnectorAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Connector agent not found")
    return agent


# ── Agent authentication middleware helper ─────────────────────────────────────

def _authenticate_agent(
    x_connector_id: str | None,
    authorization: str | None,
    db: Session,
) -> ConnectorAgent:
    if not x_connector_id or not authorization:
        raise HTTPException(status_code=401, detail="Missing connector credentials")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization scheme")
    token = authorization[7:]
    try:
        agent_uuid = uuid.UUID(x_connector_id)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid connector ID format")

    agent = db.query(ConnectorAgent).filter(ConnectorAgent.id == agent_uuid).first()
    if not agent:
        raise HTTPException(status_code=401, detail="Unknown connector")
    # Verify token FIRST to avoid leaking status to unauthenticated callers
    if not agent.token_hash or not _verify_token(token, agent.token_hash):
        raise HTTPException(status_code=401, detail="Invalid connector token")
    # Now that identity is confirmed, check administrative status
    if agent.status == ConnectorAgentStatus.revoked:
        raise HTTPException(status_code=403, detail="Connector has been revoked")
    if not agent.is_enabled:
        raise HTTPException(status_code=403, detail="Connector is disabled")
    if agent.status == ConnectorAgentStatus.pending:
        raise HTTPException(status_code=403, detail="Connector pending approval")
    return agent


# ═══════════════════════════════════════════════════════════════════════════════
# CONSOLE-FACING ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

# ── Enrollment token management ────────────────────────────────────────────────

@router.post("/connector-agents/enrollment-tokens",
             response_model=GenerateEnrollmentTokenResponse,
             status_code=status.HTTP_201_CREATED)
def generate_enrollment_token(
    body: GenerateEnrollmentTokenRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(_CONNECTOR_ADMIN),
):
    """Generate a one-time enrollment token to register a new connector agent."""
    token, token_hash, token_prefix = _generate_token()
    expires_at = datetime.now(UTC) + timedelta(seconds=body.expires_in_seconds)
    record = ConnectorEnrollmentToken(
        token_hash=token_hash,
        token_prefix=token_prefix,
        expected_hostname=body.expected_hostname,
        expected_site=body.expected_site,
        expected_environment=body.expected_environment,
        auto_approve=body.auto_approve,
        expires_at=expires_at,
        created_by=p.email,
    )
    db.add(record)
    db.flush()
    log_action(db, "connector.enrollment_token.generated",
               actor_id=p.id, actor_email=p.email,
               subject_type="enrollment_token", subject_id=str(record.id),
               context={"prefix": token_prefix, "auto_approve": body.auto_approve,
                        "expires_at": expires_at.isoformat()})
    db.commit()
    return GenerateEnrollmentTokenResponse(
        token=token, token_prefix=token_prefix,
        expires_at=expires_at, auto_approve=body.auto_approve,
    )


# ── Connector list + detail ────────────────────────────────────────────────────

@router.get("/connector-agents", response_model=Page[ConnectorAgentOut])
def list_connector_agents(
    search: str | None = None,
    site: str | None = None,
    environment: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(ConnectorAgent)
    if search:
        q = q.filter(
            ConnectorAgent.name.ilike(f"%{search}%") |
            ConnectorAgent.hostname.ilike(f"%{search}%")
        )
    if site:
        q = q.filter(ConnectorAgent.site == site)
    if environment:
        q = q.filter(ConnectorAgent.environment == environment)
    total = q.count()
    agents = q.order_by(ConnectorAgent.name).offset(offset).limit(limit).all()

    # Resolve live status based on heartbeat recency
    out = []
    for a in agents:
        live_status = _resolve_agent_status(a)
        a.status = live_status
        if status_filter and live_status.value != status_filter:
            continue
        out.append(ConnectorAgentOut.model_validate(a))
    return Page(items=out, total=total, limit=limit, offset=offset)


@router.post("/connector-agents",
             response_model=ConnectorAgentOut,
             status_code=status.HTTP_201_CREATED)
def create_connector_agent(
    body: ConnectorAgentCreate,
    db: Session = Depends(get_db),
    p: Principal = Depends(_CONNECTOR_ADMIN),
):
    """Pre-create a connector agent record before deployment."""
    if db.query(ConnectorAgent).filter(ConnectorAgent.name == body.name).first():
        raise HTTPException(status_code=409, detail=f"Connector '{body.name}' already exists")
    agent = ConnectorAgent(
        name=body.name, description=body.description,
        site=body.site, location=body.location, environment=body.environment,
        status=ConnectorAgentStatus.pending,
        created_by=p.email, updated_by=p.email,
    )
    db.add(agent)
    db.flush()
    # Create default settings
    db.add(ConnectorAgentSettings(agent_id=agent.id, updated_by=p.email))
    log_action(db, "connector.created", actor_id=p.id, actor_email=p.email,
               subject_type="connector_agent", subject_id=str(agent.id),
               context={"name": agent.name})
    db.commit()
    db.refresh(agent)
    return ConnectorAgentOut.model_validate(agent)


@router.get("/connector-agents/{agent_id}", response_model=ConnectorAgentOut)
def get_connector_agent(
    agent_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    agent = _get_agent_or_404(agent_id, db)
    agent.status = _resolve_agent_status(agent)
    return ConnectorAgentOut.model_validate(agent)


@router.patch("/connector-agents/{agent_id}", response_model=ConnectorAgentOut)
def update_connector_agent(
    agent_id: uuid.UUID,
    body: ConnectorAgentUpdate,
    db: Session = Depends(get_db),
    p: Principal = Depends(_CONNECTOR_MANAGER),
):
    agent = _get_agent_or_404(agent_id, db)
    changes: dict = {}
    for field in ("name", "description", "site", "location", "environment", "is_enabled"):
        val = getattr(body, field)
        if val is not None:
            changes[field] = val
            setattr(agent, field, val)
    agent.updated_by = p.email
    log_action(db, "connector.updated", actor_id=p.id, actor_email=p.email,
               subject_type="connector_agent", subject_id=str(agent.id),
               context={"changes": changes})
    db.commit()
    db.refresh(agent)
    agent.status = _resolve_agent_status(agent)
    return ConnectorAgentOut.model_validate(agent)


@router.post("/connector-agents/{agent_id}/approve", response_model=ConnectorAgentOut)
def approve_connector(
    agent_id: uuid.UUID,
    body: ApproveConnectorRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(_CONNECTOR_ADMIN),
):
    """Approve a pending connector. Issues a bearer token."""
    agent = _get_agent_or_404(agent_id, db)
    if agent.status not in (ConnectorAgentStatus.pending, ConnectorAgentStatus.approved):
        raise HTTPException(status_code=409, detail="Connector is not in pending state")

    token, token_hash, token_prefix = _generate_token()
    agent.token_hash = token_hash
    agent.token_prefix = token_prefix
    agent.status = ConnectorAgentStatus.approved
    agent.approved_by = p.email
    agent.approved_at = datetime.now(UTC)
    agent.updated_by = p.email

    log_action(db, "connector.approved", actor_id=p.id, actor_email=p.email,
               subject_type="connector_agent", subject_id=str(agent.id),
               context={"name": agent.name, "notes": body.notes})
    db.commit()
    db.refresh(agent)
    agent.status = _resolve_agent_status(agent)
    out = ConnectorAgentOut.model_validate(agent)
    # We embed the token in the response once — caller must forward to the operator
    out.token_prefix = token_prefix
    return out


@router.post("/connector-agents/{agent_id}/revoke", response_model=ConnectorAgentOut)
def revoke_connector(
    agent_id: uuid.UUID,
    body: RevokeConnectorRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(_CONNECTOR_ADMIN),
):
    agent = _get_agent_or_404(agent_id, db)
    if agent.status == ConnectorAgentStatus.revoked:
        raise HTTPException(status_code=409, detail="Connector already revoked")
    agent.status = ConnectorAgentStatus.revoked
    agent.is_enabled = False
    agent.revoked_by = p.email
    agent.revoked_at = datetime.now(UTC)
    agent.revocation_reason = body.reason
    # Do NOT clear token_hash — the status check in _authenticate_agent returns
    # 403 (Forbidden) for revoked agents, which is more informative than 401.
    agent.updated_by = p.email
    log_action(db, "connector.revoked", actor_id=p.id, actor_email=p.email,
               subject_type="connector_agent", subject_id=str(agent.id),
               context={"name": agent.name, "reason": body.reason})
    db.commit()
    db.refresh(agent)
    return ConnectorAgentOut.model_validate(agent)


@router.post("/connector-agents/{agent_id}/disable", response_model=ConnectorAgentOut)
def disable_connector(
    agent_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(_CONNECTOR_MANAGER),
):
    agent = _get_agent_or_404(agent_id, db)
    agent.is_enabled = False
    agent.updated_by = p.email
    log_action(db, "connector.disabled", actor_id=p.id, actor_email=p.email,
               subject_type="connector_agent", subject_id=str(agent.id))
    db.commit()
    db.refresh(agent)
    agent.status = _resolve_agent_status(agent)
    return ConnectorAgentOut.model_validate(agent)


@router.post("/connector-agents/{agent_id}/enable", response_model=ConnectorAgentOut)
def enable_connector(
    agent_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(_CONNECTOR_MANAGER),
):
    agent = _get_agent_or_404(agent_id, db)
    if agent.status == ConnectorAgentStatus.revoked:
        raise HTTPException(status_code=409, detail="Revoked connectors cannot be re-enabled")
    agent.is_enabled = True
    agent.updated_by = p.email
    log_action(db, "connector.enabled", actor_id=p.id, actor_email=p.email,
               subject_type="connector_agent", subject_id=str(agent.id))
    db.commit()
    db.refresh(agent)
    agent.status = _resolve_agent_status(agent)
    return ConnectorAgentOut.model_validate(agent)


@router.post("/connector-agents/{agent_id}/rotate-token", response_model=TokenRotateResponse)
def rotate_agent_token(
    agent_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(_CONNECTOR_ADMIN),
):
    """Issue a new bearer token, immediately invalidating the old one."""
    agent = _get_agent_or_404(agent_id, db)
    if agent.status == ConnectorAgentStatus.revoked:
        raise HTTPException(status_code=409, detail="Revoked connector")
    token, token_hash, token_prefix = _generate_token()
    agent.token_hash = token_hash
    agent.token_prefix = token_prefix
    agent.updated_by = p.email
    log_action(db, "connector.token_rotated", actor_id=p.id, actor_email=p.email,
               subject_type="connector_agent", subject_id=str(agent.id))
    db.commit()
    settings = agent.settings
    rotation_days = settings.token_rotation_days if settings else 90
    return TokenRotateResponse(
        token=token,
        token_prefix=token_prefix,
        expires_at=datetime.now(UTC) + timedelta(days=rotation_days),
    )


# ── Settings (console manages, agent reads) ────────────────────────────────────

@router.get("/connector-agents/{agent_id}/settings", response_model=ConnectorAgentSettingsOut)
def get_connector_settings(
    agent_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    agent = _get_agent_or_404(agent_id, db)
    if not agent.settings:
        raise HTTPException(status_code=404, detail="Settings not configured")
    return ConnectorAgentSettingsOut.model_validate(agent.settings)


@router.put("/connector-agents/{agent_id}/settings", response_model=ConnectorAgentSettingsOut)
def update_connector_settings(
    agent_id: uuid.UUID,
    body: ConnectorAgentSettingsIn,
    db: Session = Depends(get_db),
    p: Principal = Depends(_CONNECTOR_MANAGER),
):
    agent = _get_agent_or_404(agent_id, db)
    if not agent.settings:
        s = ConnectorAgentSettings(agent_id=agent.id)
        db.add(s)
        db.flush()
        agent.settings = s
    s = agent.settings
    for field, val in body.model_dump().items():
        setattr(s, field, val)
    s.updated_by = p.email
    log_action(db, "connector.settings_updated", actor_id=p.id, actor_email=p.email,
               subject_type="connector_agent", subject_id=str(agent.id))
    db.commit()
    db.refresh(s)
    return ConnectorAgentSettingsOut.model_validate(s)


# ── Jobs (console side) ────────────────────────────────────────────────────────

@router.get("/connector-agents/{agent_id}/jobs", response_model=Page[ConnectorAgentJobOut])
def list_agent_jobs(
    agent_id: uuid.UUID,
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    _get_agent_or_404(agent_id, db)
    q = db.query(ConnectorAgentJob).filter(ConnectorAgentJob.agent_id == agent_id)
    if status_filter:
        q = q.filter(ConnectorAgentJob.status == status_filter)
    total = q.count()
    jobs = q.order_by(ConnectorAgentJob.created_at.desc()).offset(offset).limit(limit).all()
    return Page(
        items=[ConnectorAgentJobOut.model_validate(j) for j in jobs],
        total=total, limit=limit, offset=offset,
    )


@router.post("/connector-agents/{agent_id}/jobs",
             response_model=ConnectorAgentJobOut,
             status_code=status.HTTP_201_CREATED)
def dispatch_job(
    agent_id: uuid.UUID,
    body: DispatchJobRequest,
    db: Session = Depends(get_db),
    p: Principal = Depends(_CONNECTOR_MANAGER),
):
    """Dispatch a scan job to a specific connector agent."""
    agent = _get_agent_or_404(agent_id, db)
    if agent.status == ConnectorAgentStatus.revoked or not agent.is_enabled:
        raise HTTPException(status_code=409, detail="Cannot dispatch job to disabled/revoked connector")

    payload_str = json.dumps(body.payload, sort_keys=True)
    checksum = hashlib.sha256(payload_str.encode()).hexdigest()

    expires_at = None
    if body.expires_in_seconds:
        expires_at = datetime.now(UTC) + timedelta(seconds=body.expires_in_seconds)

    job = ConnectorAgentJob(
        agent_id=agent_id,
        job_type=body.job_type,
        payload=body.payload,
        payload_checksum=checksum,
        priority=body.priority,
        expires_at=expires_at,
        created_by=p.email,
    )
    db.add(job)
    db.flush()
    log_action(db, "connector.job_dispatched", actor_id=p.id, actor_email=p.email,
               subject_type="connector_agent_job", subject_id=str(job.id),
               context={"agent_id": str(agent_id), "job_type": body.job_type.value})
    db.commit()
    db.refresh(job)
    return ConnectorAgentJobOut.model_validate(job)


@router.post("/connector-agents/{agent_id}/jobs/{job_id}/cancel",
             response_model=ConnectorAgentJobOut)
def cancel_job(
    agent_id: uuid.UUID,
    job_id: uuid.UUID,
    db: Session = Depends(get_db),
    p: Principal = Depends(_CONNECTOR_MANAGER),
):
    job = db.query(ConnectorAgentJob).filter(
        ConnectorAgentJob.id == job_id,
        ConnectorAgentJob.agent_id == agent_id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status in (ConnectorAgentJobStatus.success,
                       ConnectorAgentJobStatus.failed,
                       ConnectorAgentJobStatus.cancelled):
        raise HTTPException(status_code=409, detail="Job already completed")
    job.status = ConnectorAgentJobStatus.cancelled
    job.cancel_requested_by = p.email
    job.cancel_requested_at = datetime.now(UTC)
    job.completed_at = datetime.now(UTC)
    log_action(db, "connector.job_cancelled", actor_id=p.id, actor_email=p.email,
               subject_type="connector_agent_job", subject_id=str(job.id))
    db.commit()
    db.refresh(job)
    return ConnectorAgentJobOut.model_validate(job)


# ── Heartbeats & Logs (read-only console views) ────────────────────────────────

@router.get("/connector-agents/{agent_id}/heartbeats",
            response_model=list[ConnectorAgentHeartbeatOut])
def get_agent_heartbeats(
    agent_id: uuid.UUID,
    limit: int = Query(default=20, le=100),
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    _get_agent_or_404(agent_id, db)
    heartbeats = (
        db.query(ConnectorAgentHeartbeat)
        .filter(ConnectorAgentHeartbeat.agent_id == agent_id)
        .order_by(ConnectorAgentHeartbeat.received_at.desc())
        .limit(limit)
        .all()
    )
    return [ConnectorAgentHeartbeatOut.model_validate(h) for h in heartbeats]


@router.get("/connector-agents/{agent_id}/logs")
def get_agent_logs(
    agent_id: uuid.UUID,
    level: str | None = None,
    job_id: uuid.UUID | None = None,
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    _get_agent_or_404(agent_id, db)
    q = db.query(ConnectorAgentLog).filter(ConnectorAgentLog.agent_id == agent_id)
    if level:
        q = q.filter(ConnectorAgentLog.level == level)
    if job_id:
        q = q.filter(ConnectorAgentLog.job_id == job_id)
    logs = q.order_by(ConnectorAgentLog.received_at.desc()).limit(limit).all()
    return [
        {
            "id": str(l.id),
            "level": l.level,
            "message": l.message,
            "context": l.context,
            "job_id": str(l.job_id) if l.job_id else None,
            "agent_timestamp": l.agent_timestamp.isoformat() if l.agent_timestamp else None,
            "received_at": l.received_at.isoformat(),
        }
        for l in logs
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT-FACING ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

# ── Self-registration (no auth required — uses one-time token) ─────────────────

@router.post("/connector-agents/enroll",
             response_model=EnrollResponse,
             status_code=status.HTTP_201_CREATED)
def enroll_agent(
    body: EnrollRequest,
    db: Session = Depends(get_db),
):
    """Agent self-registers with a one-time enrollment token."""
    token_hash = _hash_token(body.registration_token)
    et = db.query(ConnectorEnrollmentToken).filter(
        ConnectorEnrollmentToken.token_hash == token_hash,
        ConnectorEnrollmentToken.is_used == False,     # noqa: E712
        ConnectorEnrollmentToken.is_revoked == False,  # noqa: E712
    ).first()
    if not et:
        raise HTTPException(status_code=401, detail="Invalid or expired enrollment token")
    if et.expires_at.replace(tzinfo=UTC) < datetime.now(UTC):
        raise HTTPException(status_code=401, detail="Enrollment token has expired")

    # Mark token as used
    et.is_used = True
    et.used_at = datetime.now(UTC)

    # Create the agent record
    agent_name = body.name or body.hostname
    # Ensure name uniqueness
    existing_count = db.query(func.count(ConnectorAgent.id)).filter(
        ConnectorAgent.name.like(f"{agent_name}%")
    ).scalar() or 0
    if existing_count > 0:
        agent_name = f"{agent_name}-{existing_count}"

    agent = ConnectorAgent(
        name=agent_name,
        hostname=body.hostname,
        ip_address=body.ip_address,
        os_platform=body.os_platform,
        os_version=body.os_version,
        agent_version=body.agent_version,
        site=body.site or et.expected_site,
        location=body.location,
        environment=body.environment or et.expected_environment,
        status=ConnectorAgentStatus.pending,
        is_enabled=True,
    )

    bearer_token = None
    if et.auto_approve:
        token, token_hash_new, token_prefix = _generate_token()
        agent.token_hash = token_hash_new
        agent.token_prefix = token_prefix
        agent.status = ConnectorAgentStatus.approved
        agent.approved_by = "auto-approve"
        agent.approved_at = datetime.now(UTC)
        bearer_token = token

    db.add(agent)
    db.flush()
    et.agent_id = agent.id

    # Create default settings
    db.add(ConnectorAgentSettings(agent_id=agent.id))
    db.commit()
    db.refresh(agent)

    return EnrollResponse(
        connector_id=agent.id,
        status=agent.status,
        token=bearer_token,
        token_prefix=agent.token_prefix,
        message=(
            "Enrollment complete. Connector is ready." if et.auto_approve
            else "Enrollment received. Awaiting admin approval."
        ),
    )


@router.get("/connector-agents/enroll/status",
            response_model=EnrollStatusResponse)
def check_enrollment_status(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    """Agent polls this to find out if it has been approved and get its bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization[7:]
    token_hash = _hash_token(token)
    et = db.query(ConnectorEnrollmentToken).filter(
        ConnectorEnrollmentToken.token_hash == token_hash,
    ).first()
    if not et or not et.agent_id:
        raise HTTPException(status_code=404, detail="Enrollment not found")

    agent = db.query(ConnectorAgent).filter(ConnectorAgent.id == et.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agent.status == ConnectorAgentStatus.pending:
        return EnrollStatusResponse(connector_id=agent.id, status=agent.status)

    # If approved, issue a fresh bearer token (agent picks it up here once)
    if agent.status == ConnectorAgentStatus.approved and not agent.token_hash:
        tkn, tkn_hash, tkn_prefix = _generate_token()
        agent.token_hash = tkn_hash
        agent.token_prefix = tkn_prefix
        db.commit()
        return EnrollStatusResponse(
            connector_id=agent.id, status=agent.status,
            token=tkn, token_prefix=tkn_prefix,
        )

    return EnrollStatusResponse(connector_id=agent.id, status=agent.status)


# ── Agent runtime endpoints (require agent Bearer token + X-Connector-ID) ──────

@router.post("/connector-agents/{agent_id}/heartbeat",
             response_model=HeartbeatResponse)
def agent_heartbeat(
    agent_id: uuid.UUID,
    body: HeartbeatRequest,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_connector_id: str | None = Header(default=None),
):
    """Agent sends heartbeat. Console responds with optional commands."""
    agent = _authenticate_agent(x_connector_id, authorization, db)
    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="Connector ID mismatch")

    now = datetime.now(UTC)
    # Record heartbeat
    hb = ConnectorAgentHeartbeat(
        agent_id=agent.id,
        received_at=now,
        agent_timestamp=body.agent_timestamp,
        agent_version=body.agent_version,
        status=body.status,
        active_jobs=body.active_jobs,
        queued_results=body.queued_results,
        queue_size_mb=body.queue_size_mb,
        cpu_percent=body.cpu_percent,
        memory_mb=body.memory_mb,
        disk_free_mb=body.disk_free_mb,
        error_count=body.error_count,
        payload=body.payload,
    )
    db.add(hb)

    # Update agent last seen
    agent.last_heartbeat_at = now
    agent.last_seen_at = now
    if body.agent_version:
        agent.agent_version = body.agent_version
    if body.status == "error":
        agent.status = ConnectorAgentStatus.error
    elif agent.status in (ConnectorAgentStatus.approved, ConnectorAgentStatus.offline,
                           ConnectorAgentStatus.stale, ConnectorAgentStatus.error):
        agent.status = ConnectorAgentStatus.online

    # Get settings config version (use updated_at epoch as version integer)
    config_version = None
    if agent.settings:
        config_version = int(agent.settings.updated_at.timestamp())

    db.commit()
    return HeartbeatResponse(
        acknowledged=True,
        server_time=now,
        config_version=config_version,
    )


@router.get("/connector-agents/{agent_id}/config")
def agent_pull_config(
    agent_id: uuid.UUID,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_connector_id: str | None = Header(default=None),
):
    """Agent pulls its latest console-managed configuration."""
    agent = _authenticate_agent(x_connector_id, authorization, db)
    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="Connector ID mismatch")

    settings = agent.settings
    if not settings:
        return {"config": {}, "version": 0}

    config = {
        "connector_id": str(agent.id),
        "polling": {
            "heartbeat_interval_seconds": settings.heartbeat_interval_seconds,
            "job_poll_interval_seconds": settings.job_poll_interval_seconds,
            "config_refresh_interval_seconds": settings.config_refresh_interval_seconds,
        },
        "retry": {
            "max_attempts": settings.retry_max_attempts,
            "backoff_base_seconds": settings.retry_backoff_base_seconds,
            "backoff_max_seconds": settings.retry_backoff_max_seconds,
        },
        "execution": {
            "job_timeout_seconds": settings.job_timeout_seconds,
            "max_concurrent_jobs": settings.max_concurrent_jobs,
            "result_chunk_size_mb": settings.result_chunk_size_mb,
        },
        "security": {
            "verify_console_certificate": settings.verify_console_certificate,
            "verify_console_fingerprint": settings.verify_console_fingerprint,
            "console_fingerprint": settings.console_fingerprint,
            "token_rotation_days": settings.token_rotation_days,
        },
        "storage": {
            "offline_queue_max_mb": settings.offline_queue_max_mb,
            "result_retention_hours": settings.result_retention_hours,
            "log_retention_days": settings.log_retention_days,
        },
        "proxy": settings.proxy_config or {},
        "logging": {
            "level": settings.log_level,
            "sanitize_secrets": settings.sanitize_secrets_in_logs,
        },
        "scope": {
            "allowed_scan_profiles": settings.allowed_scan_profiles or [],
            "allowed_scan_modes": settings.allowed_scan_modes or ["safe"],
            "allowed_environments": settings.allowed_environments or [],
            "allowed_tags": settings.allowed_tags or [],
            "denied_tags": settings.denied_tags or [],
            "max_targets_per_job": settings.max_targets_per_job,
        },
        "upgrade": {
            "auto_upgrade": settings.auto_upgrade,
            "channel": settings.upgrade_channel,
        },
        "is_enabled": agent.is_enabled,
        "config_version": int(settings.updated_at.timestamp()),
    }
    return {"config": config, "version": int(settings.updated_at.timestamp())}


@router.get("/connector-agents/{agent_id}/jobs/pending",
            response_model=list[ConnectorJobOut])
def agent_poll_jobs(
    agent_id: uuid.UUID,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_connector_id: str | None = Header(default=None),
):
    """Agent polls for pending jobs it should execute."""
    agent = _authenticate_agent(x_connector_id, authorization, db)
    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="Connector ID mismatch")

    now = datetime.now(UTC)
    jobs = (
        db.query(ConnectorAgentJob)
        .filter(
            ConnectorAgentJob.agent_id == agent_id,
            ConnectorAgentJob.status == ConnectorAgentJobStatus.pending,
        )
        .filter(
            (ConnectorAgentJob.expires_at == None) |  # noqa: E711
            (ConnectorAgentJob.expires_at > now)
        )
        .order_by(ConnectorAgentJob.priority, ConnectorAgentJob.created_at)
        .limit(10)
        .all()
    )
    return [ConnectorJobOut.model_validate(j) for j in jobs]


@router.patch("/connector-agents/{agent_id}/jobs/{job_id}/status",
              response_model=ConnectorAgentJobOut)
def agent_update_job_status(
    agent_id: uuid.UUID,
    job_id: uuid.UUID,
    body: JobStatusUpdate,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_connector_id: str | None = Header(default=None),
):
    """Agent updates job status and progress."""
    agent = _authenticate_agent(x_connector_id, authorization, db)
    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="Connector ID mismatch")

    job = db.query(ConnectorAgentJob).filter(
        ConnectorAgentJob.id == job_id,
        ConnectorAgentJob.agent_id == agent_id,
    ).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status == ConnectorAgentJobStatus.cancelled:
        # Return the cancelled status — agent should stop processing
        return ConnectorAgentJobOut.model_validate(job)

    now = datetime.now(UTC)
    job.status = body.status
    job.progress_pct = body.progress_pct
    if body.progress_message:
        job.progress_message = body.progress_message
    if body.targets_total is not None:
        job.targets_total = body.targets_total
    if body.targets_done is not None:
        job.targets_done = body.targets_done
    if body.targets_failed is not None:
        job.targets_failed = body.targets_failed
    if body.error_message:
        job.error_message = body.error_message

    if body.status == ConnectorAgentJobStatus.accepted and not job.accepted_at:
        job.accepted_at = now
    if body.status == ConnectorAgentJobStatus.running and not job.started_at:
        job.started_at = now
    if body.status in (
        ConnectorAgentJobStatus.success,
        ConnectorAgentJobStatus.partial_success,
        ConnectorAgentJobStatus.failed,
        ConnectorAgentJobStatus.timed_out,
    ):
        job.completed_at = now

    db.commit()
    db.refresh(job)
    return ConnectorAgentJobOut.model_validate(job)


@router.post("/connector-agents/{agent_id}/results",
             response_model=ResultUploadResponse,
             status_code=status.HTTP_202_ACCEPTED)
def agent_upload_result(
    agent_id: uuid.UUID,
    body: ResultUploadRequest,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_connector_id: str | None = Header(default=None),
):
    """Agent uploads scan result (single or chunked)."""
    agent = _authenticate_agent(x_connector_id, authorization, db)
    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="Connector ID mismatch")

    # Verify chunk checksum — agent sends sha256 of the raw compressed bytes,
    # not of the base64 string, so decode first.
    try:
        chunk_bytes = base64.b64decode(body.data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 data")
    chunk_checksum = hashlib.sha256(chunk_bytes).hexdigest()
    if chunk_checksum != body.checksum:
        raise HTTPException(status_code=400, detail="Chunk checksum mismatch")

    # Find or create result record
    result = db.query(ConnectorAgentResult).filter(
        ConnectorAgentResult.agent_id == agent_id,
        ConnectorAgentResult.job_id == body.job_id,
        ConnectorAgentResult.is_complete == False,  # noqa: E712
    ).first()

    now = datetime.now(UTC)
    if not result:
        result = ConnectorAgentResult(
            agent_id=agent_id,
            job_id=body.job_id,
            chunk_count=body.chunk_count,
            content_encoding=body.content_encoding,
        )
        db.add(result)
        db.flush()

    # Idempotent: skip if chunk already received
    existing_chunk = db.query(ConnectorAgentResultChunk).filter(
        ConnectorAgentResultChunk.result_id == result.id,
        ConnectorAgentResultChunk.chunk_index == body.chunk_index,
    ).first()
    if not existing_chunk:
        db.add(ConnectorAgentResultChunk(
            result_id=result.id,
            chunk_index=body.chunk_index,
            data=body.data,
            checksum=body.checksum,
            received_at=now,
        ))
        result.chunks_received += 1
        db.flush()

    # Check if all chunks received
    is_complete = result.chunks_received >= result.chunk_count
    result.is_complete = is_complete
    if is_complete and body.total_checksum:
        result.checksum = body.total_checksum
    if is_complete:
        _process_completed_result(result, db)
        if body.total_checksum:
            result.checksum = body.total_checksum
        # Update job result link
        job = db.query(ConnectorAgentJob).filter(
            ConnectorAgentJob.id == body.job_id,
            ConnectorAgentJob.agent_id == agent_id,
        ).first()
        if job:
            job.result_id = result.id

    db.commit()
    db.refresh(result)
    return ResultUploadResponse(
        result_id=result.id,
        chunks_received=result.chunks_received,
        is_complete=result.is_complete,
    )


@router.post("/connector-agents/{agent_id}/logs",
             status_code=status.HTTP_202_ACCEPTED)
def agent_upload_logs(
    agent_id: uuid.UUID,
    body: LogUploadRequest,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
    x_connector_id: str | None = Header(default=None),
):
    """Agent uploads a batch of diagnostic log entries."""
    agent = _authenticate_agent(x_connector_id, authorization, db)
    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="Connector ID mismatch")

    now = datetime.now(UTC)
    for entry in body.entries:
        db.add(ConnectorAgentLog(
            agent_id=agent_id,
            job_id=entry.job_id,
            level=entry.level,
            message=entry.message,
            context=entry.context,
            agent_timestamp=entry.timestamp,
            received_at=now,
        ))
    db.commit()
    return {"accepted": len(body.entries)}
