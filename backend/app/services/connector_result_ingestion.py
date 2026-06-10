"""Ingest completed connector-agent result payloads into canonical tables."""
from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.collectors.base import NormalizedAccount, NormalizedEntitlement
from app.models.account import Account, AccountEntitlement
from app.models.asset import Asset
from app.models.connector_agent import ConnectorAgentResult
from app.models.enums import (
    AuthSource,
    EnabledStatus,
    InteractiveStatus,
    Platform,
    PrincipalType,
    PRIVILEGE_SEVERITY,
    PrivilegeClass,
)
from app.models.rule import ClassificationRule
from app.models.finding import PrivilegeFinding
from app.rules_engine.engine import RulesEngine, RuleSpec


_WINDOWS_DATE_RE = re.compile(r"^/Date\\(([-0-9]+)\\)/$")


def ingest_connector_result(db: Session, result: ConnectorAgentResult) -> None:
    """Persist agent-discovered accounts so the normal Accounts UI can show them."""
    payload = result.payload or {}
    target_results = payload.get("target_results")
    if not isinstance(target_results, list):
        return

    for target in target_results:
        if not isinstance(target, dict) or target.get("status") != "success":
            continue
        asset = _upsert_asset(db, target)
        normalized = [_normalized_account(a) for a in target.get("accounts") or [] if isinstance(a, dict)]
        accounts = _upsert_accounts(db, asset, normalized)
        _classify_accounts(db, result.job_id, accounts, normalized)


def _upsert_asset(db: Session, target: dict) -> Asset:
    hostname = str(target.get("hostname") or target.get("ip_address") or "unknown").strip()
    platform = _enum(Platform, target.get("platform"), Platform.windows)
    asset = (
        db.query(Asset)
        .filter(Asset.hostname == hostname, Asset.instance.is_(None))
        .first()
    )
    if asset is None:
        asset = Asset(hostname=hostname, platform=platform, discovery_enabled=True)
        db.add(asset)
    asset.platform = platform
    if target.get("ip_address"):
        asset.ip_address = str(target.get("ip_address"))
    asset.connection_type = "connector_agent"
    db.flush()
    return asset


def _normalized_account(data: dict) -> NormalizedAccount:
    return NormalizedAccount(
        account_name=str(data.get("account_name") or ""),
        source_type=str(data.get("source_type") or "connector_agent"),
        principal_type=_enum(PrincipalType, data.get("principal_type"), PrincipalType.unknown),
        auth_source=_enum(AuthSource, data.get("auth_source"), AuthSource.unknown),
        enabled_status=_enum(EnabledStatus, data.get("enabled_status"), EnabledStatus.unknown),
        interactive_status=_enum(InteractiveStatus, data.get("interactive_status"), InteractiveStatus.unknown),
        last_login=_parse_datetime(data.get("last_login")),
        last_login_source=data.get("last_login_source"),
        is_shared=bool(data.get("is_shared") or False),
        password_never_expires=bool(data.get("password_never_expires") or False),
        owner=data.get("owner"),
        evidence_summary=data.get("evidence_summary") or {},
        entitlements=[
            NormalizedEntitlement(
                kind=str(ent.get("kind") or "unknown"),
                name=str(ent.get("name") or ""),
                scope=ent.get("scope"),
                source=ent.get("source"),
                inherited=bool(ent.get("inherited") or False),
                via=ent.get("via"),
                attributes=ent.get("attributes") or {},
            )
            for ent in (data.get("entitlements") or [])
            if isinstance(ent, dict)
        ],
        win_interactive_confidence=int(data.get("win_interactive_confidence") or 0),
        win_interactive_detection_method=data.get("win_interactive_detection_method"),
        win_interactive_evidence=data.get("win_interactive_evidence"),
        win_allows_local_logon=data.get("win_allows_local_logon"),
        win_allows_remote_interactive=data.get("win_allows_remote_interactive"),
        win_allows_service_logon=data.get("win_allows_service_logon"),
        win_allows_batch_logon=data.get("win_allows_batch_logon"),
        win_allows_network_logon=data.get("win_allows_network_logon"),
        win_last_observed_logon_type=data.get("win_last_observed_logon_type"),
        win_review_required_reason=data.get("win_review_required_reason"),
        principal_source=str(data.get("principal_source")) if data.get("principal_source") is not None else None,
    )


def _upsert_accounts(db: Session, asset: Asset, normalized: list[NormalizedAccount]) -> list[Account]:
    rows: list[Account] = []
    now = datetime.now(UTC)
    for na in normalized:
        if not na.account_name:
            continue
        acc = (
            db.query(Account)
            .filter(
                Account.asset_id == asset.id,
                Account.account_name == na.account_name,
                Account.auth_source == na.auth_source,
            )
            .first()
        )
        if acc is None:
            acc = Account(asset_id=asset.id, platform=asset.platform, discovered_at=now)
            db.add(acc)
        acc.platform = asset.platform
        acc.source_type = na.source_type
        acc.account_name = na.account_name
        acc.principal_type = na.principal_type
        acc.auth_source = na.auth_source
        acc.enabled_status = na.enabled_status
        acc.interactive_status = na.interactive_status
        acc.last_login = na.last_login
        acc.last_login_source = na.last_login_source
        acc.is_shared = na.is_shared
        acc.password_never_expires = na.password_never_expires
        acc.owner = na.owner
        acc.evidence_summary = na.evidence_summary
        acc.principal_source = na.principal_source
        acc.interactive_confidence = na.win_interactive_confidence or None
        acc.interactive_detection_method = na.win_interactive_detection_method
        acc.interactive_evidence_summary = na.win_interactive_evidence
        acc.allows_local_logon = na.win_allows_local_logon
        acc.allows_remote_interactive_logon = na.win_allows_remote_interactive
        acc.allows_service_logon = na.win_allows_service_logon
        acc.allows_batch_logon = na.win_allows_batch_logon
        acc.allows_network_logon = na.win_allows_network_logon
        acc.interactive_last_observed_logon_type = (
            str(na.win_last_observed_logon_type)
            if na.win_last_observed_logon_type is not None
            else None
        )
        acc.review_required_reason = na.win_review_required_reason
        acc.updated_at = now
        db.flush()

        db.query(AccountEntitlement).filter(AccountEntitlement.account_id == acc.id).delete()
        for ent in na.entitlements:
            db.add(AccountEntitlement(
                account_id=acc.id,
                kind=ent.kind,
                name=ent.name,
                scope=ent.scope,
                source=ent.source,
                inherited=ent.inherited,
                via=ent.via,
                attributes=ent.attributes or {},
            ))
        rows.append(acc)
    db.flush()
    return rows


def _classify_accounts(
    db: Session,
    connector_agent_job_id,
    accounts: list[Account],
    normalized: list[NormalizedAccount],
) -> None:
    rules_db = db.query(ClassificationRule).filter(ClassificationRule.enabled.is_(True)).all()
    engine = RulesEngine([
        RuleSpec(
            id=str(r.id),
            rule_key=r.rule_key,
            name=r.name,
            platform=r.platform.value if r.platform else None,
            predicate=r.predicate,
            classify_as=r.classify_as,
            confidence=r.confidence,
            risk_modifier=r.risk_modifier,
            explanation_template=r.explanation_template,
            priority=r.priority,
            version=r.version,
        )
        for r in rules_db
    ])
    for acc, na in zip(accounts, normalized):
        evaluated = engine.evaluate(na)
        acc.privilege_classification = evaluated.winning_classification
        acc.privilege_confidence = evaluated.winning_confidence
        acc.risk_score = evaluated.risk_score

        if connector_agent_job_id:
            db.query(PrivilegeFinding).filter(
                PrivilegeFinding.connector_agent_job_id == connector_agent_job_id,
                PrivilegeFinding.account_id == acc.id,
            ).delete()

        winning_idx = -1
        if evaluated.matches:
            winning_idx = max(
                range(len(evaluated.matches)),
                key=lambda i: (
                    PRIVILEGE_SEVERITY.get(evaluated.matches[i].classification, 0),
                    evaluated.matches[i].confidence,
                ),
            )
            best = evaluated.matches[winning_idx]
            for idx, match in enumerate(evaluated.matches):
                db.add(PrivilegeFinding(
                    job_id=None,
                    connector_agent_job_id=connector_agent_job_id,
                    account_id=acc.id,
                    rule_id=uuid.UUID(match.rule.id),
                    rule_key=match.rule.rule_key,
                    rule_version=match.rule.version,
                    classification=match.classification,
                    confidence=match.confidence,
                    risk_score=match.risk_score,
                    is_winning=(idx == winning_idx),
                    direct=match.direct,
                    inheritance_path=match.inheritance_path,
                    explanation=match.explanation,
                    matched_evidence=match.evidence,
                    evaluated_at=datetime.now(UTC),
                ))
            acc.evidence_summary = {
                **(acc.evidence_summary or {}),
                "connector_agent_rule_match": {
                    "rule_key": best.rule.rule_key,
                    "classification": best.classification.value,
                    "explanation": best.explanation,
                },
            }
    db.flush()


def _enum(enum_cls, value: Any, default):
    try:
        return enum_cls(value)
    except Exception:
        return default


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value)
    match = _WINDOWS_DATE_RE.match(text)
    if match:
        try:
            return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=UTC)
        except Exception:
            return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        return None
