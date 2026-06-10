"""Scan orchestration service.

Handles building job/target rows, dispatching Celery tasks, retry logic, delta
computation, and writing normalized accounts + findings back to the DB.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy.orm import Session

from app.collectors import get_collector
from app.collectors.base import CollectionResult, NormalizedAccount
from app.models.account import Account, AccountEntitlement, DiscoveryResultRaw
from app.models.asset import Asset
from app.models.enums import (
    AuthSource,
    EnabledStatus,
    InteractiveStatus,
    JobStatus,
    Platform,
    PRIVILEGE_SEVERITY,
    PrincipalType,
    PrivilegeClass,
)
from app.models.finding import FindingReviewState, PrivilegeFinding
from app.models.job import DiscoveryJob, DiscoveryJobTarget
from app.models.notification import Notification
from app.models.rule import ClassificationRule
from app.rules_engine.engine import RuleEvaluationResult, RulesEngine, RuleSpec

log = structlog.get_logger("adpct.scan")

# Maps platform → connector kind string used in the connectors table
_PLATFORM_KIND: dict[Platform, str] = {
    # Unix / Linux (SSH-based)
    Platform.rhel:       "ssh",
    Platform.centos:     "ssh",
    Platform.ubuntu:     "ssh",
    Platform.sles:       "ssh",
    Platform.solaris:    "ssh",
    Platform.aix:        "ssh",
    Platform.hpux:       "ssh",
    # Windows
    Platform.windows:    "winrm",
    # Databases
    Platform.mysql:      "mysql",
    Platform.mssql:      "mssql",
    Platform.mongodb:    "mongodb",
    Platform.oracle_db:  "oracle",
    Platform.postgresql: "postgresql",
    Platform.redis:      "redis",
}


def _resolve_credential(db: Session, asset: Asset):
    """Return a CollectorCredential for the asset, or None in mock mode."""
    from app.config import get_settings
    if get_settings().collector_mode == "mock":
        return None

    from app.models.connector import Connector, Credential as CredModel
    from app.collectors.base import Credential as CollectorCredential
    from app.services.vault import get_vault

    # Prefer connector explicitly assigned to asset via connector_id column, then tags fallback.
    connector_id = asset.connector_id or (asset.tags or {}).get("connector_id")
    kind = _PLATFORM_KIND.get(asset.platform)

    if connector_id:
        conn = db.query(Connector).filter(
            Connector.id == connector_id, Connector.is_active.is_(True)
        ).first()
        if not conn:
            raise RuntimeError(
                f"No active connector found with id={connector_id} (assigned via asset tags)."
            )
    else:
        conn = db.query(Connector).filter(
            Connector.kind == kind, Connector.is_active.is_(True)
        ).first() if kind else None
        if not conn:
            raise RuntimeError(
                f"No active connector configured for platform '{asset.platform.value}' "
                f"(kind='{kind}'). Create a connector of kind '{kind}' in the Connectors page "
                "and link a credential to it."
            )

    if not conn.credential_id:
        raise RuntimeError(
            f"Connector '{conn.name}' has no credential linked. "
            "Edit the connector and select a credential."
        )

    cred = db.query(CredModel).filter(CredModel.id == conn.credential_id).first()
    if not cred:
        raise RuntimeError(
            f"Credential referenced by connector '{conn.name}' no longer exists."
        )

    try:
        secret = get_vault().resolve(cred.vault_ref)
    except LookupError:
        raise RuntimeError(
            f"Secret for credential '{cred.name}' (vault_ref={cred.vault_ref!r}) not found in vault. "
            "Re-save the credential on the Connectors page to re-store the secret."
        )
    except Exception as exc:
        raise RuntimeError(
            f"Vault resolution failed for credential '{cred.name}': {exc}"
        ) from exc

    return CollectorCredential(
        username=cred.username,
        secret=secret,
        auth_method=cred.auth_method,
    )


def _get_connector_options(db: Session, asset: Asset) -> dict:
    """Return the active connector's options dict for this asset (or {}).

    These are merged into target.options so collectors (especially DB ones)
    can read settings like sslmode, dbname, service_name, etc.
    """
    from app.config import get_settings
    if get_settings().collector_mode == "mock":
        return {}

    from app.models.connector import Connector

    connector_id = asset.connector_id or (asset.tags or {}).get("connector_id")
    kind = _PLATFORM_KIND.get(asset.platform)

    if connector_id:
        conn = db.query(Connector).filter(
            Connector.id == connector_id, Connector.is_active.is_(True)
        ).first()
    else:
        conn = (
            db.query(Connector)
            .filter(Connector.kind == kind, Connector.is_active.is_(True))
            .first()
            if kind else None
        )
    return dict(conn.options) if conn and conn.options else {}


# ---------------------------------------------------------------------------
# Job creation
# ---------------------------------------------------------------------------

def create_job(
    db: Session,
    *,
    asset_ids: list[uuid.UUID],
    profile_id: uuid.UUID | None,
    triggered_by: str | None,
    triggered_kind: str,
    note: str | None,
    collect_password_policy: bool = False,
) -> DiscoveryJob:
    assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()

    # If profile has platform restrictions, filter assets to matching platforms only
    if profile_id:
        from app.models.job import ScanProfile as SP
        profile = db.query(SP).filter(SP.id == profile_id).first()
        if profile and profile.platforms:
            allowed = set(profile.platforms)
            assets = [a for a in assets if a.platform.value in allowed]
            scope_desc = f"{len(assets)} asset(s) [{', '.join(sorted(allowed))}]"
        else:
            scope_desc = f"{len(assets)} asset(s)"
    else:
        scope_desc = f"{len(assets)} asset(s)"
    job = DiscoveryJob(
        scope_description=scope_desc,
        # Store collect_password_policy in the scope JSONB so run_target can
        # read it without needing to look up the profile again.
        scope={"asset_ids": [str(a.id) for a in assets], "collect_password_policy": collect_password_policy},
        profile_id=profile_id,
        triggered_by=triggered_by,
        triggered_kind=triggered_kind,
        notes=note,
        status=JobStatus.pending,
    )
    db.add(job)
    db.flush()

    for asset in assets:
        target = DiscoveryJobTarget(
            job_id=job.id,
            asset_id=asset.id,
            platform=asset.platform,
            status=JobStatus.pending,
        )
        db.add(target)
    db.flush()
    return job


# ---------------------------------------------------------------------------
# Single-target execution (called from Celery task)
# ---------------------------------------------------------------------------

def run_target(db: Session, job_target_id: uuid.UUID) -> None:
    target_row = db.query(DiscoveryJobTarget).filter(DiscoveryJobTarget.id == job_target_id).first()
    if not target_row:
        return

    asset = db.query(Asset).filter(Asset.id == target_row.asset_id).first()
    if not asset:
        _fail_target(db, target_row, "asset_missing", "Asset not found in DB")
        return

    target_row.status = JobStatus.running
    target_row.started_at = datetime.now(UTC)
    target_row.attempt += 1
    # Clear stale error fields from any previous attempt so a successful retry
    # doesn't display the prior failure's error message in the UI.
    target_row.error_detail = None
    target_row.error_bucket = None
    db.flush()

    # Read the collect_password_policy flag stored in the job scope at creation time
    job_row = db.query(DiscoveryJob).filter(DiscoveryJob.id == target_row.job_id).first()
    collect_policy_flag: bool = bool(
        (job_row.scope or {}).get("collect_password_policy", False)
    ) if job_row else False

    try:
        from app.collectors.base import Target as CollectorTarget, Credential as CollectorCredential
        # Start with asset tags, then layer in connector-level options (sslmode,
        # dbname, service_name, etc.) so collectors can read them via target.options.
        target_opts = dict(asset.tags or {})
        target_opts.update(_get_connector_options(db, asset))
        # SSH TOFU fingerprint always wins over any connector option of the same key.
        if asset.ssh_host_fingerprint:
            target_opts["ssh_host_fingerprint"] = asset.ssh_host_fingerprint
        # Signal collectors to also collect password policy data when enabled.
        if collect_policy_flag:
            target_opts["collect_password_policy"] = True
        ct = CollectorTarget(
            asset_id=str(asset.id),
            hostname=asset.hostname,
            ip_address=asset.ip_address,
            instance=asset.instance,
            port=asset.port,
            platform=asset.platform,
            options=target_opts,
        )
        collector = get_collector(asset.platform)
        cred_obj = _resolve_credential(db, asset)
        result: CollectionResult = collector.collect(ct, credential=cred_obj)

        # TOFU: persist the observed SSH fingerprint on first-ever connection.
        if result.observed_ssh_fingerprint and not asset.ssh_host_fingerprint:
            asset.ssh_host_fingerprint = result.observed_ssh_fingerprint
            log.info(
                "ssh.tofu.stored",
                asset_id=str(asset.id),
                fingerprint=f"SHA256:{result.observed_ssh_fingerprint}",
            )

        _persist_raw(db, target_row.id, result)
        accounts, normalized = _upsert_accounts(db, asset, result)
        _evaluate_and_write_findings(db, target_row.job_id, asset, accounts, normalized)

        # Always run: generate PWPOL-019/PWPOL-008 findings for accounts where
        # password_never_expires=True (detected from shadow field 5).
        pne_count = _generate_password_never_expires_findings(db, asset, accounts, normalized)

        # Optional: full password policy collection (enabled per-job via collect_password_policy)
        policies_count = 0
        if collect_policy_flag and result.password_policies:
            policies_count = _upsert_password_policies(
                db, asset, accounts, result, job_id=target_row.job_id
            )

        target_row.status = JobStatus.success
        target_row.finished_at = datetime.now(UTC)
        if target_row.started_at:
            target_row.duration_ms = int(
                (target_row.finished_at - target_row.started_at).total_seconds() * 1000
            )
        target_row.stats = {
            "accounts": len(accounts),
            "probes": len(result.probes),
            **({"password_never_expires": pne_count} if pne_count else {}),
            **({"policies": policies_count} if collect_policy_flag else {}),
        }
        db.flush()
        log.info("scan.target.done", job_target_id=str(job_target_id), accounts=len(accounts))

    except Exception as exc:
        log.exception("scan.target.error", job_target_id=str(job_target_id))
        _fail_target(db, target_row, "collector_error", str(exc)[:1024])


def _fail_target(db: Session, row: DiscoveryJobTarget, bucket: str, detail: str) -> None:
    # The session may be in a "must rollback" state if a previous DB error
    # triggered a failed flush (e.g. SMALLINT overflow).  Roll back first so
    # we can write the failure status without raising PendingRollbackError.
    try:
        db.rollback()
    except Exception:
        pass
    row.status = JobStatus.failed
    row.finished_at = datetime.now(UTC)
    row.error_bucket = bucket
    row.error_detail = detail
    try:
        db.flush()
    except Exception:
        # Last resort: if even the status update fails, at least log it.
        log.error("scan.fail_target.flush_error", bucket=bucket, detail=detail[:200])


# ---------------------------------------------------------------------------
# Persist raw probe results
# ---------------------------------------------------------------------------

def _persist_raw(db: Session, job_target_id: uuid.UUID, result: CollectionResult) -> None:
    for probe in result.probes:
        raw = DiscoveryResultRaw(
            job_target_id=job_target_id,
            probe_key=probe.probe_key,
            command=probe.command,
            exit_code=probe.exit_code,
            stderr_excerpt=probe.stderr_excerpt,
            output=probe.output,
            output_hash=probe.output_hash,
            duration_ms=probe.duration_ms,
            collected_at=probe.collected_at,
        )
        db.add(raw)
    db.flush()


# ---------------------------------------------------------------------------
# Upsert normalized accounts
# ---------------------------------------------------------------------------

def _upsert_accounts(
    db: Session, asset: Asset, result: CollectionResult
) -> tuple[list[Account], list[NormalizedAccount]]:
    """Upsert accounts and their entitlements.

    Returns a parallel pair of ORM Account rows and the original
    NormalizedAccount objects from the collector.  The NAs are threaded
    through so that ``_evaluate_and_write_findings`` can use their
    entitlements directly rather than reading the stale SQLAlchemy
    relationship cache (bulk DELETE does not invalidate the in-memory list).
    """
    from app.config import get_settings
    rows: list[Account] = []
    nas: list[NormalizedAccount] = []
    now = datetime.now(UTC)

    for na in result.accounts:
        existing = (
            db.query(Account)
            .filter(
                Account.asset_id == asset.id,
                Account.account_name == na.account_name,
                Account.auth_source == na.auth_source,
            )
            .first()
        )
        if existing:
            acc = existing
            acc.updated_at = now
        else:
            acc = Account(
                asset_id=asset.id,
                platform=asset.platform,
                discovered_at=now,
            )
            db.add(acc)

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
        acc.password_last_changed = na.password_last_changed
        acc.password_expires_at = na.password_expires_at
        acc.account_expires_at = na.account_expires_at
        acc.platform_created_at = na.platform_created_at
        acc.never_logged_in = na.never_logged_in
        acc.collection_mode = get_settings().collector_mode
        acc.owner = na.owner
        acc.evidence_summary = na.evidence_summary

        # Windows interactive classification fields (None for non-Windows accounts)
        if na.win_interactive_confidence:
            acc.interactive_confidence = na.win_interactive_confidence
        if na.win_interactive_detection_method is not None:
            acc.interactive_detection_method = na.win_interactive_detection_method
        if na.win_interactive_evidence is not None:
            acc.interactive_evidence_summary = na.win_interactive_evidence
        if na.win_allows_local_logon is not None:
            acc.allows_local_logon = na.win_allows_local_logon
        if na.win_allows_remote_interactive is not None:
            acc.allows_remote_interactive_logon = na.win_allows_remote_interactive
        if na.win_allows_service_logon is not None:
            acc.allows_service_logon = na.win_allows_service_logon
        if na.win_allows_batch_logon is not None:
            acc.allows_batch_logon = na.win_allows_batch_logon
        if na.win_allows_network_logon is not None:
            acc.allows_network_logon = na.win_allows_network_logon
        if na.win_last_observed_logon_type is not None:
            acc.interactive_last_observed_logon_type = str(na.win_last_observed_logon_type)
        if na.win_review_required_reason is not None:
            acc.review_required_reason = na.win_review_required_reason
        if na.principal_source is not None:
            acc.principal_source = na.principal_source

        db.flush()

        # Replace entitlements for this scan.
        # NOTE: bulk DELETE does not invalidate the SQLAlchemy relationship
        # cache on `acc`, so we do NOT read back acc.entitlements later —
        # we use the original NormalizedAccount (na) instead.
        db.query(AccountEntitlement).filter(AccountEntitlement.account_id == acc.id).delete()
        for ent in na.entitlements:
            db.add(
                AccountEntitlement(
                    account_id=acc.id,
                    kind=ent.kind,
                    name=ent.name,
                    scope=ent.scope,
                    source=ent.source,
                    inherited=ent.inherited,
                    via=ent.via,
                    attributes=ent.attributes or {},
                )
            )
        db.flush()
        rows.append(acc)
        nas.append(na)
    return rows, nas


# ---------------------------------------------------------------------------
# Password policy upsert (runs when collect_password_policy=True in the job)
# ---------------------------------------------------------------------------

def _upsert_password_policies(
    db: Session,
    asset: Asset,
    accounts: list[Account],
    result: "CollectionResult",
    job_id: uuid.UUID,
) -> int:
    """Persist normalized password policies from a scan result.

    For each NormalizedPasswordPolicy in result.password_policies:
      1. Find-or-create PasswordPolicy by (asset_id, policy_source, policy_name).
      2. Update all fields and link to the discovery job.
      3. Create/update AccountPolicyException rows for per-account deviations.
      4. Delete stale findings and re-run the rules engine.

    Returns the count of policies upserted.
    """
    from app.collectors.base import NormalizedPasswordPolicy as NPP
    from app.models.enums import PolicyScope, PolicySource
    from app.models.password_policy import (
        AccountPolicyException,
        PasswordPolicy,
        PasswordPolicyFinding,
    )
    from app.services.password_policy_rules import evaluate_policy

    now = datetime.now(UTC)
    upserted = 0

    for np in result.password_policies:
        try:
            # Coerce string values to enums (collectors emit string values)
            try:
                p_source = PolicySource(np.policy_source)
            except ValueError:
                p_source = PolicySource.unknown
            try:
                p_scope = PolicyScope(np.policy_scope)
            except ValueError:
                p_scope = PolicyScope.host

            # ── Find-or-create ────────────────────────────────────────────
            pol = (
                db.query(PasswordPolicy)
                .filter(
                    PasswordPolicy.asset_id == asset.id,
                    PasswordPolicy.policy_source == p_source,
                    PasswordPolicy.policy_name == (np.policy_name or ""),
                )
                .first()
            )
            if pol is None:
                pol = PasswordPolicy(asset_id=asset.id, discovered_at=now)
                db.add(pol)

            pol.job_id = job_id
            pol.platform = asset.platform
            pol.policy_source = p_source
            pol.policy_scope = p_scope
            pol.policy_name = np.policy_name or ""
            pol.is_effective_policy = np.is_effective_policy
            pol.precedence = np.precedence
            pol.applies_to = np.applies_to
            pol.min_password_length = np.min_password_length
            pol.complexity_enabled = np.complexity_enabled
            pol.password_history_count = np.password_history_count
            pol.max_password_age_days = np.max_password_age_days
            pol.min_password_age_days = np.min_password_age_days
            pol.reversible_encryption_enabled = np.reversible_encryption_enabled
            pol.lockout_threshold = np.lockout_threshold
            pol.lockout_duration_minutes = np.lockout_duration_minutes
            pol.reset_lockout_counter_after_minutes = np.reset_lockout_counter_after_minutes
            pol.dictionary_check_enabled = np.dictionary_check_enabled
            pol.min_char_classes = np.min_char_classes
            pol.min_uppercase = np.min_uppercase
            pol.min_lowercase = np.min_lowercase
            pol.min_digits = np.min_digits
            pol.min_special_chars = np.min_special_chars
            pol.external_policy_enforced = np.external_policy_enforced
            pol.requires_external_review = np.requires_external_review
            pol.evidence_summary = np.evidence_summary
            pol.collection_error = np.collection_error
            pol.confidence_score = np.confidence_score
            db.flush()

            # ── Account exceptions ────────────────────────────────────────
            # Build name→Account lookup from the accounts collected this scan.
            acc_by_name: dict[str, Account] = {a.account_name: a for a in accounts}

            for exc_data in (np.account_exceptions or []):
                acc_obj = acc_by_name.get(exc_data.account_name)
                acc_id = acc_obj.id if acc_obj else None

                # Find or create by (policy_id, account_id OR account_name in evidence, exception_type)
                existing_exc = None
                if acc_id is not None:
                    existing_exc = (
                        db.query(AccountPolicyException)
                        .filter(
                            AccountPolicyException.policy_id == pol.id,
                            AccountPolicyException.account_id == acc_id,
                            AccountPolicyException.exception_type == exc_data.exception_type,
                        )
                        .first()
                    )

                if existing_exc is None:
                    exc_row = AccountPolicyException(
                        asset_id=asset.id,
                        account_id=acc_id,
                        policy_id=pol.id,
                        exception_type=exc_data.exception_type,
                        evidence={**exc_data.evidence, "account_name": exc_data.account_name},
                        discovered_at=now,
                    )
                    db.add(exc_row)
                else:
                    existing_exc.evidence = {
                        **exc_data.evidence,
                        "account_name": exc_data.account_name,
                    }
            db.flush()

            # ── Re-run rules engine ───────────────────────────────────────
            exceptions = list(pol.exceptions)
            db.query(PasswordPolicyFinding).filter(
                PasswordPolicyFinding.policy_id == pol.id
            ).delete()
            for finding in evaluate_policy(pol, exceptions):
                db.add(finding)
            db.flush()

            upserted += 1
            log.info(
                "policy.upserted",
                asset_id=str(asset.id),
                policy_name=np.policy_name,
                policy_source=np.policy_source,
            )
        except Exception as exc:
            log.warning(
                "policy.upsert_failed",
                asset_id=str(asset.id),
                policy_name=getattr(np, "policy_name", "?"),
                error=str(exc),
            )

    return upserted


# ---------------------------------------------------------------------------
# Rules evaluation and finding persistence
# ---------------------------------------------------------------------------

def _evaluate_and_write_findings(
    db: Session,
    job_id: uuid.UUID,
    asset: Asset,
    accounts: list[Account],
    normalized: list[NormalizedAccount],
) -> None:
    """Evaluate classification rules for each account and persist findings.

    ``normalized`` is the parallel list of NormalizedAccount objects from the
    collector — used directly instead of re-reading ``acc.entitlements`` from
    the ORM, which would return a stale cache after the bulk DELETE/re-insert
    performed by ``_upsert_accounts``.
    """
    rules_db = db.query(ClassificationRule).filter(ClassificationRule.enabled.is_(True)).all()
    rule_specs = [
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
    ]
    engine = RulesEngine(rule_specs)
    now = datetime.now(UTC)

    for acc, na in zip(accounts, normalized):
        # Use the collector's NormalizedAccount directly — it carries the
        # freshly collected entitlements without the stale-cache problem.
        result: RuleEvaluationResult = engine.evaluate(na)

        # Update the canonical account classification.
        acc.privilege_classification = result.winning_classification
        acc.privilege_confidence = result.winning_confidence
        acc.risk_score = result.risk_score
        db.flush()

        # Determine the single winning match by highest severity then confidence.
        # NOTE: result.winning_classification may be 'dormant_privileged' (an
        # account-level upgrade) which never appears in result.matches, so we
        # cannot compare match.classification against it directly.
        winning_idx = -1
        if result.matches:
            winning_idx = max(
                range(len(result.matches)),
                key=lambda i: (
                    PRIVILEGE_SEVERITY.get(result.matches[i].classification, 0),
                    result.matches[i].confidence,
                ),
            )

        # Write all matching findings; mark the winner.
        for i, match in enumerate(result.matches):
            rule_row = next((r for r in rules_db if r.rule_key == match.rule.rule_key), None)
            if rule_row is None:
                continue
            finding = PrivilegeFinding(
                job_id=job_id,
                account_id=acc.id,
                rule_id=rule_row.id,
                rule_key=match.rule.rule_key,
                rule_version=match.rule.version,
                classification=match.classification,
                confidence=match.confidence,
                risk_score=match.risk_score,
                is_winning=(i == winning_idx),
                direct=match.direct,
                inheritance_path=match.inheritance_path,
                explanation=match.explanation,
                matched_evidence=match.evidence,
                evaluated_at=now,
            )
            db.add(finding)
        db.flush()

    # Notifications for newly discovered high-severity accounts.
    new_privs = [
        a for a in accounts
        if a.privilege_classification in (
            PrivilegeClass.full_admin,
            PrivilegeClass.admin_equivalent,
            PrivilegeClass.dormant_privileged,
        )
    ]
    if new_privs:
        db.add(
            Notification(
                kind="new_privileged_accounts",
                severity="high",
                title=f"{len(new_privs)} privileged account(s) found on {asset.hostname}",
                body=f"Job {job_id}: accounts: {[a.account_name for a in new_privs[:10]]}",
                context={"job_id": str(job_id), "asset_id": str(asset.id)},
            )
        )
        db.flush()


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Password-never-expires hygiene findings (always runs, no flag required)
# ---------------------------------------------------------------------------

def _generate_password_never_expires_findings(
    db: Session,
    asset: Asset,
    accounts: list[Account],
    normalized: list[NormalizedAccount],
) -> int:
    """Create PWPOL-019 / PWPOL-008 findings for any account with
    password_never_expires=True that is currently enabled.

    Runs unconditionally — no ``collect_password_policy`` flag needed.
    Uses ``policy_id=None`` so no PasswordPolicy row is required.

    Stale rows from the previous scan are deleted before writing new ones
    so re-scanning stays idempotent.

    Returns the count of new findings written.
    """
    from app.models.password_policy import AccountPolicyException, PasswordPolicyFinding
    from app.models.enums import PolicyFindingReviewState, PolicyFindingSeverity

    _PRIV_CLASSES = {
        PrivilegeClass.full_admin,
        PrivilegeClass.admin_equivalent,
        PrivilegeClass.operator_high_impact,
        PrivilegeClass.delegated_admin,
        PrivilegeClass.privileged_service,
        PrivilegeClass.dormant_privileged,
    }
    _NON_PRIV = {PrivilegeClass.non_privileged, PrivilegeClass.unknown_review_required, None}

    # ── 1. Delete stale standalone exceptions + their findings ────────────────
    stale_excs = (
        db.query(AccountPolicyException)
        .filter(
            AccountPolicyException.asset_id == asset.id,
            AccountPolicyException.exception_type == "password_never_expires",
            AccountPolicyException.policy_id.is_(None),
        )
        .all()
    )
    for exc in stale_excs:
        db.query(PasswordPolicyFinding).filter(
            PasswordPolicyFinding.exception_id == exc.id
        ).delete(synchronize_session=False)
        db.delete(exc)
    db.flush()

    # ── 2. Create new exceptions + findings ───────────────────────────────────
    now = datetime.now(UTC)
    written = 0

    for acc, na in zip(accounts, normalized):
        if not na.password_never_expires:
            continue
        if acc.enabled_status != EnabledStatus.enabled:
            continue

        is_privileged = acc.privilege_classification not in _NON_PRIV

        exc = AccountPolicyException(
            asset_id=asset.id,
            account_id=acc.id,
            policy_id=None,
            exception_type="password_never_expires",
            description=(
                f"Account '{acc.account_name}' has password_never_expires=True "
                "(shadow max_days is 99999 or empty)."
            ),
            evidence={
                "is_privileged": is_privileged,
                "privilege_classification": (
                    acc.privilege_classification.value
                    if acc.privilege_classification else None
                ),
                "shadow_max_days_never_expires": True,
                "source": "shadow_field5",
            },
            discovered_at=now,
        )
        db.add(exc)
        db.flush()

        rule_key = "PWPOL-019" if is_privileged else "PWPOL-008"
        sev = PolicyFindingSeverity.high if is_privileged else PolicyFindingSeverity.medium
        title = (
            "Privileged account has password set to never expire"
            if is_privileged
            else "Account has password set to never expire"
        )
        description = (
            f"Account '{acc.account_name}' has PASSWORD_NEVER_EXPIRES set "
            "(shadow max_days is 99999 or empty). "
            "Passwords that never expire remain valid indefinitely, increasing the exposure "
            "window if the credential is compromised."
            + (" This account has elevated privileges, increasing the risk." if is_privileged else "")
        )

        finding = PasswordPolicyFinding(
            asset_id=asset.id,
            account_id=acc.id,
            policy_id=None,
            exception_id=exc.id,
            rule_key=rule_key,
            severity=sev,
            title=title,
            description=description,
            recommendation=(
                "Remove the 'password never expires' override and enforce the host's "
                "max password age with: chage -M 90 <username> (or edit /etc/shadow field 5). "
                "For service accounts, consider a secrets manager or a group Managed Service "
                "Account (gMSA) with auto-rotating credentials."
            ),
            affected_scope=f"Account: {acc.account_name}",
            evidence={
                "account_name": acc.account_name,
                "is_privileged": is_privileged,
                "shadow_max_days_never_expires": True,
            },
            is_exception_finding=True,
            review_state=PolicyFindingReviewState.open,
            discovered_at=now,
        )
        db.add(finding)
        written += 1

    db.flush()
    log.info(
        "scan.password_never_expires.findings",
        asset_id=str(asset.id),
        written=written,
    )
    return written


# ---------------------------------------------------------------------------
# Job completion rollup
# ---------------------------------------------------------------------------

def finalize_job(db: Session, job_id: uuid.UUID) -> None:
    job = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id).first()
    if not job:
        return
    targets = db.query(DiscoveryJobTarget).filter(DiscoveryJobTarget.job_id == job_id).all()
    statuses = [t.status for t in targets]
    if all(s == JobStatus.success for s in statuses):
        job.status = JobStatus.success
    elif any(s == JobStatus.success for s in statuses):
        job.status = JobStatus.partial_success
    else:
        job.status = JobStatus.failed
    job.finished_at = datetime.now(UTC)
    job.totals = {
        "total": len(targets),
        "success": sum(1 for s in statuses if s == JobStatus.success),
        "failed": sum(1 for s in statuses if s == JobStatus.failed),
    }
    db.flush()


# ---------------------------------------------------------------------------
# Delta computation
# ---------------------------------------------------------------------------

def compute_delta(db: Session, baseline_job_id: uuid.UUID, current_job_id: uuid.UUID) -> list[dict]:
    """Compare privileged findings between two jobs. Returns list of delta dicts."""
    from app.models.finding import PrivilegeFinding

    def get_findings(job_id: uuid.UUID) -> dict[uuid.UUID, PrivilegeFinding]:
        rows = (
            db.query(PrivilegeFinding)
            .filter(PrivilegeFinding.job_id == job_id, PrivilegeFinding.is_winning.is_(True))
            .all()
        )
        return {r.account_id: r for r in rows}

    baseline = get_findings(baseline_job_id)
    current = get_findings(current_job_id)
    all_account_ids = set(baseline) | set(current)
    NON_PRIV = {PrivilegeClass.non_privileged, PrivilegeClass.unknown_review_required}

    deltas = []
    for aid in all_account_ids:
        b = baseline.get(aid)
        c = current.get(aid)
        bc = b.classification if b else None
        cc = c.classification if c else None

        if bc in NON_PRIV and cc not in NON_PRIV:
            change = "new_privileged"
        elif bc not in NON_PRIV and cc in NON_PRIV:
            change = "removed_privileged"
        elif bc and cc and bc != cc:
            change = "upgraded" if PRIVILEGE_SEVERITY.get(cc, 0) > PRIVILEGE_SEVERITY.get(bc, 0) else "downgraded"
        elif cc == PrivilegeClass.dormant_privileged and bc != PrivilegeClass.dormant_privileged:
            change = "became_dormant"
        else:
            continue

        acc_row = db.query(Account).filter(Account.id == aid).first()
        asset_row = db.query(Asset).filter(Asset.id == acc_row.asset_id).first() if acc_row else None
        deltas.append({
            "account_id": str(aid),
            "account_name": acc_row.account_name if acc_row else "unknown",
            "asset_hostname": asset_row.hostname if asset_row else "unknown",
            "platform": acc_row.platform.value if acc_row else "unknown",
            "change": change,
            "before": bc.value if bc else None,
            "after": cc.value if cc else None,
            "explanation": f"{change}: was {bc.value if bc else 'none'}, now {cc.value if cc else 'none'}",
        })
    return deltas
