"""Base collector types, probe result, and normalization helpers.

Collectors are modular per-platform modules. Each collector declares the probes
it can run, returns a `CollectionResult` bundling raw probe outputs with a set
of `NormalizedAccount` objects (canonical, UI-ready, rules-engine-ready).

In production the concrete collector opens a real SSH/WinRM/DB connection.
In mock mode (`COLLECTOR_MODE=mock`) the same interface is fulfilled by
deterministic fixtures. The boundary is entirely inside each collector; no
downstream code changes when switching modes.
"""
from __future__ import annotations

import abc
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime

from app.config import get_settings
from app.models.enums import (
    AuthSource,
    EnabledStatus,
    InteractiveStatus,
    Platform,
    PrincipalType,
)


@dataclass
class Target:
    """Everything a collector needs to run a probe against a target."""

    asset_id: str
    hostname: str
    ip_address: str | None
    instance: str | None
    port: int | None
    platform: Platform
    options: dict = field(default_factory=dict)


@dataclass
class Credential:
    """Resolved credential material (dev only).

    In production, this is filled transiently from the vault and cleared after
    use. It is NEVER persisted and NEVER serialized.
    """

    username: str
    auth_method: str
    secret: str | None = None  # password/token/key content
    extra: dict = field(default_factory=dict)


@dataclass
class ProbeResult:
    probe_key: str
    command: str
    exit_code: int | None
    stderr_excerpt: str | None
    output: dict | list | str | None
    duration_ms: int
    collected_at: datetime

    @property
    def output_hash(self) -> str:
        blob = json.dumps(self.output, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()


@dataclass
class NormalizedEntitlement:
    kind: str
    name: str
    scope: str | None = None
    source: str | None = None
    inherited: bool = False
    via: str | None = None
    attributes: dict = field(default_factory=dict)


@dataclass
class NormalizedAccount:
    account_name: str
    source_type: str
    principal_type: PrincipalType = PrincipalType.unknown
    auth_source: AuthSource = AuthSource.unknown
    enabled_status: EnabledStatus = EnabledStatus.unknown
    interactive_status: InteractiveStatus = InteractiveStatus.unknown
    last_login: datetime | None = None
    last_login_source: str | None = None
    is_shared: bool = False
    password_never_expires: bool = False
    password_last_changed: datetime | None = None
    password_expires_at: datetime | None = None
    account_expires_at: datetime | None = None
    platform_created_at: datetime | None = None
    never_logged_in: bool | None = None   # True = positive "never" evidence
    owner: str | None = None
    evidence_summary: dict = field(default_factory=dict)
    entitlements: list[NormalizedEntitlement] = field(default_factory=list)

    # ── Windows interactive classification fields ─────────────────────────────
    # Populated only by the Windows collector; None/0 on all other platforms.
    win_interactive_confidence: int = 0
    win_interactive_detection_method: str | None = None
    win_interactive_evidence: dict | None = None          # serialised WinInteractiveEvidence
    win_allows_local_logon: bool | None = None
    win_allows_remote_interactive: bool | None = None
    win_allows_service_logon: bool | None = None
    win_allows_batch_logon: bool | None = None
    win_allows_network_logon: bool | None = None
    win_last_observed_logon_type: int | None = None       # numeric logon type (e.g. 10)
    win_review_required_reason: str | None = None
    # The raw PrincipalSource string returned by WinRM (Local/ActiveDirectory/Unknown)
    principal_source: str | None = None


@dataclass
class NormalizedPolicyException:
    """An account-level policy deviation detected during policy collection.

    Examples: password_never_expires flag set, SQL CHECK_POLICY OFF, etc.
    Stored as AccountPolicyException rows after the scan.
    """

    account_name: str
    exception_type: str  # matches AccountPolicyException.exception_type values
    evidence: dict = field(default_factory=dict)


@dataclass
class NormalizedPasswordPolicy:
    """Platform-neutral password policy snapshot collected from a target.

    Field semantics mirror PasswordPolicy (the ORM model).  None means
    "not collected / unknown" — never use None to mean "zero" or "disabled".
    The scan service converts this into a PasswordPolicy row.
    """

    # Required identity fields
    policy_source: str       # PolicySource enum value, e.g. "pam_module"
    policy_scope: str        # PolicyScope enum value, e.g. "host"
    policy_name: str         # Human-readable, e.g. "pam_pwquality", "Default Domain Policy"

    is_effective_policy: bool = True
    precedence: int | None = None
    applies_to: dict | None = None  # FGPP PSO target scope

    # ── Password settings ─────────────────────────────────────────────────────
    min_password_length: int | None = None
    complexity_enabled: bool | None = None
    password_history_count: int | None = None
    max_password_age_days: int | None = None
    min_password_age_days: int | None = None
    reversible_encryption_enabled: bool | None = None

    # ── Lockout settings ──────────────────────────────────────────────────────
    lockout_threshold: int | None = None
    lockout_duration_minutes: int | None = None
    reset_lockout_counter_after_minutes: int | None = None

    # ── PAM / Unix-specific ───────────────────────────────────────────────────
    dictionary_check_enabled: bool | None = None
    min_char_classes: int | None = None
    min_uppercase: int | None = None
    min_lowercase: int | None = None
    min_digits: int | None = None
    min_special_chars: int | None = None

    # ── External / federation ─────────────────────────────────────────────────
    external_policy_enforced: bool | None = None
    requires_external_review: bool | None = None

    # ── Metadata ──────────────────────────────────────────────────────────────
    evidence_summary: dict | None = None
    collection_error: str | None = None
    confidence_score: int = 80

    # Per-account exceptions discovered alongside this policy (e.g. sa with
    # CHECK_EXPIRATION OFF, accounts with password_never_expires flag set).
    account_exceptions: list[NormalizedPolicyException] = field(default_factory=list)


@dataclass
class CollectionResult:
    platform: Platform
    probes: list[ProbeResult]
    accounts: list[NormalizedAccount]
    warnings: list[str] = field(default_factory=list)
    # Set by SSH collectors on live runs: SHA-256 host-key fingerprint observed
    # during the session (base64, no padding).  The scan service persists this
    # back to asset.ssh_host_fingerprint for TOFU verification on future scans.
    observed_ssh_fingerprint: str | None = None
    # Populated when the scan profile has collect_password_policy=True.
    # Empty list means either the flag was off or no policy was discoverable.
    password_policies: list[NormalizedPasswordPolicy] = field(default_factory=list)


class BaseCollector(abc.ABC):
    """Interface every platform collector must implement."""

    platform: Platform

    def collect(self, target: Target, credential: Credential | None) -> CollectionResult:
        if get_settings().collector_mode == "mock":
            return self.collect_mock(target)
        return self.collect_live(target, credential)

    # Subclasses must implement both, but live may raise NotImplementedError in
    # the first release for platforms where live code is still being certified.
    @abc.abstractmethod
    def collect_mock(self, target: Target) -> CollectionResult: ...

    def collect_live(self, target: Target, credential: Credential | None) -> CollectionResult:
        raise NotImplementedError(
            f"Live collection for {self.platform.value} is not enabled in this build. "
            "Run in mock mode or provide a certified live collector."
        )
