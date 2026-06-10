"""Windows interactive / non-interactive account classification.

Classifies a Windows account's interactive logon capability based on a
nine-rule priority chain:

  Rule 1  gMSA identity                    → service_or_batch_only  (97)
  Rule 2  Computer/machine account         → service_or_batch_only  (93)
  Rule 3  Domain group object              → unknown_review_required (45)
  Rule 4  Unresolved / orphaned SID        → unknown_review_required (20)
  Rule 5  Known non-interactive built-ins  → non_interactive_only   (92-97)
  Rule 6  User Rights Assignment (secedit) → interactive_capable /
                                             non_interactive_only /
                                             service_or_batch_only  (80-97)
  Rule 7  Event 4624 logon type history    → interactive_capable /
                                             service_or_batch_only /
                                             network_only            (82-97)
  Rule 8  Service / task run-as            → service_or_batch_only  (60-72)
  Rule 9  Default fallback                 → unknown_review_required (30)

No eval(), no exec(), no name-pattern heuristics.  All logic is driven by
evidence data collected from the target.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple

# ── Logon type constants (Security Event 4624) ────────────────────────────────

LOGON_TYPE_NAMES: dict[int, str] = {
    2:  "Interactive",
    3:  "Network",
    4:  "Batch",
    5:  "Service",
    7:  "Unlock",
    8:  "NetworkCleartext",
    9:  "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive",
    13: "CachedUnlock",
}

# Logon types that indicate direct interactive access
INTERACTIVE_LOGON_TYPES: frozenset[int] = frozenset({2, 10, 11})
# Logon types used by services / batch jobs
SERVICE_BATCH_LOGON_TYPES: frozenset[int] = frozenset({4, 5})
# Logon types that are purely network-based
NETWORK_LOGON_TYPES: frozenset[int] = frozenset({3, 8, 9})

# ── Well-known built-ins that are always non-interactive ──────────────────────
# key = short account name, lower-cased; value = confidence
_NON_INTERACTIVE_BUILTINS: dict[str, int] = {
    "wdagutilityaccount": 97,   # Windows Defender Application Guard isolation
    "defaultaccount":     92,   # System-managed placeholder account
}

# ── Evidence container ────────────────────────────────────────────────────────


@dataclass
class WinInteractiveEvidence:
    """All evidence gathered for one Windows account.

    Populated by ``_build_interactive_evidence`` in windows.py and consumed
    by ``classify_interactive`` here.  All fields are optional / nullable so
    partial evidence is handled gracefully.
    """

    # --- Account identity (derived from source_type) ---
    is_gmsa: bool = False
    is_computer_account: bool = False
    is_domain_group: bool = False
    is_unresolved_sid: bool = False
    # Set to lower-cased short name when source_type == "windows_builtin"
    builtin_name: str | None = None

    # --- User Rights Assignment (secedit /export /areas USER_RIGHTS) ---
    # True if secedit data was successfully collected for this host
    user_rights_available: bool = False
    # Whether the account (or any of its groups) holds each right:
    has_interactive_logon_right: bool | None = None    # SeInteractiveLogonRight
    has_rdp_logon_right: bool | None = None            # SeRemoteInteractiveLogonRight
    deny_interactive: bool | None = None               # SeDenyInteractiveLogonRight
    deny_rdp: bool | None = None                       # SeDenyRemoteInteractiveLogonRight
    has_service_logon_right: bool | None = None        # SeServiceLogonRight
    has_batch_logon_right: bool | None = None          # SeBatchLogonRight
    has_network_logon_right: bool | None = None        # SeNetworkLogonRight

    # --- Security event log (Event 4624 last 30 days) ---
    # True if event log data was collected (even if this account had no events)
    event_log_available: bool = False
    observed_logon_types: frozenset[int] = field(default_factory=frozenset)
    # The numeric logon type of the most recent observed event (for display)
    last_observed_logon_type: int | None = None

    # --- Service / task run-as memberships ---
    runs_service: bool = False
    runs_scheduled_task: bool = False

    # --- Fallback hint from principal_type inference (name-based heuristics) ---
    # Set when the account's principal_type was inferred as "service" and no
    # harder evidence (URA / event log / run-as) fired first.  Confidence is
    # intentionally low (40) to flag that a re-scan should confirm.
    is_service_principal: bool = False


# ── Classification result ─────────────────────────────────────────────────────


class InteractiveClassification(NamedTuple):
    """Returned by ``classify_interactive()``."""

    status: str                          # InteractiveStatus enum value
    confidence: int                      # 0–100
    detection_method: str                # short label for UI / logging
    explanation: str                     # human-readable sentence
    allows_local_logon: bool | None      # None = unknown
    allows_remote_interactive_logon: bool | None
    allows_service_logon: bool | None
    allows_batch_logon: bool | None
    allows_network_logon: bool | None
    last_observed_logon_type: int | None
    review_required_reason: str | None


# ── Classifier ────────────────────────────────────────────────────────────────


def classify_interactive(ev: WinInteractiveEvidence) -> InteractiveClassification:
    """Apply the 9-rule chain and return an ``InteractiveClassification``.

    Rules are evaluated in descending confidence order; the first matching rule
    wins.  Each rule returns immediately — no accumulation.
    """

    def _result(
        status: str,
        confidence: int,
        method: str,
        explanation: str,
        *,
        local: bool | None = None,
        rdp: bool | None = None,
        svc: bool | None = None,
        batch: bool | None = None,
        net: bool | None = None,
        last_type: int | None = None,
        reason: str | None = None,
    ) -> InteractiveClassification:
        return InteractiveClassification(
            status=status,
            confidence=confidence,
            detection_method=method,
            explanation=explanation,
            allows_local_logon=local,
            allows_remote_interactive_logon=rdp,
            allows_service_logon=svc,
            allows_batch_logon=batch,
            allows_network_logon=net,
            last_observed_logon_type=last_type,
            review_required_reason=reason,
        )

    # ── Rule 1: gMSA ─────────────────────────────────────────────────────────
    if ev.is_gmsa:
        return _result(
            "service_or_batch_only", 97, "account_identity",
            "Group Managed Service Account — cannot perform interactive logon by design.",
            local=False, rdp=False, svc=True, batch=False, net=False,
        )

    # ── Rule 2: Computer / machine account ───────────────────────────────────
    if ev.is_computer_account:
        return _result(
            "service_or_batch_only", 93, "account_identity",
            "Computer/machine account — authenticates machine-to-machine only.",
            local=False, rdp=False, svc=True, batch=False, net=True,
        )

    # ── Rule 3: Domain group ──────────────────────────────────────────────────
    if ev.is_domain_group:
        return _result(
            "unknown_review_required", 45, "account_identity",
            "Domain group object — groups cannot logon directly; review member accounts.",
            reason=(
                "Domain group accounts cannot directly logon. "
                "Review group membership for privileged individuals."
            ),
        )

    # ── Rule 4: Unresolved / orphaned SID ────────────────────────────────────
    if ev.is_unresolved_sid:
        return _result(
            "unknown_review_required", 20, "account_identity",
            "Orphaned or unresolvable SID — interactive capability cannot be determined.",
            reason=(
                "Orphaned/unresolved SID; principal identity unknown. "
                "Investigate and remove stale ACE if appropriate."
            ),
        )

    # ── Rule 5: Known non-interactive built-in accounts ──────────────────────
    if ev.builtin_name and ev.builtin_name in _NON_INTERACTIVE_BUILTINS:
        conf = _NON_INTERACTIVE_BUILTINS[ev.builtin_name]
        return _result(
            "non_interactive_only", conf, "builtin_account",
            f"Well-known non-interactive built-in account ({ev.builtin_name!r}).",
            local=False, rdp=False, svc=False, batch=False, net=False,
        )

    # ── Rule 6: User Rights Assignment (secedit) ──────────────────────────────
    if ev.user_rights_available:
        both_denied   = ev.deny_interactive is True and ev.deny_rdp is True
        either_denied = ev.deny_interactive is True or ev.deny_rdp is True
        has_int = ev.has_interactive_logon_right is True
        has_rdp = ev.has_rdp_logon_right is True
        has_svc = ev.has_service_logon_right is True
        has_bat = ev.has_batch_logon_right is True
        has_net = ev.has_network_logon_right is True

        if both_denied:
            return _result(
                "non_interactive_only", 97, "user_rights_assignment",
                "User Rights Assignment explicitly denies both local and remote interactive logon.",
                local=False, rdp=False, svc=has_svc, batch=has_bat, net=has_net,
            )

        if has_int or has_rdp:
            rights_granted = []
            if has_int:
                rights_granted.append("SeInteractiveLogonRight")
            if has_rdp:
                rights_granted.append("SeRemoteInteractiveLogonRight")
            conf = 88 if either_denied else 95
            return _result(
                "interactive_capable", conf, "user_rights_assignment",
                f"User Rights Assignment grants interactive logon: {', '.join(rights_granted)}.",
                local=has_int, rdp=has_rdp, svc=has_svc, batch=has_bat, net=has_net,
            )

        if has_svc or has_bat:
            # Has service/batch rights; no interactive rights granted
            return _result(
                "service_or_batch_only", 80, "user_rights_assignment",
                "User Rights Assignment grants only service/batch logon; no interactive right assigned.",
                local=False, rdp=False, svc=has_svc, batch=has_bat, net=has_net,
            )

        # URA available but zero relevant rights for this account — fall through

    # ── Rule 7: Security event log — Event 4624 logon types ──────────────────
    if ev.event_log_available and ev.observed_logon_types:
        interactive_obs  = ev.observed_logon_types & INTERACTIVE_LOGON_TYPES
        svc_batch_obs    = ev.observed_logon_types & SERVICE_BATCH_LOGON_TYPES
        network_obs      = ev.observed_logon_types & NETWORK_LOGON_TYPES

        if interactive_obs:
            return _result(
                "interactive_capable", 97, "event_log_4624",
                f"Event 4624 observed interactive logon type(s): {sorted(interactive_obs)}.",
                local=(2 in ev.observed_logon_types or 11 in ev.observed_logon_types),
                rdp=(10 in ev.observed_logon_types),
                svc=bool(svc_batch_obs),
                batch=(4 in ev.observed_logon_types),
                net=bool(network_obs),
                last_type=ev.last_observed_logon_type,
            )

        if svc_batch_obs and not network_obs:
            return _result(
                "service_or_batch_only", 88, "event_log_4624",
                f"Event 4624 observed only service/batch logon type(s): {sorted(svc_batch_obs)}.",
                local=False, rdp=False,
                svc=(5 in ev.observed_logon_types),
                batch=(4 in ev.observed_logon_types),
                net=False,
                last_type=ev.last_observed_logon_type,
            )

        if network_obs and not svc_batch_obs:
            return _result(
                "network_only", 82, "event_log_4624",
                f"Event 4624 observed only network logon type(s): {sorted(network_obs)}.",
                local=False, rdp=False, svc=False, batch=False, net=True,
                last_type=ev.last_observed_logon_type,
            )

    # ── Rule 8: Service / task run-as (no URA or event-log data available) ───
    if ev.runs_service or ev.runs_scheduled_task:
        parts: list[str] = []
        if ev.runs_service:
            parts.append("Windows service")
        if ev.runs_scheduled_task:
            parts.append("scheduled task")
        conf = 72 if (ev.runs_service and ev.runs_scheduled_task) else 65 if ev.runs_service else 60
        return _result(
            "service_or_batch_only", conf, "service_task_runas",
            f"Account is configured as run-as principal for: {', '.join(parts)}.",
            local=None, rdp=None, svc=ev.runs_service, batch=ev.runs_scheduled_task, net=None,
        )

    # ── Rule 8.5: Service principal type hint (name-based, low confidence) ───
    # Fires when principal_type was inferred as "service" (e.g. name contains
    # "svc", "service", "agent") but no URA, event-log, or run-as evidence was
    # collected.  Confidence is capped at 40 — a re-scan with secedit data
    # will upgrade this to a URA-backed result.
    if ev.is_service_principal:
        return _result(
            "service_or_batch_only", 40, "principal_type_hint",
            "Account name/type suggests a service account; no interactive logon expected "
            "(re-scan with User Rights Assignment probe to confirm).",
            local=False, rdp=False, svc=None, batch=None, net=None,
            reason=(
                "Classification based on principal_type heuristic only. "
                "Run a fresh scan to collect secedit User Rights Assignment data for definitive classification."
            ),
        )

    # ── Rule 9: Insufficient evidence — default fallback ─────────────────────
    reasons: list[str] = []
    if not ev.user_rights_available:
        reasons.append(
            "User Rights Assignment not collected (secedit probe unavailable or failed)"
        )
    if not ev.event_log_available:
        reasons.append(
            "Security event log not collected (Event 4624 probe unavailable or no recent events)"
        )
    if not ev.runs_service and not ev.runs_scheduled_task:
        reasons.append("Account not observed running any service or scheduled task")

    return _result(
        "unknown_review_required", 30, "insufficient_data",
        "Insufficient evidence to determine interactive logon capability.",
        reason="; ".join(reasons) or "No classification evidence was collected.",
    )
