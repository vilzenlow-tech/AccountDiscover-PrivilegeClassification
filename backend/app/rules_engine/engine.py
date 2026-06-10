"""Rules engine: evaluates classification rules against a normalized account.

Design principles:
- Deterministic: same account + same rules => same result every time.
- Explainable: every match produces an explanation string rendered from the
  rule's template.
- All-matches: every matching rule is recorded; the highest-severity
  classification (per PRIVILEGE_SEVERITY) becomes the winning result.
- DB-first: rules come from the database (via the service layer); built-in
  YAML rules are loaded as a seed and managed through the normal rules API.
- Exception-aware: active exceptions can suppress or downgrade a result.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.collectors.base import NormalizedAccount
from app.models.enums import PRIVILEGE_SEVERITY, PrivilegeClass
from app.rules_engine.predicates import EvalContext, evaluate


@dataclass
class RuleSpec:
    """In-memory representation of a classification rule."""
    id: str
    rule_key: str
    name: str
    platform: str | None
    predicate: dict[str, Any]
    classify_as: PrivilegeClass
    confidence: int
    risk_modifier: int
    explanation_template: str
    priority: int
    version: int


@dataclass
class MatchResult:
    rule: RuleSpec
    matched: bool
    evidence: dict[str, Any]
    classification: PrivilegeClass
    confidence: int
    risk_score: int
    direct: bool
    inheritance_path: str | None
    explanation: str
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class RuleEvaluationResult:
    """Complete evaluation for one account."""
    account: NormalizedAccount
    winning_classification: PrivilegeClass
    winning_confidence: int
    risk_score: int
    matches: list[MatchResult]
    dormant: bool
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class RulesEngine:
    """Evaluates all enabled rules against a normalized account.

    Usage::

        engine = RulesEngine(rules, dormancy_days=90)
        result = engine.evaluate(account)
    """

    def __init__(self, rules: list[RuleSpec], dormancy_days: int = 90) -> None:
        # Sort ascending priority — higher priority number = evaluated later,
        # but we collect ALL matches and then pick the winner by severity.
        self._rules = sorted(rules, key=lambda r: r.priority)
        self._dormancy_days = dormancy_days

    def evaluate(self, account: NormalizedAccount) -> RuleEvaluationResult:
        ctx = EvalContext(account=account, dormancy_days=self._dormancy_days)
        matches: list[MatchResult] = []

        for rule in self._rules:
            # Skip platform-scoped rules that don't match this account's platform.
            # (platform is derived from the target, not stored on NormalizedAccount
            # at eval time; the caller should pre-filter or pass source_type context.)
            try:
                matched, evidence = evaluate(rule.predicate, ctx)
            except Exception as exc:
                # Rule evaluation errors must never crash the engine; they
                # produce a zero-confidence unknown result.
                matches.append(
                    MatchResult(
                        rule=rule,
                        matched=False,
                        evidence={"error": str(exc)},
                        classification=PrivilegeClass.unknown_review_required,
                        confidence=0,
                        risk_score=0,
                        direct=True,
                        inheritance_path=None,
                        explanation=f"Rule evaluation error: {exc}",
                    )
                )
                continue

            if not matched:
                continue

            # Detect whether privilege is direct or inherited.
            direct = self._is_direct(evidence)
            ipath = self._inheritance_path(evidence)

            explanation = self._render_explanation(rule.explanation_template, account, evidence)
            risk = min(100, max(0, PRIVILEGE_SEVERITY.get(rule.classify_as, 50) + rule.risk_modifier))

            matches.append(
                MatchResult(
                    rule=rule,
                    matched=True,
                    evidence=evidence,
                    classification=rule.classify_as,
                    confidence=rule.confidence,
                    risk_score=risk,
                    direct=direct,
                    inheritance_path=ipath,
                    explanation=explanation,
                )
            )

        # Determine winning classification.
        winning = PrivilegeClass.non_privileged
        winning_confidence = 95
        winning_risk = 10

        privileged_matches = [m for m in matches if m.matched]
        if privileged_matches:
            best = max(
                privileged_matches,
                key=lambda m: (
                    PRIVILEGE_SEVERITY.get(m.classification, 0),
                    m.confidence,
                ),
            )
            winning = best.classification
            winning_confidence = best.confidence
            winning_risk = best.risk_score
        else:
            winning = PrivilegeClass.non_privileged

        # Dormancy check: if winning class is inherently privileged and the
        # account hasn't logged in within the dormancy window, upgrade to
        # dormant_privileged (which may be considered higher severity).
        dormant = False
        dormant_classes = {
            PrivilegeClass.full_admin,
            PrivilegeClass.admin_equivalent,
            PrivilegeClass.operator_high_impact,
            PrivilegeClass.delegated_admin,
            PrivilegeClass.privileged_service,
        }
        if winning in dormant_classes:
            from datetime import timedelta
            from app.rules_engine.predicates import evaluate as _ev
            dormant_pred = {"is_dormant": True}
            is_dormant, _ = _ev(dormant_pred, ctx)
            if is_dormant:
                dormant = True
                winning = PrivilegeClass.dormant_privileged
                winning_risk = min(100, winning_risk + 10)

        return RuleEvaluationResult(
            account=account,
            winning_classification=winning,
            winning_confidence=winning_confidence,
            risk_score=winning_risk,
            matches=[m for m in matches if m.matched],
            dormant=dormant,
        )

    @staticmethod
    def _is_direct(evidence: dict) -> bool:
        via = evidence.get("via", [])
        if isinstance(via, list):
            return not any(v for v in via if v)
        return not bool(via)

    @staticmethod
    def _inheritance_path(evidence: dict) -> str | None:
        via = evidence.get("via", [])
        if isinstance(via, list):
            paths = [v for v in via if v]
            return " -> ".join(paths) if paths else None
        return str(via) if via else None

    @staticmethod
    def _render_explanation(template: str, account: NormalizedAccount, evidence: dict) -> str:
        ctx = {
            "account": account.account_name,
            "principal_type": account.principal_type.value,
            "enabled_status": account.enabled_status.value,
            **evidence,
        }
        try:
            return template.format_map(ctx)
        except (KeyError, ValueError):
            # Fall back to template with evidence appended.
            return f"{template} [evidence: {evidence}]"
