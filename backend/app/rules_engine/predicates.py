"""Declarative predicate evaluator for classification rules.

A predicate is a JSON-serialisable dict that the rules engine evaluates
against an `EvalContext` (account + entitlements). No `eval()` or exec is
involved — predicates are a small, closed vocabulary of operators. This keeps
rule definitions safe to store in the database and edit through the UI.

Supported predicate shapes
--------------------------
{"uid_equals": 0}
{"entitlement_kind_is": "unix_uid0"}
{"entitlement_kind_name_in": {"kind": "unix_group", "names": ["wheel", "sudo"]}}
{"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "broad"}}
{"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "nopasswd"}}
{"entitlement_kind_name_in": {"kind": "windows_local_group", "names": ["Administrators", ...]}}
{"entitlement_kind_attr_true": {"kind": "windows_local_group", "attr": "is_administrators"}}
{"entitlement_kind_attr_true": {"kind": "windows_local_group", "attr": "high_impact"}}
{"entitlement_kind_name_in": {"kind": "mssql_server_role", "names": ["sysadmin", ...]}}
{"entitlement_kind_attr_true": {"kind": "mssql_server_role", "attr": "high_risk"}}
{"entitlement_kind_name_in": {"kind": "mssql_db_role", "names": ["db_owner", ...]}}
{"entitlement_kind_attr_true": {"kind": "mysql_grant", "attr": "global_admin"}}
{"entitlement_kind_name_in": {"kind": "mongo_role", "names": ["root", ...]}}
{"entitlement_kind_attr_true": {"kind": "mongo_role", "attr": "admin_critical"}}
{"entitlement_kind_attr_true": {"kind": "aix_rbac_role", "attr": "broad"}}
{"entitlement_kind_attr_true": {"kind": "solaris_rbac_profile", "attr": "broad"}}
{"principal_type_in": ["service", "application"]}
{"enabled_status_in": ["enabled", "locked"]}
{"interactive_shell_is_non_interactive": true}
{"all_of": [<predicate>, ...]}
{"any_of": [<predicate>, ...]}
{"not": <predicate>}
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from app.collectors.base import NormalizedAccount, NormalizedEntitlement


@dataclass
class EvalContext:
    account: NormalizedAccount
    dormancy_days: int = 90


def _ents(account: NormalizedAccount, kind: str) -> list[NormalizedEntitlement]:
    return [e for e in account.entitlements if e.kind == kind]


def evaluate(predicate: dict[str, Any], ctx: EvalContext) -> tuple[bool, dict]:
    """Return (matched, evidence_dict)."""
    acc = ctx.account
    ents = acc.entitlements

    if "uid_equals" in predicate:
        uid = predicate["uid_equals"]
        ev = acc.evidence_summary or {}
        matched = ev.get("uid") == uid
        return matched, {"uid": ev.get("uid")}

    if "entitlement_kind_is" in predicate:
        kind = predicate["entitlement_kind_is"]
        matches = [e for e in ents if e.kind == kind]
        return bool(matches), {"matched": [e.name for e in matches]}

    if "entitlement_kind_name_in" in predicate:
        p = predicate["entitlement_kind_name_in"]
        kind, names = p["kind"], set(p["names"])
        matches = [e for e in ents if e.kind == kind and e.name in names]
        return bool(matches), {"kind": kind, "matched": [e.name for e in matches], "via": [e.via for e in matches if e.via]}

    if "entitlement_kind_attr_true" in predicate:
        p = predicate["entitlement_kind_attr_true"]
        kind, attr = p["kind"], p["attr"]
        matches = [e for e in ents if e.kind == kind and (e.attributes or {}).get(attr)]
        return bool(matches), {"kind": kind, "attr": attr, "matched": [e.name for e in matches]}

    if "source_type_in" in predicate:
        types = set(predicate["source_type_in"])
        matched = acc.source_type in types
        return matched, {"source_type": acc.source_type}

    if "principal_type_in" in predicate:
        types = set(predicate["principal_type_in"])
        matched = acc.principal_type.value in types
        return matched, {"principal_type": acc.principal_type.value}

    if "enabled_status_in" in predicate:
        statuses = set(predicate["enabled_status_in"])
        matched = acc.enabled_status.value in statuses
        return matched, {"enabled_status": acc.enabled_status.value}

    if "interactive_shell_is_non_interactive" in predicate:
        matched = acc.interactive_status.value == "non_interactive"
        return matched, {"interactive_status": acc.interactive_status.value}

    if "is_dormant" in predicate:
        days = ctx.dormancy_days
        if acc.last_login is None:
            matched = True
            return matched, {"last_login": None, "dormancy_days": days}
        cutoff = datetime.now(tz=UTC) - timedelta(days=days)
        matched = acc.last_login < cutoff
        return matched, {"last_login": acc.last_login.isoformat(), "dormancy_days": days, "cutoff": cutoff.isoformat()}

    if "all_of" in predicate:
        evidence: dict = {}
        for sub in predicate["all_of"]:
            ok, ev = evaluate(sub, ctx)
            evidence.update(ev)
            if not ok:
                return False, evidence
        return True, evidence

    if "any_of" in predicate:
        for sub in predicate["any_of"]:
            ok, ev = evaluate(sub, ctx)
            if ok:
                return True, ev
        return False, {}

    if "not" in predicate:
        ok, ev = evaluate(predicate["not"], ctx)
        return not ok, ev

    raise ValueError(f"Unknown predicate operator: {list(predicate.keys())}")
