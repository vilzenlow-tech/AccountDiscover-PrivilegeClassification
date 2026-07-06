"""Derived account context helpers."""
from __future__ import annotations

def schema_name_for_account(account: object) -> str | None:
    evidence = getattr(account, "evidence_summary", None) or {}
    for key in ("schema_name", "database_name", "auth_db", "dbname", "default_db", "database"):
        value = evidence.get(key)
        if value:
            return str(value)

    scopes = [
        ent.scope
        for ent in (getattr(account, "entitlements", None) or [])
        if ent.scope and str(ent.scope).strip() not in {"*", "*.*", "server", "global"}
    ]
    return sorted(set(str(scope) for scope in scopes))[0] if scopes else None


def origin_for_account(account: object) -> str:
    auth_source = getattr(getattr(account, "auth_source", None), "value", getattr(account, "auth_source", None))
    source_type = str(getattr(account, "source_type", "") or "").lower()
    principal_source = str(getattr(account, "principal_source", "") or "").lower()
    if auth_source in {"ad", "ldap"} or principal_source == "activedirectory" or source_type.startswith("windows_domain"):
        return "domain"
    if auth_source == "local" or principal_source == "local" or source_type in {"windows_local", "windows_builtin", "windows_service", "windows_system", "linux_local"}:
        return "local"
    if auth_source == "db_native":
        return "database"
    if auth_source == "os_integrated":
        return "os_integrated"
    return "unknown"


def domain_for_account(account: object) -> str | None:
    evidence = getattr(account, "evidence_summary", None) or {}
    domain = evidence.get("domain")
    if domain:
        return str(domain)
    account_name = str(getattr(account, "account_name", "") or "")
    if "\\" in account_name:
        return account_name.split("\\", 1)[0]
    if origin_for_account(account) == "local":
        asset = getattr(account, "asset", None)
        return getattr(asset, "hostname", None) or getattr(account, "asset_hostname", None)
    return None
