from types import SimpleNamespace

from app.services.account_context import domain_for_account, origin_for_account, schema_name_for_account


def test_schema_name_prefers_database_evidence():
    account = SimpleNamespace(evidence_summary={"auth_db": "admin"}, entitlements=[])

    assert schema_name_for_account(account) == "admin"


def test_schema_name_falls_back_to_entitlement_scope():
    entitlement = SimpleNamespace(scope="appdb")
    account = SimpleNamespace(evidence_summary={}, entitlements=[entitlement])

    assert schema_name_for_account(account) == "appdb"


def test_origin_identifies_windows_domain_account():
    account = SimpleNamespace(
        auth_source="ad",
        source_type="windows_domain_user",
        principal_source="ActiveDirectory",
        account_name="DEMO\\administrator",
        evidence_summary={"domain": "DEMO"},
    )

    assert origin_for_account(account) == "domain"
    assert domain_for_account(account) == "DEMO"


def test_origin_identifies_local_account_with_asset_hostname():
    asset = SimpleNamespace(hostname="192.168.7.135")
    account = SimpleNamespace(
        auth_source="local",
        source_type="windows_local",
        principal_source="Local",
        account_name="administrator",
        evidence_summary={},
        asset=asset,
    )

    assert origin_for_account(account) == "local"
    assert domain_for_account(account) == "192.168.7.135"
