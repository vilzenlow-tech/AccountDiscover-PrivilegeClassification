from __future__ import annotations

from app.collectors.windows import WindowsCollector


def test_windows_domain_controller_admin_group_maps_to_local_user_by_sid():
    sid = "S-1-5-21-1918487076-637626318-2353424730-1127"
    accounts, _ = WindowsCollector._assemble_collection(
        "DC01",
        users_raw=[
            {
                "Name": "adm991",
                "SID": {"Value": sid},
                "Enabled": True,
                "PasswordRequired": True,
                "PasswordNeverExpires": False,
                "LastLogon": None,
                "Description": "",
            }
        ],
        groups_data={
            "hostname": "DC01",
            "groups": {
                "Administrators": [
                    {
                        "Name": "DEMO\\adm991",
                        "SID": {"Value": sid},
                        "ObjectClass": "User",
                        "PrincipalSource": "ActiveDirectory",
                    }
                ]
            },
            "errors": {},
            "expanded": {},
        },
        svcs_raw=[],
        tasks_raw=[],
        is_mock=False,
    )

    adm991 = next(account for account in accounts if account.account_name == "adm991")
    assert any(
        entitlement.kind == "windows_local_group"
        and entitlement.name == "Administrators"
        and entitlement.attributes["is_administrators"] is True
        for entitlement in adm991.entitlements
    )
    assert not any(account.account_name == "DEMO\\adm991" for account in accounts)
