import json

import pytest

from adpct_agent.scanners.windows import WindowsScanError, WindowsScanner, credential_from_payload


class FakeResult:
    def __init__(self, payload, status_code=0, stderr=""):
        self.status_code = status_code
        self.std_out = json.dumps(payload).encode()
        self.std_err = stderr.encode()


class FakeSession:
    def __init__(self):
        self.calls = 0

    def run_ps(self, script):
        self.calls += 1
        if self.calls == 1:
            return FakeResult([
                {
                    "Name": "svc_backup",
                    "SID": "S-1-5-21-1-2-3-1001",
                    "Enabled": True,
                    "PasswordRequired": True,
                    "PasswordNeverExpires": True,
                    "LastLogon": "2026-05-01T01:00:00Z",
                }
            ])
        if self.calls == 2:
            return FakeResult({
                "hostname": "WIN01",
                "groups": {
                    "Administrators": [
                        {
                            "Name": "WIN01\\svc_backup",
                            "SID": "S-1-5-21-1-2-3-1001",
                            "ObjectClass": "User",
                            "PrincipalSource": "Local",
                        },
                        {
                            "Name": "CORP\\Domain Admins",
                            "SID": "S-1-5-21-4-5-6-512",
                            "ObjectClass": "Group",
                            "PrincipalSource": "ActiveDirectory",
                        },
                    ]
                },
            })
        if self.calls == 3:
            return FakeResult([
                {
                    "Name": "BackupAgent",
                    "DisplayName": "Backup Agent",
                    "StartName": "WIN01\\svc_backup",
                    "State": "Running",
                    "StartMode": "Auto",
                }
            ])
        if self.calls == 4:
            return FakeResult({})
        return FakeResult({})


def test_credential_from_payload_does_not_require_one_shape():
    target = {"credentials": {"username": "Administrator", "password": "Secret123!"}}

    cred = credential_from_payload(target, {})

    assert cred.username == "Administrator"
    assert cred.secret == "Secret123!"


def test_windows_scanner_builds_accounts_from_winrm_json():
    scanner = WindowsScanner(session_factory=lambda **kwargs: FakeSession())

    result = scanner.scan(
        {"hostname": "192.168.7.131", "platform": "windows"},
        {"credential": {"username": "Administrator", "secret": "Secret123!"}},
    )

    assert result["status"] == "success"
    assert result["hostname"] == "WIN01"
    assert result["accounts_discovered"] == 2
    names = {a["account_name"] for a in result["accounts"]}
    assert names == {"WIN01\\svc_backup", "CORP\\Domain Admins"}
    svc = next(a for a in result["accounts"] if a["account_name"] == "WIN01\\svc_backup")
    assert svc["password_never_expires"] is True
    assert {e["kind"] for e in svc["entitlements"]} == {
        "windows_local_group",
        "windows_service_logon",
    }
    assert "Secret123!" not in json.dumps(result)


def test_windows_scanner_requires_credential_material():
    scanner = WindowsScanner(session_factory=lambda **kwargs: FakeSession())

    with pytest.raises(WindowsScanError, match="requires username and secret"):
        scanner.scan({"hostname": "192.168.7.131", "platform": "windows"}, {})


def test_net_localgroup_fallback_members_merge_with_local_users():
    from adpct_agent.scanners.windows import build_accounts

    accounts = build_accounts(
        "WINDOWS_PILOT",
        users=[
            {
                "Name": "admin",
                "SID": "S-1-5-21-1-2-3-1002",
                "Enabled": True,
                "PasswordRequired": True,
                "PasswordNeverExpires": False,
            }
        ],
        groups_data={
            "groups": {
                "Administrators": [
                    {
                        "Name": "admin",
                        "SID": None,
                        "ObjectClass": "Unknown",
                        "PrincipalSource": "Unknown",
                        "FallbackSource": "net localgroup",
                    }
                ]
            },
            "errors": {
                "Administrators": "An unspecified error occurred: error code = 1789"
            },
        },
        services=[],
        tasks=[],
        user_rights_data={},
        logon_types_data={},
    )

    assert len(accounts) == 1
    assert accounts[0]["account_name"] == "WINDOWS_PILOT\\admin"
    assert accounts[0]["entitlements"][0]["name"] == "Administrators"
    assert accounts[0]["entitlements"][0]["attributes"]["principal_source"] == "Unknown"


def test_user_rights_mark_rdp_group_member_interactive_capable():
    from adpct_agent.scanners.windows import build_accounts

    accounts = build_accounts(
        "WINDOWS_PILOT",
        users=[{"Name": "admin", "SID": "S-1-5-21-1-2-3-1002", "Enabled": True}],
        groups_data={"groups": {"Remote Desktop Users": [{"Name": "admin", "PrincipalSource": "Local"}]}},
        services=[],
        tasks=[],
        user_rights_data={"SeRemoteInteractiveLogonRight": ["S-1-5-32-555"]},
        logon_types_data={},
    )

    admin = accounts[0]
    assert admin["interactive_status"] == "interactive_capable"
    assert admin["win_interactive_confidence"] == 95
    assert admin["win_allows_remote_interactive"] is True
    assert admin["win_interactive_detection_method"] == "user_rights_assignment"


def test_service_logon_right_marks_account_service_or_batch_only():
    from adpct_agent.scanners.windows import build_accounts

    accounts = build_accounts(
        "WINDOWS_PILOT",
        users=[{"Name": "svc_batch", "SID": "S-1-5-21-1-2-3-1003", "Enabled": True}],
        groups_data={"groups": {}},
        services=[],
        tasks=[],
        user_rights_data={"SeServiceLogonRight": ["S-1-5-21-1-2-3-1003"]},
        logon_types_data={},
    )

    svc = accounts[0]
    assert svc["interactive_status"] == "service_or_batch_only"
    assert svc["win_allows_service_logon"] is True
    assert svc["win_interactive_detection_method"] == "user_rights_assignment"


def test_event_logon_type_marks_interactive_capable_without_user_rights():
    from adpct_agent.scanners.windows import build_accounts

    accounts = build_accounts(
        "WINDOWS_PILOT",
        users=[{"Name": "admin", "SID": "S-1-5-21-1-2-3-1002", "Enabled": True}],
        groups_data={"groups": {}},
        services=[],
        tasks=[],
        user_rights_data={},
        logon_types_data={"admin": [3, 10]},
    )

    admin = accounts[0]
    assert admin["interactive_status"] == "interactive_capable"
    assert admin["win_last_observed_logon_type"] == 10
    assert admin["win_allows_remote_interactive"] is True
    assert admin["win_allows_network_logon"] is True
    assert admin["win_interactive_detection_method"] == "event_log_4624"
