from adpct_agent.config import AgentConfig
from adpct_agent.executor import JobExecutor


class RecordingClient:
    def update_job_status(self, job_id, status, **kwargs):
        return {"status": status}


class FakeWindowsScanner:
    def scan(self, target, payload):
        return {
            "asset_id": target.get("asset_id"),
            "hostname": "WIN01",
            "platform": "windows",
            "status": "success",
            "accounts_discovered": 1,
            "accounts": [{"account_name": "WIN01\\Administrator"}],
            "evidence": {},
            "scanned_at": "2026-05-09T00:00:00+00:00",
        }


def test_scan_target_dispatches_windows_to_windows_scanner():
    executor = JobExecutor(AgentConfig(), RecordingClient())
    executor._windows_scanner = FakeWindowsScanner()

    result = executor._scan_target(
        {"hostname": "192.168.7.131", "platform": "windows"},
        {"credential": {"username": "Administrator", "secret": "Secret123!"}},
        "discovery_credentialed",
    )

    assert result["status"] == "success"
    assert result["accounts_discovered"] == 1
    assert result["accounts"][0]["account_name"] == "WIN01\\Administrator"
