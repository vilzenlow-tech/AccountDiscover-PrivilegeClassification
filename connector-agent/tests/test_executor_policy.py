from adpct_agent.config import AgentConfig
from adpct_agent.executor import JobExecutor


class RecordingClient:
    def __init__(self):
        self.status_updates = []

    def update_job_status(self, job_id, status, **kwargs):
        self.status_updates.append((job_id, status, kwargs))
        return {"status": status}


def test_policy_rejected_job_is_marked_failed():
    cfg = AgentConfig(allowed_scan_modes=["safe"])
    client = RecordingClient()
    executor = JobExecutor(cfg, client)

    accepted = executor.submit({
        "id": "da502952-b7cb-4d4e-b93f-aef4ad994809",
        "job_type": "discovery_credentialed",
        "payload": {
            "scan_mode": "deep",
            "scan_profile": "standard",
            "targets": [{"hostname": "192.168.7.131", "platform": "windows"}],
        },
    })

    assert accepted is False
    assert client.status_updates == [
        (
            "da502952-b7cb-4d4e-b93f-aef4ad994809",
            "failed",
            {
                "progress_pct": 0,
                "error_message": "Scan mode 'deep' not in allowed modes: ['safe']",
            },
        )
    ]
