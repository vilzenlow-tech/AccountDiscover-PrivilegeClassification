"""Secure HTTPS client for connector ↔ console communication.

All traffic is outbound-only over TCP 443.  Never opens listening sockets.
"""
from __future__ import annotations

import hashlib
import logging
import platform
import socket
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import AgentConfig

log = logging.getLogger("adpct.client")

AGENT_VERSION = "1.0.0"


def _sanitize_token(token: str) -> str:
    return token[:4] + "…" if token else "<none>"


class ConsoleClient:
    """Outbound-only HTTPS client for the ADPCT console.

    All methods raise requests.HTTPError on non-2xx responses.
    Callers are responsible for retry/backoff logic.
    """

    def __init__(self, cfg: AgentConfig) -> None:
        self.cfg = cfg
        self._session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()

        # TLS verification
        if self.cfg.console_ca_bundle:
            session.verify = self.cfg.console_ca_bundle
        else:
            session.verify = self.cfg.verify_tls

        # Proxy
        if self.cfg.proxy_url:
            session.proxies = {
                "http": self.cfg.proxy_url,
                "https": self.cfg.proxy_url,
            }
            if self.cfg.no_proxy:
                session.proxies["no_proxy"] = self.cfg.no_proxy

        # Retry adapter (for transient network errors only — not for auth/4xx)
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PATCH"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)

        return session

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.cfg.token}",
            "X-Connector-ID": self.cfg.connector_id,
            "X-Agent-Version": AGENT_VERSION,
            "Content-Type": "application/json",
        }

    def _url(self, path: str) -> str:
        base = self.cfg.console_url.rstrip("/")
        return f"{base}/api/v1{path}"

    # ── Enrollment ────────────────────────────────────────────────────────────

    def enroll(self, registration_token: str) -> dict:
        """One-time enrollment — exchange registration token for connector_id."""
        payload = {
            "registration_token": registration_token,
            "hostname": socket.getfqdn(),
            "ip_address": _get_local_ip(),
            "os_platform": platform.system().lower(),
            "os_version": platform.release(),
            "agent_version": AGENT_VERSION,
        }
        log.info("Enrolling with console at %s", self.cfg.console_url)
        r = self._session.post(
            self._url("/connector-agents/enroll"),
            json=payload,
            timeout=30,
            verify=self.cfg.verify_tls,
        )
        r.raise_for_status()
        return r.json()

    def check_enrollment_status(self, registration_token: str) -> dict:
        r = self._session.get(
            self._url("/connector-agents/enroll/status"),
            headers={"Authorization": f"Bearer {registration_token}"},
            timeout=15,
            verify=self.cfg.verify_tls,
        )
        r.raise_for_status()
        return r.json()

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def heartbeat(self, health_payload: dict) -> dict:
        r = self._session.post(
            self._url(f"/connector-agents/{self.cfg.connector_id}/heartbeat"),
            json=health_payload,
            headers=self._headers(),
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    # ── Config ────────────────────────────────────────────────────────────────

    def pull_config(self) -> dict:
        r = self._session.get(
            self._url(f"/connector-agents/{self.cfg.connector_id}/config"),
            headers=self._headers(),
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    # ── Jobs ──────────────────────────────────────────────────────────────────

    def poll_jobs(self) -> list[dict]:
        r = self._session.get(
            self._url(f"/connector-agents/{self.cfg.connector_id}/jobs/pending"),
            headers=self._headers(),
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    def update_job_status(self, job_id: str, status: str, **kwargs: Any) -> dict:
        payload = {"status": status, **kwargs}
        r = self._session.patch(
            self._url(f"/connector-agents/{self.cfg.connector_id}/jobs/{job_id}/status"),
            json=payload,
            headers=self._headers(),
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    # ── Result upload (chunked) ───────────────────────────────────────────────

    def upload_result_chunk(
        self,
        job_id: str,
        chunk_index: int,
        chunk_count: int,
        data_b64: str,
        checksum: str,
        total_checksum: str | None = None,
    ) -> dict:
        payload = {
            "job_id": job_id,
            "chunk_index": chunk_index,
            "chunk_count": chunk_count,
            "data": data_b64,
            "checksum": checksum,
            "total_checksum": total_checksum,
            "content_encoding": "gzip",
        }
        r = self._session.post(
            self._url(f"/connector-agents/{self.cfg.connector_id}/results"),
            json=payload,
            headers=self._headers(),
            timeout=60,
        )
        r.raise_for_status()
        return r.json()

    # ── Log upload ────────────────────────────────────────────────────────────

    def upload_logs(self, entries: list[dict]) -> dict:
        r = self._session.post(
            self._url(f"/connector-agents/{self.cfg.connector_id}/logs"),
            json={"entries": entries},
            headers=self._headers(),
            timeout=30,
        )
        r.raise_for_status()
        return r.json()


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def exponential_backoff(attempt: int, base: int = 2, max_wait: int = 300) -> float:
    wait = min(base ** attempt, max_wait)
    return wait
