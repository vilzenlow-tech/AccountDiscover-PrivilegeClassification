"""Shared SSH runner used by RHEL, Solaris, and AIX live collectors.

Security — Trust On First Use (TOFU)
--------------------------------------
The runner verifies the remote host key against a stored fingerprint.
On the very first connection to an asset (no stored fingerprint), the
observed fingerprint is recorded and returned so the caller can persist it.
On subsequent connections, the observed fingerprint must match exactly;
a mismatch raises ``SSHHostKeyMismatch``.
"""
from __future__ import annotations

import base64
import hashlib
import io
import structlog

log = structlog.get_logger("adpct.ssh")


class SSHHostKeyMismatch(RuntimeError):
    """Raised when the remote host key does not match the stored fingerprint."""


class SSHRunner:
    """Thin paramiko wrapper. Use as a context manager.

    Parameters
    ----------
    expected_fingerprint:
        SHA-256 fingerprint (base64, no padding) of the host key last seen
        for this asset.  Pass ``None`` on first-ever connection (TOFU).
        After ``__enter__`` the ``observed_fingerprint`` attribute is set.
        The caller is responsible for persisting it when it was previously
        ``None``.
    """

    def __init__(
        self,
        hostname: str,
        port: int,
        username: str,
        password: str | None = None,
        pkey_str: str | None = None,
        timeout: int = 30,
        expected_fingerprint: str | None = None,
    ) -> None:
        import paramiko

        self._hostname = hostname
        self._port = port
        self._expected_fp = expected_fingerprint
        self.observed_fingerprint: str | None = None

        self._client = paramiko.SSHClient()
        # Collect the host key but do not auto-accept yet — we verify below.
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = dict(
            hostname=hostname,
            port=port,
            username=username,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        if pkey_str:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(pkey_str))
            connect_kwargs["pkey"] = pkey
        else:
            connect_kwargs["password"] = password

        self._client.connect(**connect_kwargs)

        # After connect, fetch the actual host key and compute its fingerprint.
        transport = self._client.get_transport()
        host_key = transport.get_remote_server_key() if transport else None
        if host_key is not None:
            key_bytes = base64.b64decode(host_key.get_base64())
            digest = hashlib.sha256(key_bytes).digest()
            # OpenSSH-style: base64 without padding
            self.observed_fingerprint = base64.b64encode(digest).decode().rstrip("=")

        # TOFU verification
        if self._expected_fp is not None and self.observed_fingerprint is not None:
            if self.observed_fingerprint != self._expected_fp:
                self._client.close()
                raise SSHHostKeyMismatch(
                    f"Host key fingerprint mismatch for {hostname}:{port} — "
                    f"expected SHA256:{self._expected_fp}, "
                    f"got SHA256:{self.observed_fingerprint}. "
                    "If the server was re-keyed intentionally, clear the stored "
                    "fingerprint from the asset record and re-run the scan."
                )

        if self.observed_fingerprint:
            log.debug(
                "ssh.hostkey",
                host=hostname,
                port=port,
                fingerprint=f"SHA256:{self.observed_fingerprint}",
                tofu="first_use" if self._expected_fp is None else "verified",
            )

    def run(self, cmd: str, timeout: int = 30) -> str:
        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if err.strip():
            log.debug("ssh.stderr", cmd=cmd[:80], stderr=err[:200])
        return out

    def __enter__(self) -> "SSHRunner":
        return self

    def __exit__(self, *_) -> None:
        self._client.close()
