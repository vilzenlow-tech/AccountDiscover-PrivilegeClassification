"""Credential vault service.

Retrieves secret material at scan launch time. Secrets are NEVER cached in
memory beyond the scan task lifetime and NEVER serialised to disk, logs, or
API responses.

Provider adapters
-----------------
- local     : Fernet-encrypted local store (dev / pilot only)
- cyberark  : CyberArk Central Credential Provider (stub, ready for SDK wiring)
- hashicorp : HashiCorp Vault KV v2 (stub, ready for hvac wiring)
- azure     : Azure Key Vault (stub, ready for azure-keyvault-secrets wiring)
- aws       : AWS Secrets Manager (stub, ready for boto3 wiring)

All providers implement the same interface: `resolve(vault_ref) -> str`.
"""
from __future__ import annotations

import base64
import json
import os
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings
from app.models.enums import VaultBackend


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------

class VaultProvider(ABC):
    @abstractmethod
    def resolve(self, vault_ref: str) -> str:
        """Return the secret material for *vault_ref*. Never returns None."""


# ---------------------------------------------------------------------------
# Local encrypted store (dev / pilot only)
# ---------------------------------------------------------------------------

_LOCAL_STORE_PATH = Path("/app/vault_data/local_vault.json")  # shared across all containers via the ./backend:/app mount


class LocalVaultProvider(VaultProvider):
    """AES-128-CBC via Fernet. Key must be set via VAULT_LOCAL_FERNET_KEY.

    If the key is absent we generate a random one at startup and warn loudly.
    Never use this in production.
    """

    def __init__(self) -> None:
        settings = get_settings()
        raw = self._load_key(settings)
        if raw:
            self._fernet = Fernet(raw.encode() if isinstance(raw, str) else raw)
        else:
            key = Fernet.generate_key()
            self._fernet = Fernet(key)
            import warnings
            warnings.warn(
                "VAULT_LOCAL_FERNET_KEY not set — generated ephemeral key. "
                "Secrets stored in this session will be unreadable after restart. "
                "Set VAULT_LOCAL_FERNET_KEY in .env or mount a Docker secret at "
                "/run/secrets/vault_fernet_key for persistent local vault.",
                stacklevel=2,
            )

    @staticmethod
    def _load_key(settings) -> str | None:
        """Load the Fernet key with this priority order:
        1. /run/secrets/vault_fernet_key  (Docker secrets mount)
        2. VAULT_LOCAL_FERNET_KEY_FILE    (explicit file path env var)
        3. VAULT_LOCAL_FERNET_KEY         (inline env var — legacy / dev)
        """
        # 1. Docker secrets
        docker_secret = Path("/run/secrets/vault_fernet_key")
        if docker_secret.exists():
            try:
                key = docker_secret.read_text().strip()
                if key:
                    return key
            except OSError:
                pass

        # 2. Explicit file path env var
        if settings.vault_local_fernet_key_file:
            key_path = Path(settings.vault_local_fernet_key_file)
            if key_path.exists():
                try:
                    key = key_path.read_text().strip()
                    if key:
                        return key
                except OSError:
                    pass

        # 3. Inline env var (dev / fallback)
        return settings.vault_local_fernet_key

    def _load_store(self) -> dict:
        if _LOCAL_STORE_PATH.exists():
            return json.loads(_LOCAL_STORE_PATH.read_bytes())
        return {}

    def _save_store(self, store: dict) -> None:
        _LOCAL_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _LOCAL_STORE_PATH.write_bytes(json.dumps(store).encode())
        _LOCAL_STORE_PATH.chmod(0o600)

    def store(self, vault_ref: str, secret: str) -> None:
        store = self._load_store()
        encrypted = self._fernet.encrypt(secret.encode()).decode()
        store[vault_ref] = {"encrypted": encrypted, "stored_at": datetime.now(UTC).isoformat()}
        self._save_store(store)

    def resolve(self, vault_ref: str) -> str:
        store = self._load_store()
        entry = store.get(vault_ref)
        if not entry:
            raise LookupError(f"vault_ref not found in local store: {vault_ref}")
        try:
            return self._fernet.decrypt(entry["encrypted"].encode()).decode()
        except InvalidToken as e:
            raise ValueError(f"Decryption failed for {vault_ref} — key mismatch?") from e


# ---------------------------------------------------------------------------
# Provider stubs (wired to real clients in production)
# ---------------------------------------------------------------------------

class CyberArkVaultProvider(VaultProvider):
    """CyberArk Central Credential Provider (CCP) via REST.

    Production wiring: install `py-conjur` or call the AIM CCP endpoint with
    the AppID, Safe, and Object query. This stub is contract-ready.
    """

    def resolve(self, vault_ref: str) -> str:
        # vault_ref format: cyberark://Safe/Object
        # In production: call CCP /AIMWebService/api/Accounts?AppID=...&Safe=...&Object=...
        raise NotImplementedError(
            "CyberArk CCP provider not yet wired. "
            "Set VAULT_PROVIDER=local for development."
        )


class HashiCorpVaultProvider(VaultProvider):
    """HashiCorp Vault KV v2 via hvac.

    Production wiring: ``pip install hvac`` and use
    ``client.secrets.kv.v2.read_secret_version(path=..., mount_point=...)``.
    vault_ref format: ``vault://mount/path``
    """

    def resolve(self, vault_ref: str) -> str:
        raise NotImplementedError("HashiCorp Vault provider not yet wired.")


class AzureKeyVaultProvider(VaultProvider):
    """Azure Key Vault via azure-keyvault-secrets SDK.

    vault_ref format: ``azure://vault-name/secret-name``
    """

    def resolve(self, vault_ref: str) -> str:
        raise NotImplementedError("Azure Key Vault provider not yet wired.")


class AWSSecretsManagerProvider(VaultProvider):
    """AWS Secrets Manager via boto3.

    vault_ref format: ``aws://region/secret-name``
    """

    def resolve(self, vault_ref: str) -> str:
        raise NotImplementedError("AWS Secrets Manager provider not yet wired.")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PROVIDERS: dict[VaultBackend, type[VaultProvider]] = {
    VaultBackend.local: LocalVaultProvider,
    VaultBackend.cyberark: CyberArkVaultProvider,
    VaultBackend.hashicorp: HashiCorpVaultProvider,
    VaultBackend.azure: AzureKeyVaultProvider,
    VaultBackend.aws: AWSSecretsManagerProvider,
}

_instance: VaultProvider | None = None


def get_vault() -> VaultProvider:
    global _instance
    if _instance is None:
        backend = VaultBackend(get_settings().vault_provider)
        _instance = _PROVIDERS[backend]()
    return _instance
