"""Application configuration loaded from environment variables."""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP_", env_file=".env", extra="ignore")

    name: str = Field(default="adpct", alias="APP_NAME")
    env: Literal["dev", "staging", "prod"] = Field(default="dev", alias="APP_ENV")
    secret_key: str = Field(default="dev-only-change-me", alias="APP_SECRET_KEY")
    jwt_alg: str = Field(default="HS256", alias="APP_JWT_ALG")
    access_token_ttl_min: int = Field(default=60, alias="APP_ACCESS_TOKEN_TTL_MIN")
    refresh_token_ttl_min: int = Field(default=720, alias="APP_REFRESH_TOKEN_TTL_MIN")
    cors_origins: str = Field(default="http://localhost:5173", alias="APP_CORS_ORIGINS")
    rate_limit_login_per_min: int = Field(default=5, alias="APP_RATE_LIMIT_LOGIN_PER_MIN")

    database_url: str = Field(
        default="postgresql+psycopg://adpct:adpct@postgres:5432/adpct",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")
    celery_broker_url: str = Field(default="redis://redis:6379/1", alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://redis:6379/2", alias="CELERY_RESULT_BACKEND")

    collector_mode: Literal["mock", "live"] = Field(default="mock", alias="COLLECTOR_MODE")
    collector_ssh_timeout: int = Field(default=30, alias="COLLECTOR_SSH_TIMEOUT")
    collector_winrm_timeout: int = Field(default=30, alias="COLLECTOR_WINRM_TIMEOUT")
    collector_db_timeout: int = Field(default=20, alias="COLLECTOR_DB_TIMEOUT")

    vault_provider: Literal["local", "cyberark", "hashicorp", "azure", "aws"] = Field(
        default="local", alias="VAULT_PROVIDER"
    )
    vault_local_fernet_key: str | None = Field(default=None, alias="VAULT_LOCAL_FERNET_KEY")
    # Path to a file containing the Fernet key (Docker secrets mount or plain file).
    # Takes precedence over VAULT_LOCAL_FERNET_KEY when set.
    vault_local_fernet_key_file: str | None = Field(default=None, alias="VAULT_LOCAL_FERNET_KEY_FILE")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_json: bool = Field(default=True, alias="LOG_JSON")

    # AI Assistant (optional — feature is disabled when key is absent or blank)
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
