"""Application configuration loaded from environment variables."""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AppEnv = Literal["development", "test", "uat", "staging", "production"]
PRODUCTION_LIKE_ENVS = {"uat", "staging", "production"}
PRODUCTION_SECRET_SENTINELS = {
    "dev-only-change-me",
    "change-me-please-to-a-long-random-string",
    "secret",
    "changeme",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP_", env_file=".env", extra="ignore")

    name: str = Field(default="adpct", alias="APP_NAME")
    env: AppEnv = Field(alias="APP_ENV")
    secret_key: str = Field(default="dev-only-change-me", alias="APP_SECRET_KEY")
    jwt_alg: str = Field(default="HS256", alias="APP_JWT_ALG")
    access_token_ttl_min: int = Field(default=60, alias="APP_ACCESS_TOKEN_TTL_MIN")
    refresh_token_ttl_min: int = Field(default=720, alias="APP_REFRESH_TOKEN_TTL_MIN")
    cors_origins: str = Field(default="http://localhost:5173", alias="APP_CORS_ORIGINS")
    rate_limit_login_per_min: int = Field(default=5, alias="APP_RATE_LIMIT_LOGIN_PER_MIN")
    # Inactivity tiering thresholds (days). Governance defaults: 30 warn / 90 critical.
    inactivity_warn_days: int = Field(default=30, alias="INACTIVITY_WARN_DAYS")
    inactivity_critical_days: int = Field(default=90, alias="INACTIVITY_CRITICAL_DAYS")

    database_url: str = Field(
        default="postgresql+psycopg://adpct:adpct@postgres:5432/adpct",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")
    celery_broker_url: str = Field(default="redis://redis:6379/1", alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://redis:6379/2", alias="CELERY_RESULT_BACKEND")

    demo_mode: bool = Field(default=False, alias="DEMO_MODE")
    demo_seed_enabled: bool = Field(default=False, alias="DEMO_SEED_ENABLED")

    collector_mode: Literal["mock", "live"] = Field(default="live", alias="COLLECTOR_MODE")
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

    @field_validator("env", mode="before")
    @classmethod
    def normalize_env(cls, value: str) -> str:
        if value == "dev":
            return "development"
        if value == "prod":
            return "production"
        return value

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


def validate_startup_settings(settings: Settings) -> None:
    """Fail closed when a production-like environment is configured unsafely."""
    if settings.env in PRODUCTION_LIKE_ENVS and settings.demo_mode:
        raise RuntimeError(
            f"DEMO_MODE=true is not permitted when APP_ENV={settings.env}. "
            "Disable demo mode before starting UAT, staging, or production."
        )

    if settings.env in PRODUCTION_LIKE_ENVS and settings.collector_mode == "mock":
        raise RuntimeError(
            f"COLLECTOR_MODE=mock is not permitted when APP_ENV={settings.env}. "
            "Mock collectors fabricate discovery data; set COLLECTOR_MODE=live."
        )

    if settings.env == "production":
        if (
            settings.secret_key in PRODUCTION_SECRET_SENTINELS
            or len(settings.secret_key) < 32
        ):
            raise RuntimeError(
                "APP_SECRET_KEY must be a cryptographically random string of at least 32 "
                "characters in production. Generate one with: "
                "python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if settings.demo_seed_enabled:
            raise RuntimeError(
                "DEMO_SEED_ENABLED=true is not permitted when APP_ENV=production. "
                "Production startup must not seed demo/sample data."
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
