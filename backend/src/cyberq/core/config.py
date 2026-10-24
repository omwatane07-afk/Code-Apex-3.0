"""Core configuration management for CYBERQ."""

from enum import StrEnum
from functools import lru_cache
from typing import Any

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class EnvironmentType(StrEnum):
    PRODUCTION = "production"
    PILOT = "pilot"
    DEMO = "demo"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CYBERQ_",
        env_file=".env",
        extra="ignore",
    )

    ENV: EnvironmentType = Field(default=EnvironmentType.PRODUCTION)
    HOST: str = Field(default="127.0.0.1", description="Server bind host")
    PORT: int = Field(default=8000, description="Server bind port")

    @field_validator("ENV", mode="before")
    @classmethod
    def parse_env(cls, v: Any) -> EnvironmentType:
        if isinstance(v, EnvironmentType):
            return v
        if not v or not isinstance(v, str):
            return EnvironmentType.PRODUCTION
        v_clean = v.strip().lower()
        if v_clean == "pilot":
            return EnvironmentType.PILOT
        if v_clean in ("demo", "development", "dev"):
            return EnvironmentType.DEMO
        return EnvironmentType.PRODUCTION
    APP_NAME: str = Field(default="CYBERQ")
    APP_VERSION: str = Field(default="0.1.0")

    # Database: Postgres in pilot/production, sqlite permitted in testing/local dev
    DATABASE_URL: str = Field(
        default="sqlite:///./cyberq_dev.db",
        description="SQLAlchemy database URL",
    )

    # Server sessions and crypto
    SESSION_SECRET: str = Field(
        default="dev-session-secret-change-in-production-must-be-32-bytes",
        min_length=32,
        description="Secret key for signing server-side session references",
    )
    AUDIT_SIGNING_SEED: str = Field(
        default="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        description="Hex-encoded 32-byte seed for the Ed25519 audit checkpoint signer",
    )

    # Reliability & Clocks
    MAX_NTP_SKEW_SECONDS: float = Field(
        default=1.0, description="Max allowed clock skew in seconds"
    )
    SESSION_IDLE_TIMEOUT_MINUTES: int = Field(
        default=15, description="Idle session timeout in minutes"
    )
    SESSION_ABSOLUTE_TIMEOUT_HOURS: int = Field(
        default=8, description="Absolute session timeout in hours"
    )

    # Security headers
    STRICT_CSP: bool = Field(default=True, description="Enforce strict Content-Security-Policy")
    COOKIE_SECURE: bool = Field(
        default=False, description="Enforce Secure flag on cookies (auto True in production)"
    )
    TRUSTED_PROXIES: list[str] = Field(
        default_factory=list,
        description="Allow-list of trusted reverse proxy IPs permitted to set X-Forwarded headers",
    )
    WALLBOARD_ALLOWED_IPS: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "::1"],
        description="Allow-list of client IPs permitted to access the sanitized wallboard endpoint",
    )
    PILOT_MODE: bool = Field(
        default=False,
        description="Enable statutory simulation pilot mode for pre-enforcement obligation packs",
    )

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        if self.ENV == EnvironmentType.PRODUCTION:
            if "dev-session-secret" in self.SESSION_SECRET:
                raise ValueError(
                    "Production mode requires an explicitly configured, non-default SESSION_SECRET"
                )
            if self.AUDIT_SIGNING_SEED.startswith("0123456789abcdef"):
                raise ValueError(
                    "Production mode requires an explicitly configured, non-default AUDIT_SIGNING_SEED"
                )
        return self

    def is_production(self) -> bool:
        return self.ENV == EnvironmentType.PRODUCTION

    def is_demo(self) -> bool:
        return self.ENV == EnvironmentType.DEMO

    def should_secure_cookie(self) -> bool:
        return self.is_production() or self.COOKIE_SECURE


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
