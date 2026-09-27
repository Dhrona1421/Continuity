from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import BeforeValidator, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


CsvList = Annotated[list[str], NoDecode, BeforeValidator(_csv)]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GHOSTSOC_", env_file=".env", extra="ignore", case_sensitive=False)

    env: str = "development"
    secret_key: str = "development-only-secret-key-change-me"  # noqa: S105 - rejected in production
    database_url: str = "sqlite:///./ghostsoc.db"
    cors_origins: CsvList = Field(default_factory=lambda: ["http://localhost:8080"])
    bootstrap_admin_email: str = "admin@ghostsoc.local"
    bootstrap_admin_password: str = "change-this-before-non-demo-use"  # noqa: S105 - demo only
    access_token_minutes: int = 60
    session_cookie_secure: bool = False
    session_cookie_partitioned: bool = False
    dry_run: bool = True
    demo_mode: bool = True
    demo_auto_access: bool = False
    authorized_targets: CsvList = Field(default_factory=lambda: ["demo-endpoint-01", "demo-endpoint-02"])
    web_allowed_hosts: CsvList = Field(default_factory=lambda: ["demo-web.local", "authorized-web.test"])
    report_dir: Path = Path("./reports")
    evidence_dir: Path = Path("./evidence")

    llm_base_url: str | None = None
    llm_api_key: str | None = None
    llm_model: str = "openai/gpt-oss-120b"
    llm_timeout_seconds: float = Field(default=15.0, ge=1, le=60)

    hindsight_url: str | None = None
    hindsight_api_key: str | None = None
    hindsight_bank_id: str = "ghostsoc-security"
    hindsight_timeout_seconds: float = Field(default=60.0, ge=1, le=180)

    opensearch_url: str | None = None
    opensearch_username: str | None = None
    opensearch_password: str | None = None
    opensearch_verify_tls: bool = True
    allow_private_connectors: bool = False

    wazuh_url: str | None = None
    wazuh_token: str | None = None
    velociraptor_url: str | None = None
    velociraptor_token: str | None = None
    arkime_url: str | None = None
    misp_url: str | None = None
    misp_api_key: str | None = None
    opencti_url: str | None = None
    opencti_token: str | None = None
    shuffle_url: str | None = None
    shuffle_api_key: str | None = None
    abuse_ch_auth_key: str | None = None
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None

    @field_validator("env")
    @classmethod
    def validate_env(cls, value: str) -> str:
        allowed = {"development", "test", "production"}
        if value not in allowed:
            raise ValueError(f"env must be one of {sorted(allowed)}")
        return value

    @model_validator(mode="after")
    def secure_production_defaults(self) -> Settings:
        if self.session_cookie_partitioned and not self.session_cookie_secure:
            raise ValueError("partitioned session cookies require session_cookie_secure")
        if self.demo_auto_access and (not self.demo_mode or not self.dry_run):
            raise ValueError("demo_auto_access requires demo_mode and dry_run")
        if self.env == "production":
            if self.demo_auto_access:
                raise ValueError("demo_auto_access must be disabled in production")
            if len(self.secret_key) < 32 or "change-me" in self.secret_key:
                raise ValueError("production secret_key must be at least 32 non-default characters")
            if "change-this" in self.bootstrap_admin_password:
                raise ValueError("production bootstrap password must be changed")
            if self.demo_mode:
                raise ValueError("demo_mode must be disabled in production")
            if not self.session_cookie_secure:
                raise ValueError("session_cookie_secure must be enabled in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
