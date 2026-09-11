"""Runtime settings via environment, prefix PIP_ (spec §12)."""

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PIP_")

    private_key_file: str = "./data/instance.key"
    display_name: str = "poke"
    policy_file: str = "./config/policy.yaml"
    store_url: str = "memory://"
    http_host: str = "127.0.0.1"
    http_port: int = 8642
    mcp_port: int = 8643
    public_http_url: str | None = None
    public_mcp_url: str | None = None
    http_bearer_token: str | None = None
    max_clock_skew_seconds: int = 300
    idempotency_ttl_seconds: int = 86400
    log_level: str = "INFO"
    allow_insecure_key_perms: bool = False

    @field_validator("public_http_url", "public_mcp_url", "http_bearer_token", mode="before")
    @classmethod
    def _empty_is_none(cls, v):  # type: ignore[no-untyped-def]
        # an empty value in .env files must not enable features
        return None if v == "" else v
