"""Centralized configuration management for DBShield using pydantic-settings.

Defines conservative defaults, validates operational limits, and ensures safe
exposure of non-sensitive parameters.
"""

import json
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from dbshield.exceptions import ConfigurationError


class LenientEnvSettingsSource(EnvSettingsSource):
    """Environment source allowing comma-separated or JSON list representations."""

    def decode_complex_value(self, field_name: str, field: Any, value: Any) -> Any:
        try:
            return super().decode_complex_value(field_name, field, value)
        except Exception:
            if isinstance(value, str):
                return [x.strip() for x in value.split(",") if x.strip()]
            raise


class Settings(BaseSettings):
    """Centralized DBShield settings with environment variable override support."""

    model_config = SettingsConfigDict(
        env_prefix="DBSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,  # noqa: ARG003
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            LenientEnvSettingsSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
        )

    # HTTP Client Configuration
    http_timeout: float = Field(
        default=10.0,
        description="HTTP request timeout in seconds.",
        ge=0.5,
        le=300.0,
    )
    max_redirects: int = Field(
        default=5,
        description="Maximum number of HTTP redirects to follow.",
        ge=0,
        le=30,
    )
    user_agent: str = Field(
        default="DBShield/0.1.0 (Database Vulnerability Assessment Framework)",
        description="Default HTTP User-Agent header string.",
        min_length=5,
    )

    # Logging Configuration
    log_level: str = Field(
        default="INFO",
        description="Logging severity level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )
    log_file: Path | None = Field(
        default=None,
        description="Optional file path to persist structured log records.",
    )

    # Storage and Workspace
    data_dir: Path = Field(
        default_factory=lambda: Path.home() / ".local" / "share" / "dbshield",
        description="Directory for local session caches, logs, and artifacts.",
    )

    # Scope Constraints
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="List of hostnames or domains explicitly authorized for scanning.",
    )
    allow_subdomains: bool = Field(
        default=False,
        description="Whether subdomains of allowed hosts are automatically in-scope.",
    )

    # Operational Limits
    rate_limit: float = Field(
        default=10.0,
        description="Maximum requests per second to target hosts.",
        gt=0.0,
        le=1000.0,
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = {"DEBUG", "INFO", "WARNING", "WARN", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid_levels:
            raise ValueError(f"Invalid log_level '{v}'. Must be one of {sorted(valid_levels)}.")
        return "WARNING" if upper == "WARN" else upper

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def clean_allowed_hosts(cls, hosts: list[str] | str) -> list[str]:
        if isinstance(hosts, str):
            stripped = hosts.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, list):
                        hosts = parsed
                except Exception:
                    pass
            if isinstance(hosts, str):
                hosts = [h.strip() for h in stripped.split(",") if h.strip()]
        cleaned: list[str] = []
        for h in hosts:
            stripped = str(h).strip().lower()
            # Strip scheme if accidentally provided in allowed_hosts (e.g. https://example.com)
            if "://" in stripped:
                stripped = stripped.split("://", 1)[1]
            # Strip path and port if present
            stripped = stripped.split("/", 1)[0].split(":", 1)[0]
            if stripped and stripped not in cleaned:
                cleaned.append(stripped)
        return cleaned

    def get_safe_dict(self) -> dict[str, Any]:
        """Return a dictionary of settings safe for display or logging without secrets."""
        return {
            "http_timeout": self.http_timeout,
            "max_redirects": self.max_redirects,
            "user_agent": self.user_agent,
            "log_level": self.log_level,
            "log_file": str(self.log_file) if self.log_file else None,
            "data_dir": str(self.data_dir),
            "allowed_hosts": self.allowed_hosts,
            "allow_subdomains": self.allow_subdomains,
            "rate_limit": self.rate_limit,
        }


def get_settings(env_file: Path | None = None, **overrides: Any) -> Settings:
    """Factory function to load and validate DBShield settings.

    Raises:
        ConfigurationError: If any configuration value fails validation.
    """
    try:
        if env_file:
            return Settings(_env_file=env_file, **overrides)  # type: ignore[call-arg]
        return Settings(**overrides)
    except Exception as exc:
        raise ConfigurationError(
            message=f"Failed to load or validate DBShield configuration: {exc}",
            cause=str(exc),
            remedy="Check your environment variables, .env file, or CLI flags against supported settings.",
        ) from exc
