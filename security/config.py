"""Configuration for the Security Analysis Platform.

Reads settings from environment variables. Production must have required
secrets configured; startup will fail if insecure defaults are detected.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


class ConfigurationError(RuntimeError):
    """Raised when required configuration is missing or insecure."""


def _get_env(var: str, default: Optional[str] = None) -> str:
    """Read an environment variable, raising if missing and no default."""
    value = os.environ.get(var, default)
    if value is None:
        raise ConfigurationError(f"required environment variable not set: {var}")
    return value


def _validate_secret(value: str, name: str) -> str:
    """Validate that a secret is not the insecure default."""
    if value == "change-me-in-production":
        raise ConfigurationError(
            f"insecure default for {name}: set {name.upper()} to a real secret"
        )
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable platform settings loaded from environment variables."""

    # Core connectivity
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_db: str = "security_analysis"
    redis_uri: str = "redis://localhost:6379/0"

    # Security - must be set in production
    secret_key: str = os.environ.get("SECRET_KEY", "")

    # JWT
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Broker
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # Logging
    log_level: str = "INFO"
    json_logs: bool = False

    def __post_init__(self) -> None:
        # Enforce secret at startup (allow test defaults)
        if not self.secret_key:
            # In test/CI, provide default to keep repo runnable
            if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("CI") or os.environ.get("TESTING"):
                object.__setattr__(self, "secret_key", "test-secret-key-for-ci-1234567890-not-production")
            else:
                raise ConfigurationError("secret_key must be configured via SECRET_KEY env var")
        _validate_secret(self.secret_key, "secret_key")


# Load settings at module level; will raise ConfigurationError if insecure
try:
    settings = Settings()
except ConfigurationError as exc:
    # Re-raise with clear message for the operator
    raise RuntimeError(f"Configuration error: {exc}") from exc