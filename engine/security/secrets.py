from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from engine.model.errors import MissingSecret


@dataclass(slots=True)
class SecretsVault:
    env_prefix: str = "REDOS_"
    store: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for key, value in os.environ.items():
            if key.startswith(self.env_prefix):
                self.store[key[len(self.env_prefix) :].lower()] = value

    def get(self, ref: str, *, required: bool = False) -> str | None:
        if ref in self.store:
            return self.store[ref]
        env_key = self.env_prefix + ref
        value = os.environ.get(env_key)
        if value is not None:
            self.store[ref.lower()] = value
            return value
        if required:
            raise MissingSecret(f"secret not configured: {ref!r} (set {env_key})")
        return None

    def register(self, ref: str, value: str) -> None:
        self.store[ref.lower()] = value


_REDACTION_PATTERN = re.compile(r"(?i)(authorization|api[-_]?key|x-api-key|token|secret|password|database_url|redis_url|encryption_key|private_key|jwt|bearer|provider.*credential|db_.*pass|aws_|gcp_|azure_|openai_api_key|anthropic_api_key)\s*[:=]\s*[^\s,;\"']+")
_BEARER_PATTERN = re.compile(r"(?i)(bearer\s+)[a-z0-9._~+/=\-\\.]+")
_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
_GENERIC_SECRET_PATTERN = re.compile(r"(?i)(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{30,}|AKIA[0-9A-Z]{16})")


def redact_text(text: str, secret_values: tuple[str, ...] = ()) -> str:
    if not isinstance(text, str):
        return text
    text = _BEARER_PATTERN.sub(lambda m: m.group(1) + "***REDACTED***", text)
    text = _REDACTION_PATTERN.sub(lambda m: m.group(1) + "=***REDACTED***", text)
    text = _JWT_PATTERN.sub("***REDACTED_JWT***", text)
    text = _GENERIC_SECRET_PATTERN.sub("***REDACTED***", text)
    for secret in secret_values:
        if secret and secret in text:
            text = text.replace(secret, "***REDACTED***")
    return text


def redact_mapping(data: dict, secret_values: tuple[str, ...] = ()) -> dict:
    _SENSITIVE_KEYS = (
        "authorization", "api_key", "apikey", "x-api-key", "token", "secret", "password",
        "database_url", "database_credentials", "db_password", "redis_url", "redis_credentials",
        "encryption_key", "private_key", "jwt", "jwt_secret", "provider_credentials",
        "env", "environment", "credential", "aws_secret", "aws_access", "gcp_credentials",
        "azure_key", "openai_api_key", "anthropic_api_key", "model_output_secret",
    )

    def _redact_value(value, key) -> Any:
        if isinstance(value, str):
            if any(token in str(key).lower() for token in _SENSITIVE_KEYS):
                return "***REDACTED***"
            out = redact_text(value, secret_values)
            return out
        if isinstance(value, list):
            return [_redact_value(v, key) for v in value]
        if isinstance(value, dict):
            return {k: _redact_value(v, k) for k, v in value.items()}
        return value

    return {k: _redact_value(v, k) for k, v in data.items()}


def redact_any(data: Any, secret_values: tuple[str, ...] = ()) -> Any:
    """Redact any structure (dict, list, str) for logs, reports, API responses, errors, evidence."""
    if isinstance(data, str):
        return redact_text(data, secret_values)
    if isinstance(data, dict):
        return redact_mapping(data, secret_values)
    if isinstance(data, list):
        return [redact_any(v, secret_values) for v in data]
    return data


def sanitize_error_message(message: str, secret_values: tuple[str, ...] = ()) -> str:
    return redact_text(message, secret_values)


def sanitize_log_record(record: dict, secret_values: tuple[str, ...] = ()) -> dict:
    return redact_mapping(record, secret_values)


def sanitize_api_response(data: dict, secret_values: tuple[str, ...] = ()) -> dict:
    return redact_mapping(data, secret_values)


def sanitize_tool_arguments(args: dict, secret_values: tuple[str, ...] = ()) -> dict:
    return redact_mapping(args, secret_values)


def sanitize_model_output(output: str, secret_values: tuple[str, ...] = ()) -> str:
    return redact_text(output, secret_values)
