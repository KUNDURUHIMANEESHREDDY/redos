from __future__ import annotations

from engine.security.secrets import SecretsVault
from engine.targets.config import TargetConfig


class AuthResolver:
    def __init__(self, vault: SecretsVault | None = None) -> None:
        self.vault = vault or SecretsVault()

    def resolve_headers(self, config: TargetConfig) -> dict[str, str]:
        headers = dict(config.headers)
        if config.api_key_ref:
            key = self.vault.get(config.api_key_ref, required=True)
            if config.kind.value == "anthropic_compatible":
                headers.setdefault("x-api-key", key)
                headers.setdefault("anthropic-version", "2023-06-01")
            else:
                headers.setdefault("Authorization", f"Bearer {key}")
        return headers

    def resolved_secret_values(self, config: TargetConfig) -> tuple[str, ...]:
        if not config.api_key_ref:
            return ()
        key = self.vault.get(config.api_key_ref)
        return (key,) if key else ()