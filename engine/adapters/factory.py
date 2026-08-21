from __future__ import annotations

from engine.adapters.agent import AgentAdapter, RAGAdapter
from engine.adapters.base import TargetAdapter
from engine.adapters.custom import CustomHTTPAdapter
from engine.adapters.openai import AnthropicAdapter, LocalModelAdapter, OpenAICompatAdapter
from engine.model.attack import Provenance
from engine.model.errors import ConfigurationError
from engine.security.secrets import SecretsVault
from engine.targets.auth import AuthResolver
from engine.targets.config import RAGTargetConfig, TargetConfig


class FakeAdapter(TargetAdapter):
    provenance = Provenance.MOCK
    adapter_kind = "fake"

    def __init__(self, replies: list | None = None) -> None:
        self.replies = list(replies or [])
        self.requests: list[list] = []

    async def chat(
        self,
        messages: list,
        *,
        tools: list | None = None,
        timeout: float | None = None,
    ):
        self.requests.append(list(messages))
        if self.replies:
            return self.replies.pop(0)
        return None


def create_adapter(config: TargetConfig, vault: SecretsVault | None = None, headers: dict[str, str] | None = None) -> TargetAdapter:
    resolver = AuthResolver(vault or SecretsVault())
    resolved = dict(headers or {})
    resolved.update(resolver.resolve_headers(config))
    kind = config.kind.value
    if kind == "anthropic_compatible":
        return AnthropicAdapter(config, resolved)
    if kind == "local_model":
        return LocalModelAdapter(config, resolved)
    if kind == "custom_http":
        return CustomHTTPAdapter(config, resolved)
    if kind == "agent":
        return AgentAdapter(OpenAICompatAdapter(config, resolved), config.base_url, resolved)
    if kind == "rag":
        if not isinstance(config, RAGTargetConfig) or not config.retrieval_url:
            raise ConfigurationError(f"RAG target {config.target_id!r} requires retrieval_url")
        return RAGAdapter(OpenAICompatAdapter(config, resolved), config.retrieval_url, resolved)
    if kind == "openai_compatible":
        return OpenAICompatAdapter(config, resolved)
    raise ConfigurationError(f"unsupported target kind: {config.kind}")


__all__ = [
    "AgentAdapter",
    "AnthropicAdapter",
    "CustomHTTPAdapter",
    "FakeAdapter",
    "LocalModelAdapter",
    "OpenAICompatAdapter",
    "RAGAdapter",
    "TargetAdapter",
    "create_adapter",
]