from __future__ import annotations

import pytest

from engine.model.attack import TargetKind
from engine.targets import RAGTargetConfig, TargetConfig

from .emulators import (
    AgentToolsHandler,
    AnthropicHandler,
    AuthHandler,
    CustomProtocolHandler,
    FlakyHandler,
    MalformedMissingChoicesHandler,
    MalformedNonJsonHandler,
    MalformedWrongTypeHandler,
    OllamaHandler,
    OpenAIBareHandler,
    RagVariantHandler,
    StrictNoToolsHandler,
    TimeoutHandler,
    shutdown,
    serve,
)


@pytest.fixture(scope="session")
def emulators():
    servers = {}
    urls = {}
    try:
        for name, handler in {
            "openai_bare": OpenAIBareHandler,
            "agent_tools": AgentToolsHandler,
            "anthropic": AnthropicHandler,
            "ollama": OllamaHandler,
            "custom": CustomProtocolHandler,
            "rag_variant": RagVariantHandler,
            "strict_no_tools": StrictNoToolsHandler,
            "auth": AuthHandler,
            "timeout": TimeoutHandler,
            "malformed_non_json": MalformedNonJsonHandler,
            "malformed_missing_choices": MalformedMissingChoicesHandler,
            "malformed_wrong_type": MalformedWrongTypeHandler,
            "flaky": FlakyHandler,
        }.items():
            urls[name], servers[name] = serve(handler)
        yield urls
    finally:
        for server in servers.values():
            shutdown(server)


def openai_bare(emulators) -> TargetConfig:
    return TargetConfig(target_id="val-bare", kind=TargetKind.OPENAI_COMPATIBLE, base_url=emulators["openai_bare"], model="m")


def agent_tools(emulators) -> TargetConfig:
    return TargetConfig(
        target_id="val-agent",
        kind=TargetKind.AGENT,
        base_url=emulators["agent_tools"],
        model="m",
        extra={"tool_invoke_url": emulators["agent_tools"]},
    )


def anthropic(emulators) -> TargetConfig:
    return TargetConfig(target_id="val-anthropic", kind=TargetKind.ANTHROPIC_COMPATIBLE, base_url=emulators["anthropic"], model="m")


def ollama(emulators) -> TargetConfig:
    return TargetConfig(target_id="val-ollama", kind=TargetKind.LOCAL_MODEL, base_url=f"{emulators['ollama']}/v1", model="llama3")


def custom_http(emulators) -> TargetConfig:
    return TargetConfig(
        target_id="val-custom",
        kind=TargetKind.CUSTOM_HTTP,
        base_url=emulators["custom"],
        model="m",
        extra={
            "request_path": "/api/infer",
            "body_template": {"prompt": "{messages}"},
            "response_text_path": "reply.text",
        },
    )


def rag_variant(emulators) -> RAGTargetConfig:
    return RAGTargetConfig(
        target_id="val-rag",
        kind=TargetKind.RAG,
        base_url=emulators["rag_variant"],
        model="m",
        retrieval_url=f"{emulators['rag_variant']}/retrieve",
    )


def auth_target(emulators) -> TargetConfig:
    return TargetConfig(
        target_id="val-auth",
        kind=TargetKind.OPENAI_COMPATIBLE,
        base_url=emulators["auth"],
        model="m",
        api_key_ref="val_api_key",
    )


def strict_no_tools(emulators) -> TargetConfig:
    return TargetConfig(
        target_id="val-strict",
        kind=TargetKind.AGENT,
        base_url=emulators["strict_no_tools"],
        model="m",
        extra={"tool_invoke_url": emulators["strict_no_tools"]},
    )