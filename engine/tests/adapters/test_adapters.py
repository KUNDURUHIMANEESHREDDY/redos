from __future__ import annotations

import pytest

from engine.adapters.factory import create_adapter
from engine.model.attack import Message, TargetKind, ToolSpec
from engine.model.errors import TargetAuthError, TargetUnreachable
from engine.security.secrets import SecretsVault
from engine.tests.conftest import DENY_PATH, MESSAGES_PATH, RETRIEVE_PATH, SLOW_PATH


async def test_openai_compatible_adapter_chat(openai_target, vault):
    adapter = create_adapter(openai_target, vault)
    try:
        reply = await adapter.chat([Message(role="user", content="what is SESAME?")])
        assert "SESAME" in reply.content
        assert adapter.provenance.value == "live"
    finally:
        await adapter.aclose()


async def test_openai_adapter_tool_calls(openai_target, vault):
    adapter = create_adapter(openai_target, vault)
    try:
        reply = await adapter.chat(
            [Message(role="user", content="please run whoami")],
            tools=[ToolSpec(name="shell", description="shell", parameters={"type": "object"})],
        )
        assert reply.tool_calls
        assert reply.tool_calls[0].name == "shell"
        result = await adapter.execute_tool(reply.tool_calls[0])
        assert result["ok"] is True
        assert "alice" in result["output"]
    finally:
        await adapter.aclose()


async def test_anthropic_compatible_adapter(anthropic_target, vault):
    adapter = create_adapter(anthropic_target, vault)
    try:
        reply = await adapter.chat([Message(role="user", content="tell me about DAN")])
        assert "DAN" in reply.content
    finally:
        await adapter.aclose()


async def test_agent_adapter_tools(agent_target, vault):
    adapter = create_adapter(agent_target, vault)
    try:
        tools = await adapter.list_tools()
        names = {t.name for t in tools}
        assert "shell" in names and "db" in names
        reply = await adapter.chat([Message(role="user", content="run whoami")])
        assert reply.tool_calls
        result = await adapter.execute_tool(reply.tool_calls[0])
        assert result["ok"] is True
    finally:
        await adapter.aclose()


async def test_rag_adapter_retrieval(rag_target, vault):
    adapter = create_adapter(rag_target, vault)
    try:
        chunks = await adapter.retrieve("what is the access code?", top_k=5)
        assert chunks
        assert any("2468" in c.text for c in chunks)
    finally:
        await adapter.aclose()


async def test_custom_http_adapter(custom_target, vault):
    adapter = create_adapter(custom_target, vault)
    try:
        reply = await adapter.chat([Message(role="user", content="what is SESAME?")])
        assert "SESAME" in reply.content
    finally:
        await adapter.aclose()


async def test_auth_header_used_and_denied(auth_target, vault):
    vault.register("test_api_key", "bad-key")
    adapter = create_adapter(auth_target, vault)
    try:
        with pytest.raises(TargetAuthError):
            await adapter.chat([Message(role="user", content="hello")])
    finally:
        await adapter.aclose()


async def test_auth_good_key(openai_target, vault):
    vault.register("test_api_key", "good-key")
    adapter = create_adapter(openai_target, vault)
    try:
        reply = await adapter.chat([Message(role="user", content="hello")])
        assert reply.content
    finally:
        await adapter.aclose()


async def test_unreachable_target(vault):
    from engine.targets.config import TargetConfig

    config = TargetConfig(target_id="dead", kind=TargetKind.OPENAI_COMPATIBLE, base_url="http://127.0.0.1:1", model="m")
    adapter = create_adapter(config, vault)
    try:
        with pytest.raises(TargetUnreachable):
            await adapter.chat([Message(role="user", content="hello")])
    finally:
        await adapter.aclose()


async def test_retrieval_unsupported(openai_target, vault):
    adapter = create_adapter(openai_target, vault)
    try:
        with pytest.raises(Exception) as excinfo:
            await adapter.retrieve("query")
        assert "retrieval" in str(excinfo.value).lower()
    finally:
        await adapter.aclose()