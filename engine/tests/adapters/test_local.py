from __future__ import annotations

from engine.adapters.factory import create_adapter
from engine.adapters.openai import LocalModelAdapter
from engine.model.attack import Message, TargetKind
from engine.targets.config import TargetConfig


def local_target(chat_server) -> TargetConfig:
    return TargetConfig(
        target_id="local-model",
        kind=TargetKind.LOCAL_MODEL,
        base_url=chat_server,
        model="test-model",
        extra={"tool_invoke_url": chat_server},
    )


async def test_factory_returns_local_adapter(chat_server, vault):
    adapter = create_adapter(local_target(chat_server), vault)
    try:
        assert isinstance(adapter, LocalModelAdapter)
        assert adapter.provenance.value == "live"
    finally:
        await adapter.aclose()


async def test_local_adapter_chat(chat_server, vault):
    adapter = create_adapter(local_target(chat_server), vault)
    try:
        reply = await adapter.chat([Message(role="user", content="what is SESAME?")])
        assert "SESAME" in reply.content
    finally:
        await adapter.aclose()


async def test_local_adapter_tool_execution(chat_server, vault):
    adapter = create_adapter(local_target(chat_server), vault)
    try:
        reply = await adapter.chat([Message(role="user", content="please run whoami")])
        assert reply.tool_calls
        result = await adapter.execute_tool(reply.tool_calls[0])
        assert result["ok"] is True
    finally:
        await adapter.aclose()