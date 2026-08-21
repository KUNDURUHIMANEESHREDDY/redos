from __future__ import annotations

import pytest

from engine.model.attack import TargetKind
from engine.model.errors import SSRFBlocked
from engine.reconnaissance import ReconnaissanceRunner, TargetProfile, profile_from_dict
from engine.targets import TargetConfig


async def test_recon_agent_target_discovers_tools(agent_target, vault):
    profile = await ReconnaissanceRunner(vault=vault).run(agent_target)
    assert profile.tool_capability is True
    assert "shell" in profile.tool_names
    assert "db" in profile.tool_names
    assert profile.chat_observed is True
    assert profile.chat_sample
    assert profile.adapter_kind == "agent"


async def test_recon_rag_target_confirms_retrieval(rag_target, vault):
    profile = await ReconnaissanceRunner(vault=vault).run(rag_target)
    assert profile.retrieval_supported is True
    assert profile.retrieval_sample


async def test_recon_bare_openai_target_no_capabilities(chat_server, vault):
    target = TargetConfig(target_id="bare", kind=TargetKind.OPENAI_COMPATIBLE, base_url=chat_server, model="m")
    profile = await ReconnaissanceRunner(vault=vault).run(target)
    assert profile.tool_capability is False
    assert profile.retrieval_supported is False
    assert profile.chat_observed is True


async def test_recon_respects_ssrf(chat_server, vault):
    target = TargetConfig(target_id="evil", kind=TargetKind.OPENAI_COMPATIBLE, base_url="http://169.254.169.254/", model="m")
    with pytest.raises(SSRFBlocked):
        await ReconnaissanceRunner(vault=vault).run(target)


async def test_recon_records_probe_events(agent_target, vault):
    events = []
    await ReconnaissanceRunner(vault=vault, listener=events.append).run(agent_target)
    actions = [e["probe"] for e in events]
    assert "list_tools" in actions
    assert "chat" in actions


def test_profile_serialization_roundtrip(agent_target, vault):
    import asyncio

    profile = asyncio.run(ReconnaissanceRunner(vault=vault).run(agent_target))
    restored = profile_from_dict(profile.to_dict())
    assert restored.target_id == profile.target_id
    assert restored.tool_names == profile.tool_names
    assert restored.retrieval_supported == profile.retrieval_supported
    assert restored.chat_sample == profile.chat_sample