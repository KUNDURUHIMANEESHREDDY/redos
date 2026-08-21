from __future__ import annotations

import pytest

from engine.adaptive import AttackObservationRecord
from engine.attack_surface import AttackSurface
from engine.discovery import AttackSurfaceDiscovery
from engine.model.attack import TargetKind
from engine.model.errors import SSRFBlocked
from engine.targets import RAGTargetConfig, TargetConfig


async def test_discovery_derives_tools_and_parameters(agent_target, vault):
    surface = await AttackSurfaceDiscovery(vault=vault).discover(agent_target)
    assert surface.tool_capability is True
    assert "shell" in surface.tool_names
    assert surface.tool_parameters["shell"]["properties"]["command"]["type"] == "string"
    assert surface.agent_delegation is True
    assert surface.fact("tool") is not None
    assert surface.fact("tool_parameters") is not None


async def test_discovery_derives_rag_sources(rag_target, vault):
    surface = await AttackSurfaceDiscovery(vault=vault).discover(rag_target)
    assert surface.retrieval_supported is True
    assert surface.rag_sources == [rag_target.retrieval_url]
    assert surface.retrieval_sample
    assert surface.fact("rag_source") is not None


async def test_discovery_derives_authentication_boundary_from_config(chat_server, vault):
    vault.register("test_api_key", "test-key-value")
    target = TargetConfig(target_id="auth", kind=TargetKind.OPENAI_COMPATIBLE, base_url=chat_server, model="m", api_key_ref="test_api_key")
    surface = await AttackSurfaceDiscovery(vault=vault).discover(target)
    assert surface.authentication["boundary"] is None
    assert surface.authentication["configured"] is True
    fact = surface.fact("authentication")
    assert fact is not None
    assert "credential configured" in fact.value["observed"]


async def test_discovery_honest_unknowns_on_bare_target(chat_server, vault):
    target = TargetConfig(target_id="bare", kind=TargetKind.OPENAI_COMPATIBLE, base_url=chat_server, model="m")
    surface = await AttackSurfaceDiscovery(vault=vault).discover(target)
    assert surface.tool_capability is False
    assert surface.retrieval_supported is False
    assert surface.document_ingestion in (None, False)
    assert surface.memory in (None, False)
    assert surface.authentication["boundary"] is None
    assert surface.authentication["configured"] is False
    assert surface.fact("agent_delegation") is not None
    assert surface.fact("agent_delegation").value is None
    assert surface.agent_delegation is False


async def test_discovery_probes_delegation_behaviorally(agent_target, vault):
    surface = await AttackSurfaceDiscovery(vault=vault).discover(agent_target)
    assert surface.agent_delegation is True
    fact = surface.fact("agent_delegation")
    assert fact is not None
    assert "delegation_probe" in fact.evidence_refs


async def test_discovery_respects_ssrf(chat_server, vault):
    target = TargetConfig(target_id="evil", kind=TargetKind.OPENAI_COMPATIBLE, base_url="http://169.254.169.254/", model="m")
    with pytest.raises(SSRFBlocked):
        await AttackSurfaceDiscovery(vault=vault).discover(target)


async def test_discovery_emits_probe_events(agent_target, vault):
    events = []
    await AttackSurfaceDiscovery(vault=vault, listener=events.append).discover(agent_target)
    categories = [e["probe"] for e in events]
    assert "list_tools" in categories
    assert "chat" in categories
    assert "document_ingestion" in categories
    assert "memory" in categories
    assert "authentication" in categories


def test_surface_serialization_roundtrip():
    surface = AttackSurface(target_id="t", adapter_kind="agent", model="m", tool_capability=True, retrieval_supported=True, chat_observed=True)
    surface.rag_sources = ["http://x/retrieve"]
    surface.retrieval_sample = ["frag"]
    surface.permissions = {"shell": True}
    restored = AttackSurface.from_dict(surface.to_dict())
    assert restored.tool_capability is True
    assert restored.rag_sources == ["http://x/retrieve"]
    assert restored.retrieval_sample == ["frag"]
    assert restored.permissions == {"shell": True}


async def test_enrich_records_tool_execution_evidence(rag_target, vault):
    discovery = AttackSurfaceDiscovery(vault=vault)
    surface = await discovery.discover(rag_target)
    observations = {
        "unsafe_tool_call.shell": AttackObservationRecord("unsafe_tool_call.shell", "unsafe_tool_call", "failure", "no match", [], 1, 0, 1)
    }
    surface = await discovery.enrich(surface, observations)
    assert "unsafe_tool_call" in surface.permissions
    fact = surface.fact("permission")
    assert fact is not None
    assert "tool execution observed" in fact.observation