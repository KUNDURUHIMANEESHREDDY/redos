from __future__ import annotations

import pytest

from engine.model.attack import AttackPolicy, AttackType, TargetKind
from engine.model.errors import ConfigurationError, UnsupportedOperation
from engine.orchestration import AttackOrchestrator
from engine.reconnaissance import ReconnaissanceRunner
from engine.targets import RAGTargetConfig, TargetConfig, TargetRegistry

from .conftest import openai_bare


def definition(config, plugin, **params) -> AttackDefinition:
    from engine.model.plan import AttackDefinition

    return AttackDefinition(
        attack_id=f"unsup-{plugin}",
        name=plugin,
        attack_type=AttackType.CUSTOM,
        plugin=plugin,
        params=params,
        target=config,
        policy=AttackPolicy(),
    )


def test_mcp_target_kind_not_supported_fails_cleanly():
    with pytest.raises(ValueError):
        TargetKind("mcp")
    with pytest.raises(ValueError):
        TargetKind("multi_agent")


def test_rag_target_without_retrieval_url_fails_cleanly(emulators):
    config = RAGTargetConfig(target_id="val-norag", kind=TargetKind.RAG, base_url=emulators["openai_bare"], model="m")
    with pytest.raises(ConfigurationError):
        from engine.adapters.factory import create_adapter

        create_adapter(config, None)


def test_registry_unknown_target_is_clean_error(emulators):
    registry = TargetRegistry()
    with pytest.raises(ConfigurationError):
        registry.get("does-not-exist")


async def test_tool_listing_unsupported_is_honest(emulators, vault):
    config = openai_bare(emulators)
    events = []
    profile = await ReconnaissanceRunner(vault=vault, listener=lambda e: events.append(e)).run(config)
    failed = [e for e in events if e["probe"] == "list_tools" and e["ok"] is False]
    assert failed, "recon must report the unsupported tool listing honestly"
    assert profile.tools == []
    assert profile.tool_capability is False


async def test_retrieval_unsupported_is_honest(emulators, vault):
    config = openai_bare(emulators)
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(config, "rag_poisoning.plant"))
    assert result.outcome.value == "indeterminate"
    assert any(e.type == "error" for e in result.execution.events)


async def test_plugin_requires_capability_not_satisfied_is_never_selected(emulators, vault):
    from engine.attack_surface import AttackSurface
    from engine.chaining import DependencyGraph
    from engine.hypotheses import AttackHypothesis, HypothesisGenerator

    surface = await _discover(openai_bare(emulators), vault)
    graph = DependencyGraph()
    assert not graph.satisfied("unsafe_tool_call.shell", surface)
    assert not graph.satisfied("rag_poisoning.plant", surface)
    assert graph.satisfied("prompt_injection.ignore_previous", surface)


async def test_tool_attack_against_unsupported_execution_is_indeterminate(emulators, vault):
    from engine.adapters.factory import create_adapter
    from engine.model.attack import ToolCall

    config = TargetConfig(
        target_id="val-noexec",
        kind=TargetKind.ANTHROPIC_COMPATIBLE,
        base_url=emulators["anthropic"],
        model="m",
    )
    adapter = create_adapter(config, vault)
    try:
        with pytest.raises(UnsupportedOperation):
            await adapter.execute_tool(ToolCall(call_id="c1", name="shell", arguments="{}"))
    finally:
        await adapter.aclose()


async def _discover(config, vault):
    from engine.discovery import AttackSurfaceDiscovery

    return await AttackSurfaceDiscovery(vault=vault).discover(config)