from __future__ import annotations

from datetime import datetime, timezone

import pytest

from engine.attacks.base import AttackPlugin
from engine.attacks.registry import PluginRegistry, attack_plugin, discover_plugins
from engine.model.attack import AttackOutcome, AttackType, Message, Payload
from engine.model.errors import PluginError
from engine.model.execution import ObservedExecution


def test_all_plugins_registered():
    from engine.attacks import PLUGIN_REGISTRY

    keys = PLUGIN_REGISTRY.keys()
    expected = {
        "prompt_injection.ignore_previous",
        "prompt_injection.indirect",
        "jailbreak.role_play",
        "jailbreak.developer_mode",
        "jailbreak.base64_obfuscation",
        "data_leakage.probe",
        "data_leakage.pii",
        "tool_abuse.overload",
        "tool_abuse.negation",
        "malicious_document.inline",
        "malicious_document.url",
        "rag_poisoning.plant",
        "rag_poisoning.rank_boost",
        "agent_escalation.system_override",
        "agent_escalation.tool_privilege",
        "permission.reask",
        "permission.sudo",
        "unsafe_tool_call.shell",
        "unsafe_tool_call.sql",
        "model_manipulation.token_smuggling",
        "model_manipulation.repetition_bias",
        "model_manipulation.format_confusion",
    }
    assert expected <= set(keys)


def test_every_plugin_builds_payload():
    from engine.attacks import PLUGIN_REGISTRY

    for plugin in PLUGIN_REGISTRY.all():
        payload = plugin.build_payload(plugin.default_params())
        assert isinstance(payload, Payload)
        assert payload.messages


def test_plugin_can_be_added_without_orchestrator_change():
    from engine.attacks import PLUGIN_REGISTRY

    @attack_plugin
    class CustomProbePlugin(AttackPlugin):
        key = "custom.probe"
        attack_type = AttackType.CUSTOM.value

        def build_payload(self, params):
            return Payload(messages=(Message(role="user", content="custom probe"),), indicators=("x",))

    try:
        assert PLUGIN_REGISTRY.get("custom.probe") is not None
        payload = PLUGIN_REGISTRY.get("custom.probe").build_payload({})
        assert "custom probe" in payload.messages[0].content
    finally:
        PLUGIN_REGISTRY._plugins.pop("custom.probe", None)


def test_duplicate_plugin_key_rejected():
    from engine.attacks import PLUGIN_REGISTRY

    registry = PluginRegistry()
    registry.register(PLUGIN_REGISTRY.get("data_leakage.probe"))
    with pytest.raises(PluginError):
        registry.register(PLUGIN_REGISTRY.get("data_leakage.probe"))


def test_discovery_scans_package():
    registry = PluginRegistry()
    discover_plugins(registry=registry)
    assert "jailbreak.role_play" in registry.keys()


async def test_every_plugin_executes_against_real_target(openai_target, rag_target, vault):
    from engine.attacks import PLUGIN_REGISTRY
    from engine.model.plan import AttackDefinition
    from engine.orchestration.orchestrator import AttackOrchestrator

    orch = AttackOrchestrator(vault=vault)
    for plugin in PLUGIN_REGISTRY.all():
        target = rag_target if plugin.attack_type == AttackType.RAG_POISONING.value else openai_target
        definition = AttackDefinition(
            attack_id=f"a-{plugin.key}",
            name=plugin.key,
            attack_type=AttackType(plugin.attack_type),
            plugin=plugin.key,
            params=plugin.default_params(),
            target=target,
        )
        result = await orch.execute(definition)
        assert result.execution.status in ("success", "failure", "indeterminate", "timed_out", "cancelled")
        assert result.execution.events
        assert result.execution.execution_id
        assert result.outcome in (AttackOutcome.SUCCESS, AttackOutcome.FAILURE, AttackOutcome.INDETERMINATE)


def test_default_evaluate_needs_outputs():
    from engine.attacks import PLUGIN_REGISTRY
    from engine.execution.context import AttackContext
    from engine.execution.timeouts import AttackClock, TurnBudget
    from engine.model.plan import AttackDefinition

    plugin = PLUGIN_REGISTRY.get("data_leakage.probe")
    execution = ObservedExecution(
        execution_id="e",
        target_id="t",
        attack_id="a",
        plan_id="p",
        started_at=datetime.now(timezone.utc),
    )
    context = AttackContext(
        execution_id="e",
        adapter=object(),
        enforcer=object(),
        execution=execution,
        clock=AttackClock(deadline=1e18),
        turns=TurnBudget(max=1),
    )
    definition = AttackDefinition(
        attack_id="a",
        name="x",
        attack_type=AttackType.DATA_LEAKAGE,
        plugin=plugin.key,
        params={},
        target=object(),
    )
    observation = plugin.evaluate(definition, context)
    assert observation.outcome == AttackOutcome.INDETERMINATE