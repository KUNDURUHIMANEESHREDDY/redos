from __future__ import annotations

import asyncio

from engine.model.attack import AttackPolicy, AttackType
from engine.model.execution import ExecutionStatus
from engine.model.plan import AttackDefinition
from engine.orchestration.orchestrator import AttackOrchestrator


def definition(target, plugin, policy=None, **params) -> AttackDefinition:
    return AttackDefinition(
        attack_id=f"res-{plugin}",
        name=plugin,
        attack_type=AttackType.CUSTOM,
        plugin=plugin,
        params=params,
        target=target,
        policy=policy or AttackPolicy(),
    )


async def test_turn_budget_prevents_resource_exhaustion(openai_target, vault, register_probe_plugins):
    policy = AttackPolicy(max_turns=2, overall_timeout_s=60)
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "probe.turn_budget", policy=policy))
    assert result.execution.status == ExecutionStatus.TIMED_OUT
    model_interactions = result.execution.model_interactions
    assert len(model_interactions) <= 2


async def test_artifact_budget_capped(openai_target, vault, register_probe_plugins):
    policy = AttackPolicy(max_artifacts=10)
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "probe.artifact_flood", policy=policy))
    assert result.execution.status.is_final()
    assert len(result.execution.artifacts) == 10
    audits = [e for e in result.execution.events if e.type == "audit"]
    assert any("artifact_limit" in str(a.data.get("action", "")) for a in audits)


async def test_artifact_events_have_digests(openai_target, vault, register_probe_plugins):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "probe.artifact_flood"))
    assert result.execution.artifacts
    for artifact in result.execution.artifacts:
        assert artifact.data.get("artifact_id")
        assert artifact.data.get("digest")


async def test_retry_recovers_from_flaky_target(flaky_target, vault, flaky_failures):
    policy = AttackPolicy(max_retries=2, retry_backoff_s=0.01, per_turn_timeout_s=5)
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(flaky_target, "data_leakage.probe", policy=policy))
    assert result.execution.status in (ExecutionStatus.SUCCESS, ExecutionStatus.FAILURE)
    audits = [e for e in result.execution.events if e.type == "audit"]
    retries = [a for a in audits if a.data.get("action") == "execution.retry"]
    assert len(retries) >= 1


async def test_no_retry_when_disabled(flaky_target, vault, flaky_failures):
    policy = AttackPolicy(max_retries=0)
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(flaky_target, "data_leakage.probe", policy=policy))
    assert result.execution.status == ExecutionStatus.INDETERMINATE
    error_events = [e for e in result.execution.events if e.type == "error"]
    assert error_events
    assert error_events[0].data["code"] == "TARGET_PROTOCOL_ERROR"


async def test_concurrent_attacks_respect_policy(openai_target, vault):
    from engine.sandbox import Sandbox

    sandbox = Sandbox(max_concurrency=2)
    orch = AttackOrchestrator(vault=vault, sandbox=sandbox)
    results = await asyncio.gather(*[orch.execute(definition(openai_target, "data_leakage.probe")) for _ in range(4)])
    assert len(results) == 4
    for result in results:
        assert result.execution.status.is_final()