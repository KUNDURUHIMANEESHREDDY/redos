from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from engine.model.attack import AttackOutcome, AttackPolicy, AttackType, TargetKind
from engine.model.execution import ExecutionStatus, ObservedExecution
from engine.model.plan import AttackDefinition
from engine.orchestration.orchestrator import AttackOrchestrator
from engine.targets.config import TargetConfig


def definition(target, plugin, policy=None, **params) -> AttackDefinition:
    return AttackDefinition(
        attack_id=f"life-{plugin}",
        name=plugin,
        attack_type=AttackType.CUSTOM,
        plugin=plugin,
        params=params,
        target=target,
        policy=policy or AttackPolicy(),
    )


def slow_target(openai_target) -> TargetConfig:
    return TargetConfig(
        target_id="slow-life",
        kind=TargetKind.CUSTOM_HTTP,
        base_url=openai_target.base_url,
        model="m",
        extra={
            "request_path": "/slow",
            "body_template": {"messages": "{messages}"},
            "response_text_path": "choices.0.message.content",
        },
    )


def test_pending_is_default_state():
    obs = ObservedExecution(
        execution_id="e",
        target_id="t",
        attack_id="a",
        plan_id="p",
        started_at=datetime.now(timezone.utc),
    )
    assert obs.status == ExecutionStatus.PENDING
    assert obs.to_dict()["status"] == "pending"
    assert not obs.status.is_final()


async def test_running_observed_mid_flight(openai_target, vault, register_probe_plugins):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "probe.lifecycle"))
    probes = [e for e in result.execution.events if e.type == "probe_status"]
    assert probes
    assert probes[0].data["status"] == "running"
    assert result.execution.status.is_final()


async def test_success_state(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "malicious_document.inline"))
    assert result.execution.status == ExecutionStatus.SUCCESS
    assert result.outcome == AttackOutcome.SUCCESS


async def test_failure_state(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "data_leakage.pii"))
    assert result.execution.status == ExecutionStatus.FAILURE
    assert result.outcome == AttackOutcome.FAILURE


async def test_per_turn_timeout_state(openai_target, vault):
    policy = AttackPolicy(per_turn_timeout_s=0.2, overall_timeout_s=30)
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(slow_target(openai_target), "data_leakage.pii", policy=policy))
    assert result.execution.status == ExecutionStatus.TIMED_OUT
    assert any(e.type == "timeout" for e in result.execution.events)


async def test_global_timeout_state(openai_target, vault, register_probe_plugins):
    policy = AttackPolicy(overall_timeout_s=0.3, per_turn_timeout_s=60)
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "probe.stall", policy=policy))
    assert result.execution.status == ExecutionStatus.TIMED_OUT
    assert any(e.type == "timeout" for e in result.execution.events)


async def test_turn_budget_exhaustion_is_timed_out(openai_target, vault, register_probe_plugins):
    policy = AttackPolicy(max_turns=3, overall_timeout_s=60)
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "probe.turn_budget", policy=policy))
    assert result.execution.status == ExecutionStatus.TIMED_OUT
    timeout_events = [e for e in result.execution.events if e.type == "timeout"]
    assert timeout_events
    assert "turn budget" in str(timeout_events[0].data.get("reason", ""))


async def test_cancelled_state(openai_target, vault):
    cancel_event = asyncio.Event()
    policy = AttackPolicy(overall_timeout_s=60, per_turn_timeout_s=30)
    orch = AttackOrchestrator(vault=vault)

    async def cancel_later():
        await asyncio.sleep(0.05)
        cancel_event.set()

    task = asyncio.create_task(cancel_later())
    result = await orch.execute(
        definition(slow_target(openai_target), "data_leakage.pii", policy=policy),
        cancel_event=cancel_event,
    )
    await task
    assert result.execution.status == ExecutionStatus.CANCELLED
    assert any(e.type == "cancellation" for e in result.execution.events)


async def test_indeterminate_on_unreachable_target(vault):
    dead = TargetConfig(target_id="dead", kind=TargetKind.OPENAI_COMPATIBLE, base_url="http://127.0.0.1:1", model="m")
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(dead, "data_leakage.pii"))
    assert result.execution.status == ExecutionStatus.INDETERMINATE
    assert any(e.type == "error" for e in result.execution.events)


async def test_indeterminate_on_unexpected_error(openai_target, vault, register_probe_plugins):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "probe.error"))
    assert result.execution.status == ExecutionStatus.INDETERMINATE
    error_events = [e for e in result.execution.events if e.type == "error"]
    assert error_events
    assert error_events[0].data["code"] == "UNEXPECTED"


async def test_finished_event_records_state_and_outcome(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "data_leakage.pii"))
    finished = [e for e in result.execution.events if e.type == "execution_finished"]
    assert finished
    assert finished[0].data["status"] == "failure"
    assert finished[0].data["outcome"] == "failure"