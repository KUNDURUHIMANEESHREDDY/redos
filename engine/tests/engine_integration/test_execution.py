from __future__ import annotations

import asyncio

import pytest

from engine.adapters.factory import create_adapter, FakeAdapter
from engine.execution.executor import AttackExecutor, ExecutionEnvironment
from engine.model.attack import AttackOutcome, AttackPolicy, AttackType, CapturePolicy, TargetKind
from engine.model.errors import AttackTimeout, PluginError
from engine.model.execution import ExecutionStatus
from engine.model.plan import AttackDefinition
from engine.orchestration.orchestrator import AttackOrchestrator
from engine.targets.config import TargetConfig


def make_definition(target, plugin: str, policy=None, **params) -> AttackDefinition:
    return AttackDefinition(
        attack_id="att-1",
        name="exec test",
        attack_type=AttackType.PROMPT_INJECTION,
        plugin=plugin,
        params=params,
        target=target,
        policy=policy or AttackPolicy(),
    )


async def test_execution_ids_unique(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    d1 = make_definition(openai_target, "prompt_injection.ignore_previous")
    d2 = make_definition(openai_target, "prompt_injection.ignore_previous")
    r1 = await orch.execute(d1)
    r2 = await orch.execute(d2)
    assert r1.execution.execution_id != r2.execution.execution_id
    assert r1.execution.execution_id and r2.execution.execution_id


async def test_successful_attack_produces_success_outcome(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(make_definition(openai_target, "malicious_document.inline"))
    assert result.execution.status == ExecutionStatus.SUCCESS
    assert result.outcome == AttackOutcome.SUCCESS
    assert result.observation is not None
    assert result.observation.evidence_event_ids


async def test_failed_attack_distinguishable_from_success(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    success = await orch.execute(make_definition(openai_target, "malicious_document.inline"))
    failure = await orch.execute(make_definition(openai_target, "data_leakage.pii"))
    assert success.outcome == AttackOutcome.SUCCESS
    assert failure.outcome == AttackOutcome.FAILURE
    assert failure.execution.status == ExecutionStatus.FAILURE


async def test_evidence_events_recorded(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(make_definition(openai_target, "prompt_injection.ignore_previous"))
    types = {e.type for e in result.execution.events}
    assert "execution_started" in types
    assert "model_request" in types
    assert "model_response" in types
    assert "model_interaction" in types
    assert "attack_payload" in types
    assert "attack_result" in types
    assert "execution_finished" in types
    assert result.validation.valid, result.validation.violations


async def test_tool_calls_captured(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(make_definition(openai_target, "unsafe_tool_call.shell", command="whoami"))
    tool_calls = result.execution.tool_calls
    assert tool_calls
    assert tool_calls[0]["name"] == "shell"
    tool_results = [e for e in result.execution.events if e.type == "tool_result"]
    assert tool_results
    assert any("alice" in str(e.data.get("output", "")) for e in tool_results)


async def test_retrieved_documents_captured(rag_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(make_definition(rag_target, "rag_poisoning.plant"))
    retrieval = result.execution.retrieval_events
    assert retrieval
    assert any("2468" in str(c.get("text", "")) for c in retrieval[0]["chunks"])
    assert result.outcome == AttackOutcome.SUCCESS


async def test_capture_policy_blocks_inputs(openai_target, vault):
    policy = AttackPolicy(capture=CapturePolicy.minimal())
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(make_definition(openai_target, "data_leakage.probe", policy=policy))
    for event in result.execution.events:
        if event.type == "model_request":
            assert "messages" not in event.data


async def test_capture_policy_full_includes_inputs(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(make_definition(openai_target, "data_leakage.probe"))
    request_data = [e.data for e in result.execution.events if e.type == "model_request"]
    assert request_data
    assert any("messages" in data for data in request_data)


async def test_timeout_produces_timed_out_status(openai_target, vault):
    slow = TargetConfig(
        target_id="slow",
        kind=TargetKind.CUSTOM_HTTP,
        base_url=openai_target.base_url,
        model="m",
        extra={
            "request_path": "/slow",
            "body_template": {"messages": "{messages}"},
            "response_text_path": "choices.0.message.content",
        },
    )
    policy = AttackPolicy(overall_timeout_s=0.3, per_turn_timeout_s=0.2)
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(make_definition(slow, "data_leakage.probe", policy=policy))
    assert result.execution.status == ExecutionStatus.TIMED_OUT
    assert result.outcome == AttackOutcome.INDETERMINATE
    assert any(e.type == "timeout" for e in result.execution.events)


async def test_cancellation_produces_cancelled_status(openai_target, vault):
    slow = TargetConfig(
        target_id="slow-cancel",
        kind=TargetKind.CUSTOM_HTTP,
        base_url=openai_target.base_url,
        model="m",
        extra={
            "request_path": "/slow",
            "body_template": {"messages": "{messages}"},
            "response_text_path": "choices.0.message.content",
        },
    )
    cancel_event = asyncio.Event()
    policy = AttackPolicy(overall_timeout_s=60.0, per_turn_timeout_s=30.0)
    orch = AttackOrchestrator(vault=vault)

    async def cancel_later():
        await asyncio.sleep(0.05)
        cancel_event.set()

    cancel_task = asyncio.create_task(cancel_later())
    result = await orch.execute(
        make_definition(slow, "data_leakage.probe", policy=policy),
        cancel_event=cancel_event,
    )
    await cancel_task
    assert result.execution.status == ExecutionStatus.CANCELLED
    assert result.outcome == AttackOutcome.INDETERMINATE
    assert any(e.type == "cancellation" for e in result.execution.events)


async def test_unknown_plugin_fails_fast(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    with pytest.raises(PluginError):
        await orch.execute(make_definition(openai_target, "no.such.plugin"))


async def test_failed_execution_status_for_unreachable_target(vault):
    dead = TargetConfig(target_id="dead", kind=TargetKind.OPENAI_COMPATIBLE, base_url="http://127.0.0.1:1", model="m")
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(make_definition(dead, "data_leakage.probe"))
    assert result.execution.status == ExecutionStatus.INDETERMINATE
    assert result.outcome == AttackOutcome.INDETERMINATE
    assert any(e.type == "error" for e in result.execution.events)


async def test_fake_adapter_cannot_reach_storage(openai_target, vault):
    from engine.attacks import PLUGIN_REGISTRY
    from engine.security.storage import FindingsGateway, InMemoryFindingSink

    adapter = FakeAdapter()
    result = await AttackExecutor(
        ExecutionEnvironment(adapter=adapter, vault=vault),
        registry=PLUGIN_REGISTRY,
    ).execute(
        AttackOrchestrator(vault=vault).plan(make_definition(openai_target, "data_leakage.probe"))
    )
    assert result.execution.status == ExecutionStatus.INDETERMINATE
    gateway = FindingsGateway(InMemoryFindingSink())
    with pytest.raises(Exception):
        gateway.submit(result)


async def test_audit_events_recorded(openai_target, vault):
    audits = []
    orch = AttackOrchestrator(vault=vault, audit=lambda event: audits.append(event))
    await orch.execute(make_definition(openai_target, "data_leakage.probe"))
    actions = [a["action"] for a in audits]
    assert "execution.started" in actions
    assert "execution.finished" in actions