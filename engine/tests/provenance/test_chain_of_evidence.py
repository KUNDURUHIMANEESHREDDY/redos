from __future__ import annotations

import json

from engine.model.attack import AttackOutcome, AttackPolicy, AttackType
from engine.model.plan import AttackDefinition
from engine.orchestration.orchestrator import AttackOrchestrator
from engine.security.storage import FindingsGateway, InMemoryFindingSink


def definition(target, plugin, **params) -> AttackDefinition:
    return AttackDefinition(
        attack_id="chain-a",
        name="chain of evidence",
        attack_type=AttackType.MALICIOUS_DOCUMENT,
        plugin=plugin,
        params=params,
        target=target,
        policy=AttackPolicy(),
    )


async def test_chain_of_evidence_real_target_to_result(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "malicious_document.inline"))

    execution = result.execution
    events = execution.events
    assert events

    start_event = next(e for e in events if e.type == "execution_started")
    finish_event = next(e for e in events if e.type == "execution_finished")
    assert start_event.data["target_id"] == openai_target.target_id
    assert start_event.data["provenance"] == "live"
    assert finish_event.data["provenance"] == "live"

    shared_ids = {e.execution_id for e in events}
    assert shared_ids == {execution.execution_id}

    provenance_values = {
        e.data.get("provenance")
        for e in events
        if e.type
        in (
            "execution_started",
            "execution_finished",
            "model_request",
            "model_response",
            "model_interaction",
            "tool_call",
            "tool_result",
            "retrieval",
            "artifact",
            "attack_result",
        )
    }
    assert provenance_values == {"live"}

    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)
    assert execution.started_at <= execution.finished_at
    assert timestamps[-1] <= execution.finished_at

    assert any(e.type == "attack_payload" for e in events)
    assert any(e.type == "model_request" for e in events)
    assert any(e.type == "model_response" for e in events)
    assert any(e.type == "attack_result" for e in events)

    assert execution.status.value in ("success", "failure")
    assert result.outcome in (AttackOutcome.SUCCESS, AttackOutcome.FAILURE)
    assert result.validation.valid, result.validation.violations
    assert result.observation is not None
    assert result.observation.evidence_event_ids

    sink = InMemoryFindingSink()
    record = FindingsGateway(sink).submit(result)
    assert record.execution_id == execution.execution_id
    assert record.validation_valid is True

    serialized = json.loads(execution.to_json())
    assert serialized["execution_id"] == execution.execution_id
    assert serialized["target_id"] == openai_target.target_id


async def test_every_event_belongs_to_same_execution(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "data_leakage.pii"))
    for event in result.execution.events:
        assert event.execution_id == result.execution.execution_id
        assert event.event_id


async def test_no_placeholders_in_evidence(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "data_leakage.pii"))
    blob = result.to_json()
    for placeholder in ("<...>", "...", "TODO", "lorem", "PLACEHOLDER", "{placeholder"):
        assert placeholder not in blob
    for event in result.execution.events:
        if event.type == "model_response":
            assert event.data.get("content") not in (None, "", "<...>")