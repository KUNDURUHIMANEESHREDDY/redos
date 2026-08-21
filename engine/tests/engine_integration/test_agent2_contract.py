from __future__ import annotations

import json

from engine.model.attack import AttackPolicy, AttackType
from engine.model.execution import ExecutionStatus
from engine.model.plan import AttackDefinition
from engine.orchestration.orchestrator import AttackOrchestrator
from engine.security.storage import FindingsGateway, InMemoryFindingSink

FINDING_SCHEMA_FIELDS = {
    "finding_id": str,
    "execution_id": str,
    "target_id": str,
    "attack_id": str,
    "outcome": str,
    "outcome_reason": str,
    "validation_valid": bool,
    "stored_at": str,
    "severity": (str, type(None)),
}

EXECUTION_SCHEMA_FIELDS = {
    "execution_id": str,
    "target_id": str,
    "attack_id": str,
    "started_at": str,
    "finished_at": str,
    "status": str,
    "events": list,
    "tool_calls": list,
    "model_interactions": list,
    "retrieval_events": list,
    "artifacts": list,
}


def definition(target, plugin, **params) -> AttackDefinition:
    return AttackDefinition(
        attack_id="contract-a",
        name="contract",
        attack_type=AttackType.PROMPT_INJECTION,
        plugin=plugin,
        params=params,
        target=target,
        policy=AttackPolicy(),
    )


async def test_execution_result_json_contract(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "data_leakage.probe"))
    payload = json.loads(result.to_json())
    assert set(payload.keys()) == {"execution", "plan", "outcome", "outcome_reason", "observation", "validation", "replay_hash"}
    assert set(payload["execution"].keys()) == set(EXECUTION_SCHEMA_FIELDS)
    for field, expected in EXECUTION_SCHEMA_FIELDS.items():
        assert isinstance(payload["execution"][field], expected), field
    assert set(payload["validation"].keys()) == {"valid", "violations"}
    assert payload["validation"]["valid"] is True
    assert set(payload["plan"].keys()) == {"plan_id", "attack", "steps", "replay_hash", "created_at"}


async def test_finding_record_contract_for_agent2(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "malicious_document.inline"))
    sink = InMemoryFindingSink()
    gateway = FindingsGateway(sink)
    record = gateway.submit(result)
    doc = record.to_dict()
    assert set(doc.keys()) == set(FINDING_SCHEMA_FIELDS)
    for field, expected in FINDING_SCHEMA_FIELDS.items():
        assert isinstance(doc[field], expected), field
    assert doc["execution_id"] == result.execution.execution_id
    assert doc["target_id"] == result.execution.target_id
    assert doc["attack_id"] == result.execution.attack_id
    assert doc["validation_valid"] is True
    assert doc["severity"] is None


async def test_severity_is_never_computed_by_engine(openai_target, vault):
    from engine.orchestration.orchestrator import AttackOrchestrator

    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "data_leakage.probe"))
    payload = result.to_dict()
    assert "severity" not in payload
    assert "severity" not in payload["observation"]
    record = FindingsGateway(InMemoryFindingSink()).submit(result)
    assert record.severity is None


async def test_failed_execution_cannot_produce_finding(openai_target, vault):
    from engine.model.errors import MockEvidenceRejected

    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(openai_target, "data_leakage.probe"))
    assert result.execution.status == ExecutionStatus.SUCCESS or result.execution.status == ExecutionStatus.FAILURE
    assert result.validation.valid
    gateway = FindingsGateway(InMemoryFindingSink())
    record = gateway.submit(result)
    assert record.finding_id


async def test_audit_events_present_for_agent2_consumers(openai_target, vault):
    audits = []
    orch = AttackOrchestrator(vault=vault, audit=lambda event: audits.append(event))
    await orch.execute(definition(openai_target, "data_leakage.probe"))
    assert audits
    actions = {a["action"] for a in audits}
    assert "execution.started" in actions
    assert "execution.finished" in actions