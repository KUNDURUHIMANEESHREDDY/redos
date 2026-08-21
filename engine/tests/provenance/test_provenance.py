from __future__ import annotations

from datetime import datetime, timezone

import pytest

from engine.adapters.factory import FakeAdapter
from engine.model.attack import AttackOutcome, AttackPolicy, AttackType, TargetKind
from engine.model.events import EvidenceEvent, EventTypes
from engine.model.execution import ExecutionResult, ExecutionStatus, ObservedExecution
from engine.model.plan import AttackDefinition, ExecutionPlan, PlanStep
from engine.security.guard import ProductionGate, validate_evidence_chain
from engine.security.secrets import SecretsVault, redact_mapping, redact_text
from engine.security.storage import FindingsGateway, InMemoryFindingSink
from engine.targets.config import TargetConfig


def target() -> TargetConfig:
    return TargetConfig(target_id="t", kind=TargetKind.OPENAI_COMPATIBLE, base_url="https://example.invalid", model="m")


def live_execution() -> ObservedExecution:
    now = datetime.now(timezone.utc)
    obs = ObservedExecution(
        execution_id="e-live",
        target_id="t",
        attack_id="a",
        plan_id="p",
        started_at=now,
        finished_at=now,
        status=ExecutionStatus.SUCCESS,
    )
    obs.record(EvidenceEvent.now("e-live", EventTypes.EXECUTION_STARTED, {"provenance": "live"}))
    obs.record(EvidenceEvent.now("e-live", EventTypes.MODEL_REQUEST, {"messages": [{"role": "user", "content": "x"}], "provenance": "live"}))
    obs.record(EvidenceEvent.now("e-live", EventTypes.MODEL_RESPONSE, {"content": "y", "provenance": "live"}))
    obs.record(EvidenceEvent.now("e-live", EventTypes.EXECUTION_FINISHED, {"status": "success", "provenance": "live"}))
    return obs


def plan() -> ExecutionPlan:
    return ExecutionPlan(
        plan_id="p",
        attack=AttackDefinition(
            attack_id="a",
            name="x",
            attack_type=AttackType.PROMPT_INJECTION,
            plugin="prompt_injection.ignore_previous",
            params={},
            target=target(),
            policy=AttackPolicy(),
        ),
        steps=(PlanStep(0, "plan", "plan"),),
        replay_hash="hash",
    )


def test_live_chain_validates():
    validation = validate_evidence_chain(live_execution())
    assert validation.valid, validation.violations


def test_mock_event_fails_validation():
    obs = live_execution()
    obs.record(EvidenceEvent.now("e-live", EventTypes.MODEL_RESPONSE, {"content": "fake", "provenance": "mock"}))
    validation = validate_evidence_chain(obs)
    assert not validation.valid
    assert any("provenance" in v for v in validation.violations)


def test_unfinalized_execution_fails_validation():
    obs = live_execution()
    obs.status = ExecutionStatus.RUNNING
    validation = validate_evidence_chain(obs)
    assert not validation.valid
    assert any("finalized" in v for v in validation.violations)


def test_empty_execution_fails_validation():
    obs = ObservedExecution(
        execution_id="e",
        target_id="t",
        attack_id="a",
        plan_id="p",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        status=ExecutionStatus.SUCCESS,
    )
    validation = validate_evidence_chain(obs)
    assert not validation.valid


def test_production_gate_rejects_mock():
    obs = live_execution()
    obs.record(EvidenceEvent.now("e-live", EventTypes.MODEL_RESPONSE, {"content": "fake", "provenance": "mock"}))
    gate = ProductionGate()
    with pytest.raises(Exception) as excinfo:
        gate.validate(obs)
    assert "mock" in str(excinfo.value).lower()


def test_no_mock_reaches_finding_storage():
    from engine.model.errors import MockEvidenceRejected

    sink = InMemoryFindingSink()
    gateway = FindingsGateway(sink)
    obs = live_execution()
    obs.record(EvidenceEvent.now("e-live", EventTypes.MODEL_RESPONSE, {"content": "fake", "provenance": "mock"}))
    result = ExecutionResult(
        execution=obs,
        plan=plan(),
        outcome=AttackOutcome.SUCCESS,
        outcome_reason="x",
        replay_hash="hash",
    )
    with pytest.raises(MockEvidenceRejected):
        gateway.submit(result)
    assert sink.records == []


def test_real_chain_reaches_finding_storage():
    sink = InMemoryFindingSink()
    gateway = FindingsGateway(sink)
    result = ExecutionResult(
        execution=live_execution(),
        plan=plan(),
        outcome=AttackOutcome.SUCCESS,
        outcome_reason="x",
        replay_hash="hash",
    )
    record = gateway.submit(result)
    assert record.finding_id
    assert record.outcome == "success"
    assert sink.records[0].finding_id == record.finding_id


def test_finding_id_unique():
    sink = InMemoryFindingSink()
    gateway = FindingsGateway(sink)
    r1 = gateway.submit(ExecutionResult(execution=live_execution(), plan=plan(), outcome=AttackOutcome.SUCCESS, outcome_reason="x", replay_hash="h"))
    r2 = gateway.submit(ExecutionResult(execution=live_execution(), plan=plan(), outcome=AttackOutcome.SUCCESS, outcome_reason="x", replay_hash="h"))
    assert r1.finding_id != r2.finding_id


def test_fake_adapter_is_mock_provenance():
    assert FakeAdapter().provenance.value == "mock"


def test_redaction_removes_secrets():
    text = "Authorization: Bearer sk-abc123 and api_key=secret42"
    redacted = redact_text(text)
    assert "sk-abc123" not in redacted
    assert "secret42" not in redacted
    assert "REDACTED" in redacted


def test_redaction_mapping():
    out = redact_mapping({"api_key": "s3cr3t", "messages": ["x"]}, ("s3cr3t",))
    assert out["api_key"] == "***REDACTED***"


def test_vault_resolves_env_ref():
    vault = SecretsVault(env_prefix="")
    vault.register("my_key", "value-1")
    assert vault.get("my_key") == "value-1"