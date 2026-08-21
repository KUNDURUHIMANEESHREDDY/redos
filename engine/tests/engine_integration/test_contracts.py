from __future__ import annotations

import json

from engine.model.attack import AttackPolicy, AttackType, CapturePolicy, Message, Payload, TargetKind
from engine.model.errors import AttackTimeout
from engine.model.events import EvidenceEvent, EventTypes
from engine.model.execution import ExecutionStatus, ObservedExecution
from engine.model.plan import AttackDefinition, ReplayManifest
from engine.targets.config import TargetConfig

from engine.tests.conftest import PLANTED_VAULT_CODE


def sample_target() -> TargetConfig:
    return TargetConfig(
        target_id="t1",
        kind=TargetKind.OPENAI_COMPATIBLE,
        base_url="https://example.invalid",
        model="m",
    )


def sample_definition() -> AttackDefinition:
    return AttackDefinition(
        attack_id="a1",
        name="test attack",
        attack_type=AttackType.PROMPT_INJECTION,
        plugin="prompt_injection.ignore_previous",
        params={"secret": "system prompt"},
        target=sample_target(),
        policy=AttackPolicy(overall_timeout_s=5.0, max_turns=3),
    )


def test_replay_hash_is_deterministic():
    d1 = sample_definition()
    d2 = sample_definition()
    assert d1.replay_hash() == d2.replay_hash()
    assert len(d1.replay_hash()) == 64


def test_replay_hash_changes_with_attack_params():
    d1 = sample_definition()
    d2 = sample_definition()
    d2 = AttackDefinition(
        attack_id="a2",
        name=d2.name,
        attack_type=d2.attack_type,
        plugin=d2.plugin,
        params={"secret": "different"},
        target=d2.target,
        policy=d2.policy,
    )
    assert d1.replay_hash() != d2.replay_hash()


def test_target_fingerprint_stable():
    assert sample_target().fingerprint() == sample_target().fingerprint()


def test_execution_schema_contract():
    obs = ObservedExecution(
        execution_id="e1",
        target_id="t1",
        attack_id="a1",
        plan_id="p1",
        started_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        finished_at=None,
        status=ExecutionStatus.RUNNING,
    )
    obs.record(EvidenceEvent.now("e1", EventTypes.EXECUTION_STARTED, {"provenance": "live"}))
    obs.finished_at = obs.started_at
    obs.status = ExecutionStatus.SUCCESS
    doc = obs.to_dict()
    assert set(doc.keys()) == {
        "execution_id",
        "target_id",
        "attack_id",
        "started_at",
        "finished_at",
        "status",
        "events",
        "tool_calls",
        "model_interactions",
        "retrieval_events",
        "artifacts",
    }
    assert doc["status"] == "success"
    assert isinstance(doc["events"], list)
    assert isinstance(doc["tool_calls"], list)
    assert isinstance(doc["model_interactions"], list)
    assert isinstance(doc["retrieval_events"], list)
    assert isinstance(doc["artifacts"], list)
    parsed = json.loads(obs.to_json())
    assert parsed["execution_id"] == "e1"


def test_event_ids_unique():
    ev1 = EvidenceEvent.now("e1", EventTypes.AUDIT, {})
    ev2 = EvidenceEvent.now("e1", EventTypes.AUDIT, {})
    assert ev1.event_id != ev2.event_id


def test_capture_policy_minimal_hides_inputs():
    policy = CapturePolicy.minimal()
    assert policy.model_inputs is False
    assert policy.model_outputs is True


def test_payload_roundtrip():
    payload = Payload(
        messages=(Message(role="user", content="hello"),),
        indicators=("x",),
    )
    doc = payload.to_dict()
    assert doc["messages"][0]["content"] == "hello"
    assert doc["indicators"] == ["x"]


def test_timeout_error_code():
    assert AttackTimeout().code == "ATTACK_TIMEOUT"


def test_replay_manifest_roundtrip():
    from engine.orchestration.replay import build_manifest, definition_from_manifest

    d = sample_definition()
    manifest = build_manifest(d)
    rebuilt = definition_from_manifest(manifest)
    assert rebuilt.replay_hash() == d.replay_hash()
    assert rebuilt.target.target_id == d.target.target_id


def test_planted_code_constant_used():
    assert "2468" in PLANTED_VAULT_CODE