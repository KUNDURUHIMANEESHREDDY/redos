from __future__ import annotations

import asyncio

import pytest

from engine.model.attack import AttackOutcome, AttackPolicy, AttackType, TargetKind
from engine.model.errors import ReplayMismatch
from engine.model.plan import AttackDefinition
from engine.orchestration.chaining import ChainContext
from engine.orchestration.orchestrator import AttackOrchestrator
from engine.orchestration.replay import (
    build_manifest,
    compare_regression,
    definition_from_manifest,
    make_regression_case,
    replay_attack,
    verify_manifest,
)
from engine.targets.config import TargetConfig


def definition(target, plugin="data_leakage.probe", **params) -> AttackDefinition:
    return AttackDefinition(
        attack_id="d1",
        name="orch",
        attack_type=AttackType.DATA_LEAKAGE,
        plugin=plugin,
        params=params,
        target=target,
        policy=AttackPolicy(),
    )


async def test_same_attack_same_target_replay_hash(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    r1 = await orch.execute(definition(openai_target))
    r2 = await orch.execute(definition(openai_target))
    assert r1.replay_hash == r2.replay_hash
    assert r1.execution.execution_id != r2.execution.execution_id


async def test_replay_manifest_replays_same_configuration(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    first = await orch.execute(definition(openai_target))
    manifest = build_manifest(first.plan.attack)
    verify_manifest(first.plan.attack, manifest)
    replay = await replay_attack(manifest, orch)
    assert replay.replay_hash == first.replay_hash
    assert replay.execution.execution_id != first.execution.execution_id
    assert replay.execution.status == first.execution.status


async def test_manifest_tampering_detected(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    first = await orch.execute(definition(openai_target))
    manifest = build_manifest(first.plan.attack)
    tampered = definition(openai_target, probe="different probe")
    with pytest.raises(ReplayMismatch):
        verify_manifest(tampered, manifest)


async def test_definition_from_manifest_roundtrip(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    first = await orch.execute(definition(openai_target))
    manifest = build_manifest(first.plan.attack)
    rebuilt = definition_from_manifest(manifest)
    assert rebuilt.replay_hash() == manifest.replay_hash
    assert rebuilt.target.target_id == openai_target.target_id


async def test_regression_case_and_compare(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    first = await orch.execute(definition(openai_target))
    manifest = build_manifest(first.plan.attack)
    case = make_regression_case("reg-1", manifest, first)
    assert case.regression_test_id == "reg-1"
    replay = await replay_attack(manifest, orch)
    differences = compare_regression(case, replay)
    assert differences == []


async def test_regression_detects_status_change(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    first = await orch.execute(definition(openai_target))
    manifest = build_manifest(first.plan.attack)
    case = make_regression_case("reg-2", manifest, first)
    changed = make_regression_case("reg-2", manifest, first)
    changed = type(changed)(
        regression_test_id=changed.regression_test_id,
        manifest=changed.manifest,
        baseline={**changed.baseline, "status": "timed_out"},
        recorded_at=changed.recorded_at,
    )
    differences = compare_regression(changed, first)
    assert differences
    assert any("status" in d for d in differences)


async def test_chaining_feeds_next_attack(openai_target, vault):
    orch = AttackOrchestrator(vault=vault)
    chain = ChainContext()
    first = await orch.execute(definition(openai_target, "malicious_document.inline"), chain=chain)
    assert chain.get(first.plan.attack.attack_id)["outcome"] == "success"
    second = await orch.execute(definition(openai_target, "data_leakage.probe", probe="{chain.%s}" % first.plan.attack.attack_id), chain=chain)
    rendered = second.plan.attack.params["probe"]
    assert "{chain." not in rendered
    assert "outcome" in rendered


async def test_chain_template_substitution_unit():
    chain = ChainContext()
    chain.record("a9", {"secret": "vault-2468"})
    assert chain.render("open {chain.a9.secret}") == "open vault-2468"


async def test_sandbox_rate_limiter_runs(openai_target, vault):
    from engine.sandbox import Sandbox

    sandbox = Sandbox(max_concurrency=2)
    orch = AttackOrchestrator(vault=vault, sandbox=sandbox)
    results = await asyncio.gather(
        *[orch.execute(definition(openai_target)) for _ in range(3)]
    )
    assert len(results) == 3
    assert all(r.execution.status.value == "success" for r in results)