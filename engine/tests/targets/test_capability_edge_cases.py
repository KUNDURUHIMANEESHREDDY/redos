from __future__ import annotations

import pytest

from engine.campaigns import CampaignBudget
from engine.experiment import IntelligenceRunner
from engine.model.attack import AttackPolicy, AttackType, TargetKind
from engine.model.execution import ExecutionStatus
from engine.model.plan import AttackDefinition
from engine.orchestration import AttackOrchestrator
from engine.reconnaissance import ReconnaissanceRunner
from engine.security import SecretsVault
from engine.targets import TargetConfig

from .conftest import agent_tools, auth_target, custom_http, openai_bare, rag_variant, strict_no_tools
from .emulators import GOOD_AUTH_KEY, FlakyHandler

TOOL_OUTCOME_SETS = {"success", "failure", "indeterminate"}


def definition(config, plugin, policy=None, **params) -> AttackDefinition:
    return AttackDefinition(
        attack_id=f"edge-{plugin}",
        name=plugin,
        attack_type=AttackType.CUSTOM,
        plugin=plugin,
        params=params,
        target=config,
        policy=policy or AttackPolicy(),
    )


async def test_no_tools_target_never_selects_tool_attacks(emulators, vault):
    config = openai_bare(emulators)
    surface = await _discover(config, vault)
    assert surface.tool_capability is False
    assert surface.tools == []
    from engine.hypotheses import HypothesisGenerator

    hypotheses = HypothesisGenerator().generate(surface)
    assert not any(h.attack_surface == "tool_authorization" for h in hypotheses)
    runner = IntelligenceRunner(orchestrator=AttackOrchestrator(vault=vault), budget=CampaignBudget(max_attacks=4))
    report = await runner.run(config)
    families = {e.experiment.plugin.split(".", 1)[0] for e in report.experiments}
    assert not (families & {"unsafe_tool_call", "tool_abuse", "agent_escalation"})


async def test_assumed_tool_capability_is_not_fabricated_into_success(emulators, vault):
    """kind=AGENT declares tool capability in config, but the endpoint has no
    tools: recon must not fabricate discovery, and attacks must not fake success."""
    config = strict_no_tools(emulators)
    recon_events = []
    profile = await ReconnaissanceRunner(vault=vault, listener=lambda e: recon_events.append(e)).run(config)
    assert profile.tool_capability is True, "config-declared capability should be retained as an assumption"
    assert profile.tools == [], "no tools were observed"
    failed = [e for e in recon_events if e["probe"] == "list_tools" and e["ok"] is False]
    assert failed, "recon did not honestly record the failed tool listing"

    surface = await _discover(config, vault)
    assert surface.fact("tool") is None, "surface must not claim observed tools that were never seen"
    assert surface.tool_names == []

    runner = IntelligenceRunner(orchestrator=AttackOrchestrator(vault=vault), budget=CampaignBudget(max_attacks=6))
    report = await runner.run(config)
    tool_runs = [e for e in report.experiments if e.experiment.plugin.split(".", 1)[0] in {"unsafe_tool_call", "tool_abuse", "agent_escalation"}]
    assert tool_runs, "tool hypothesis was generated from the config assumption"
    assert all(r.outcome != "success" for r in tool_runs), "tool attacks reported success against a target with no tool execution"


async def test_different_tool_names_produce_honest_outcomes(emulators, vault):
    config = agent_tools(emulators)
    orch = AttackOrchestrator(vault=vault)
    shell = await orch.execute(definition(config, "unsafe_tool_call.shell"))
    assert shell.outcome.value == "success", f"shell attack should succeed via observed execute_command: {shell.outcome_reason}"

    sql = await orch.execute(definition(config, "unsafe_tool_call.sql"))
    assert sql.outcome.value == "success", f"sql attack should succeed via observed query_database: {sql.outcome_reason}"

    negation = await orch.execute(definition(config, "tool_abuse.negation"))
    assert negation.outcome.value == "failure", (
        f"negation payload references catalog default tool name 'read_file' and must fail honestly on differently-named tools: {negation.outcome_reason}"
    )
    assert any(e.type == "tool_result" for e in negation.execution.events), "negation execution produced no tool evidence"


async def test_different_rag_structure_is_exploited(emulators, vault):
    config = rag_variant(emulators)
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(config, "rag_poisoning.plant", plant="The access code to the vault is 2468.", probe="access code"))
    assert result.outcome.value == "success", f"plant must succeed through {'results': []} retrieval structure: {result.outcome_reason}"
    assert any(e.type == "retrieval" for e in result.execution.events)


async def test_malformed_responses_are_honest_not_crashes(emulators, vault):
    cases = ["malformed_non_json", "malformed_missing_choices", "malformed_wrong_type"]
    for name in cases:
        config = TargetConfig(target_id=f"val-{name}", kind=TargetKind.OPENAI_COMPATIBLE, base_url=emulators[name], model="m")
        orch = AttackOrchestrator(vault=vault)
        result = await orch.execute(definition(config, "data_leakage.probe"))
        assert result.execution.status in (ExecutionStatus.INDETERMINATE, ExecutionStatus.FAILURE), name
        assert result.outcome.value in ("indeterminate", "failure"), name
        assert any(e.type == "error" for e in result.execution.events) or result.execution.status == ExecutionStatus.FAILURE, name


async def test_timeout_is_honest(emulators, vault):
    config = TargetConfig(target_id="val-timeout", kind=TargetKind.OPENAI_COMPATIBLE, base_url=emulators["timeout"], model="m")
    policy = AttackPolicy(per_turn_timeout_s=0.3, overall_timeout_s=5.0)
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(config, "data_leakage.probe", policy=policy))
    assert result.execution.status == ExecutionStatus.TIMED_OUT
    assert result.outcome.value == "indeterminate"
    assert any(e.type == "timeout" for e in result.execution.events)


async def test_authentication_rejection_is_honest(emulators, vault):
    bad_vault = SecretsVault()
    bad_vault.register("val_api_key", "bad-key")
    config = auth_target(emulators)
    orch = AttackOrchestrator(vault=bad_vault)
    result = await orch.execute(definition(config, "data_leakage.probe"))
    assert result.execution.status == ExecutionStatus.INDETERMINATE
    assert result.outcome.value == "indeterminate"
    assert any(e.type == "error" for e in result.execution.events)


async def test_authentication_with_valid_credential_runs_pipeline(emulators, vault):
    vault.register("val_api_key", GOOD_AUTH_KEY)
    config = auth_target(emulators)
    runner = IntelligenceRunner(orchestrator=AttackOrchestrator(vault=vault), budget=CampaignBudget(max_attacks=3))
    report = await runner.run(config)
    assert report.experiments
    for run in report.experiments:
        assert run.execution_id


async def test_partial_failure_retries_then_succeeds(emulators, vault):
    FlakyHandler.failures_remaining = 2
    config = TargetConfig(target_id="val-flaky", kind=TargetKind.OPENAI_COMPATIBLE, base_url=emulators["flaky"], model="m")
    audits = []
    orch = AttackOrchestrator(vault=vault, audit=lambda event: audits.append(event))
    result = await orch.execute(definition(config, "data_leakage.probe"))
    assert result.execution.status == ExecutionStatus.SUCCESS
    retries = [a for a in audits if a.get("action") == "execution.retry"]
    assert len(retries) == 2, f"expected 2 retries after partial failures, got {retries}"


async def test_unreachable_target_is_honest(emulators, vault):
    config = TargetConfig(target_id="val-dead", kind=TargetKind.OPENAI_COMPATIBLE, base_url="http://127.0.0.1:1", model="m")
    orch = AttackOrchestrator(vault=vault)
    result = await orch.execute(definition(config, "data_leakage.probe"))
    assert result.execution.status == ExecutionStatus.INDETERMINATE
    assert result.outcome.value == "indeterminate"


async def _discover(config, vault):
    from engine.discovery import AttackSurfaceDiscovery

    return await AttackSurfaceDiscovery(vault=vault).discover(config)