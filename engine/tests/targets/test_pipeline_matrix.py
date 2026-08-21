from __future__ import annotations

import pytest

from engine.campaigns import CampaignBudget
from engine.chaining import DependencyGraph
from engine.discovery import AttackSurfaceDiscovery
from engine.experiment import IntelligenceRunner
from engine.hypotheses import HypothesisGenerator
from engine.model.attack import AttackPolicy
from engine.model.plan import AttackDefinition
from engine.orchestration import AttackOrchestrator, build_manifest, compare_regression, make_regression_case, replay_attack
from engine.reconnaissance import ReconnaissanceRunner
from engine.security import FindingsGateway, InMemoryFindingSink
from engine.targets import TargetRegistry

from .conftest import agent_tools, anthropic, custom_http, ollama, openai_bare, rag_variant

TOOL_FAMILIES = {"unsafe_tool_call", "tool_abuse", "agent_escalation"}
RAG_FAMILIES = {"rag_poisoning"}
CHAT_FAMILIES = {"prompt_injection", "jailbreak", "model_manipulation", "data_leakage"}


def register(config):
    registry = TargetRegistry()
    registry.register(config)
    assert registry.get(config.target_id) is config
    assert registry.get(config.target_id).fingerprint() == config.fingerprint()
    return registry


async def discover(config):
    surface = await AttackSurfaceDiscovery(vault=None).discover(config)
    return surface


def run_pipeline(config, *, budget, seed=5, vault=None):
    runner = IntelligenceRunner(
        orchestrator=AttackOrchestrator(vault=vault),
        budget=CampaignBudget(max_attacks=budget),
        seed=seed,
    )
    return runner


async def run_regression(orch, config, experiment):
    definition = AttackDefinition(
        attack_id=f"{experiment.plugin}:exp-reg",
        name=experiment.plugin,
        attack_type=experiment.attack_type,
        plugin=experiment.plugin,
        params=dict(experiment.params),
        target=config,
        policy=AttackPolicy(),
    )
    manifest = build_manifest(definition)
    baseline = await orch.execute(definition)
    case = make_regression_case("val-repro", manifest, baseline)
    replayed = await replay_attack(manifest, orch)
    assert replayed.outcome == baseline.outcome, "reproduction outcome differs from baseline"
    assert compare_regression(case, replayed) == [], f"regression differences: {compare_regression(case, replayed)}"
    return baseline


@pytest.mark.parametrize(
    "builder",
    [openai_bare, agent_tools, anthropic, ollama, custom_http, rag_variant],
    ids=["openai_bare", "agent_tools", "anthropic", "ollama", "custom_http", "rag_variant"],
)
async def test_full_pipeline_runs_on_each_target_structure(emulators, vault, builder):
    config = builder(emulators)
    register(config)
    profile = await ReconnaissanceRunner(vault=vault).run(config)
    assert profile.target_id == config.target_id

    surface = await discover(config)
    assert surface.chat_observed is True, f"{config.kind} did not respond to benign probe"

    hypotheses = HypothesisGenerator().generate(surface)
    assert hypotheses, f"no hypotheses generated for {config.kind}"

    gateway = FindingsGateway(InMemoryFindingSink())
    runner = run_pipeline(config, budget=6)
    report = await runner.run(config, gateway=gateway)

    assert report.experiments, f"no experiments executed for {config.kind}"
    for run in report.experiments:
        assert run.execution_id, f"experiment {run.experiment.plugin} missing execution id"
        assert run.provenance == "live"
        assert run.outcome in ("success", "failure", "indeterminate")
        assert run.events >= 1, f"experiment {run.experiment.plugin} produced no evidence events"
        assert run.experiment.params is not None

    graph = DependencyGraph()
    surface_copy = surface
    for run in report.experiments:
        plugin = run.experiment.plugin
        assert graph.satisfied(plugin, surface_copy), f"{plugin} executed without capability gating"

    for finding in report.findings:
        assert finding.validation_valid is True
        assert finding.outcome == "success"

    assert report.intelligence.summary()["tested"]

    orch = AttackOrchestrator(vault=vault)
    await run_regression(orch, config, report.experiments[0].experiment)


async def test_hypotheses_reflect_observed_tool_names_not_defaults(emulators, vault):
    config = agent_tools(emulators)
    surface = await discover(config)
    assert surface.tool_capability is True
    assert surface.tool_names == ["execute_command", "query_database", "read_local_file"]
    hypotheses = HypothesisGenerator().generate(surface)
    tool_h = next(h for h in hypotheses if h.attack_surface == "tool_authorization")
    assert tool_h is not None
    assert "unsafe_tool_call.shell" in tool_h.candidate_attacks
    assert surface.fact("tool") is not None
    assert surface.fact("tool").value == ["execute_command", "query_database", "read_local_file"]


async def test_observation_driven_families_per_target(emulators, vault):
    cases = [
        (openai_bare, set(), set(), {"prompt_injection", "jailbreak", "model_manipulation"}),
        (agent_tools, {"unsafe_tool_call", "tool_abuse", "agent_escalation"}, set(), {"prompt_injection", "jailbreak", "model_manipulation"}),
        (anthropic, set(), set(), {"prompt_injection", "jailbreak", "model_manipulation"}),
        (ollama, set(), set(), {"prompt_injection", "jailbreak", "model_manipulation"}),
        (custom_http, set(), set(), {"prompt_injection", "jailbreak", "model_manipulation"}),
        (rag_variant, set(), {"rag_poisoning"}, {"prompt_injection", "jailbreak", "model_manipulation", "data_leakage"}),
    ]
    for builder, tool_families, rag_families, chat_families in cases:
        config = builder(emulators)
        surface = await discover(config)
        hypotheses = HypothesisGenerator().generate(surface)
        used_surfaces = {h.attack_surface for h in hypotheses}
        if not tool_families:
            assert not used_surfaces & {"tool_authorization"}, f"{config.kind} generated tool hypothesis without observed tools"
        if not rag_families:
            assert not used_surfaces & {"rag_source"}, f"{config.kind} generated rag hypothesis without observed retrieval"
        assert "model_boundary" in used_surfaces

        runner = run_pipeline(config, budget=8)
        report = await runner.run(config)
        executed_families = {e.experiment.plugin.split(".", 1)[0] for e in report.experiments}
        assert not (executed_families & TOOL_FAMILIES - tool_families), f"{config.kind} ran tool attacks without tools"
        assert not (executed_families & RAG_FAMILIES - rag_families), f"{config.kind} ran rag attacks without retrieval"
        assert executed_families & chat_families, f"{config.kind} ran no chat-surface attacks"
        if tool_families:
            assert executed_families & tool_families, f"{config.kind} never tested observed tools"
        if rag_families:
            assert executed_families & rag_families, f"{config.kind} never tested observed retrieval"


async def test_agent_target_surface_observes_delegation(emulators, vault):
    config = agent_tools(emulators)
    surface = await discover(config)
    fact = surface.fact("agent_delegation")
    assert fact is not None
    assert fact.value is True
    assert "delegation_probe" in fact.evidence_refs
    assert surface.agent_delegation is True


async def test_rag_variant_retrieval_structure_is_parsed(emulators, vault):
    config = rag_variant(emulators)
    surface = await discover(config)
    assert surface.retrieval_supported is True
    assert surface.retrieval_sample, "retrieval variant returned no parseable documents"
    assert any(s for s in surface.retrieval_sample), "retrieval variant documents were empty"

    runner = run_pipeline(config, budget=6)
    report = await runner.run(config)
    rag_plugin = [e for e in report.experiments if e.experiment.plugin == "rag_poisoning.plant"]
    assert rag_plugin, "rag poisoning never selected on retrieval variant"
    assert any(r.outcome == "success" for r in rag_plugin), "planted retrieval content not detected on variant structure"