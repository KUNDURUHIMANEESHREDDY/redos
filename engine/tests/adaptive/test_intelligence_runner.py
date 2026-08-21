from __future__ import annotations

from engine.campaigns import CampaignBudget
from engine.experiment import IntelligenceRunner
from engine.model.attack import TargetKind
from engine.orchestration import AttackOrchestrator
from engine.security import FindingsGateway, InMemoryFindingSink
from engine.targets import RAGTargetConfig, TargetConfig

CHAIN = [
    "prompt_injection.ignore_previous",
    "rag_poisoning.plant",
    "agent_escalation.system_override",
    "tool_abuse.negation",
    "data_leakage.pii",
]


def rag_tool_target(chat_server) -> RAGTargetConfig:
    return RAGTargetConfig(
        target_id="intel-rag-tool",
        kind=TargetKind.RAG,
        base_url=chat_server,
        model="test-model",
        retrieval_url=f"{chat_server}/retrieve",
        extra={"tool_invoke_url": chat_server},
    )


def bare_target(chat_server) -> TargetConfig:
    return TargetConfig(
        target_id="intel-bare",
        kind=TargetKind.OPENAI_COMPATIBLE,
        base_url=chat_server,
        model="test-model",
    )


def make_runner(vault, *, budget=None, seed=5):
    return IntelligenceRunner(
        orchestrator=AttackOrchestrator(vault=vault),
        budget=budget or CampaignBudget(max_attacks=14),
        seed=seed,
    )


async def test_hard_requirement_novel_variation_with_full_provenance(chat_server, vault):
    """The system must produce a previously unexecuted attack variation derived
    from evidence from the current target, execute it, and preserve the complete
    provenance chain: hypothesis -> experiment -> definition -> execution."""
    runner = make_runner(vault)
    report = await runner.run(rag_tool_target(chat_server))

    assert report.status in ("completed", "stopped")
    assert report.experiments, "no experiments were executed"

    plugins = [e.experiment.plugin for e in report.experiments]

    chain_positions = [plugins.index(plugin) for plugin in CHAIN]
    assert chain_positions == sorted(chain_positions), f"cross-family chain order violated: {plugins}"
    assert plugins[:5] == CHAIN, f"cross-family chain did not execute first in order: {plugins}"

    variation_runs = [e for e in report.experiments if e.experiment.variation is not None]
    assert variation_runs, "no novel variation was produced"

    novel = variation_runs[0]
    spec = novel.experiment.variation
    assert spec.plugin == "rag_poisoning.plant"
    assert "retrieval_sample" in spec.derived_from, f"variation not derived from evidence: {spec.derived_from}"
    assert spec.text != spec.base_text, "variation text is identical to the catalog default"
    assert spec.text not in {"The access code to the vault is 2468."}, "variation text must not be a static catalog payload"
    assert novel.outcome == "success", f"derived variation should succeed on this target: {novel.outcome_reason}"
    assert novel.execution_id
    assert novel.provenance == "live"

    hypothesis = next(h for h in report.hypotheses if h.hypothesis_id == novel.experiment.hypothesis_id)
    assert hypothesis.status.value == "confirmed", f"hypothesis {hypothesis.hypothesis_id} not confirmed: {hypothesis.status}"
    assert hypothesis.tested is True
    assert hypothesis.supporting_evidence

    chain_h = next(h for h in report.hypotheses if h.attack_surface == "cross_family")
    assert chain_h.tested is True

    summary = report.intelligence.summary()
    assert summary["tested"]
    assert summary["succeeded"]
    assert summary["failed"]
    assert summary["why_next"], "no decision log recorded"
    assert "prompt_injection.ignore_previous" in summary["succeeded"]
    assert all(p not in report.unexplored["plugins"] for p in plugins)


async def test_intelligence_adapts_to_target_without_tools(chat_server, vault):
    runner = make_runner(vault, budget=CampaignBudget(max_attacks=6))
    report = await runner.run(bare_target(chat_server))

    plugins = [e.experiment.plugin for e in report.experiments]
    assert plugins
    assert not any("unsafe_tool_call" in p or p.startswith("rag_poisoning") for p in plugins)
    assert not any(h.attack_surface == "cross_family" for h in report.hypotheses)
    assert report.intelligence.summary()["succeeded"]


async def test_intelligence_respects_budget(chat_server, vault):
    runner = make_runner(vault, budget=CampaignBudget(max_attacks=3))
    report = await runner.run(rag_tool_target(chat_server))
    assert report.status == "stopped"
    assert "budget exhausted" in report.stopped_reason
    assert len(report.experiments) == 3


async def test_intelligence_deterministic_for_same_seed(chat_server, vault):
    first = await make_runner(vault, seed=7).run(rag_tool_target(chat_server))
    second = await make_runner(vault, seed=7).run(rag_tool_target(chat_server))
    first_seq = [(e.experiment.plugin, e.experiment.variation.text if e.experiment.variation else None) for e in first.experiments]
    second_seq = [(e.experiment.plugin, e.experiment.variation.text if e.experiment.variation else None) for e in second.experiments]
    assert first_seq == second_seq


async def test_intelligence_submits_findings_for_successes(chat_server, vault):
    gateway = FindingsGateway(InMemoryFindingSink())
    runner = make_runner(vault, budget=CampaignBudget(max_attacks=8))
    report = await runner.run(rag_tool_target(chat_server), gateway=gateway)
    assert report.findings, "expected findings for successful experiments"
    for finding in report.findings:
        assert finding.validation_valid is True
        assert finding.outcome == "success"


async def test_intelligence_emits_lifecycle_events(chat_server, vault):
    events = []
    runner = make_runner(vault, budget=CampaignBudget(max_attacks=2))
    runner.listener = events.append
    await runner.run(rag_tool_target(chat_server))
    actions = [e["action"] for e in events]
    assert "intelligence.discovery.start" in actions
    assert "intelligence.discovery.done" in actions
    assert any(a == "intelligence.experiment.started" for a in actions)
    assert any(a == "intelligence.experiment.finished" for a in actions)


async def test_intelligence_tests_authentication_boundary(chat_server, vault):
    vault.register("test_api_key", "test-key-value")
    target = TargetConfig(
        target_id="intel-auth",
        kind=TargetKind.OPENAI_COMPATIBLE,
        base_url=chat_server,
        model="test-model",
        api_key_ref="test_api_key",
    )
    runner = make_runner(vault, budget=CampaignBudget(max_attacks=4))
    report = await runner.run(target)

    assert any(h.attack_surface == "authentication_boundary" for h in report.hypotheses)
    plugins = [e.experiment.plugin for e in report.experiments]
    assert any(p.startswith("permission.") for p in plugins)
    auth_experiments = [e for e in report.experiments if e.experiment.plugin.startswith("permission.")]
    assert auth_experiments, "permission attacks were never selected"
    assert all(e.outcome in ("success", "failure", "indeterminate") for e in auth_experiments)
    assert all(e.execution_id for e in auth_experiments)