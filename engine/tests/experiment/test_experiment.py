from __future__ import annotations

import random

from engine.adaptive import CampaignState
from engine.attack_surface import AttackSurface
from engine.coverage import CoverageTracker
from engine.experiment import ExperimentSelector
from engine.experiment.scoring import score_candidate
from engine.hypotheses import AttackHypothesis, HypothesisStatus
from engine.model.attack import TargetKind


def make_surface(*, tools=False, retrieval=False, chat=True, sample=None) -> AttackSurface:
    surface = AttackSurface(target_id="t", adapter_kind="agent", model="m")
    surface.tool_capability = tools
    surface.retrieval_supported = retrieval
    surface.chat_observed = chat
    if sample:
        surface.retrieval_sample = [sample]
    return surface


def chain_hypothesis() -> AttackHypothesis:
    return AttackHypothesis(
        "chain",
        "multiple attack surfaces compose",
        "cross_family",
        "composition",
        ("model_response", "retrieval", "tool_result"),
        ("prompt_injection.ignore_previous", "rag_poisoning.plant", "agent_escalation.system_override", "tool_abuse.negation", "data_leakage.pii"),
        confidence=0.5,
        priority=1,
    )


def test_selector_picks_chain_stage_first_in_order():
    selector = ExperimentSelector()
    surface = make_surface(tools=True, retrieval=True, sample="General knowledge about the product.")
    coverage = CoverageTracker()
    state = CampaignState()

    first = selector.select([chain_hypothesis()], surface, state, coverage, random.Random(1), 0)
    assert first.plugin == "prompt_injection.ignore_previous"
    coverage.record_plugin(first.plugin, "success")

    second = selector.select([chain_hypothesis()], surface, state, coverage, random.Random(1), 1)
    assert second.plugin == "rag_poisoning.plant"
    coverage.record_plugin(second.plugin, "success")

    third = selector.select([chain_hypothesis()], surface, state, coverage, random.Random(1), 2)
    assert third.plugin == "agent_escalation.system_override"
    coverage.record_plugin(third.plugin, "failure")

    fourth = selector.select([chain_hypothesis()], surface, state, coverage, random.Random(1), 3)
    assert fourth.plugin == "tool_abuse.negation"
    coverage.record_plugin(fourth.plugin, "success")

    fifth = selector.select([chain_hypothesis()], surface, state, coverage, random.Random(1), 4)
    assert fifth.plugin == "data_leakage.pii"
    coverage.record_plugin(fifth.plugin, "failure")

    sixth = selector.select([chain_hypothesis()], surface, state, coverage, random.Random(1), 5)
    assert sixth is not None
    assert sixth.plugin == "rag_poisoning.plant"
    assert sixth.variation is not None
    coverage.record_plugin(sixth.plugin, "success")

    assert selector.select([chain_hypothesis()], surface, state, coverage, random.Random(1), 6) is None


def test_selector_gates_attacks_by_capability():
    selector = ExperimentSelector()
    surface = make_surface(tools=False, retrieval=False)
    tool_h = AttackHypothesis("t1", "a", "tool_authorization", "e", ("tool_result",), ("unsafe_tool_call.shell",), priority=1)
    chat_h = AttackHypothesis("c1", "a", "model_boundary", "e", ("model_response",), ("prompt_injection.ignore_previous",), priority=2)
    coverage = CoverageTracker()
    experiment = selector.select([tool_h, chat_h], surface, CampaignState(), coverage, random.Random(1), 0)
    assert experiment.plugin == "prompt_injection.ignore_previous"
    assert experiment.hypothesis_id == "c1"


def test_selector_returns_variation_once_then_stops():
    selector = ExperimentSelector()
    surface = make_surface(retrieval=True, sample="The access code to the vault is 2468.")
    h = AttackHypothesis("r1", "a", "rag_source", "e", ("retrieval",), ("rag_poisoning.plant",), priority=1)
    coverage = CoverageTracker()
    coverage.record_plugin("rag_poisoning.plant", "success")

    second = selector.select([h], surface, CampaignState(), coverage, random.Random(1), 1)
    assert second is not None
    assert second.variation is not None
    assert second.plugin == "rag_poisoning.plant"
    assert second.params["plant"] == "access code to the vault is 2468"
    coverage.record_plugin("rag_poisoning.plant", "success")

    third = selector.select([h], surface, CampaignState(), coverage, random.Random(1), 2)
    assert third is None


def test_selector_skips_tried_plugins_without_variation():
    selector = ExperimentSelector()
    surface = make_surface(tools=True, sample=None)
    h = AttackHypothesis("t1", "a", "tool_authorization", "e", ("tool_result",), ("unsafe_tool_call.shell",), priority=1)
    coverage = CoverageTracker()
    coverage.record_plugin("unsafe_tool_call.shell", "failure")
    experiment = selector.select([h], surface, CampaignState(), coverage, random.Random(1), 1)
    assert experiment is None


def test_scoring_prefers_untried_families():
    surface = make_surface(tools=True)
    coverage = CoverageTracker()
    untried = score_candidate("unsafe_tool_call.sql", surface, coverage)
    coverage.record_plugin("unsafe_tool_call.sql", "failure")
    tried = score_candidate("unsafe_tool_call.sql", surface, coverage)
    assert untried.total > tried.total
    assert untried.coverage_gap > tried.coverage_gap


def test_scoring_variation_boosts_information_gain():
    surface = make_surface(retrieval=True, sample="x")
    coverage = CoverageTracker()
    coverage.record_plugin("rag_poisoning.plant", "success")
    variation = score_candidate("rag_poisoning.plant", surface, coverage, is_variation=True)
    assert variation.information_gain > 0.5
    assert variation.plugin == "rag_poisoning.plant"


def test_selector_deterministic_with_seed():
    selector = ExperimentSelector()
    surface = make_surface(tools=True, retrieval=True, sample="General knowledge about the product.")
    hypotheses = [chain_hypothesis()]
    state = CampaignState()
    coverage = CoverageTracker()
    picks = [selector.select(hypotheses, surface, state, coverage, random.Random(9), 0) for _ in range(3)]
    assert all(p.plugin == picks[0].plugin for p in picks)
    assert all(p.hypothesis_id == picks[0].hypothesis_id for p in picks)


def test_selector_ignores_terminal_hypotheses():
    selector = ExperimentSelector()
    surface = make_surface(tools=True)
    h = AttackHypothesis("t1", "a", "tool_authorization", "e", ("tool_result",), ("unsafe_tool_call.shell",), priority=1, status=HypothesisStatus.CONFIRMED, tested=True)
    coverage = CoverageTracker()
    assert selector.select([h], surface, CampaignState(), coverage, random.Random(1), 0) is None