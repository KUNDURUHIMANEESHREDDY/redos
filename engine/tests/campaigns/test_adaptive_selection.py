from __future__ import annotations

import random

from engine.adaptive import AttackObservationRecord, CampaignState
from engine.chaining import DependencyGraph
from engine.coverage import CoverageTracker
from engine.model.attack import AttackType, TargetKind, ToolSpec
from engine.reconnaissance import TargetProfile
from engine.strategies import AttackCandidate, ObservationDrivenStrategy


def profile(*, tools=False, retrieval=False, tool_names=None) -> TargetProfile:
    return TargetProfile(
        target_id="t",
        adapter_kind="test",
        tools=[ToolSpec(name=name, description="", parameters={}) for name in (tool_names or [])],
        tool_capability=tools,
        retrieval_supported=retrieval,
        chat_observed=True,
    )


def state_with(plugin: str, outcome: str, tool_evidence: int = 0, retrieval_evidence: int = 0) -> CampaignState:
    state = CampaignState()
    state.observations[plugin] = AttackObservationRecord(
        plugin=plugin,
        attack_type="unknown",
        outcome=outcome,
        reason="r",
        matched_indicators=[],
        tool_evidence=tool_evidence,
        retrieval_evidence=retrieval_evidence,
        model_interactions=1,
    )
    return state


def test_strategy_probes_first_when_no_observations():
    strategy = ObservationDrivenStrategy()
    candidate = strategy.select(
        profile=profile(tools=True, retrieval=True),
        state=CampaignState(),
        coverage=CoverageTracker(),
        step_index=0,
        rng=random.Random(1),
    )
    assert candidate.plugin == "data_leakage.probe"
    assert candidate.attack_type == AttackType.DATA_LEAKAGE


def test_strategy_escalates_to_tools_after_probe():
    strategy = ObservationDrivenStrategy()
    state = state_with("data_leakage.probe", "failure")
    candidate = strategy.select(
        profile=profile(tools=True, tool_names=["shell"]),
        state=state,
        coverage=CoverageTracker(),
        step_index=1,
        rng=random.Random(1),
    )
    assert candidate.plugin == "unsafe_tool_call.shell"
    assert candidate.depends_on == 0
    assert "data_leakage.probe" in candidate.reasoning


def test_strategy_tries_alternate_tool_after_evidence_failure():
    strategy = ObservationDrivenStrategy()
    state = state_with("unsafe_tool_call.shell", "failure", tool_evidence=1)
    coverage = CoverageTracker()
    coverage.record_plugin("unsafe_tool_call.shell", "failure")
    candidate = strategy.select(
        profile=profile(tools=True, tool_names=["shell"]),
        state=state,
        coverage=coverage,
        step_index=2,
        rng=random.Random(1),
    )
    assert candidate.plugin == "unsafe_tool_call.sql"
    assert candidate.depends_on == 1
    assert "evidence" in candidate.reasoning


def test_strategy_moves_on_after_tool_family_exhausted():
    strategy = ObservationDrivenStrategy()
    state = state_with("unsafe_tool_call.shell", "failure", tool_evidence=1)
    coverage = CoverageTracker()
    coverage.record_plugin("unsafe_tool_call.shell", "failure")
    coverage.record_plugin("unsafe_tool_call.sql", "failure")
    candidate = strategy.select(
        profile=profile(tools=True, tool_names=["shell"]),
        state=state,
        coverage=coverage,
        step_index=3,
        rng=random.Random(1),
    )
    assert candidate.plugin == "prompt_injection.ignore_previous"


def test_strategy_uses_retrieval_when_available():
    strategy = ObservationDrivenStrategy()
    state = state_with("data_leakage.probe", "success")
    candidate = strategy.select(
        profile=profile(retrieval=True),
        state=state,
        coverage=CoverageTracker(),
        step_index=1,
        rng=random.Random(1),
    )
    assert candidate.plugin == "rag_poisoning.plant"
    assert "retrieval" in candidate.reasoning


def test_strategy_falls_back_to_prompt_injection():
    strategy = ObservationDrivenStrategy()
    state = state_with("data_leakage.probe", "failure")
    candidate = strategy.select(
        profile=profile(),
        state=state,
        coverage=CoverageTracker(),
        step_index=1,
        rng=random.Random(1),
    )
    assert candidate.plugin == "prompt_injection.ignore_previous"
    assert candidate.depends_on == 0


def test_strategy_returns_none_when_all_attempted():
    strategy = ObservationDrivenStrategy()
    state = state_with("data_leakage.probe", "failure")
    coverage = CoverageTracker()
    for plugin in (
        "data_leakage.probe",
        "prompt_injection.ignore_previous",
        "jailbreak.developer_mode",
        "malicious_document.inline",
        "model_manipulation.format_confusion",
        "permission.sudo",
        "agent_escalation.system_override",
    ):
        coverage.record_plugin(plugin, "failure")
    candidate = strategy.select(
        profile=profile(),
        state=state,
        coverage=coverage,
        step_index=7,
        rng=random.Random(1),
    )
    assert candidate is None


def test_state_family_failed_with_evidence():
    state = state_with("unsafe_tool_call.shell", "failure", tool_evidence=2)
    assert state.family_failed_with_evidence("unsafe_tool_call") is True
    assert state.total_tool_evidence() == 2
    assert state.family_succeeded("unsafe_tool_call") is False

    state.observations["unsafe_tool_call.sql"] = AttackObservationRecord(
        "unsafe_tool_call.sql", "unknown", "success", "r", [], 1, 0, 1
    )
    assert state.family_failed_with_evidence("unsafe_tool_call") is False
    assert state.family_succeeded("unsafe_tool_call") is True


def test_dependency_graph_requires_capabilities():
    graph = DependencyGraph()
    assert graph.requires("unsafe_tool_call.sql") == {"tools"}
    assert graph.requires("rag_poisoning.plant") == {"retrieval"}
    assert graph.requires("data_leakage.probe") == set()

    p = profile(tools=False, retrieval=False)
    assert graph.satisfied("unsafe_tool_call.sql", p) is False
    assert graph.satisfied("rag_poisoning.plant", p) is False
    assert graph.satisfied("data_leakage.probe", p) is True

    p2 = profile(tools=True, retrieval=True)
    assert graph.satisfied("unsafe_tool_call.sql", p2) is True
    assert graph.satisfied("rag_poisoning.plant", p2) is True


def test_candidate_defaults_depends_on_none():
    candidate = AttackCandidate(plugin="x.y", attack_type=AttackType.PROMPT_INJECTION, params={}, reasoning="r")
    assert candidate.depends_on is None