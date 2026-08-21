from __future__ import annotations

from engine.coverage import CoverageTracker, EffectivenessScore, score_result, summarize
from engine.model.attack import AttackOutcome, AttackType


def test_coverage_tracker_tracks_attempts_and_ratio():
    tracker = CoverageTracker()
    tracker.set_available(["a.one", "a.two", "b.three"])
    assert tracker.coverage_ratio() == 0.0

    tracker.record_plugin("a.one", "success")
    tracker.record_plugin("a.two", "failure")
    assert tracker.coverage_ratio() == 2 / 3
    assert tracker.attempted("a") is True
    assert tracker.attempted("b") is False
    assert tracker.uncovered_families() == ["b"]
    assert tracker.uncovered_plugins() == ["b.three"]
    assert tracker.tried("a.one") is True


def test_coverage_tracker_outcomes_last_wins():
    tracker = CoverageTracker()
    tracker.record_plugin("a.one", "failure")
    tracker.record_plugin("a.one", "success")
    assert tracker.outcomes["a.one"] == "success"
    assert len(tracker.attempts["a.one"]) == 2


def test_score_success_beats_failure(openai_target, vault):
    import asyncio

    from engine.model.plan import AttackDefinition
    from engine.orchestration import AttackOrchestrator

    orch = AttackOrchestrator(vault=vault)
    success = asyncio.run(orch.execute(AttackDefinition.create("s", AttackType.MALICIOUS_DOCUMENT, "malicious_document.inline", {}, openai_target)))
    failure = asyncio.run(orch.execute(AttackDefinition.create("f", AttackType.DATA_LEAKAGE, "data_leakage.pii", {}, openai_target)))

    success_score = score_result(success)
    failure_score = score_result(failure)
    assert success_score.outcome == AttackOutcome.SUCCESS
    assert failure_score.outcome == AttackOutcome.FAILURE
    assert success_score.score > failure_score.score


def test_score_tool_evidence_floors_failure():
    from engine.model.execution import ExecutionResult

    result = ExecutionResult(
        execution=None,
        plan=None,
        outcome=AttackOutcome.FAILURE,
        outcome_reason="no indicator matched",
        observation=None,
    )
    score = score_result(result)
    assert score.score == 0.3


def test_score_indeterminate_is_zero():
    from engine.model.execution import ExecutionResult

    result = ExecutionResult(
        execution=None,
        plan=None,
        outcome=AttackOutcome.INDETERMINATE,
        outcome_reason="no conclusion",
        observation=None,
    )
    assert score_result(result).score == 0.0


def test_summarize_counts():
    from engine.model.execution import ExecutionResult

    def result(outcome):
        return ExecutionResult(execution=None, plan=None, outcome=outcome, outcome_reason="r", observation=None)

    summary = summarize([score_result(result(AttackOutcome.SUCCESS)), score_result(result(AttackOutcome.FAILURE)), score_result(result(AttackOutcome.INDETERMINATE))])
    assert summary["attacks"] == 3
    assert summary["successes"] == 1
    assert summary["failures"] == 1
    assert summary["indeterminate"] == 1
    assert 0 < summary["avg_score"] < 1

    assert summarize([])["attacks"] == 0