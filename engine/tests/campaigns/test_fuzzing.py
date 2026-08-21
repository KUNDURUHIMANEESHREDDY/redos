from __future__ import annotations

from engine.fuzzing import AdaptiveFuzzer, SeedManager
from engine.orchestration import AttackOrchestrator


def test_seed_manager_deduplicates_and_tracks_usage():
    manager = SeedManager()
    assert manager.add("a.one", "abc") == manager.digest("abc")
    assert manager.add("a.one", "abc") == manager.digest("abc")
    assert manager.unused("a.one") == ["abc"]
    manager.mark_used("a.one", "abc")
    assert manager.unused("a.one") == []
    assert manager.add("a.one", "def") != manager.digest("abc")
    assert len(manager.digest("abc")) == 16
    assert set(manager.all_digests()) == {manager.digest("abc"), manager.digest("def")}


async def test_fuzzer_runs_against_real_target(openai_target, vault):
    fuzzer = AdaptiveFuzzer(orchestrator=AttackOrchestrator(vault=vault), max_runs=3)
    runs = await fuzzer.run(openai_target)
    assert 1 <= len(runs) <= 3
    for run in runs:
        assert run.variant_id
        assert run.recipe
        assert run.outcome in ("success", "failure", "indeterminate")
        assert run.execution_id


async def test_fuzzer_respects_max_runs(openai_target, vault):
    fuzzer = AdaptiveFuzzer(orchestrator=AttackOrchestrator(vault=vault), max_runs=0)
    runs = await fuzzer.run(openai_target)
    assert runs == []


async def test_fuzzer_deterministic_variants(openai_target, vault):
    first = await AdaptiveFuzzer(orchestrator=AttackOrchestrator(vault=vault), max_runs=2).run(openai_target)
    second = await AdaptiveFuzzer(orchestrator=AttackOrchestrator(vault=vault), max_runs=2).run(openai_target)
    assert [r.variant_id for r in first] == [r.variant_id for r in second]