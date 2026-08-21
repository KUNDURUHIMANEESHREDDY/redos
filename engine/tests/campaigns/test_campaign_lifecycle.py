from __future__ import annotations

import asyncio

import pytest

from engine.campaigns import Campaign, CampaignBudget, CampaignConfig, CampaignRunner, CampaignStatus
from engine.orchestration import AttackOrchestrator
from engine.strategies import CoverageDrivenStrategy


def make_campaign(target, budget, *, strategy="observation_driven", seed=11) -> CampaignConfig:
    return CampaignConfig.create(name="lifecycle", target=target, strategy=strategy, seed=seed, budget=budget)


async def test_attack_budget_stops_campaign(openai_target, vault):
    budget = CampaignBudget(max_attacks=3)
    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch)
    campaign = await runner.run(Campaign(config=make_campaign(openai_target, budget)))

    assert campaign.status == CampaignStatus.STOPPED
    assert "attack budget exhausted" in campaign.stopped_reason
    assert len(campaign.steps) == 3
    assert campaign.finished_at is not None


async def test_turn_budget_stops_campaign(openai_target, vault):
    budget = CampaignBudget(max_attacks=20, max_turns_total=2)
    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch)
    campaign = await runner.run(Campaign(config=make_campaign(openai_target, budget)))

    assert campaign.status == CampaignStatus.STOPPED
    assert "turn budget exhausted" in campaign.stopped_reason
    assert len(campaign.steps) == 2
    assert campaign.turns_used() == 2


async def test_cost_budget_stops_campaign(openai_target, vault):
    budget = CampaignBudget(max_attacks=20, cost_per_turn=1.0, max_cost=3.0)
    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch)
    campaign = await runner.run(Campaign(config=make_campaign(openai_target, budget)))

    assert campaign.status == CampaignStatus.STOPPED
    assert "cost budget exhausted" in campaign.stopped_reason
    assert len(campaign.steps) == 3
    assert campaign.estimated_cost() == 3.0
    for step in campaign.steps:
        assert step.estimated_cost == step.turns_used


async def test_duration_budget_stops_campaign(openai_target, vault):
    budget = CampaignBudget(max_attacks=20, max_duration_s=0.0)
    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch)
    campaign = await runner.run(Campaign(config=make_campaign(openai_target, budget)))

    assert campaign.status == CampaignStatus.STOPPED
    assert "duration budget exhausted" in campaign.stopped_reason
    assert len(campaign.steps) == 0


async def test_campaign_completes_when_all_techniques_attempted(openai_target, vault):
    budget = CampaignBudget(max_attacks=50)
    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch)
    campaign = await runner.run(Campaign(config=make_campaign(openai_target, budget)))

    assert campaign.status == CampaignStatus.COMPLETED
    assert "all eligible techniques attempted" in campaign.stopped_reason
    assert len(campaign.steps) > 0


async def test_campaign_pause_and_resume(openai_target, vault):
    budget = CampaignBudget(max_attacks=4)
    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch)
    first_step_done = asyncio.Event()
    paused = asyncio.Event()

    def listener(event):
        if event.get("action") == "campaign.step.finished" and event.get("index") == 0:
            runner.pause()
            first_step_done.set()
            paused.set()

    runner.listener = listener
    task = asyncio.create_task(runner.run(Campaign(config=make_campaign(openai_target, budget))))
    await paused.wait()
    await first_step_done.wait()
    assert not runner.pause_event.is_set()
    runner.resume()
    campaign = await task

    assert campaign.status.is_terminal()
    assert len(campaign.steps) >= 2


async def test_campaign_cancel_stops_loop(openai_target, vault):
    budget = CampaignBudget(max_attacks=20)
    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch)
    cancelled = asyncio.Event()

    def listener(event):
        if event.get("action") == "campaign.step.finished" and event.get("index") == 0:
            runner.cancel()
            cancelled.set()

    runner.listener = listener
    task = asyncio.create_task(runner.run(Campaign(config=make_campaign(openai_target, budget))))
    await cancelled.wait()
    campaign = await task

    assert campaign.status == CampaignStatus.CANCELLED
    assert "cancellation requested" in campaign.stopped_reason
    assert len(campaign.steps) == 1


async def test_campaign_parallel_batch_execution(openai_target, vault):
    budget = CampaignBudget(max_attacks=4)
    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch, strategy=CoverageDrivenStrategy(), concurrency=2)
    campaign = await runner.run(Campaign(config=make_campaign(openai_target, budget, strategy="coverage_driven")))

    assert campaign.status == CampaignStatus.STOPPED
    assert len(campaign.steps) == 4
    execution_ids = [s.execution_id for s in campaign.steps]
    assert len(set(execution_ids)) == 4
    for step in campaign.steps:
        assert step.outcome in ("success", "failure", "indeterminate")