from __future__ import annotations

import pytest

from engine.campaigns import Campaign, CampaignBudget, CampaignConfig, CampaignRunner, CampaignStatus
from engine.campaigns.replay import build_campaign_manifest, config_from_manifest, replay_campaign, verify_campaign_manifest
from engine.chaining import DependencyGraph
from engine.model.attack import TargetKind
from engine.model.errors import ReplayMismatch
from engine.orchestration import AttackOrchestrator
from engine.security import FindingsGateway, InMemoryFindingSink
from engine.targets import RAGTargetConfig, TargetConfig


def rag_tool_target(chat_server) -> RAGTargetConfig:
    return RAGTargetConfig(
        target_id="acceptance-rag",
        kind=TargetKind.RAG,
        base_url=chat_server,
        model="test-model",
        retrieval_url=f"{chat_server}/retrieve",
        extra={"tool_invoke_url": chat_server},
    )


def bare_target(chat_server) -> TargetConfig:
    return TargetConfig(
        target_id="acceptance-bare",
        kind=TargetKind.OPENAI_COMPATIBLE,
        base_url=chat_server,
        model="test-model",
    )


def make_campaign(target, *, seed=7, budget=None, strategy="observation_driven") -> CampaignConfig:
    return CampaignConfig.create(
        name="acceptance-campaign",
        target=target,
        strategy=strategy,
        seed=seed,
        budget=budget or CampaignBudget(max_attacks=6),
    )


async def test_campaign_full_journey_probe_to_tool_to_rag(chat_server, vault):
    target = rag_tool_target(chat_server)
    orch = AttackOrchestrator(vault=vault)
    gateway = FindingsGateway(InMemoryFindingSink())
    runner = CampaignRunner(orchestrator=orch)
    campaign = Campaign(config=make_campaign(target))

    result = await runner.run(campaign, gateway=gateway)

    assert result.status in (CampaignStatus.COMPLETED, CampaignStatus.STOPPED)
    assert len(result.steps) >= 4

    step0 = result.steps[0]
    assert step0.plugin == "data_leakage.probe"
    assert step0.outcome in ("success", "failure")

    step1 = result.steps[1]
    assert step1.plugin == "unsafe_tool_call.shell"
    assert step1.depends_on == 0
    assert "tool capability" in step1.reasoning
    assert "data_leakage.probe" in step1.reasoning

    step2 = result.steps[2]
    assert step2.plugin == "unsafe_tool_call.sql"
    assert step2.depends_on == 1
    assert step2.tool_evidence >= 1
    assert "tool execution observed" in step2.reasoning

    step3 = result.steps[3]
    assert step3.plugin == "rag_poisoning.plant"
    assert step3.depends_on == 0
    assert "retrieval" in step3.reasoning

    assert step0.execution_id != step1.execution_id != step2.execution_id != step3.execution_id
    for step in result.steps:
        assert step.execution_id

    findings = result.evidence["findings"]
    assert len(findings) >= 2
    for finding in findings:
        assert finding["validation_valid"] is True
        assert finding["outcome"] == "success"

    links = result.evidence["links"]
    assert any(l["from"] == "data_leakage.probe" and l["to"] == "unsafe_tool_call.shell" for l in links)
    assert any(l["from"] == "unsafe_tool_call.shell" and l["to"] == "unsafe_tool_call.sql" for l in links)


async def test_campaign_adapts_attack_sequence_to_target_capabilities(chat_server, vault):
    tooled = make_campaign(rag_tool_target(chat_server))
    bare = make_campaign(bare_target(chat_server))

    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch)

    campaign_tooled = await runner.run(Campaign(config=tooled))
    campaign_bare = await runner.run(Campaign(config=bare))

    plugins_tooled = [s.plugin for s in campaign_tooled.steps]
    plugins_bare = [s.plugin for s in campaign_bare.steps]

    assert plugins_tooled[0] == "data_leakage.probe"
    assert plugins_bare[0] == "data_leakage.probe"
    assert "unsafe_tool_call.shell" in plugins_tooled
    assert "unsafe_tool_call.shell" not in plugins_bare
    assert "rag_poisoning.plant" in plugins_tooled
    assert "rag_poisoning.plant" not in plugins_bare
    assert plugins_tooled != plugins_bare


async def test_campaign_selection_is_deterministic_for_same_seed(chat_server, vault):
    target = rag_tool_target(chat_server)
    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch)

    first = await runner.run(Campaign(config=make_campaign(target)))
    second = await runner.run(Campaign(config=make_campaign(target)))

    assert [s.plugin for s in first.steps] == [s.plugin for s in second.steps]


async def test_campaign_manifest_replay_and_tamper_detection(chat_server, vault):
    target = rag_tool_target(chat_server)
    config = make_campaign(target)
    manifest = build_campaign_manifest(config)

    verify_campaign_manifest(config, manifest)
    rebuilt = config_from_manifest(manifest)
    assert rebuilt.replay_hash() == manifest.campaign_replay_hash

    tampered = CampaignConfig(
        campaign_id=rebuilt.campaign_id,
        name=rebuilt.name,
        target=rebuilt.target,
        strategy=rebuilt.strategy,
        seed=rebuilt.seed + 1,
        budget=rebuilt.budget,
    )
    with pytest.raises(ReplayMismatch):
        verify_campaign_manifest(tampered, manifest)

    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch)
    campaign = await replay_campaign(manifest, runner)
    assert campaign.status in (CampaignStatus.COMPLETED, CampaignStatus.STOPPED)
    assert len(campaign.steps) > 0


async def test_dependency_graph_gates_capability_specific_attacks(chat_server, vault):
    graph = DependencyGraph()
    target = bare_target(chat_server)
    orch = AttackOrchestrator(vault=vault)
    runner = CampaignRunner(orchestrator=orch)
    campaign = Campaign(config=make_campaign(target))
    await runner.run(campaign)

    profile = campaign.evidence["profile"]
    assert profile["tool_capability"] is False
    assert profile["retrieval_supported"] is False
    assert graph.satisfied("rag_poisoning.plant", __import__("engine.reconnaissance.profile", fromlist=["profile_from_dict"]).profile_from_dict(profile)) is False
    assert graph.satisfied("unsafe_tool_call.sql", __import__("engine.reconnaissance.profile", fromlist=["profile_from_dict"]).profile_from_dict(profile)) is False