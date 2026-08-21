"""Acceptance: v1 -> v2 change analysis.

Scans a real emulated agent target twice (tools enabled, then tools
disabled) and verifies that the fleet layers detect the change from real
evidence: surface facts, finding sets, plugin outcomes, and replay
regression.

Finding identity across scans is the plugin that produced the finding
(per target); raw finding ids are per-submission and are not used as issue
identity, so `ChangeDetector` compares stable issue keys.
"""

from __future__ import annotations

import pytest

from engine.adapters.factory import create_adapter
from engine.discovery import AttackSurfaceDiscovery
from engine.fleet.change import ChangeDetector, TargetSnapshot
from engine.fleet.correlation import plugin_from_attack_id
from engine.fleet.regression_intel import RegressionIntelligence
from engine.model.attack import AttackPolicy, AttackType, TargetKind
from engine.model.plan import AttackDefinition
from engine.orchestration import AttackOrchestrator, build_manifest, make_regression_case
from engine.reconnaissance import ReconnaissanceRunner
from engine.security import FindingsGateway, InMemoryFindingSink
from engine.targets import TargetConfig


def definition(target, plugin, **params) -> AttackDefinition:
    return AttackDefinition(
        attack_id=f"accept-{plugin}",
        name="acceptance",
        attack_type=AttackType.PROMPT_INJECTION,
        plugin=plugin,
        params=params,
        target=target,
        policy=AttackPolicy(),
    )


def agent_config(emulator_url: str) -> TargetConfig:
    return TargetConfig(
        target_id="acceptance-agent",
        kind=TargetKind.AGENT,
        base_url=emulator_url,
        model="m",
    )


async def scan(config, vault):
    """Recon + surface discovery + direct executions of the two plugins,
    returning everything the change analysis consumes."""
    profile = await ReconnaissanceRunner(vault=vault).run(config)
    surface = await AttackSurfaceDiscovery(vault=vault).discover(config)

    orch = AttackOrchestrator(vault=vault)
    gateway = FindingsGateway(InMemoryFindingSink())
    results = {}
    findings = {}
    for plugin in ("prompt_injection.ignore_previous", "unsafe_tool_call.shell"):
        result = await orch.execute(definition(config, plugin))
        results[plugin] = result
        if result.outcome.value == "success":
            findings[plugin] = gateway.submit(result)

    snapshot = TargetSnapshot(
        target_id=config.target_id,
        facts={f.category: f.observation for f in surface.facts},
        finding_ids=frozenset(findings.keys()),
        plugin_outcomes={plugin: results[plugin].outcome.value for plugin in results},
    )
    return {
        "profile": profile,
        "surface": surface,
        "results": results,
        "findings": findings,
        "snapshot": snapshot,
    }


@pytest.mark.asyncio
async def test_v1_v2_change_analysis_detects_tool_surface_loss(agent_tools_emulator, vault):
    from engine.tests.targets.emulators import AgentToolsHandler

    config = agent_config(agent_tools_emulator)
    AgentToolsHandler.tools_enabled = True
    v1 = await scan(config, vault)

    AgentToolsHandler.tools_enabled = False
    v2 = await scan(config, vault)

    assert v1["findings"].keys() >= {"prompt_injection.ignore_previous", "unsafe_tool_call.shell"}, v1["findings"].keys()
    assert "unsafe_tool_call.shell" not in v2["findings"], "tool attack must honestly fail without tools"

    report = ChangeDetector().diff(v1["snapshot"], v2["snapshot"])
    assert report.observed_change is True
    # with no tools to list, the probe records nothing: the tool facts are
    # removed from the surface rather than changed in value
    assert "tool" in report.removed_fact_categories
    assert "tool_parameters" in report.removed_fact_categories
    assert report.resolved_findings == ("unsafe_tool_call.shell",)
    assert report.added_findings == ()
    assert "prompt_injection.ignore_previous" not in report.resolved_findings
    assert report.changed_plugin_outcomes["unsafe_tool_call.shell"] == ("success", "failure")
    assert "prompt_injection.ignore_previous" not in report.changed_plugin_outcomes


@pytest.mark.asyncio
async def test_v1_v2_regression_intelligence_detects_tool_regression(agent_tools_emulator, vault):
    from engine.tests.targets.emulators import AgentToolsHandler

    config = agent_config(agent_tools_emulator)
    orch = AttackOrchestrator(vault=vault)

    AgentToolsHandler.tools_enabled = True
    v1 = await scan(config, vault)
    shell_manifest = build_manifest(definition(config, "unsafe_tool_call.shell"))
    intel = RegressionIntelligence()
    intel.register_manifest_baseline(
        config.target_id, "unsafe_tool_call.shell", shell_manifest, v1["results"]["unsafe_tool_call.shell"]
    )

    AgentToolsHandler.tools_enabled = False
    v2 = await scan(config, vault)

    differences = await intel.evaluate(
        config.target_id, "unsafe_tool_call.shell", v2["results"]["unsafe_tool_call.shell"], orchestrator=orch
    )
    assert differences, "replay of the baseline must diverge once tools are gone"
    assert any("status" in d for d in differences)

    trend = intel.trend(
        {("acceptance-agent", "unsafe_tool_call.shell"): []},
        {("acceptance-agent", "unsafe_tool_call.shell"): differences},
    )
    assert trend.regressed == (("acceptance-agent", "unsafe_tool_call.shell"),)


@pytest.mark.asyncio
async def test_v1_v2_no_change_when_target_unchanged(agent_tools_emulator, vault):
    from engine.tests.targets.emulators import AgentToolsHandler

    config = agent_config(agent_tools_emulator)
    AgentToolsHandler.tools_enabled = True
    v1 = await scan(config, vault)
    v2 = await scan(config, vault)

    report = ChangeDetector().diff(v1["snapshot"], v2["snapshot"])
    assert report.observed_change is False
    assert report.added_findings == ()
    assert report.resolved_findings == ()