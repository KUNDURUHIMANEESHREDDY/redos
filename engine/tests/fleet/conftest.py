from __future__ import annotations

import pytest

from engine.tests.targets.emulators import AgentToolsHandler, shutdown, serve


@pytest.fixture(scope="session")
def agent_tools_emulator():
    url, server = serve(AgentToolsHandler)
    try:
        yield url
    finally:
        shutdown(server)


async def run_scan(config, vault, *, budget=6, seed=5):
    """Run the full pipeline for a target and return everything the fleet
    layers consume. Real executions only."""
    from engine.campaigns import CampaignBudget
    from engine.discovery import AttackSurfaceDiscovery
    from engine.experiment import IntelligenceRunner
    from engine.hypotheses import HypothesisGenerator
    from engine.orchestration import AttackOrchestrator
    from engine.reconnaissance import ReconnaissanceRunner
    from engine.security import FindingsGateway, InMemoryFindingSink

    await ReconnaissanceRunner(vault=vault).run(config)
    surface = await AttackSurfaceDiscovery(vault=vault).discover(config)
    hypotheses = HypothesisGenerator().generate(surface)

    sink = InMemoryFindingSink()
    gateway = FindingsGateway(sink)
    runner = IntelligenceRunner(
        orchestrator=AttackOrchestrator(vault=vault),
        budget=CampaignBudget(max_attacks=budget),
        seed=seed,
    )
    report = await runner.run(config, gateway=gateway)
    return {
        "surface": surface,
        "hypotheses": hypotheses,
        "report": report,
        "findings": sink.records,
    }