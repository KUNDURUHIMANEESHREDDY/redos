"""Run the full validation matrix and print real measured metrics.

Not collected by pytest (does not match test_*). Run directly:
    python -m engine.tests.targets.metrics_report
"""

from __future__ import annotations

import asyncio
import json

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

from .conftest import (
    agent_tools,
    anthropic,
    auth_target,
    custom_http,
    ollama,
    openai_bare,
    rag_variant,
    strict_no_tools,
)
from .emulators import GOOD_AUTH_KEY, AgentToolsHandler, AnthropicHandler, AuthHandler, CustomProtocolHandler, FlakyHandler, MalformedMissingChoicesHandler, MalformedNonJsonHandler, MalformedWrongTypeHandler, OllamaHandler, OpenAIBareHandler, RagVariantHandler, StrictNoToolsHandler, TimeoutHandler, shutdown, serve


def start_emulators():
    servers = {}
    urls = {}
    for name, handler in {
        "openai_bare": OpenAIBareHandler,
        "agent_tools": AgentToolsHandler,
        "anthropic": AnthropicHandler,
        "ollama": OllamaHandler,
        "custom": CustomProtocolHandler,
        "rag_variant": RagVariantHandler,
        "auth": AuthHandler,
        "timeout": TimeoutHandler,
        "malformed_non_json": MalformedNonJsonHandler,
        "malformed_missing_choices": MalformedMissingChoicesHandler,
        "malformed_wrong_type": MalformedWrongTypeHandler,
        "flaky": FlakyHandler,
        "strict_no_tools": StrictNoToolsHandler,
    }.items():
        urls[name], servers[name] = serve(handler)
    return urls, servers


async def measure_one(name, config, vault, *, budget=6, seed=5):
    registry = TargetRegistry()
    registry.register(config)
    profile = await ReconnaissanceRunner(vault=vault).run(config)
    surface = await AttackSurfaceDiscovery(vault=vault).discover(config)
    hypotheses = HypothesisGenerator().generate(surface)

    gateway = FindingsGateway(InMemoryFindingSink())
    runner = IntelligenceRunner(
        orchestrator=AttackOrchestrator(vault=vault),
        budget=CampaignBudget(max_attacks=budget),
        seed=seed,
    )
    report = await runner.run(config, gateway=gateway)

    graph = DependencyGraph()
    evidence_events = [r.events for r in report.experiments]
    tool_evidence = sum(1 for r in report.experiments if r.tool_evidence)
    retrieval_evidence = sum(1 for r in report.experiments if r.retrieval_evidence)
    gated = all(graph.satisfied(r.experiment.plugin, surface) for r in report.experiments)

    reproduction = None
    regression = None
    if report.experiments:
        exp = report.experiments[0].experiment
        orch = AttackOrchestrator(vault=vault)
        definition = AttackDefinition(
            attack_id=f"{exp.plugin}:metrics",
            name=exp.plugin,
            attack_type=exp.attack_type,
            plugin=exp.plugin,
            params=dict(exp.params),
            target=config,
            policy=AttackPolicy(),
        )
        manifest = build_manifest(definition)
        baseline = await orch.execute(definition)
        case = make_regression_case("metrics-repro", manifest, baseline)
        replayed = await replay_attack(manifest, orch)
        reproduction = replayed.outcome == baseline.outcome
        regression = compare_regression(case, replayed) == []

    probes = {f.category: f.observation for f in surface.facts}
    return {
        "target": name,
        "kind": config.kind.value,
        "registration_fingerprint": config.fingerprint()[:12],
        "discovery": {
            "chat_observed": surface.chat_observed,
            "tool_capability": surface.tool_capability,
            "tools_observed": list(surface.tool_names),
            "retrieval_supported": surface.retrieval_supported,
            "facts": len(surface.facts),
            "probes": probes,
        },
        "hypotheses": len(hypotheses),
        "experiments": len(report.experiments),
        "outcomes": {o: sum(1 for r in report.experiments if r.outcome == o) for o in ("success", "failure", "indeterminate")},
        "coverage": {
            "uncovered_plugins": len(report.unexplored["plugins"]),
            "uncovered_families": len(report.unexplored["families"]),
            "untested_hypotheses": len(report.unexplored["untested_hypotheses"]),
        },
        "findings": len(report.findings),
        "evidence": {
            "avg_events_per_experiment": round(sum(evidence_events) / len(evidence_events), 1) if evidence_events else 0,
            "experiments_with_tool_evidence": tool_evidence,
            "experiments_with_retrieval_evidence": retrieval_evidence,
            "all_capability_gated": gated,
        },
        "reproduction_success": reproduction,
        "regression_clean": regression,
    }


async def main():
    vault = None
    from engine.security import SecretsVault

    vault = SecretsVault()
    vault.register("val_api_key", GOOD_AUTH_KEY)
    urls, servers = start_emulators()
    try:
        builders = {
            "openai_bare": openai_bare(urls),
            "agent_tools": agent_tools(urls),
            "anthropic": anthropic(urls),
            "ollama": ollama(urls),
            "custom_http": custom_http(urls),
            "rag_variant": rag_variant(urls),
            "auth": auth_target(urls),
            "strict_no_tools": strict_no_tools(urls),
        }
        results = {}
        for name, config in builders.items():
            results[name] = await measure_one(name, config, vault)
        print(json.dumps(results, indent=2))
    finally:
        for server in servers.values():
            shutdown(server)


if __name__ == "__main__":
    asyncio.run(main())