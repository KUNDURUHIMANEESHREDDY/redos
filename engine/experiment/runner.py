from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from engine.adaptive.state import CampaignState
from engine.attack_surface.model import AttackSurface
from engine.campaigns.campaign import CampaignBudget
from engine.coverage import CoverageTracker
from engine.discovery.runner import AttackSurfaceDiscovery
from engine.experiment.model import Experiment
from engine.experiment.selection import ExperimentSelector
from engine.hypotheses.generator import HypothesisGenerator
from engine.hypotheses.model import AttackHypothesis, HypothesisStatus
from engine.hypotheses.tracker import HypothesisTracker
from engine.intelligence.campaign_intel import CampaignIntelligence
from engine.model.attack import AttackPolicy
from engine.model.errors import EngineError
from engine.model.plan import AttackDefinition
from engine.orchestration.orchestrator import AttackOrchestrator
from engine.targets.config import TargetConfig

IntelligenceListener = Callable[[dict], None]


@dataclass(frozen=True, slots=True)
class ExperimentRun:
    index: int
    experiment: Experiment
    outcome: str
    outcome_reason: str
    execution_id: str
    execution_status: str
    matched_indicators: tuple[str, ...]
    tool_evidence: int
    retrieval_evidence: int
    turns_used: int
    events: int
    provenance: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "experiment": self.experiment.to_dict(),
            "outcome": self.outcome,
            "outcome_reason": self.outcome_reason,
            "execution_id": self.execution_id,
            "execution_status": self.execution_status,
            "matched_indicators": list(self.matched_indicators),
            "tool_evidence": self.tool_evidence,
            "retrieval_evidence": self.retrieval_evidence,
            "turns_used": self.turns_used,
            "events": self.events,
            "provenance": self.provenance,
        }


@dataclass(slots=True)
class IntelligenceReport:
    target_id: str
    status: str
    stopped_reason: str
    surface: AttackSurface
    hypotheses: list[AttackHypothesis]
    experiments: list[ExperimentRun]
    intelligence: CampaignIntelligence
    findings: list[Any]
    unexplored: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "status": self.status,
            "stopped_reason": self.stopped_reason,
            "surface": self.surface.to_dict(),
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "experiments": [e.to_dict() for e in self.experiments],
            "intelligence": self.intelligence.to_dict(),
            "summary": self.intelligence.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "unexplored": dict(self.unexplored),
        }


@dataclass(slots=True)
class IntelligenceRunner:
    orchestrator: AttackOrchestrator
    discovery: AttackSurfaceDiscovery | None = None
    generator: HypothesisGenerator | None = None
    selector: ExperimentSelector | None = None
    tracker: HypothesisTracker | None = None
    budget: CampaignBudget = field(default_factory=lambda: CampaignBudget(max_attacks=10))
    seed: int = 0
    listener: IntelligenceListener | None = None
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)

    def __post_init__(self) -> None:
        self.discovery = self.discovery or AttackSurfaceDiscovery(vault=self.orchestrator.vault)
        self.generator = self.generator or HypothesisGenerator()
        self.selector = self.selector or ExperimentSelector()
        self.tracker = self.tracker or HypothesisTracker()

    def _emit(self, event: dict) -> None:
        if self.listener is not None:
            self.listener(event)

    def cancel(self) -> None:
        self.cancel_event.set()

    def _refresh_hypotheses(self, surface: AttackSurface, state: CampaignState) -> list[AttackHypothesis]:
        generated = self.generator.generate(surface, observations=state.observations)
        for hypothesis in generated:
            self.tracker.register_or_reuse(hypothesis)
        return list(self.tracker.hypotheses)

    def _enrich_from_execution(self, surface: AttackSurface, result: Any) -> None:
        for event in result.execution.events:
            if event.type == "retrieval":
                for chunk in event.data.get("chunks", []):
                    text = chunk.get("text", "") if isinstance(chunk, dict) else str(chunk)
                    if text and text[:200] not in surface.retrieval_sample:
                        surface.retrieval_sample.append(text[:200])
            elif event.type == "tool_result":
                for key in ("tool_result",):
                    output = event.data.get("output")
                    if output:
                        surface.notes.setdefault("observed_tool_outputs", []).append(str(output)[:200])

    async def run(self, target: TargetConfig, *, gateway: Any = None) -> IntelligenceReport:
        rng = random.Random(self.seed)
        state = CampaignState()
        coverage = CoverageTracker()
        coverage.set_available([key for key in self._registry_keys()])
        intel = CampaignIntelligence()
        experiments: list[ExperimentRun] = []
        findings: list[Any] = []
        started_at = datetime.now(timezone.utc)
        deadline = started_at.timestamp() + self.budget.max_duration_s
        status = "completed"
        stopped_reason = "all hypotheses explored"

        self._emit({"action": "intelligence.discovery.start", "target_id": target.target_id})
        surface = await self.discovery.discover(target)
        self._emit({"action": "intelligence.discovery.done", "target_id": target.target_id, "surface": surface.to_dict()})

        step_index = 0
        while True:
            await asyncio.sleep(0)
            if self.cancel_event.is_set():
                status = "cancelled"
                stopped_reason = "cancellation requested"
                break
            if len(experiments) >= self.budget.max_attacks:
                status = "stopped"
                stopped_reason = f"experiment budget exhausted ({self.budget.max_attacks})"
                break
            if datetime.now(timezone.utc).timestamp() >= deadline:
                status = "stopped"
                stopped_reason = f"duration budget exhausted ({self.budget.max_duration_s}s)"
                break

            hypotheses = self._refresh_hypotheses(surface, state)
            experiment = self.selector.select(hypotheses, surface, state, coverage, rng, step_index)
            if experiment is None:
                break

            self._emit(
                {
                    "action": "intelligence.experiment.started",
                    "index": step_index,
                    "plugin": experiment.plugin,
                    "hypothesis_id": experiment.hypothesis_id,
                    "reasoning": experiment.reasoning,
                }
            )
            intel.record_decision(experiment, surface, [])

            definition = AttackDefinition(
                attack_id=f"{experiment.plugin}:exp-{step_index}",
                name=experiment.plugin,
                attack_type=experiment.attack_type,
                plugin=experiment.plugin,
                params=dict(experiment.params),
                target=target,
                policy=AttackPolicy(),
            )
            result = await self.orchestrator.execute(definition, cancel_event=self.cancel_event)

            coverage.record_plugin(experiment.plugin, result.outcome.value)
            state.learn(experiment.plugin, result)
            intel.record_outcome(experiment, result)
            self.tracker.update(experiment.hypothesis_id, state.get(experiment.plugin))
            self._enrich_from_execution(surface, result)

            if gateway is not None and result.outcome.value == "success":
                findings.append(gateway.submit(result))

            provenance = "live"
            for event in result.execution.events:
                if event.data.get("provenance"):
                    provenance = event.data["provenance"]
                    break

            runs = ExperimentRun(
                index=step_index,
                experiment=experiment,
                outcome=result.outcome.value,
                outcome_reason=result.outcome_reason,
                execution_id=result.execution.execution_id,
                execution_status=result.execution.status.value,
                matched_indicators=tuple(result.observation.matched_indicators) if result.observation else (),
                tool_evidence=sum(1 for e in result.execution.events if e.type == "tool_result"),
                retrieval_evidence=sum(1 for e in result.execution.events if e.type == "retrieval"),
                turns_used=len(result.execution.model_interactions),
                events=len(result.execution.events),
                provenance=provenance,
            )
            experiments.append(runs)
            self._emit(
                {
                    "action": "intelligence.experiment.finished",
                    "index": step_index,
                    "plugin": experiment.plugin,
                    "outcome": runs.outcome,
                }
            )
            step_index += 1

        return IntelligenceReport(
            target_id=target.target_id,
            status=status,
            stopped_reason=stopped_reason,
            surface=surface,
            hypotheses=hypotheses,
            experiments=experiments,
            intelligence=intel,
            findings=findings,
            unexplored={
                "plugins": coverage.uncovered_plugins(),
                "families": coverage.uncovered_families(),
                "untested_hypotheses": [h.hypothesis_id for h in self.tracker.hypotheses if not h.tested],
            },
        )

    def _registry_keys(self) -> list[str]:
        registry = self.orchestrator.registry
        if registry is None:
            from engine.attacks.registry import PLUGIN_REGISTRY

            registry = PLUGIN_REGISTRY
        return list(registry.keys())