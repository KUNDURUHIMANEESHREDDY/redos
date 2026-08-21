from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from engine.adaptive.state import CampaignState
from engine.campaigns.campaign import Campaign, CampaignConfig, CampaignStatus, CampaignStep
from engine.chaining.chain import CampaignChain
from engine.chaining.graph import DependencyGraph
from engine.coverage.scoring import score_result, summarize
from engine.coverage.tracker import CoverageTracker
from engine.model.attack import AttackPolicy
from engine.model.errors import EngineError
from engine.model.plan import AttackDefinition
from engine.orchestration.orchestrator import AttackOrchestrator
from engine.reconnaissance.profile import TargetProfile
from engine.reconnaissance.runner import ReconnaissanceRunner
from engine.strategies.adaptive import ObservationDrivenStrategy
from engine.strategies.selector import AttackCandidate, CoverageDrivenStrategy, SelectionStrategy

CampaignListener = Callable[[dict], None]


@dataclass(slots=True)
class CampaignRunner:
    orchestrator: AttackOrchestrator
    strategy: SelectionStrategy = field(default_factory=ObservationDrivenStrategy)
    recon: ReconnaissanceRunner | None = None
    concurrency: int = 1
    listener: CampaignListener | None = None
    pause_event: asyncio.Event = field(default_factory=asyncio.Event)
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)

    def __post_init__(self) -> None:
        self.recon = self.recon or ReconnaissanceRunner(vault=self.orchestrator.vault, listener=self._emit if self.listener else None)

    def _emit(self, event: dict) -> None:
        if self.listener is not None:
            self.listener(event)

    def pause(self) -> None:
        self.pause_event.clear()

    def resume(self) -> None:
        self.pause_event.set()

    def cancel(self) -> None:
        self.cancel_event.set()

    async def _wait_until_resumed(self) -> None:
        await self.pause_event.wait()

    async def run(
        self,
        campaign: Campaign,
        *,
        gateway: Any = None,
        profile: TargetProfile | None = None,
    ) -> Campaign:
        config = campaign.config
        budget = config.budget
        rng = random.Random(config.seed)
        state = CampaignState()
        coverage = CoverageTracker()
        coverage.set_available([key for key in self._registry_keys() if self._allowed(config, key)])
        graph = DependencyGraph()
        chain = CampaignChain()
        findings: list[Any] = []
        scores: list[Any] = []
        self.pause_event.set()

        campaign.start()
        try:
            if profile is None:
                self._emit({"action": "campaign.recon.start", "campaign_id": config.campaign_id})
                profile = await self.recon.run(config.target)
                self._emit({"action": "campaign.recon.done", "campaign_id": config.campaign_id, "profile": profile.to_dict()})
            deadline = campaign.started_at.timestamp() + budget.max_duration_s

            while True:
                await self._wait_until_resumed()
                if self.cancel_event.is_set():
                    campaign.finish(CampaignStatus.CANCELLED, "cancellation requested")
                    break
                if len(campaign.steps) >= budget.max_attacks:
                    campaign.finish(CampaignStatus.STOPPED, f"attack budget exhausted ({budget.max_attacks})")
                    break
                if datetime.now(timezone.utc).timestamp() >= deadline:
                    campaign.finish(CampaignStatus.STOPPED, f"duration budget exhausted ({budget.max_duration_s}s)")
                    break
                if budget.max_turns_total is not None and campaign.turns_used() >= budget.max_turns_total:
                    campaign.finish(CampaignStatus.STOPPED, f"turn budget exhausted ({budget.max_turns_total})")
                    break
                if budget.max_cost is not None and campaign.estimated_cost() >= budget.max_cost:
                    campaign.finish(CampaignStatus.STOPPED, f"cost budget exhausted ({budget.max_cost})")
                    break

                candidates = self._next_candidates(strategy=self.strategy, state=state, coverage=coverage, profile=profile, rng=rng, campaign=campaign, graph=graph)
                if not candidates:
                    campaign.finish(CampaignStatus.COMPLETED, "all eligible techniques attempted")
                    break

                results = await self._execute_batch(campaign, candidates)
                for candidate, result in zip(candidates, results):
                    step = self._record_step(campaign, candidate, result, budget)
                    coverage.record_plugin(candidate.plugin, step.outcome)
                    state.learn(candidate.plugin, result)
                    chain.add(step)
                    scores.append(score_result(result))
                    if gateway is not None and result.outcome.value == "success":
                        findings.append(gateway.submit(result))
                    self._emit(
                        {
                            "action": "campaign.step.finished",
                            "campaign_id": config.campaign_id,
                            "index": step.index,
                            "plugin": step.plugin,
                            "outcome": step.outcome,
                        }
                    )

            campaign.evidence = {
                "profile": profile.to_dict(),
                "coverage": coverage.to_dict(),
                "effectiveness": summarize(scores),
                "chain": chain.path(),
                "links": chain.links(),
                "escalation_path": chain.escalation_path(),
                "findings": [f.to_dict() for f in findings],
                "budget": budget.to_dict(),
            }
            return campaign
        except EngineError as exc:
            campaign.finish(CampaignStatus.FAILED, f"{type(exc).__name__}: {exc}")
            raise
        except Exception as exc:  # noqa: BLE001
            campaign.finish(CampaignStatus.FAILED, f"{type(exc).__name__}: {exc}")
            raise

    def _registry_keys(self) -> list[str]:
        registry = self.orchestrator.registry
        if registry is None:
            from engine.attacks.registry import PLUGIN_REGISTRY

            registry = PLUGIN_REGISTRY
        return registry.keys()

    def _allowed(self, config: CampaignConfig, plugin: str) -> bool:
        return not config.plugin_filter or plugin in config.plugin_filter

    def _next_candidates(
        self,
        *,
        strategy: SelectionStrategy,
        state: CampaignState,
        coverage: CoverageTracker,
        profile: TargetProfile,
        rng: random.Random,
        campaign: Campaign,
        graph: DependencyGraph,
    ) -> list[AttackCandidate]:
        if self.concurrency <= 1:
            candidate = strategy.select(state, coverage, profile, rng, len(campaign.steps))
            return [candidate] if candidate is not None else []
        primary = strategy.select(state, coverage, profile, rng, len(campaign.steps))
        batch = [primary] if primary is not None else []
        if primary is not None:
            fallback = CoverageDrivenStrategy()
            while len(batch) < self.concurrency:
                extra = fallback.select(state, coverage, profile, rng, len(campaign.steps) + len(batch))
                if extra is None or extra.plugin in {c.plugin for c in batch}:
                    break
                batch.append(extra)
        return batch

    async def _execute_batch(self, campaign: Campaign, candidates: list[AttackCandidate]) -> list[Any]:
        if len(candidates) == 1:
            return [await self._execute_one(campaign, candidates[0])]
        return await asyncio.gather(*[self._execute_one(campaign, candidate) for candidate in candidates])

    async def _execute_one(self, campaign: Campaign, candidate: AttackCandidate) -> Any:
        index = len(campaign.steps)
        definition = AttackDefinition(
            attack_id=f"{candidate.plugin}:{index}",
            name=candidate.plugin,
            attack_type=candidate.attack_type,
            plugin=candidate.plugin,
            params=dict(candidate.params),
            target=campaign.config.target,
            policy=AttackPolicy(),
        )
        self._emit(
            {
                "action": "campaign.step.started",
                "campaign_id": campaign.config.campaign_id,
                "index": index,
                "plugin": candidate.plugin,
                "reasoning": candidate.reasoning,
            }
        )
        result = await self.orchestrator.execute(definition, cancel_event=self.cancel_event)
        return result

    def _record_step(self, campaign: Campaign, candidate: AttackCandidate, result: Any, budget: Any) -> CampaignStep:
        turns = len(result.execution.model_interactions)
        step = CampaignStep(
            index=len(campaign.steps),
            plugin=candidate.plugin,
            attack_type=candidate.attack_type.value,
            outcome=result.outcome.value,
            status=result.execution.status.value,
            reasoning=candidate.reasoning,
            execution_id=result.execution.execution_id,
            depends_on=candidate.depends_on,
            matched_indicators=tuple(result.observation.matched_indicators) if result.observation else (),
            tool_evidence=sum(1 for e in result.execution.events if e.type == "tool_result"),
            retrieval_evidence=sum(1 for e in result.execution.events if e.type == "retrieval"),
            turns_used=turns,
            estimated_cost=round(turns * budget.cost_per_turn, 4),
        )
        campaign.steps.append(step)
        return step