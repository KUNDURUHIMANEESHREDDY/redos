from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from engine.adaptive.state import CampaignState
from engine.adaptive.variation import EvidenceVariationGenerator, VariationSpec
from engine.attack_surface.model import AttackSurface
from engine.attacks.registry import PLUGIN_REGISTRY
from engine.chaining.cross_family import CROSS_FAMILY_CHAIN
from engine.chaining.graph import DependencyGraph
from engine.coverage import CoverageTracker
from engine.experiment.model import Experiment
from engine.experiment.scoring import score_candidate
from engine.hypotheses.model import AttackHypothesis, HypothesisStatus
from engine.model.attack import AttackType

CHAIN_PLUGINS = [plugin for _, plugin in CROSS_FAMILY_CHAIN]


def _is_chain_hypothesis(hypothesis: AttackHypothesis) -> bool:
    return list(hypothesis.candidate_attacks) == CHAIN_PLUGINS


@dataclass(slots=True)
class ExperimentSelector:
    graph: DependencyGraph = field(default_factory=DependencyGraph)
    variation_generator: EvidenceVariationGenerator | None = None

    def __post_init__(self) -> None:
        self.variation_generator = self.variation_generator or EvidenceVariationGenerator()

    def select(
        self,
        hypotheses: list[AttackHypothesis],
        surface: AttackSurface,
        state: CampaignState,
        coverage: CoverageTracker,
        rng: random.Random,
        step_index: int,
    ) -> Experiment | None:
        ordered = sorted(hypotheses, key=lambda h: (h.priority, -h.confidence))
        for hypothesis in ordered:
            if self._skip(hypothesis, coverage):
                continue
            stage = self._next_chain_stage(hypothesis, coverage)
            if stage is not None and self.graph.satisfied(stage, surface):
                return self._build(hypothesis, stage, coverage, surface, rng, step_index, is_chain=True)

        candidates: list[tuple[float, Experiment]] = []
        for hypothesis in ordered:
            if self._skip(hypothesis, coverage):
                continue
            for plugin in hypothesis.candidate_attacks:
                if not self.graph.satisfied(plugin, surface):
                    continue
                variation = self._variation_for(plugin, coverage, surface)
                if coverage.tried(plugin) and variation is None:
                    continue
                score = score_candidate(plugin, surface, coverage, is_variation=variation is not None)
                experiment = self._build(hypothesis, plugin, coverage, surface, rng, step_index, is_chain=False, variation=variation, score=score)
                candidates.append((score.total, experiment))

        if not candidates:
            return None
        best = max(score for score, _ in candidates)
        pool = [exp for score, exp in candidates if score >= best - 1e-9]
        return rng.choice(pool)

    def _skip(self, hypothesis: AttackHypothesis, coverage: CoverageTracker) -> bool:
        if _is_chain_hypothesis(hypothesis):
            return hypothesis.tested and all_plugins_tried(hypothesis, coverage)
        if hypothesis.status.is_terminal() and hypothesis.tested:
            return True
        if hypothesis.tested and hypothesis.status != HypothesisStatus.PROPOSED:
            return True
        return False

    def _next_chain_stage(self, hypothesis: AttackHypothesis, coverage: CoverageTracker) -> str | None:
        if not _is_chain_hypothesis(hypothesis):
            return None
        for plugin in hypothesis.candidate_attacks:
            if not coverage.tried(plugin):
                return plugin
        return None

    def _variation_for(self, plugin: str, coverage: CoverageTracker, surface: AttackSurface) -> VariationSpec | None:
        attempts = coverage.attempts.get(plugin)
        if attempts and len(attempts) == 1:
            return self.variation_generator.generate(plugin, surface)
        return None

    def _build(
        self,
        hypothesis: AttackHypothesis,
        plugin: str,
        coverage: CoverageTracker,
        surface: AttackSurface,
        rng: random.Random,
        step_index: int,
        *,
        is_chain: bool,
        variation: VariationSpec | None = None,
        score: Any | None = None,
    ) -> Experiment:
        if score is None:
            score = score_candidate(plugin, surface, coverage, is_variation=variation is not None)
        return Experiment(
            experiment_id=uuid4().hex[:16],
            hypothesis_id=hypothesis.hypothesis_id,
            plugin=plugin,
            attack_type=self._attack_type(plugin),
            params=self._params(plugin, variation),
            expected_information_gain=score.information_gain,
            exploitability=score.exploitability,
            potential_impact=score.impact,
            cost_estimate=1.0,
            reasoning=self._reasoning(hypothesis, plugin, score, variation),
            variation=variation,
            depends_on=step_index - 1 if step_index > 0 else None,
        )

    def _params(self, plugin: str, variation: VariationSpec | None) -> dict[str, Any]:
        registered = PLUGIN_REGISTRY.get(plugin)
        params = dict(registered.default_params()) if registered else {}
        if variation is not None:
            params[variation.param] = variation.text
        return params

    def _attack_type(self, plugin: str) -> AttackType:
        registered = PLUGIN_REGISTRY.get(plugin)
        if registered is None:
            return AttackType.CUSTOM
        return AttackType(registered.attack_type)

    def _reasoning(self, hypothesis: AttackHypothesis, plugin: str, score: Any, variation: VariationSpec | None) -> str:
        parts = [
            f"testing hypothesis {hypothesis.hypothesis_id!r} ({hypothesis.expected_behavior})",
            f"plugin={plugin!r}",
            f"info_gain={score.information_gain} exploitability={score.exploitability} impact={score.impact}",
        ]
        if variation is not None:
            parts.append(f"novel variation derived from {variation.derived_from}")
        return "; ".join(parts)


def all_plugins_tried(hypothesis: AttackHypothesis, coverage: CoverageTracker) -> bool:
    return all(coverage.tried(plugin) for plugin in hypothesis.candidate_attacks)