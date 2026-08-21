from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from engine.adaptive.mutator import ContextualMutator
from engine.fuzzing.seeds import SeedManager
from engine.model.attack import AttackPolicy, AttackType
from engine.model.execution import ExecutionResult
from engine.model.plan import AttackDefinition
from engine.mutation.mutators import Mutant, MutationPipeline
from engine.orchestration.orchestrator import AttackOrchestrator
from engine.targets.config import TargetConfig


@dataclass(frozen=True, slots=True)
class FuzzRun:
    variant_id: str
    recipe: tuple[str, ...]
    mutated_text: str
    outcome: str
    execution_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "recipe": list(self.recipe),
            "mutated_text": self.mutated_text,
            "outcome": self.outcome,
            "execution_id": self.execution_id,
        }


@dataclass(slots=True)
class AdaptiveFuzzer:
    orchestrator: AttackOrchestrator
    plugin: str = "prompt_injection.ignore_previous"
    param: str = "secret"
    attack_type: AttackType = AttackType.PROMPT_INJECTION
    pipeline: MutationPipeline = field(default_factory=MutationPipeline)
    seeds: SeedManager = field(default_factory=SeedManager)
    max_runs: int = 20
    max_depth: int = 2
    mutator: ContextualMutator | None = None

    def __post_init__(self) -> None:
        if self.mutator is None:
            self.mutator = ContextualMutator(pipeline=self.pipeline)

    async def run(self, target: TargetConfig, definition: AttackDefinition | None = None) -> list[FuzzRun]:
        base = definition or self._base_definition(target)
        seed_texts = self.seeds.unused(self.plugin)
        runs: list[FuzzRun] = []
        if not seed_texts:
            seed_texts = [str(dict(base.params).get(self.param, ""))]
        for depth in range(1, self.max_depth + 1):
            if len(runs) >= self.max_runs:
                break
            for seed_text in seed_texts:
                for mutant in self._variants(seed_text, depth):
                    if len(runs) >= self.max_runs:
                        break
                    result = await self._execute(base, mutant)
                    runs.append(
                        FuzzRun(
                            variant_id=mutant.variant_id,
                            recipe=mutant.recipe,
                            mutated_text=mutant.text,
                            outcome=result.outcome.value,
                            execution_id=result.execution.execution_id,
                        )
                    )
                    self.seeds.mark_used(self.plugin, seed_text)
        return runs

    def _variants(self, seed_text: str, depth: int) -> list[Mutant]:
        return self.pipeline.variants(seed_text, depth=depth)

    async def _execute(self, base: AttackDefinition, mutant: Mutant) -> ExecutionResult:
        params = dict(base.params)
        params[self.param] = mutant.text
        definition = AttackDefinition(
            attack_id=f"{self.plugin}:fuzz-{mutant.variant_id}",
            name=self.plugin,
            attack_type=self.attack_type,
            plugin=self.plugin,
            params=params,
            target=base.target,
            policy=base.policy,
        )
        return await self.orchestrator.execute(definition)

    def _base_definition(self, target: TargetConfig) -> AttackDefinition:
        registry = self.orchestrator.registry
        if registry is None:
            from engine.attacks.registry import PLUGIN_REGISTRY

            registry = PLUGIN_REGISTRY
        plugin = registry.get(self.plugin)
        params = dict(plugin.default_params()) if plugin else {}
        return AttackDefinition(
            attack_id=f"{self.plugin}:fuzz-base",
            name=self.plugin,
            attack_type=self.attack_type,
            plugin=self.plugin,
            params=params,
            target=target,
            policy=AttackPolicy(),
        )