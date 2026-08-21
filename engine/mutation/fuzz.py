from __future__ import annotations

import random
from dataclasses import dataclass, field

from engine.mutation.mutators import Mutant, MutationPipeline


@dataclass(slots=True)
class Fuzzer:
    seed: int = 0
    rounds: int = 10
    mutations: list[str] = field(default_factory=list)

    def fuzz(self, base_text: str) -> list[Mutant]:
        rng = random.Random(self.seed)
        pipeline = MutationPipeline(seed=self.seed, mutations=self.mutations or None)
        mutants = pipeline.variants(base_text, depth=2)
        mutants.sort(key=lambda m: m.variant_id)
        return mutants[: self.rounds]


__all__ = ["Fuzzer", "Mutant", "MutationPipeline"]