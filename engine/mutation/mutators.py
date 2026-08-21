from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Callable, Iterable

from engine.mutation import encodings

MutationFn = Callable[[str, random.Random], str]

_REGISTRY: dict[str, MutationFn] = {
    "base64": lambda text, rng: encodings.base64_encode(text),
    "hex": lambda text, rng: encodings.hex_encode(text),
    "url_encode": lambda text, rng: encodings.url_encode(text),
    "rot13": lambda text, rng: encodings.rot13(text),
    "fullwidth": lambda text, rng: encodings.unicode_fullwidth(text),
    "homoglyph": lambda text, rng: encodings.homoglyph_swap(text, rng),
    "whitespace_inject": lambda text, rng: encodings.whitespace_inject(text, rng),
    "case_swap": lambda text, rng: encodings.case_swap(text, rng),
    "char_repeat": lambda text, rng: encodings.char_repeat(text, rng),
    "interleave": lambda text, rng: encodings.interleave(text),
}


def registered_mutations() -> list[str]:
    return sorted(_REGISTRY)


def register_mutation(name: str, fn: MutationFn) -> None:
    _REGISTRY[name] = fn


@dataclass(frozen=True, slots=True)
class Mutant:
    variant_id: str
    base_text: str
    text: str
    recipe: tuple[str, ...]
    seed: int

    def digest(self) -> str:
        return hashlib.sha256(f"{self.variant_id}{self.text}{self.recipe}".encode("utf-8")).hexdigest()


@dataclass(slots=True)
class MutationPipeline:
    seed: int = 0
    mutations: list[str] = field(default_factory=list)
    max_depth: int = 2

    def __post_init__(self) -> None:
        if not self.mutations:
            self.mutations = registered_mutations()

    def apply(self, text: str, recipe: tuple[str, ...]) -> str:
        rng = random.Random(self.seed)
        for name in recipe:
            fn = _REGISTRY.get(name)
            if fn is None:
                raise ValueError(f"unknown mutation: {name!r}")
            text = fn(text, rng)
        return text

    def variants(self, base_text: str, *, depth: int | None = None) -> list[Mutant]:
        depth = self.max_depth if depth is None else depth
        rng = random.Random(self.seed)
        seen: set[str] = set()
        mutants: list[Mutant] = []
        for d in range(1, depth + 1):
            for _ in range(max(3, 8 // d)):
                recipe = tuple(rng.sample(self.mutations, d))
                if recipe in seen:
                    continue
                seen.add(recipe)
                variant_id = hashlib.sha256(f"{self.seed}:{recipe}".encode("utf-8")).hexdigest()[:16]
                mutated = self.apply(base_text, recipe)
                mutants.append(Mutant(variant_id=variant_id, base_text=base_text, text=mutated, recipe=recipe, seed=self.seed))
        return mutants

    def chain(self, texts: Iterable[str], recipe: tuple[str, ...]) -> list[str]:
        return [self.apply(text, recipe) for text in texts]