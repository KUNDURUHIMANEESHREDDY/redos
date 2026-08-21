from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from engine.model.attack import AttackType

STRATEGY_OBSERVATION_DRIVEN = "observation_driven"
STRATEGY_COVERAGE_DRIVEN = "coverage_driven"


@dataclass(frozen=True, slots=True)
class AttackCandidate:
    plugin: str
    attack_type: AttackType
    params: Mapping[str, Any]
    reasoning: str
    depends_on: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "attack_type": self.attack_type.value,
            "params": dict(self.params),
            "reasoning": self.reasoning,
            "depends_on": self.depends_on,
        }


class SelectionStrategy(Protocol):
    name: str

    def select(self, state: Any, coverage: Any, profile: Any, rng: Any, step_index: int) -> AttackCandidate | None:
        ...


@dataclass(slots=True)
class CoverageDrivenStrategy:
    name: str = STRATEGY_COVERAGE_DRIVEN

    def select(self, state: Any, coverage: Any, profile: Any, rng: Any, step_index: int) -> AttackCandidate | None:
        uncovered = coverage.uncovered_plugins()
        if not uncovered:
            return None
        by_family: dict[str, list[str]] = {}
        for plugin in uncovered:
            family = plugin.split(".", 1)[0]
            by_family.setdefault(family, []).append(plugin)
        untried_families = sorted(f for f in by_family if not coverage.attempted(f))
        pool = untried_families or sorted(by_family)
        rng.shuffle(pool)
        plugin = rng.choice(by_family[pool[0]])
        from engine.attacks.registry import PLUGIN_REGISTRY

        registered = PLUGIN_REGISTRY.get(plugin)
        attack_type = AttackType(registered.attack_type) if registered else AttackType.CUSTOM
        return AttackCandidate(
            plugin=plugin,
            attack_type=attack_type,
            params={},
            reasoning=f"coverage-driven: least-covered family {pool[0]!r} selected",
        )