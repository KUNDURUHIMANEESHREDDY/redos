from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from engine.adaptive.variation import VariationSpec
from engine.model.attack import AttackType


@dataclass(frozen=True, slots=True)
class Experiment:
    experiment_id: str
    hypothesis_id: str
    plugin: str
    attack_type: AttackType
    params: Mapping[str, Any]
    expected_information_gain: float
    exploitability: float
    potential_impact: float
    cost_estimate: float
    reasoning: str
    variation: VariationSpec | None = None
    depends_on: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "hypothesis_id": self.hypothesis_id,
            "plugin": self.plugin,
            "attack_type": self.attack_type.value,
            "params": dict(self.params),
            "expected_information_gain": self.expected_information_gain,
            "exploitability": self.exploitability,
            "potential_impact": self.potential_impact,
            "cost_estimate": self.cost_estimate,
            "reasoning": self.reasoning,
            "variation": self.variation.to_dict() if self.variation else None,
            "depends_on": self.depends_on,
        }