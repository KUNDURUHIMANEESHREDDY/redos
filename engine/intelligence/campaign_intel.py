from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from engine.experiment.model import Experiment


@dataclass(slots=True)
class CampaignIntelligence:
    decisions: list[dict] = field(default_factory=list)
    outcomes: dict[str, str] = field(default_factory=dict)
    by_family: dict[str, dict[str, int]] = field(default_factory=dict)
    experiment_ids: list[str] = field(default_factory=list)

    def record_decision(self, experiment: Experiment, surface: Any, runner_ups: list[Experiment]) -> None:
        self.decisions.append(
            {
                "experiment_id": experiment.experiment_id,
                "hypothesis_id": experiment.hypothesis_id,
                "plugin": experiment.plugin,
                "reasoning": experiment.reasoning,
                "variation": experiment.variation.to_dict() if experiment.variation else None,
                "chosen": {
                    "information_gain": experiment.expected_information_gain,
                    "exploitability": experiment.exploitability,
                    "impact": experiment.potential_impact,
                    "cost_estimate": experiment.cost_estimate,
                },
                "runner_ups": [e.plugin for e in runner_ups],
            }
        )
        self.experiment_ids.append(experiment.experiment_id)

    def record_outcome(self, experiment: Experiment, result: Any) -> None:
        outcome = result.outcome.value
        self.outcomes[experiment.plugin] = outcome
        family = experiment.plugin.split(".", 1)[0]
        counts = self.by_family.setdefault(family, {"success": 0, "failure": 0, "indeterminate": 0})
        counts[outcome] = counts.get(outcome, 0) + 1

    def summary(self) -> dict[str, Any]:
        tested = sorted(self.outcomes)
        succeeded = [p for p, o in self.outcomes.items() if o == "success"]
        failed = [p for p, o in self.outcomes.items() if o == "failure"]
        indeterminate = [p for p, o in self.outcomes.items() if o == "indeterminate"]
        return {
            "experiments": len(self.experiment_ids),
            "tested": tested,
            "succeeded": succeeded,
            "failed": failed,
            "indeterminate": indeterminate,
            "by_family": dict(self.by_family),
            "why_next": list(self.decisions),
            "coverage_gaps": sorted({family for family, counts in self.by_family.items() if counts.get("success", 0) == 0}),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "decisions": list(self.decisions),
            "outcomes": dict(self.outcomes),
            "by_family": dict(self.by_family),
            "experiment_ids": list(self.experiment_ids),
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "CampaignIntelligence":
        intel = CampaignIntelligence()
        intel.decisions = list(data.get("decisions") or [])
        intel.outcomes = dict(data.get("outcomes") or {})
        intel.by_family = dict(data.get("by_family") or {})
        intel.experiment_ids = list(data.get("experiment_ids") or [])
        return intel