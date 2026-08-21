from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engine.campaigns.campaign import CampaignStep


@dataclass(slots=True)
class CampaignChain:
    steps: list[CampaignStep] = field(default_factory=list)

    def add(self, step: CampaignStep) -> None:
        self.steps.append(step)

    def path(self) -> list[dict[str, Any]]:
        return [
            {
                "index": step.index,
                "plugin": step.plugin,
                "attack_type": step.attack_type,
                "outcome": step.outcome,
                "reasoning": step.reasoning,
                "depends_on": step.depends_on,
                "execution_id": step.execution_id,
            }
            for step in self.steps
        ]

    def links(self) -> list[dict[str, Any]]:
        by_index = {step.index: step for step in self.steps}
        links: list[dict[str, Any]] = []
        for step in self.steps:
            if step.depends_on is not None and step.depends_on in by_index:
                trigger = by_index[step.depends_on]
                links.append(
                    {
                        "from": trigger.plugin,
                        "to": step.plugin,
                        "because": step.reasoning,
                        "from_outcome": trigger.outcome,
                    }
                )
        return links

    def escalation_path(self) -> list[dict[str, Any]]:
        order = {"data_leakage": 0, "prompt_injection": 1, "jailbreak": 2, "tool_abuse": 3, "unsafe_tool_call": 3, "rag_poisoning": 4, "agent_escalation": 5}
        path: list[dict[str, Any]] = []
        last_rank = -1
        for step in self.steps:
            family = step.plugin.split(".", 1)[0]
            rank = order.get(family, 6)
            if rank >= last_rank:
                path.append({"index": step.index, "plugin": step.plugin, "outcome": step.outcome})
                last_rank = rank
        return path