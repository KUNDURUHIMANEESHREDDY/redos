from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from engine.model.execution import ExecutionResult


@dataclass(slots=True)
class AttackObservationRecord:
    plugin: str
    attack_type: str
    outcome: str
    reason: str
    matched_indicators: list[str]
    tool_evidence: int
    retrieval_evidence: int
    model_interactions: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "attack_type": self.attack_type,
            "outcome": self.outcome,
            "reason": self.reason,
            "matched_indicators": list(self.matched_indicators),
            "tool_evidence": self.tool_evidence,
            "retrieval_evidence": self.retrieval_evidence,
            "model_interactions": self.model_interactions,
        }


@dataclass(slots=True)
class CampaignState:
    observations: dict[str, AttackObservationRecord] = field(default_factory=dict)

    def learn(self, plugin: str, result: ExecutionResult) -> AttackObservationRecord:
        attack_type = getattr(getattr(result.plan, "attack", None), "attack_type", None)
        record = AttackObservationRecord(
            plugin=plugin,
            attack_type=attack_type.value if attack_type is not None else "unknown",
            outcome=result.outcome.value,
            reason=result.outcome_reason,
            matched_indicators=list(result.observation.matched_indicators) if result.observation else [],
            tool_evidence=sum(1 for e in result.execution.events if e.type == "tool_result"),
            retrieval_evidence=sum(1 for e in result.execution.events if e.type == "retrieval"),
            model_interactions=len(result.execution.model_interactions),
        )
        self.observations[plugin] = record
        return record

    def get(self, plugin: str) -> AttackObservationRecord | None:
        return self.observations.get(plugin)

    def last(self) -> AttackObservationRecord | None:
        return next(reversed(self.observations.values())) if self.observations else None

    def total_tool_evidence(self) -> int:
        return sum(r.tool_evidence for r in self.observations.values())

    def family_failed_with_evidence(self, family: str) -> bool:
        records = [r for key, r in self.observations.items() if key.startswith(f"{family}.")]
        return bool(records) and all(r.outcome != "success" for r in records) and any(r.tool_evidence for r in records)

    def family_succeeded(self, family: str) -> bool:
        return any(r.outcome == "success" for key, r in self.observations.items() if key.startswith(f"{family}."))

    def to_dict(self) -> dict[str, Any]:
        return {key: record.to_dict() for key, record in self.observations.items()}