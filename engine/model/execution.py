from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from engine.model.attack import AttackObservation, AttackOutcome, CapturePolicy
from engine.model.events import EvidenceEvent, EventTypes, _stamp
from engine.model.plan import ExecutionPlan


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILURE = "failure"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    INDETERMINATE = "indeterminate"

    def is_final(self) -> bool:
        return self in (ExecutionStatus.SUCCESS, ExecutionStatus.FAILURE, ExecutionStatus.TIMED_OUT, ExecutionStatus.CANCELLED, ExecutionStatus.INDETERMINATE)


@dataclass(slots=True)
class ObservedExecution:
    execution_id: str
    target_id: str
    attack_id: str
    plan_id: str
    started_at: datetime
    finished_at: datetime | None = None
    status: ExecutionStatus = ExecutionStatus.PENDING
    events: list[EvidenceEvent] = field(default_factory=list)
    artifacts: list[EvidenceEvent] = field(default_factory=list)
    policy_capture: CapturePolicy = field(default_factory=CapturePolicy.full)

    def record(self, event: EvidenceEvent) -> EvidenceEvent:
        if self.events and event.timestamp < self.events[-1].timestamp:
            event = EvidenceEvent(
                event_id=event.event_id,
                execution_id=event.execution_id,
                type=event.type,
                timestamp=self.events[-1].timestamp,
                data=dict(event.data),
            )
        if event.type == EventTypes.ARTIFACT:
            self.artifacts.append(event)
        self.events.append(event)
        return event

    def finish(self, status: ExecutionStatus, data: Mapping[str, Any]) -> EvidenceEvent:
        event = EvidenceEvent.now(self.execution_id, EventTypes.EXECUTION_FINISHED, data)
        event = self.record(event)
        self.finished_at = max(datetime.now(timezone.utc), event.timestamp)
        self.status = status
        return event

    @property
    def tool_calls(self) -> list[dict[str, Any]]:
        return [dict(e.data) for e in self.events if e.type == EventTypes.TOOL_CALL]

    @property
    def model_interactions(self) -> list[dict[str, Any]]:
        return [dict(e.data) for e in self.events if e.type == EventTypes.MODEL_INTERACTION]

    @property
    def retrieval_events(self) -> list[dict[str, Any]]:
        return [dict(e.data) for e in self.events if e.type == EventTypes.RETRIEVAL]

    @property
    def errors(self) -> list[dict[str, Any]]:
        return [dict(e.data) for e in self.events if e.type == EventTypes.ERROR]

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "target_id": self.target_id,
            "attack_id": self.attack_id,
            "started_at": _stamp(self.started_at),
            "finished_at": _stamp(self.finished_at),
            "status": self.status.value,
            "events": [e.to_dict() for e in self.events],
            "tool_calls": self.tool_calls,
            "model_interactions": self.model_interactions,
            "retrieval_events": self.retrieval_events,
            "artifacts": [a.to_dict() for a in self.artifacts],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, sort_keys=False)


@dataclass(frozen=True, slots=True)
class EvidenceChainValidation:
    valid: bool
    violations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "violations": list(self.violations)}


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    execution: ObservedExecution
    plan: ExecutionPlan
    outcome: AttackOutcome
    outcome_reason: str
    observation: AttackObservation | None = None
    validation: EvidenceChainValidation = EvidenceChainValidation(valid=False)
    replay_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution": self.execution.to_dict(),
            "plan": self.plan.to_dict(),
            "outcome": self.outcome.value,
            "outcome_reason": self.outcome_reason,
            "observation": self.observation.to_dict() if self.observation else None,
            "validation": self.validation.to_dict(),
            "replay_hash": self.replay_hash,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, sort_keys=False)
