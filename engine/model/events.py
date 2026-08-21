from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4

EventType = str


class EventTypes:
    EXECUTION_STARTED = "execution_started"
    EXECUTION_FINISHED = "execution_finished"
    PLAN_STEP = "plan_step"
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    MODEL_INTERACTION = "model_interaction"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    RETRIEVAL = "retrieval"
    ATTACK_PAYLOAD = "attack_payload"
    ATTACK_RESULT = "attack_result"
    ARTIFACT = "artifact"
    TIMEOUT = "timeout"
    CANCELLATION = "cancellation"
    ERROR = "error"
    AUDIT = "audit"


@dataclass(frozen=True, slots=True)
class EvidenceEvent:
    event_id: str
    execution_id: str
    type: EventType
    timestamp: datetime
    data: Mapping[str, Any] = field(default_factory=dict)

    @staticmethod
    def now(execution_id: str, type: EventType, data: Mapping[str, Any] | None = None) -> "EvidenceEvent":
        return EvidenceEvent(
            event_id=uuid4().hex,
            execution_id=execution_id,
            type=type,
            timestamp=datetime.now(timezone.utc),
            data=dict(data or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "execution_id": self.execution_id,
            "type": self.type,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, sort_keys=True)

    def __hash__(self) -> int:
        return hash(self.event_id)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None
