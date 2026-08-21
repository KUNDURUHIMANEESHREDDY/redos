from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class AttackType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_LEAKAGE = "data_leakage"
    TOOL_ABUSE = "tool_abuse"
    MALICIOUS_DOCUMENT = "malicious_document"
    RAG_POISONING = "rag_poisoning"
    AGENT_ESCALATION = "agent_escalation"
    PERMISSION = "permission"
    UNSAFE_TOOL_CALL = "unsafe_tool_call"
    MODEL_MANIPULATION = "model_manipulation"
    CUSTOM = "custom"


class TargetKind(str, Enum):
    OPENAI_COMPATIBLE = "openai_compatible"
    ANTHROPIC_COMPATIBLE = "anthropic_compatible"
    LOCAL_MODEL = "local_model"
    CUSTOM_HTTP = "custom_http"
    AGENT = "agent"
    RAG = "rag"


class CaptureMode(str, Enum):
    NONE = "none"
    OUTPUTS_ONLY = "outputs_only"
    INPUTS_AND_OUTPUTS = "inputs_and_outputs"
    FULL = "full"


class Provenance(str, Enum):
    LIVE = "live"
    MOCK = "mock"


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str = ""
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": dict(self.parameters)}


@dataclass(frozen=True, slots=True)
class ToolCall:
    call_id: str
    name: str
    arguments: str
    index: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.call_id, "name": self.name, "arguments": self.arguments, "index": self.index}


@dataclass(frozen=True, slots=True)
class ToolResult:
    call_id: str
    name: str
    ok: bool
    output: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"call_id": self.call_id, "name": self.name, "ok": self.ok, "output": self.output, "error": self.error}


@dataclass(frozen=True, slots=True)
class DocumentChunk:
    chunk_id: str
    text: str
    source: str
    score: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"chunk_id": self.chunk_id, "text": self.text, "source": self.source, "score": self.score}


@dataclass(frozen=True, slots=True)
class Message:
    role: str
    content: str
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.name:
            d["name"] = self.name
        return d


@dataclass(frozen=True, slots=True)
class ModelReply:
    content: str
    role: str = "assistant"
    tool_calls: tuple[ToolCall, ...] = ()
    stop_reason: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "role": self.role,
            "tool_calls": [tc.to_dict() for tc in self.tool_calls],
            "stop_reason": self.stop_reason,
            "raw": dict(self.raw),
        }


@dataclass(frozen=True, slots=True)
class CapturePolicy:
    model_inputs: bool = True
    model_outputs: bool = True
    raw_requests: bool = False
    tool_calls: bool = True
    retrieved_documents: bool = True

    @staticmethod
    def minimal() -> "CapturePolicy":
        return CapturePolicy(model_inputs=False, model_outputs=True, raw_requests=False, tool_calls=True, retrieved_documents=True)

    @staticmethod
    def full() -> "CapturePolicy":
        return CapturePolicy(model_inputs=True, model_outputs=True, raw_requests=True, tool_calls=True, retrieved_documents=True)


@dataclass(frozen=True, slots=True)
class AttackPolicy:
    overall_timeout_s: float = 120.0
    per_turn_timeout_s: float = 60.0
    max_turns: int = 10
    capture: CapturePolicy = field(default_factory=CapturePolicy.full)
    max_concurrency: int = 1
    rate_limit_rps: float | None = None
    max_retries: int = 2
    retry_backoff_s: float = 0.2
    max_artifacts: int = 100


@dataclass(frozen=True, slots=True)
class DocumentPayload:
    name: str
    content: str
    mime_type: str = "text/plain"
    kind: str = "inline"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "content": self.content, "mime_type": self.mime_type, "kind": self.kind}


@dataclass(frozen=True, slots=True)
class Payload:
    messages: tuple[Message, ...]
    documents: tuple[DocumentPayload, ...] = ()
    tools: tuple[ToolSpec, ...] = ()
    indicators: tuple[str, ...] = ()
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "messages": [m.to_dict() for m in self.messages],
            "documents": [d.to_dict() for d in self.documents],
            "tools": [t.to_dict() for t in self.tools],
            "indicators": list(self.indicators),
            "extra": dict(self.extra),
        }


class AttackOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class AttackObservation:
    outcome: AttackOutcome
    reason: str
    evidence_event_ids: tuple[str, ...] = ()
    matched_indicators: tuple[str, ...] = ()
    data: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "reason": self.reason,
            "evidence_event_ids": list(self.evidence_event_ids),
            "matched_indicators": list(self.matched_indicators),
            "data": dict(self.data),
        }


@dataclass(frozen=True, slots=True)
class Artifact:
    artifact_id: str
    name: str
    kind: str
    content: str
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {"artifact_id": self.artifact_id, "name": self.name, "kind": self.kind, "content": self.content, "digest": self.digest}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
