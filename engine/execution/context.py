from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping
from uuid import uuid4

from engine.adapters.base import TargetAdapter
from engine.execution.timeouts import ArtifactRecord, AttackClock, TurnBudget, await_guarded
from engine.model.attack import (
    AttackObservation,
    AttackOutcome,
    CapturePolicy,
    DocumentChunk,
    Message,
    ModelReply,
    Provenance,
    ToolCall,
    ToolResult,
)
from engine.model.errors import TargetProtocolError, TargetTimeout, TargetUnreachable, UnsupportedOperation
from engine.model.events import EvidenceEvent, EventTypes
from engine.model.execution import ObservedExecution
from engine.security.capture import CaptureEnforcer
from engine.security.secrets import SecretsVault

AuditEmitter = Callable[[dict], None]


@dataclass(slots=True)
class AttackContext:
    execution_id: str
    adapter: TargetAdapter
    enforcer: CaptureEnforcer
    execution: ObservedExecution
    clock: AttackClock
    turns: TurnBudget
    audit: AuditEmitter | None = None
    rate_limiter: Any | None = None
    per_turn_timeout_s: float = 60.0
    max_retries: int = 2
    retry_backoff_s: float = 0.2
    max_artifacts: int = 100
    _secrets: SecretsVault | None = None
    _artifacts: list[ArtifactRecord] = field(default_factory=list)

    @property
    def provenance(self) -> Provenance:
        return self.adapter.provenance

    def audit_event(self, action: str, detail: str = "") -> EvidenceEvent:
        event = EvidenceEvent.now(
            self.execution_id,
            EventTypes.AUDIT,
            {"action": action, "detail": detail, "provenance": self.provenance.value},
        )
        self.execution.record(event)
        if self.audit is not None:
            self.audit({"action": action, "execution_id": self.execution_id, "detail": detail, "at": event.timestamp.isoformat()})
        return event

    def _raise_stopped(self) -> None:
        self.clock.raise_if_stopped()
        if not self.turns.acquire():
            from engine.model.errors import AttackTimeout

            raise AttackTimeout(f"turn budget exhausted (max {self.turns.max})")

    async def _limit(self) -> None:
        if self.rate_limiter is not None:
            await self.rate_limiter.acquire()

    async def chat(
        self,
        messages: list[Message],
        *,
        tools: list | None = None,
        timeout: float | None = None,
    ) -> ModelReply:
        self._raise_stopped()
        request_event = EvidenceEvent.now(
            self.execution_id,
            EventTypes.MODEL_REQUEST,
            self.enforcer.request(
                {
                    "messages": [m.to_dict() for m in messages],
                    "tools": [t.to_dict() for t in tools] if tools else None,
                    "provenance": self.provenance.value,
                }
            ),
        )
        self.execution.record(request_event)
        await self._limit()
        attempt = 0
        while True:
            try:
                reply = await await_guarded(
                    self.adapter.chat(messages, tools=tools, timeout=timeout or self.per_turn_timeout_s),
                    self.clock,
                    timeout_s=timeout or self.per_turn_timeout_s,
                )
                break
            except (TargetUnreachable, TargetTimeout, TargetProtocolError) as exc:
                attempt += 1
                if attempt > self.max_retries:
                    raise
                self.audit_event("execution.retry", f"attempt {attempt}/{self.max_retries} after {type(exc).__name__}")
                await asyncio.sleep(self.retry_backoff_s * attempt)
        response_data = self.enforcer.response(reply)
        response_data["provenance"] = self.provenance.value
        response_event = EvidenceEvent.now(self.execution_id, EventTypes.MODEL_RESPONSE, response_data)
        self.execution.record(response_event)
        self.execution.record(
            EvidenceEvent.now(
                self.execution_id,
                EventTypes.MODEL_INTERACTION,
                {
                    "request_event_id": request_event.event_id,
                    "response_event_id": response_event.event_id,
                    "turn": self.turns.used,
                    "stop_reason": reply.stop_reason,
                    "provenance": self.provenance.value,
                },
            )
        )
        return reply

    async def retrieve(self, query: str, *, top_k: int = 5) -> list[DocumentChunk]:
        self._raise_stopped()
        await self._limit()
        chunks = await await_guarded(
            self.adapter.retrieve(query, top_k=top_k, timeout=self.per_turn_timeout_s),
            self.clock,
            timeout_s=self.per_turn_timeout_s,
        )
        self.execution.record(
            EvidenceEvent.now(
                self.execution_id,
                EventTypes.RETRIEVAL,
                self.enforcer.retrieval(query, chunks) | {"provenance": self.provenance.value},
            )
        )
        return chunks

    async def execute_tool(self, tool_call: ToolCall) -> ToolResult:
        self._raise_stopped()
        call_event = EvidenceEvent.now(
            self.execution_id,
            EventTypes.TOOL_CALL,
            {
                **tool_call.to_dict(),
                "provenance": self.provenance.value,
                "adapter_kind": self.adapter.adapter_kind,
            },
        )
        self.execution.record(call_event)
        try:
            result = await await_guarded(
                self.adapter.execute_tool(tool_call, timeout=self.per_turn_timeout_s),
                self.clock,
                timeout_s=self.per_turn_timeout_s,
            )
            ok = bool(result.get("ok", True))
            output = str(result.get("output", ""))
            error = result.get("error")
        except UnsupportedOperation:
            ok, output, error = False, "", "adapter cannot execute tools"
        self.execution.record(
            EvidenceEvent.now(
                self.execution_id,
                EventTypes.TOOL_RESULT,
                self.enforcer.tool_result(tool_call.name, output, ok, error) | {"call_id": tool_call.call_id, "provenance": self.provenance.value},
            )
        )
        return ToolResult(call_id=tool_call.call_id, name=tool_call.name, ok=ok, output=output, error=error)

    async def run_reply_tools(self, reply: ModelReply) -> list[ToolResult]:
        results: list[ToolResult] = []
        for tool_call in reply.tool_calls:
            results.append(await self.execute_tool(tool_call))
        return results

    def emit(self, type: str, data: Mapping[str, Any]) -> str:
        event = EvidenceEvent.now(
            self.execution_id,
            type,
            {**dict(data), "provenance": self.provenance.value},
        )
        self.execution.record(event)
        return event.event_id

    def add_artifact(self, name: str, kind: str, content: str) -> str:
        if len(self._artifacts) >= self.max_artifacts:
            self.audit_event("execution.artifact_limit", f"artifact budget exceeded ({self.max_artifacts}); dropped {name!r}")
            return ""
        artifact = ArtifactRecord(artifact_id=uuid4().hex, name=name, kind=kind, content=content, created_at=datetime.now(timezone.utc))
        self._artifacts.append(artifact)
        return self.emit(
            EventTypes.ARTIFACT,
            {
                "artifact_id": artifact.artifact_id,
                "name": name,
                "kind": kind,
                "digest": artifact.digest(),
                "content": content if self.enforcer.policy.raw_requests else "",
            },
        )

    def artifacts(self) -> list[ArtifactRecord]:
        return list(self._artifacts)

    def model_outputs(self) -> list[str]:
        return [
            str(e.data.get("content", ""))
            for e in self.execution.events
            if e.type == EventTypes.MODEL_RESPONSE and e.data.get("content")
        ]

    def tool_results(self) -> list[ToolResult]:
        results: list[ToolResult] = []
        for e in self.execution.events:
            if e.type == EventTypes.TOOL_RESULT:
                results.append(
                    ToolResult(
                        call_id=str(e.data.get("call_id", "")),
                        name=str(e.data.get("name", "")),
                        ok=bool(e.data.get("ok", False)),
                        output=str(e.data.get("output", "")),
                        error=e.data.get("error"),
                    )
                )
        return results