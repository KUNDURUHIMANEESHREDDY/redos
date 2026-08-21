from __future__ import annotations

from typing import Any, Mapping

from engine.model.attack import CapturePolicy, ModelReply
from engine.security.secrets import redact_mapping


class CaptureEnforcer:
    def __init__(self, policy: CapturePolicy, secret_values: tuple[str, ...] = ()) -> None:
        self.policy = policy
        self.secret_values = secret_values

    def request(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        req = dict(request)
        if not self.policy.model_inputs:
            req.pop("messages", None)
        if not self.policy.raw_requests:
            req.pop("raw_request", None)
        return redact_mapping(req, self.secret_values)

    def response(self, reply: ModelReply) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if self.policy.model_outputs:
            data["content"] = reply.content
        data["role"] = reply.role
        if self.policy.tool_calls:
            data["tool_calls"] = [tc.to_dict() for tc in reply.tool_calls]
        data["stop_reason"] = reply.stop_reason
        if self.policy.raw_requests and reply.raw:
            data["raw"] = redact_mapping(dict(reply.raw), self.secret_values)
        return data

    def tool_result(self, name: str, output: str, ok: bool, error: str | None) -> dict[str, Any]:
        return {
            "name": name,
            "ok": ok,
            "output": output if self.policy.tool_calls else "***REDACTED***",
            "error": error,
        }

    def retrieval(self, query: str, chunks: list) -> dict[str, Any]:
        return {
            "query": query,
            "chunks": (
                [c.to_dict() for c in chunks] if self.policy.retrieved_documents else [{"chunk_id": c.chunk_id} for c in chunks]
            ),
            "chunk_count": len(chunks),
        }