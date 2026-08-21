from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping

from engine.model.attack import DocumentChunk, Message, ModelReply, Provenance, ToolCall, ToolSpec


class TargetAdapter(ABC):
    provenance: Provenance = Provenance.LIVE
    adapter_kind: str = "base"

    @abstractmethod
    async def chat(
        self,
        messages: list[Message],
        *,
        tools: list[ToolSpec] | None = None,
        timeout: float | None = None,
    ) -> ModelReply:
        ...

    async def retrieve(self, query: str, *, top_k: int = 5, timeout: float | None = None) -> list[DocumentChunk]:
        from engine.model.errors import UnsupportedOperation

        raise UnsupportedOperation(f"adapter {self.adapter_kind} does not support retrieval")

    async def list_tools(self) -> list[ToolSpec]:
        from engine.model.errors import UnsupportedOperation

        raise UnsupportedOperation(f"adapter {self.adapter_kind} does not expose tools")

    async def execute_tool(self, tool_call: ToolCall, *, timeout: float | None = None) -> Mapping[str, Any]:
        from engine.model.errors import UnsupportedOperation

        raise UnsupportedOperation(f"adapter {self.adapter_kind} cannot execute tools")

    async def aclose(self) -> None:
        return None

    def describe(self) -> dict[str, Any]:
        return {"adapter_kind": self.adapter_kind, "provenance": self.provenance.value}