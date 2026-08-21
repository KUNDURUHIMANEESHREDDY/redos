from __future__ import annotations

from typing import Any, Mapping

import httpx

from engine.adapters.base import TargetAdapter
from engine.adapters.openai import OpenAICompatAdapter, _status_error
from engine.model.attack import DocumentChunk, Message, ModelReply, ToolCall, ToolSpec
from engine.model.errors import TargetProtocolError, TargetTimeout, TargetUnreachable
from engine.targets.config import TargetConfig


class AgentAdapter(TargetAdapter):
    adapter_kind = "agent"

    def __init__(self, chat_adapter: OpenAICompatAdapter, base_url: str, headers: dict[str, str]) -> None:
        self.chat_adapter = chat_adapter
        self.base_url = base_url
        self.headers = headers
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))

    async def chat(
        self,
        messages: list[Message],
        *,
        tools: list[ToolSpec] | None = None,
        timeout: float | None = None,
    ) -> ModelReply:
        return await self.chat_adapter.chat(messages, tools=tools, timeout=timeout)

    async def list_tools(self) -> list[ToolSpec]:
        url = f"{self.base_url.rstrip('/')}/tools"
        try:
            response = await self._client.get(url, headers=self.headers)
        except httpx.TransportError as exc:
            raise TargetUnreachable(f"agent endpoint unreachable: {self.base_url}: {exc}") from exc
        if response.status_code != 200:
            raise _status_error(response.status_code, response.text)
        try:
            payload = response.json()
        except ValueError as exc:
            raise TargetProtocolError(f"non-JSON agent tool listing: {exc}") from exc
        return [ToolSpec(name=t.get("name", ""), description=t.get("description", ""), parameters=t.get("parameters", {})) for t in payload]

    async def execute_tool(self, tool_call: ToolCall, *, timeout: float | None = None) -> Mapping[str, Any]:
        url = f"{self.base_url.rstrip('/')}/tools/{tool_call.name}/invoke"
        try:
            response = await self._client.post(
                url,
                headers=self.headers,
                json={"arguments": tool_call.arguments, "call_id": tool_call.call_id},
                timeout=timeout,
            )
        except httpx.TimeoutException as exc:
            raise TargetTimeout(f"tool invocation timed out: {tool_call.name}") from exc
        except httpx.TransportError as exc:
            raise TargetUnreachable(f"agent endpoint unreachable: {self.base_url}: {exc}") from exc
        if response.status_code not in (200, 201):
            raise _status_error(response.status_code, response.text)
        try:
            payload = response.json()
        except ValueError as exc:
            raise TargetProtocolError(f"non-JSON tool result: {exc}") from exc
        return {"ok": bool(payload.get("ok", True)), "output": payload.get("output", ""), "error": payload.get("error")}

    async def aclose(self) -> None:
        await self.chat_adapter.aclose()
        await self._client.aclose()


class RAGAdapter(TargetAdapter):
    adapter_kind = "rag"

    def __init__(self, chat_adapter: OpenAICompatAdapter, retrieval_url: str, headers: dict[str, str]) -> None:
        self.chat_adapter = chat_adapter
        self.retrieval_url = retrieval_url
        self.headers = headers
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))

    async def chat(
        self,
        messages: list[Message],
        *,
        tools: list[ToolSpec] | None = None,
        timeout: float | None = None,
    ) -> ModelReply:
        return await self.chat_adapter.chat(messages, tools=tools, timeout=timeout)

    async def retrieve(self, query: str, *, top_k: int = 5, timeout: float | None = None) -> list[DocumentChunk]:
        try:
            response = await self._client.post(
                self.retrieval_url,
                headers=self.headers,
                json={"query": query, "top_k": top_k},
                timeout=timeout,
            )
        except httpx.TimeoutException as exc:
            raise TargetTimeout(f"retrieval timed out: {self.retrieval_url}") from exc
        except httpx.TransportError as exc:
            raise TargetUnreachable(f"retrieval endpoint unreachable: {self.retrieval_url}: {exc}") from exc
        if response.status_code != 200:
            raise _status_error(response.status_code, response.text)
        try:
            payload = response.json()
        except ValueError as exc:
            raise TargetProtocolError(f"non-JSON retrieval response: {exc}") from exc
        raw_docs = payload.get("documents", payload.get("results", payload if isinstance(payload, list) else []))
        chunks: list[DocumentChunk] = []
        for index, item in enumerate(raw_docs):
            if not isinstance(item, dict):
                item = {"text": str(item)}
            chunks.append(
                DocumentChunk(
                    chunk_id=str(item.get("id", item.get("chunk_id", f"chunk_{index}"))),
                    text=str(item.get("text", item.get("content", ""))),
                    source=str(item.get("source", "")),
                    score=item.get("score"),
                )
            )
        return chunks

    async def aclose(self) -> None:
        await self.chat_adapter.aclose()
        await self._client.aclose()