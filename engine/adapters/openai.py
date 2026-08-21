from __future__ import annotations

from typing import Any

import httpx

from engine.adapters.base import TargetAdapter
from engine.model.attack import Message, ModelReply, Provenance, ToolCall, ToolSpec
from engine.model.errors import TargetAuthError, TargetProtocolError, TargetTimeout, TargetUnreachable
from engine.targets.config import TargetConfig


def _status_error(status_code: int, body: str) -> Exception:
    if status_code in (401, 403):
        return TargetAuthError(f"target rejected authentication (HTTP {status_code}): {body[:200]}")
    return TargetProtocolError(f"target returned HTTP {status_code}: {body[:200]}")


class OpenAICompatAdapter(TargetAdapter):
    adapter_kind = "openai_compatible"

    def __init__(self, config: TargetConfig, headers: dict[str, str]) -> None:
        self.config = config
        self.headers = headers
        self.chat_url = f"{config.base_url.rstrip('/')}/chat/completions"
        self.tool_invoke_url = str(config.extra.get("tool_invoke_url", ""))
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))

    async def chat(
        self,
        messages: list[Message],
        *,
        tools: list[ToolSpec] | None = None,
        timeout: float | None = None,
    ) -> ModelReply:
        body: dict[str, Any] = {
            "model": self.config.model,
            "messages": [m.to_dict() for m in messages],
        }
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
                }
                for t in tools
            ]
        try:
            response = await self._client.post(self.chat_url, headers=self.headers, json=body, timeout=timeout)
        except httpx.TimeoutException as exc:
            raise TargetTimeout(f"target timed out: {self.config.base_url}") from exc
        except httpx.TransportError as exc:
            raise TargetUnreachable(f"target unreachable: {self.config.base_url}: {exc}") from exc
        if response.status_code != 200:
            raise _status_error(response.status_code, response.text)
        try:
            payload = response.json()
            choice = payload["choices"][0]
            message = choice.get("message", {})
        except (KeyError, IndexError, ValueError) as exc:
            raise TargetProtocolError(f"unexpected OpenAI-compatible response shape: {exc}") from exc
        tool_calls: list[ToolCall] = []
        for index, tc in enumerate(message.get("tool_calls") or []):
            fn = tc.get("function", {})
            tool_calls.append(
                ToolCall(
                    call_id=tc.get("id", f"call_{index}"),
                    name=fn.get("name", ""),
                    arguments=fn.get("arguments", "{}"),
                    index=index,
                )
            )
        return ModelReply(
            content=message.get("content") or "",
            role=message.get("role", "assistant"),
            tool_calls=tuple(tool_calls),
            stop_reason=choice.get("finish_reason"),
            raw=payload,
        )

    async def execute_tool(self, tool_call: ToolCall, *, timeout: float | None = None) -> dict[str, Any]:
        if not self.tool_invoke_url:
            from engine.model.errors import UnsupportedOperation

            raise UnsupportedOperation(f"adapter {self.adapter_kind} cannot execute tools")
        url = f"{self.tool_invoke_url.rstrip('/')}/tools/{tool_call.name}/invoke"
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
            raise TargetUnreachable(f"tool endpoint unreachable: {self.tool_invoke_url}: {exc}") from exc
        if response.status_code not in (200, 201):
            raise _status_error(response.status_code, response.text)
        try:
            payload = response.json()
        except ValueError as exc:
            raise TargetProtocolError(f"non-JSON tool result: {exc}") from exc
        return {"ok": bool(payload.get("ok", True)), "output": payload.get("output", ""), "error": payload.get("error")}

    async def aclose(self) -> None:
        await self._client.aclose()


class LocalModelAdapter(OpenAICompatAdapter):
    adapter_kind = "local_model"

    def __init__(self, config: TargetConfig, headers: dict[str, str] | None = None) -> None:
        super().__init__(config, headers or {})


class AnthropicAdapter(TargetAdapter):
    adapter_kind = "anthropic_compatible"

    def __init__(self, config: TargetConfig, headers: dict[str, str]) -> None:
        self.config = config
        self.headers = headers
        self.messages_url = f"{config.base_url.rstrip('/')}/v1/messages"
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))

    async def chat(
        self,
        messages: list[Message],
        *,
        tools: list[ToolSpec] | None = None,
        timeout: float | None = None,
    ) -> ModelReply:
        body: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": 1024,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        if tools:
            body["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters,
                }
                for t in tools
            ]
        try:
            response = await self._client.post(self.messages_url, headers=self.headers, json=body, timeout=timeout)
        except httpx.TimeoutException as exc:
            raise TargetTimeout(f"target timed out: {self.config.base_url}") from exc
        except httpx.TransportError as exc:
            raise TargetUnreachable(f"target unreachable: {self.config.base_url}: {exc}") from exc
        if response.status_code != 200:
            raise _status_error(response.status_code, response.text)
        try:
            payload = response.json()
        except ValueError as exc:
            raise TargetProtocolError(f"non-JSON response from Anthropic-compatible target: {exc}") from exc
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        index = 0
        for block in payload.get("content") or []:
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append(
                    ToolCall(
                        call_id=block.get("id", f"call_{index}"),
                        name=block.get("name", ""),
                        arguments=str(block.get("input", {})),
                        index=index,
                    )
                )
                index += 1
        return ModelReply(
            content="".join(text_parts),
            role="assistant",
            tool_calls=tuple(tool_calls),
            stop_reason=payload.get("stop_reason"),
            raw=payload,
        )

    async def aclose(self) -> None:
        await self._client.aclose()