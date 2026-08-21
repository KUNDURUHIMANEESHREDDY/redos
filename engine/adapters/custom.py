from __future__ import annotations

import json
from typing import Any, Callable

import httpx

from engine.adapters.base import TargetAdapter
from engine.model.attack import DocumentChunk, Message, ModelReply, ToolCall, ToolSpec
from engine.model.errors import TargetAuthError, TargetProtocolError, TargetTimeout, TargetUnreachable
from engine.targets.config import TargetConfig


def get_dot_path(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            return None
    return current


class CustomHTTPAdapter(TargetAdapter):
    adapter_kind = "custom_http"

    def __init__(self, config: TargetConfig, headers: dict[str, str]) -> None:
        self.config = config
        self.headers = headers
        extra = config.extra
        self.request_path = str(extra.get("request_path", "/chat"))
        self.body_template: dict[str, Any] = dict(extra.get("body_template", {"messages": "{messages}"}))
        self.text_path = str(extra.get("response_text_path", "response"))
        self.tool_calls_path = str(extra.get("response_tool_calls_path", ""))
        self.tool_call_name_path = str(extra.get("response_tool_call_name_path", "name"))
        self.tool_call_args_path = str(extra.get("response_tool_call_args_path", "arguments"))
        self.stop_reason_path = str(extra.get("response_stop_reason_path", ""))
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))

    def _build_body(self, messages: list[Message], tools: list[ToolSpec] | None) -> dict[str, Any]:
        body: dict[str, Any] = {}
        for key, value in self.body_template.items():
            if isinstance(value, str):
                if value == "{messages}":
                    value = [m.to_dict() for m in messages]
                else:
                    value = value.replace("{model}", self.config.model or "")
            body[key] = value
        if tools is not None:
            body["tools"] = [t.to_dict() for t in tools]
        return body

    async def chat(
        self,
        messages: list[Message],
        *,
        tools: list[ToolSpec] | None = None,
        timeout: float | None = None,
    ) -> ModelReply:
        url = f"{self.config.base_url.rstrip('/')}/{self.request_path.lstrip('/')}"
        body = self._build_body(messages, tools)
        try:
            response = await self._client.post(url, headers=self.headers, json=body, timeout=timeout)
        except httpx.TimeoutException as exc:
            raise TargetTimeout(f"target timed out: {self.config.base_url}") from exc
        except httpx.TransportError as exc:
            raise TargetUnreachable(f"target unreachable: {self.config.base_url}: {exc}") from exc
        if response.status_code not in (200, 201):
            if response.status_code in (401, 403):
                raise TargetAuthError(f"target rejected authentication (HTTP {response.status_code})")
            raise TargetProtocolError(f"target returned HTTP {response.status_code}: {response.text[:200]}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise TargetProtocolError(f"non-JSON response from custom target: {exc}") from exc
        text = get_dot_path(payload, self.text_path)
        if text is None:
            raise TargetProtocolError(f"response text path {self.text_path!r} not found in payload")
        tool_calls: list[ToolCall] = []
        if self.tool_calls_path:
            raw_calls = get_dot_path(payload, self.tool_calls_path) or []
            for index, item in enumerate(raw_calls):
                if not isinstance(item, dict):
                    continue
                tool_calls.append(
                    ToolCall(
                        call_id=item.get("id", f"call_{index}"),
                        name=str(get_dot_path(item, self.tool_call_name_path) or ""),
                        arguments=str(get_dot_path(item, self.tool_call_args_path) or "{}"),
                        index=index,
                    )
                )
        stop_reason = None
        if self.stop_reason_path:
            stop_reason = get_dot_path(payload, self.stop_reason_path)
        return ModelReply(
            content=str(text),
            role="assistant",
            tool_calls=tuple(tool_calls),
            stop_reason=str(stop_reason) if stop_reason is not None else None,
            raw=payload,
        )

    async def aclose(self) -> None:
        await self._client.aclose()