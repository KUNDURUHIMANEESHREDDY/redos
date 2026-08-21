from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from engine.model.attack import ToolSpec


@dataclass(slots=True)
class TargetProfile:
    target_id: str
    adapter_kind: str
    model: str | None = None
    tools: list[ToolSpec] = field(default_factory=list)
    tool_capability: bool = False
    retrieval_supported: bool = False
    chat_observed: bool = False
    chat_sample: list[str] = field(default_factory=list)
    retrieval_sample: list[str] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)

    @property
    def tool_names(self) -> list[str]:
        return [t.name for t in self.tools]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "adapter_kind": self.adapter_kind,
            "model": self.model,
            "tools": [t.to_dict() for t in self.tools],
            "tool_capability": self.tool_capability,
            "retrieval_supported": self.retrieval_supported,
            "chat_observed": self.chat_observed,
            "chat_sample": list(self.chat_sample),
            "retrieval_sample": list(self.retrieval_sample),
            "notes": dict(self.notes),
        }

    def merge(self, other: "TargetProfile") -> "TargetProfile":
        self.tools = other.tools or self.tools
        self.tool_capability = self.tool_capability or other.tool_capability
        self.retrieval_supported = self.retrieval_supported or other.retrieval_supported
        self.chat_observed = self.chat_observed or other.chat_observed
        self.chat_sample = list(dict.fromkeys(self.chat_sample + other.chat_sample))
        self.retrieval_sample = list(dict.fromkeys(self.retrieval_sample + other.retrieval_sample))
        self.notes.update(other.notes)
        return self


def profile_from_dict(data: Mapping[str, Any]) -> TargetProfile:
    return TargetProfile(
        target_id=str(data["target_id"]),
        adapter_kind=str(data.get("adapter_kind", "unknown")),
        model=data.get("model"),
        tools=[ToolSpec(name=t.get("name", ""), description=t.get("description", ""), parameters=t.get("parameters", {})) for t in data.get("tools") or []],
        tool_capability=bool(data.get("tool_capability", False)),
        retrieval_supported=bool(data.get("retrieval_supported", False)),
        chat_observed=bool(data.get("chat_observed", False)),
        chat_sample=list(data.get("chat_sample") or []),
        retrieval_sample=list(data.get("retrieval_sample") or []),
        notes=dict(data.get("notes") or {}),
    )