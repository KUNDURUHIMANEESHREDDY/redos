from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from engine.model.attack import TargetKind, ToolSpec
from engine.reconnaissance.profile import TargetProfile

SURFACE_CATEGORIES = (
    "tool",
    "tool_parameters",
    "permission",
    "rag_source",
    "document_ingestion",
    "memory",
    "external_api",
    "agent_delegation",
    "model_boundary",
    "authentication",
)


@dataclass(frozen=True, slots=True)
class SurfaceFact:
    category: str
    observation: str
    value: Any
    evidence_refs: tuple[str, ...] = ()
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "observation": self.observation,
            "value": self.value,
            "evidence_refs": list(self.evidence_refs),
            "confidence": self.confidence,
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "SurfaceFact":
        return SurfaceFact(
            category=str(data["category"]),
            observation=str(data["observation"]),
            value=data["value"],
            evidence_refs=tuple(data.get("evidence_refs") or []),
            confidence=float(data.get("confidence", 0.5)),
        )


@dataclass(slots=True)
class AttackSurface:
    target_id: str
    adapter_kind: str
    model: str | None
    tool_capability: bool = False
    retrieval_supported: bool = False
    chat_observed: bool = False
    tools: list[ToolSpec] = field(default_factory=list)
    tool_parameters: dict[str, Any] = field(default_factory=dict)
    permissions: dict[str, Any] = field(default_factory=dict)
    rag_sources: list[str] = field(default_factory=list)
    retrieval_sample: list[str] = field(default_factory=list)
    chat_sample: list[str] = field(default_factory=list)
    document_ingestion: bool | None = None
    memory: bool | None = None
    external_apis: list[str] = field(default_factory=list)
    agent_delegation: bool | None = None
    model_boundaries: dict[str, Any] = field(default_factory=dict)
    authentication: dict[str, Any] = field(default_factory=dict)
    facts: list[SurfaceFact] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)

    def add_fact(self, fact: SurfaceFact) -> None:
        self.facts.append(fact)

    def fact(self, category: str) -> SurfaceFact | None:
        for fact in self.facts:
            if fact.category == category:
                return fact
        return None

    def facts_of(self, category: str) -> list[SurfaceFact]:
        return [fact for fact in self.facts if fact.category == category]

    @property
    def tool_names(self) -> list[str]:
        return [t.name for t in self.tools]

    @staticmethod
    def from_profile(profile: TargetProfile) -> "AttackSurface":
        surface = AttackSurface(
            target_id=profile.target_id,
            adapter_kind=profile.adapter_kind,
            model=profile.model,
            tool_capability=profile.tool_capability,
            retrieval_supported=profile.retrieval_supported,
            chat_observed=profile.chat_observed,
            tools=list(profile.tools),
            retrieval_sample=list(profile.retrieval_sample),
            chat_sample=list(profile.chat_sample),
            agent_delegation=profile.adapter_kind == TargetKind.AGENT.value,
        )
        if profile.tools:
            surface.tool_parameters = {t.name: dict(t.parameters) for t in profile.tools}
            surface.add_fact(
                SurfaceFact(
                    "tool",
                    f"target exposes {len(profile.tools)} tool(s)",
                    [t.name for t in profile.tools],
                    evidence_refs=("list_tools",),
                    confidence=0.9,
                )
            )
            surface.add_fact(
                SurfaceFact(
                    "tool_parameters",
                    "tool schemas expose parameter definitions",
                    surface.tool_parameters,
                    evidence_refs=("list_tools",),
                    confidence=0.9,
                )
            )
        if profile.retrieval_sample:
            surface.add_fact(
                SurfaceFact(
                    "rag_source",
                    f"{len(profile.retrieval_sample)} retrieved document fragment(s) observed",
                    profile.retrieval_sample,
                    evidence_refs=("retrieve",),
                    confidence=0.9,
                )
            )
        if profile.chat_observed:
            surface.add_fact(
                SurfaceFact(
                    "model_boundary",
                    "chat endpoint responds to benign probe",
                    profile.chat_sample,
                    evidence_refs=("chat",),
                    confidence=0.9,
                )
            )
        return surface

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "adapter_kind": self.adapter_kind,
            "model": self.model,
            "tool_capability": self.tool_capability,
            "retrieval_supported": self.retrieval_supported,
            "chat_observed": self.chat_observed,
            "tools": [t.to_dict() for t in self.tools],
            "tool_parameters": self.tool_parameters,
            "permissions": self.permissions,
            "rag_sources": list(self.rag_sources),
            "retrieval_sample": list(self.retrieval_sample),
            "chat_sample": list(self.chat_sample),
            "document_ingestion": self.document_ingestion,
            "memory": self.memory,
            "external_apis": list(self.external_apis),
            "agent_delegation": self.agent_delegation,
            "model_boundaries": self.model_boundaries,
            "authentication": self.authentication,
            "facts": [f.to_dict() for f in self.facts],
            "notes": dict(self.notes),
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "AttackSurface":
        return AttackSurface(
            target_id=str(data["target_id"]),
            adapter_kind=str(data.get("adapter_kind", "unknown")),
            model=data.get("model"),
            tool_capability=bool(data.get("tool_capability", False)),
            retrieval_supported=bool(data.get("retrieval_supported", False)),
            chat_observed=bool(data.get("chat_observed", False)),
            tools=[ToolSpec(name=t.get("name", ""), description=t.get("description", ""), parameters=t.get("parameters", {})) for t in data.get("tools") or []],
            tool_parameters=dict(data.get("tool_parameters") or {}),
            permissions=dict(data.get("permissions") or {}),
            rag_sources=list(data.get("rag_sources") or []),
            retrieval_sample=list(data.get("retrieval_sample") or []),
            chat_sample=list(data.get("chat_sample") or []),
            document_ingestion=data.get("document_ingestion"),
            memory=data.get("memory"),
            external_apis=list(data.get("external_apis") or []),
            agent_delegation=data.get("agent_delegation"),
            model_boundaries=dict(data.get("model_boundaries") or {}),
            authentication=dict(data.get("authentication") or {}),
            facts=[SurfaceFact.from_dict(f) for f in data.get("facts") or []],
            notes=dict(data.get("notes") or {}),
        )