from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engine.attack_surface.model import AttackSurface

CROSS_FAMILY_CHAIN: tuple[tuple[str, str], ...] = (
    ("prompt_injection", "prompt_injection.ignore_previous"),
    ("rag_poisoning", "rag_poisoning.plant"),
    ("agent_escalation", "agent_escalation.system_override"),
    ("tool_abuse", "tool_abuse.negation"),
    ("data_leakage", "data_leakage.pii"),
)

STAGE_GATING: dict[str, tuple[str, ...]] = {
    "prompt_injection": ("model_boundary",),
    "rag_poisoning": ("rag_source",),
    "agent_escalation": ("tool_authorization", "agent_delegation"),
    "tool_abuse": ("tool_authorization",),
    "data_leakage": (),
}


@dataclass(frozen=True, slots=True)
class CrossFamilyStage:
    family: str
    plugin: str
    gating: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"family": self.family, "plugin": self.plugin, "gating": list(self.gating)}


@dataclass(slots=True)
class CrossFamilyPlan:
    name: str = "prompt_injection->rag_poisoning->agent_escalation->tool_abuse->data_exfiltration"
    stages: tuple[CrossFamilyStage, ...] = field(
        default_factory=lambda: tuple(CrossFamilyStage(family, plugin, STAGE_GATING[family]) for family, plugin in CROSS_FAMILY_CHAIN)
    )

    def surface_gates(self, surface: AttackSurface) -> dict[str, str]:
        gates: dict[str, str] = {}
        if not (surface.chat_observed or surface.tool_capability):
            gates["prompt_injection"] = "no chat or tool surface observed"
        if not surface.retrieval_supported:
            gates["rag_poisoning"] = "no retrieval surface observed"
        if not (surface.tool_capability or surface.tools):
            gates["agent_escalation"] = "no tool surface observed"
            gates["tool_abuse"] = "no tool surface observed"
        return gates

    def feasible_stages(self, surface: AttackSurface) -> list[CrossFamilyStage]:
        gates = self.surface_gates(surface)
        return [stage for stage in self.stages if stage.family not in gates]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "stages": [s.to_dict() for s in self.stages],
        }