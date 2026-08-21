from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from engine.attack_surface.model import AttackSurface
from engine.coverage import CoverageTracker

FAMILY_IMPACT: dict[str, float] = {
    "data_leakage": 0.9,
    "rag_poisoning": 0.8,
    "agent_escalation": 0.8,
    "unsafe_tool_call": 0.7,
    "tool_abuse": 0.7,
    "prompt_injection": 0.6,
    "jailbreak": 0.6,
    "permission": 0.5,
    "malicious_document": 0.5,
    "model_manipulation": 0.4,
}

WEIGHTS = {
    "information_gain": 0.3,
    "exploitability": 0.25,
    "impact": 0.2,
    "prior_evidence": 0.15,
    "coverage_gap": 0.1,
}


@dataclass(frozen=True, slots=True)
class ExperimentScore:
    plugin: str
    family: str
    information_gain: float
    exploitability: float
    impact: float
    prior_evidence: float
    coverage_gap: float
    total: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "family": self.family,
            "information_gain": self.information_gain,
            "exploitability": self.exploitability,
            "impact": self.impact,
            "prior_evidence": self.prior_evidence,
            "coverage_gap": self.coverage_gap,
            "total": round(self.total, 4),
        }


def score_candidate(plugin: str, surface: AttackSurface, coverage: CoverageTracker, *, is_variation: bool = False) -> ExperimentScore:
    family = plugin.split(".", 1)[0]
    tried = coverage.attempted(family)
    if is_variation:
        information_gain = 0.6
    elif not tried:
        information_gain = 0.5
    elif coverage.tried(plugin):
        information_gain = 0.1
    else:
        information_gain = 0.3

    tool_families = ("unsafe_tool_call", "tool_abuse", "agent_escalation")
    if family in tool_families:
        permissive = any(v is True or v == "tool execution observed" for v in surface.permissions.values()) if surface.permissions else surface.tool_capability
        exploitability = 0.8 if permissive else 0.5
    elif family == "rag_poisoning":
        exploitability = 0.7 if surface.retrieval_sample else 0.5
    else:
        exploitability = 0.6 if surface.chat_observed else 0.4

    impact = FAMILY_IMPACT.get(family, 0.4)

    total = (
        WEIGHTS["information_gain"] * information_gain
        + WEIGHTS["exploitability"] * exploitability
        + WEIGHTS["impact"] * impact
        + WEIGHTS["prior_evidence"] * (0.2 if tried else 0.0)
        + WEIGHTS["coverage_gap"] * (0.5 if not tried else 0.0)
    )
    return ExperimentScore(
        plugin=plugin,
        family=family,
        information_gain=round(information_gain, 3),
        exploitability=round(exploitability, 3),
        impact=round(impact, 3),
        prior_evidence=round(0.2 if tried else 0.0, 3),
        coverage_gap=round(0.5 if not tried else 0.0, 3),
        total=round(total, 4),
    )