from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    UNTESTABLE = "untestable"

    def is_terminal(self) -> bool:
        return self in (HypothesisStatus.CONFIRMED, HypothesisStatus.REFUTED, HypothesisStatus.UNTESTABLE)


@dataclass(slots=True)
class AttackHypothesis:
    hypothesis_id: str
    assumption: str
    attack_surface: str
    expected_behavior: str
    evidence_required: tuple[str, ...]
    candidate_attacks: tuple[str, ...]
    confidence: float = 0.5
    priority: int = 5
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    tested: bool = False
    supporting_evidence: list[dict] = field(default_factory=list)
    notes: str = ""

    def clamp_confidence(self) -> None:
        self.confidence = round(min(1.0, max(0.0, self.confidence)), 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "assumption": self.assumption,
            "attack_surface": self.attack_surface,
            "expected_behavior": self.expected_behavior,
            "evidence_required": list(self.evidence_required),
            "candidate_attacks": list(self.candidate_attacks),
            "confidence": self.confidence,
            "priority": self.priority,
            "status": self.status.value,
            "tested": self.tested,
            "supporting_evidence": list(self.supporting_evidence),
            "notes": self.notes,
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "AttackHypothesis":
        return AttackHypothesis(
            hypothesis_id=str(data["hypothesis_id"]),
            assumption=str(data["assumption"]),
            attack_surface=str(data["attack_surface"]),
            expected_behavior=str(data["expected_behavior"]),
            evidence_required=tuple(data.get("evidence_required") or []),
            candidate_attacks=tuple(data.get("candidate_attacks") or []),
            confidence=float(data.get("confidence", 0.5)),
            priority=int(data.get("priority", 5)),
            status=HypothesisStatus(data.get("status", "proposed")),
            tested=bool(data.get("tested", False)),
            supporting_evidence=list(data.get("supporting_evidence") or []),
            notes=str(data.get("notes", "")),
        )