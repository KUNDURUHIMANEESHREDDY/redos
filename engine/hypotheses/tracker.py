from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from engine.hypotheses.model import AttackHypothesis, HypothesisStatus

EVIDENCE_TOKENS = {
    "tool_result": lambda record: record.tool_evidence > 0,
    "retrieval": lambda record: record.retrieval_evidence > 0,
    "model_response": lambda record: True,
}


@dataclass(slots=True)
class HypothesisTracker:
    hypotheses: list[AttackHypothesis] = field(default_factory=list)

    def register(self, hypothesis: AttackHypothesis) -> AttackHypothesis:
        self.hypotheses.append(hypothesis)
        return hypothesis

    def register_or_reuse(self, hypothesis: AttackHypothesis) -> AttackHypothesis:
        for existing in self.hypotheses:
            if (
                existing.attack_surface == hypothesis.attack_surface
                and existing.candidate_attacks == hypothesis.candidate_attacks
                and existing.assumption == hypothesis.assumption
            ):
                return existing
        return self.register(hypothesis)

    def get(self, hypothesis_id: str) -> AttackHypothesis | None:
        for hypothesis in self.hypotheses:
            if hypothesis.hypothesis_id == hypothesis_id:
                return hypothesis
        return None

    def evidence_satisfied(self, hypothesis: AttackHypothesis, record: Any) -> bool:
        if not hypothesis.evidence_required:
            return True
        return all(EVIDENCE_TOKENS.get(token, lambda r: False)(record) for token in hypothesis.evidence_required)

    def update(self, hypothesis_id: str, record: Any) -> AttackHypothesis | None:
        hypothesis = self.get(hypothesis_id)
        if hypothesis is None or hypothesis.status.is_terminal():
            return hypothesis
        satisfied = self.evidence_satisfied(hypothesis, record)
        outcome = record.outcome
        is_chain = self._is_chain(hypothesis)
        if is_chain:
            hypothesis.supporting_evidence.append(
                {"evidence": "cross-family stage executed", "outcome": outcome, "plugin": record.plugin}
            )
            if all(self._candidate_tried(hypothesis, plugin) for plugin in hypothesis.candidate_attacks):
                hypothesis.tested = True
            return hypothesis
        if outcome == "success" and satisfied:
            hypothesis.confidence = min(1.0, hypothesis.confidence + 0.25)
            hypothesis.status = HypothesisStatus.CONFIRMED
            hypothesis.supporting_evidence.append(
                {
                    "evidence": "expected behavior observed",
                    "outcome": outcome,
                    "satisfied": list(hypothesis.evidence_required),
                    "plugin": record.plugin,
                }
            )
        elif outcome == "failure" and satisfied:
            hypothesis.confidence = max(0.0, hypothesis.confidence - 0.15)
            hypothesis.status = HypothesisStatus.REFUTED
            hypothesis.supporting_evidence.append(
                {
                    "evidence": "executed with evidence captured but expected behavior did not occur",
                    "outcome": outcome,
                    "satisfied": list(hypothesis.evidence_required),
                    "plugin": record.plugin,
                }
            )
        elif outcome == "indeterminate":
            hypothesis.status = HypothesisStatus.UNTESTABLE
            hypothesis.supporting_evidence.append(
                {"evidence": "execution produced no conclusion", "outcome": outcome, "plugin": record.plugin}
            )
        else:
            hypothesis.supporting_evidence.append(
                {"evidence": "executed but evidence_required was not satisfied", "outcome": outcome, "plugin": record.plugin}
            )
        hypothesis.tested = True
        hypothesis.clamp_confidence()
        return hypothesis

    def _is_chain(self, hypothesis: AttackHypothesis) -> bool:
        from engine.experiment.selection import _is_chain_hypothesis

        return _is_chain_hypothesis(hypothesis)

    def _candidate_tried(self, hypothesis: AttackHypothesis, plugin: str) -> bool:
        return any(entry.get("plugin") == plugin for entry in hypothesis.supporting_evidence)

    def untested(self) -> list[AttackHypothesis]:
        return [h for h in self.hypotheses if not h.tested]

    def by_priority(self) -> list[AttackHypothesis]:
        return sorted(self.hypotheses, key=lambda h: (h.priority, -h.confidence))

    def to_dict(self) -> list[dict[str, Any]]:
        return [h.to_dict() for h in self.hypotheses]

    @staticmethod
    def from_dict(data: list[Mapping[str, Any]]) -> "HypothesisTracker":
        tracker = HypothesisTracker()
        for entry in data:
            tracker.register(AttackHypothesis.from_dict(entry))
        return tracker