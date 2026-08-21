from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol
from uuid import uuid4

from engine.model.errors import MockEvidenceRejected
from engine.security.guard import ProductionGate, validate_evidence_chain, validate_evidence_for_processing

if TYPE_CHECKING:
    from engine.model.execution import ExecutionResult


@dataclass(frozen=True, slots=True)
class FindingRecord:
    finding_id: str
    execution_id: str
    target_id: str
    attack_id: str
    outcome: str
    outcome_reason: str
    validation_valid: bool
    stored_at: datetime
    severity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "execution_id": self.execution_id,
            "target_id": self.target_id,
            "attack_id": self.attack_id,
            "outcome": self.outcome,
            "outcome_reason": self.outcome_reason,
            "validation_valid": self.validation_valid,
            "stored_at": self.stored_at.isoformat(),
            "severity": self.severity,
        }


class FindingSink(Protocol):
    def store(self, result: "ExecutionResult", finding_id: str, severity: str | None = None) -> FindingRecord:
        ...


@dataclass(slots=True)
class InMemoryFindingSink:
    records: list[FindingRecord] = field(default_factory=list)

    def store(self, result: "ExecutionResult", finding_id: str, severity: str | None = None) -> FindingRecord:
        record = FindingRecord(
            finding_id=finding_id,
            execution_id=result.execution.execution_id,
            target_id=result.execution.target_id,
            attack_id=result.execution.attack_id,
            outcome=result.outcome.value,
            outcome_reason=result.outcome_reason,
            validation_valid=result.validation.valid,
            stored_at=datetime.now(timezone.utc),
            severity=severity,
        )
        self.records.append(record)
        return record


class FindingsGateway:
    def __init__(self, sink: FindingSink, gate: ProductionGate | None = None) -> None:
        self.sink = sink
        self.gate = gate or ProductionGate()

    def submit(self, result: "ExecutionResult", severity: str | None = None) -> FindingRecord:
        # Tampered evidence must never become a finding/severity/regression/report
        validate_evidence_for_processing(result.execution)
        validation = validate_evidence_chain(result.execution)
        if not validation.valid:
            raise MockEvidenceRejected(
                "production finding storage rejected evidence chain: " + "; ".join(validation.violations)
            )
        finding_id = uuid4().hex
        return self.sink.store(result, finding_id, severity=severity)