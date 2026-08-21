from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from engine.model.execution import ExecutionResult
from engine.security import FindingRecord, validate_evidence_chain


@dataclass(frozen=True, slots=True)
class AssuranceReport:
    """Evidence-chain and record-keeping compliance for a set of findings."""

    findings_checked: int
    findings_with_valid_evidence: int
    findings_with_replayable_execution: int
    retention_compliance: float
    gate_compliance: float | None
    violations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings_checked": self.findings_checked,
            "findings_with_valid_evidence": self.findings_with_valid_evidence,
            "findings_with_replayable_execution": self.findings_with_replayable_execution,
            "retention_compliance": self.retention_compliance,
            "gate_compliance": self.gate_compliance,
            "violations": list(self.violations),
        }


class AssuranceEngine:
    """Assures that stored findings are backed by real evidence.

    - Evidence validity re-checks each finding's execution with the engine's
      own `validate_evidence_chain` (mock evidence is rejected).
    - Replayability counts executions whose result carries a replay hash and
      at least one model interaction (enough to build a regression case).
    - Retention compliance is the fraction of findings with valid evidence.
    - Gate compliance, when audit events are provided, is the fraction of
      gated actions that passed (blocked actions are counted as failures).
    """

    def assure(
        self,
        records: Iterable[FindingRecord],
        *,
        executions: Iterable[ExecutionResult] | None = None,
        audit_events: Iterable[dict[str, Any]] | None = None,
    ) -> AssuranceReport:
        records = list(records)
        executions_by_id = {r.execution.execution_id: r for r in (executions or [])}

        valid = 0
        replayable = 0
        violations: list[str] = []
        for record in records:
            result = executions_by_id.get(record.execution_id)
            if result is None:
                violations.append(f"finding {record.finding_id}: execution {record.execution_id} not retained")
                continue
            validation = validate_evidence_chain(result.execution)
            if validation.valid:
                valid += 1
                if result.replay_hash and len(result.execution.model_interactions) > 0:
                    replayable += 1
            else:
                violations.append(
                    f"finding {record.finding_id}: evidence chain invalid: " + "; ".join(validation.violations)
                )

        retention = (valid / len(records)) if records else 1.0

        gate_compliance = None
        if audit_events is not None:
            gated = [e for e in audit_events if e.get("gated") is not None or e.get("action", "").startswith("gate.")]
            if gated:
                passed = sum(1 for e in gated if e.get("outcome") in (None, "pass", "PASS"))
                gate_compliance = passed / len(gated)

        return AssuranceReport(
            findings_checked=len(records),
            findings_with_valid_evidence=valid,
            findings_with_replayable_execution=replayable,
            retention_compliance=round(retention, 4),
            gate_compliance=round(gate_compliance, 4) if gate_compliance is not None else None,
            violations=tuple(violations),
        )