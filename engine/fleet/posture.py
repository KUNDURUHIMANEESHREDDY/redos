from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from engine.security import FindingRecord

SEVERITY_WEIGHTS = {
    "CRITICAL": 4.0,
    "HIGH": 2.0,
    "MEDIUM": 1.0,
    "LOW": 0.5,
}

SEVERITY_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _clamp(value: float, low: float = 0.0, high: float = 10.0) -> float:
    return max(low, min(high, value))


def count_by_severity(records: Iterable[FindingRecord]) -> dict[str, int]:
    counts = {level: 0 for level in SEVERITY_ORDER}
    for record in records:
        level = str(record.severity).upper() if record.severity else None
        if level in counts:
            counts[level] += 1
    return counts


@dataclass(frozen=True, slots=True)
class PostureSnapshot:
    """A computed 0-10 security posture for a target, project, or fleet.

    Severity is read from the finding record's `severity` field; the engine
    never computes severity itself, so unclassified findings contribute
    nothing to the burden term.
    """

    subject: str
    posture_score: float
    findings_by_severity: dict[str, int]
    coverage: float
    gate_compliance: float
    average_response_hours: float
    mean_remediation_hours: float | None
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "posture_score": self.posture_score,
            "findings_by_severity": dict(self.findings_by_severity),
            "coverage": self.coverage,
            "gate_compliance": self.gate_compliance,
            "average_response_hours": self.average_response_hours,
            "mean_remediation_hours": self.mean_remediation_hours,
            "computed_at": self.computed_at.isoformat(),
        }


class PostureEngine:
    """Deterministic posture scoring.

    score = 0.6 * finding_component + factor_component, clamped to [0, 10].

    - finding_component = max(0, 10 - 0.5 * severity_burden), where
      severity_burden = 4*CRITICAL + 2*HIGH + 1*MEDIUM + 0.5*LOW.
    - factor_component = 2*coverage + 2*gate_compliance
      + 0.5*clamp(1 - response_hours/24) + 0.5*clamp(1 - remediation_hours/72)
      (remediation term contributes 0.5 when unknown).

    A target with zero findings and full coverage/gate compliance scores 10.
    """

    def score(
        self,
        subject: str,
        records: Iterable[FindingRecord],
        *,
        coverage: float = 1.0,
        gate_compliance: float = 1.0,
        average_response_hours: float = 0.0,
        mean_remediation_hours: float | None = None,
    ) -> PostureSnapshot:
        counts = count_by_severity(records)
        burden = sum(SEVERITY_WEIGHTS[level] * counts[level] for level in SEVERITY_ORDER)
        finding_component = max(0.0, 10.0 - 0.5 * burden)

        response_term = 0.5 * _clamp(1.0 - average_response_hours / 24.0)
        if mean_remediation_hours is None:
            remediation_term = 0.5
        else:
            remediation_term = 0.5 * _clamp(1.0 - mean_remediation_hours / 72.0)
        factor_component = 2.0 * _clamp(coverage) + 2.0 * _clamp(gate_compliance) + response_term + remediation_term

        score = round(_clamp(0.6 * finding_component + factor_component), 2)
        return PostureSnapshot(
            subject=subject,
            posture_score=score,
            findings_by_severity=counts,
            coverage=round(coverage, 4),
            gate_compliance=round(gate_compliance, 4),
            average_response_hours=round(average_response_hours, 4),
            mean_remediation_hours=mean_remediation_hours,
        )