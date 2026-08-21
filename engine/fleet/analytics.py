from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from engine.fleet.posture import count_by_severity
from engine.model.execution import ExecutionResult, ExecutionStatus
from engine.security import FindingRecord

SCANNABLE_STATUSES = (ExecutionStatus.SUCCESS, ExecutionStatus.FAILURE, ExecutionStatus.TIMED_OUT, ExecutionStatus.INDETERMINATE)


@dataclass(frozen=True, slots=True)
class FleetMetrics:
    """Measured fleet numbers. No value here is estimated; fields without
    data are None or zero."""

    period_hours: float
    targets_known: int
    targets_scanned: int
    scan_coverage: float
    executions_total: int
    executions_succeeded: int
    scan_success_rate: float | None
    findings_total: int
    findings_by_severity: dict[str, int]
    critical_findings_unaddressed: int
    campaigns_gated: int
    campaigns_blocked: int
    gate_blocking_rate: float | None
    measured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "period_hours": self.period_hours,
            "targets_known": self.targets_known,
            "targets_scanned": self.targets_scanned,
            "scan_coverage": self.scan_coverage,
            "executions_total": self.executions_total,
            "executions_succeeded": self.executions_succeeded,
            "scan_success_rate": self.scan_success_rate,
            "findings_total": self.findings_total,
            "findings_by_severity": dict(self.findings_by_severity),
            "critical_findings_unaddressed": self.critical_findings_unaddressed,
            "campaigns_gated": self.campaigns_gated,
            "campaigns_blocked": self.campaigns_blocked,
            "gate_blocking_rate": self.gate_blocking_rate,
            "measured_at": self.measured_at.isoformat(),
        }


class FleetAnalytics:
    """Computes fleet-level metrics from real records only."""

    def compute(
        self,
        *,
        targets_known: int,
        executions: Iterable[ExecutionResult],
        findings: Iterable[FindingRecord],
        audits: Iterable[dict[str, Any]] | None = None,
        period_hours: float = 24.0,
    ) -> FleetMetrics:
        executions = list(executions)
        findings = list(findings)
        audits = list(audits or [])

        scanned_targets = {e.execution.target_id for e in executions}
        successes = sum(1 for e in executions if e.execution.status == ExecutionStatus.SUCCESS)
        scan_success_rate = (successes / len(executions)) if executions else None

        counts = count_by_severity(findings)
        critical_unaddressed = counts["CRITICAL"] + counts["HIGH"]

        gated = [a for a in audits if a.get("action", "").startswith("gate.")]
        blocked = [a for a in gated if str(a.get("outcome", "pass")).lower() == "block"]
        gate_blocking_rate = (len(blocked) / len(gated)) if gated else None

        return FleetMetrics(
            period_hours=period_hours,
            targets_known=targets_known,
            targets_scanned=len(scanned_targets),
            scan_coverage=round(len(scanned_targets) / targets_known, 4) if targets_known else 0.0,
            executions_total=len(executions),
            executions_succeeded=successes,
            scan_success_rate=round(scan_success_rate, 4) if scan_success_rate is not None else None,
            findings_total=len(findings),
            findings_by_severity=counts,
            critical_findings_unaddressed=critical_unaddressed,
            campaigns_gated=len(gated),
            campaigns_blocked=len(blocked),
            gate_blocking_rate=round(gate_blocking_rate, 4) if gate_blocking_rate is not None else None,
        )