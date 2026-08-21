from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field, ConfigDict
from security.database import get_database
from security.baselines.models import Baseline, BaselineComparison
import structlog

logger = structlog.get_logger()


class Baseline(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    baseline_id: UUID = Field(default_factory=uuid4)
    target: str
    name: str
    description: str
    metrics: dict[str, float] = Field(default_factory=dict)
    findings_summary: dict[str, int] = Field(default_factory=dict)
    period_start: datetime
    period_end: datetime
    execution_ids: list[UUID] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class BaselineComparison(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    comparison_id: UUID = Field(default_factory=uuid4)
    baseline_id: UUID
    execution_id: UUID
    metric_changes: dict[str, float] = Field(default_factory=dict)
    new_findings: int = 0
    resolved_findings: int = 0
    regressed_findings: int = 0
    risk_score_delta: float = 0.0
    compared_at: datetime = Field(default_factory=datetime.utcnow)


class BaselineService:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.baselines_collection = self.db.baselines
        self.comparisons_collection = self.db.baseline_comparisons
        self.findings_collection = self.db.findings

    async def create_baseline(
        self,
        target: str,
        name: str,
        description: str,
        execution_ids: list[UUID],
        days_back: int = 30,
    ) -> Baseline:
        period_end = datetime.utcnow()
        period_start = period_end - timedelta(days=days_back)

        findings = await self._get_findings_for_executions(execution_ids)

        metrics = self._calculate_metrics(findings)
        findings_summary = self._summarize_findings(findings)

        baseline = Baseline(
            target=target,
            name=name,
            description=description,
            metrics=metrics,
            findings_summary=findings_summary,
            period_start=period_start,
            period_end=period_end,
            execution_ids=execution_ids,
        )
        await self.baselines_collection.insert_one(baseline.model_dump())
        logger.info("Baseline created", baseline_id=str(baseline.baseline_id), target=target)
        return baseline

    async def compare_to_baseline(self, baseline_id: UUID, execution_id: UUID) -> BaselineComparison:
        baseline = await self.get_baseline(baseline_id)
        if not baseline:
            raise ValueError(f"Baseline {baseline_id} not found")

        current_findings = await self._get_findings_for_executions([execution_id])
        current_metrics = self._calculate_metrics(current_findings)

        metric_changes = {}
        for key, current_value in current_metrics.items():
            baseline_value = baseline.metrics.get(key, 0)
            if baseline_value != 0:
                metric_changes[key] = round((current_value - baseline_value) / baseline_value * 100, 2)
            else:
                metric_changes[key] = 100.0 if current_value > 0 else 0.0

        baseline_findings = await self._get_findings_for_executions(baseline.execution_ids)
        baseline_finding_ids = {f.id for f in baseline_findings}
        current_finding_ids = {f.id for f in current_findings}

        new_findings = len(current_finding_ids - baseline_finding_ids)
        resolved_findings = len(baseline_finding_ids - current_finding_ids)

        regressed = 0
        for finding in current_findings:
            if finding.status.value == "open" and finding.id in baseline_finding_ids:
                regressed += 1

        risk_score_delta = current_metrics.get("avg_risk_score", 0) - baseline.metrics.get("avg_risk_score", 0)

        comparison = BaselineComparison(
            baseline_id=baseline_id,
            execution_id=execution_id,
            metric_changes=metric_changes,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            regressed_findings=regressed,
            risk_score_delta=risk_score_delta,
        )
        await self.comparisons_collection.insert_one(comparison.model_dump())
        logger.info("Baseline comparison completed", comparison_id=str(comparison.comparison_id))
        return comparison

    async def detect_regression(self, execution_id: UUID, threshold: float = 10.0) -> dict[str, Any]:
        baselines = await self.list_baselines(target=None)
        if not baselines:
            return {"regression_detected": False, "reason": "No baselines available"}

        latest_baseline = max(baselines, key=lambda b: b.created_at)
        comparison = await self.compare_to_baseline(latest_baseline.baseline_id, execution_id)

        regression_detected = (
            comparison.risk_score_delta > threshold
            or comparison.new_findings > 5
            or comparison.regressed_findings > 0
        )

        return {
            "regression_detected": regression_detected,
            "comparison": comparison.model_dump(),
            "threshold": threshold,
        }

    def _calculate_metrics(self, findings: list) -> dict[str, float]:
        if not findings:
            return {"total_findings": 0, "avg_risk_score": 0, "critical_count": 0, "high_count": 0}

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_risk = 0

        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
            total_risk += f.risk_score

        return {
            "total_findings": len(findings),
            "avg_risk_score": round(total_risk / len(findings), 2),
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "info_count": severity_counts["info"],
        }

    def _summarize_findings(self, findings: list) -> dict[str, int]:
        summary = {}
        for f in findings:
            key = f.vulnerability_type.value
            summary[key] = summary.get(key, 0) + 1
        return summary

    async def _get_findings_for_executions(self, execution_ids: list[UUID]) -> list:
        if not execution_ids:
            return []
        cursor = self.findings_collection.find({"execution_id": {"$in": [str(e) for e in execution_ids]}})
        from security.findings.models import Finding
        return [Finding(**doc) async for doc in cursor]

    async def get_baseline(self, baseline_id: UUID) -> Baseline | None:
        doc = await self.baselines_collection.find_one({"baseline_id": str(baseline_id)})
        return Baseline(**doc) if doc else None

    async def list_baselines(self, target: str | None = None) -> list[Baseline]:
        query = {"target": target} if target else {}
        cursor = self.baselines_collection.find(query).sort("created_at", -1)
        return [Baseline(**doc) async for doc in cursor]

    async def get_comparison(self, comparison_id: UUID) -> BaselineComparison | None:
        doc = await self.comparisons_collection.find_one({"comparison_id": str(comparison_id)})
        return BaselineComparison(**doc) if doc else None