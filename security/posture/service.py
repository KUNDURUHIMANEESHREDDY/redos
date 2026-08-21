from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from security.database import get_database
from security.posture.models import (
    Target,
    TargetVersion,
    TargetStatus,
    PostureMetric,
    PostureSnapshot,
    PostureLevel,
    RiskHistoryEntry,
    TargetRiskHistory,
    PostureComparison,
)
from security.findings.models import Finding, FindingStatus, SeverityLevel
from security.evidence.models import Evidence
import structlog

logger = structlog.get_logger()


class PostureEngine:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.targets_collection = self.db.targets
        self.target_versions_collection = self.db.target_versions
        self.posture_snapshots_collection = self.db.posture_snapshots
        self.risk_history_collection = self.db.risk_history
        self.findings_collection = self.db.findings
        self.evidence_collection = self.db.evidence

    async def register_target(self, target: Target) -> Target:
        existing = await self.targets_collection.find_one({"name": target.name, "target_type": target.target_type.value})
        if existing:
            raise ValueError(f"Target {target.name} of type {target.target_type.value} already exists")
        await self.targets_collection.insert_one(target.model_dump())
        logger.info("Target registered", target_id=str(target.id), name=target.name)
        return target

    async def get_target(self, target_id: UUID) -> Optional[Target]:
        doc = await self.targets_collection.find_one({"id": str(target_id)})
        return Target(**doc) if doc else None

    async def list_targets(self, target_type: Optional[str] = None, status: Optional[TargetStatus] = None) -> list[Target]:
        query = {}
        if target_type:
            query["target_type"] = target_type
        if status:
            query["status"] = status.value
        cursor = self.targets_collection.find(query)
        return [Target(**doc) async for doc in cursor]

    async def update_target_version(self, target_id: UUID, version: str, configuration: dict[str, Any], change_summary: str, changed_by: Optional[str] = None) -> TargetVersion:
        target = await self.get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id} not found")

        target_version = TargetVersion(
            target_id=target_id,
            version=version,
            configuration_snapshot=configuration,
            change_summary=change_summary,
            changed_by=changed_by,
        )
        await self.target_versions_collection.insert_one(target_version.model_dump())

        target.version = version
        target.configuration = configuration
        target.updated_at = datetime.utcnow()
        await self.targets_collection.replace_one({"id": str(target_id)}, target.model_dump())

        await self.compute_posture(target_id)
        logger.info("Target version updated", target_id=str(target_id), version=version)
        return target_version

    async def compute_posture(self, target_id: UUID) -> PostureSnapshot:
        target = await self.get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id} not found")

        findings = await self._get_findings_for_target(target_id)
        evidence = await self._get_evidence_for_target(target_id)

        metrics = self._calculate_metrics(findings, evidence)
        overall_score = self._calculate_overall_score(metrics)
        posture_level = self._score_to_posture(overall_score)

        snapshot = PostureSnapshot(
            target_id=target_id,
            posture_level=posture_level,
            overall_score=overall_score,
            metrics=metrics,
            critical_findings_count=len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            high_findings_count=len([f for f in findings if f.severity == SeverityLevel.HIGH]),
            medium_findings_count=len([f for f in findings if f.severity == SeverityLevel.MEDIUM]),
            low_findings_count=len([f for f in findings if f.severity == SeverityLevel.LOW]),
            total_findings_count=len(findings),
            attack_coverage=await self._calculate_attack_coverage(target_id),
            remediation_rate=await self._calculate_remediation_rate(target_id),
            regression_rate=await self._calculate_regression_rate(target_id),
            unresolved_risk_score=self._calculate_unresolved_risk(findings),
        )

        await self.posture_snapshots_collection.insert_one(snapshot.model_dump())

        history_entry = RiskHistoryEntry(
            target_id=target_id,
            timestamp=datetime.utcnow(),
            posture_snapshot=snapshot,
            trigger="posture_computation",
            finding_ids=[f.id for f in findings],
            change_type="posture_update",
            description=f"Posture computed: {posture_level.value} (score: {overall_score:.1f})",
        )
        await self.risk_history_collection.insert_one(history_entry.model_dump())

        logger.info("Posture computed", target_id=str(target_id), level=posture_level.value, score=overall_score)
        return snapshot

    def _calculate_metrics(self, findings: list[Finding], evidence: list[Evidence]) -> list[PostureMetric]:
        metrics = []

        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        high_count = len([f for f in findings if f.severity == SeverityLevel.HIGH])
        medium_count = len([f for f in findings if f.severity == SeverityLevel.MEDIUM])
        low_count = len([f for f in findings if f.severity == SeverityLevel.LOW])

        metrics.append(PostureMetric(
            name="critical_findings",
            value=critical_count,
            unit="count",
            threshold_critical=5,
            threshold_high=3,
            threshold_medium=1,
            threshold_low=0,
            description="Number of critical severity findings",
            computed_at=datetime.utcnow(),
        ))
        metrics.append(PostureMetric(
            name="high_findings",
            value=high_count,
            unit="count",
            threshold_critical=10,
            threshold_high=5,
            threshold_medium=2,
            threshold_low=0,
            description="Number of high severity findings",
            computed_at=datetime.utcnow(),
        ))
        metrics.append(PostureMetric(
            name="total_findings",
            value=len(findings),
            unit="count",
            threshold_critical=50,
            threshold_high=25,
            threshold_medium=10,
            threshold_low=5,
            description="Total number of findings",
            computed_at=datetime.utcnow(),
        ))

        if findings:
            avg_risk = sum(f.risk_score for f in findings) / len(findings)
            metrics.append(PostureMetric(
                name="average_risk_score",
                value=round(avg_risk, 2),
                unit="cvss",
                threshold_critical=8.0,
                threshold_high=6.0,
                threshold_medium=4.0,
                threshold_low=2.0,
                description="Average CVSS risk score across findings",
                computed_at=datetime.utcnow(),
            ))

        evidence_count = len(evidence)
        metrics.append(PostureMetric(
            name="evidence_count",
            value=evidence_count,
            unit="count",
            description="Total evidence items collected",
            computed_at=datetime.utcnow(),
        ))

        return metrics

    def _calculate_overall_score(self, metrics: list[PostureMetric]) -> float:
        critical = next((m.value for m in metrics if m.name == "critical_findings"), 0)
        high = next((m.value for m in metrics if m.name == "high_findings"), 0)
        avg_risk = next((m.value for m in metrics if m.name == "average_risk_score"), 0)

        score = (critical * 10) + (high * 5) + (avg_risk * 2)
        return min(100.0, max(0.0, score))

    def _score_to_posture(self, score: float) -> PostureLevel:
        if score >= 70:
            return PostureLevel.CRITICAL
        elif score >= 40:
            return PostureLevel.HIGH
        elif score >= 20:
            return PostureLevel.MEDIUM
        elif score >= 5:
            return PostureLevel.LOW
        return PostureLevel.MINIMAL

    def _calculate_unresolved_risk(self, findings: list[Finding]) -> float:
        open_findings = [f for f in findings if f.status in (FindingStatus.NEW, FindingStatus.CONFIRMED, FindingStatus.REMEDIATED, FindingStatus.REGRESSION_TESTED)]
        if not open_findings:
            return 0.0
        return sum(f.risk_score for f in open_findings) / len(open_findings)

    async def _calculate_attack_coverage(self, target_id: UUID) -> float:
        from security.intelligence.models import AttackCoverageAnalytics
        latest = await self.db.attack_coverage_analytics.find_one(
            {"target_id": str(target_id)},
            sort=[("computed_at", -1)]
        )
        if latest:
            return latest.get("coverage_percentage", 0.0)
        return 0.0

    async def _calculate_remediation_rate(self, target_id: UUID) -> float:
        findings = await self._get_findings_for_target(target_id)
        if not findings:
            return 1.0
        remediated = len([f for f in findings if f.status in (FindingStatus.FIXED, FindingStatus.VERIFIED)])
        return remediated / len(findings)

    async def _calculate_regression_rate(self, target_id: UUID) -> float:
        from security.regression.models import RegressionRun
        runs = await self.db.regression_runs.find({"finding_id": {"$in": [str(f.id) for f in await self._get_findings_for_target(target_id)]}}).to_list(None)
        if not runs:
            return 0.0
        regressions = len([r for r in runs if r.get("result") == "regression"])
        return regressions / len(runs)

    async def _get_findings_for_target(self, target_id: UUID) -> list[Finding]:
        target = await self.get_target(target_id)
        if not target:
            return []
        cursor = self.findings_collection.find({"target_id": target_id})
        return [Finding(**doc) async for doc in cursor]

    async def _get_evidence_for_target(self, target_id: UUID) -> list[Evidence]:
        target = await self.get_target(target_id)
        if not target:
            return []
        cursor = self.evidence_collection.find({"target_id": target_id})
        return [Evidence(**doc) async for doc in cursor]

    async def get_risk_history(self, target_id: UUID, days: int = 30) -> TargetRiskHistory:
        cutoff = datetime.utcnow() - timedelta(days=days)
        cursor = self.risk_history_collection.find({"target_id": str(target_id), "timestamp": {"$gte": cutoff}}).sort("timestamp", 1)
        entries = [RiskHistoryEntry(**doc) async for doc in cursor]

        current = None
        if entries:
            current = entries[-1].posture_snapshot

        trend = "stable"
        risk_velocity = 0.0
        if len(entries) >= 2:
            recent = entries[-1].posture_snapshot.overall_score
            older = entries[0].posture_snapshot.overall_score
            delta = recent - older
            risk_velocity = delta / len(entries)
            if delta > 5:
                trend = "deteriorating"
            elif delta < -5:
                trend = "improving"

        return TargetRiskHistory(
            target_id=target_id,
            entries=entries,
            current_posture=current,
            trend=trend,
            risk_velocity=risk_velocity,
        )

    async def compare_posture(self, target_id: UUID, baseline_snapshot_id: UUID) -> PostureComparison:
        current = await self.compute_posture(target_id)
        baseline_doc = await self.posture_snapshots_collection.find_one({"snapshot_id": str(baseline_snapshot_id)})
        if not baseline_doc:
            raise ValueError(f"Baseline snapshot {baseline_snapshot_id} not found")
        baseline = PostureSnapshot(**baseline_doc)

        score_delta = current.overall_score - baseline.overall_score
        posture_changed = current.posture_level != baseline.posture_level

        current_findings = await self._get_findings_for_target(target_id)
        current_finding_ids = {f.id for f in current_findings}
        baseline_findings = await self._get_findings_for_target_at(target_id, baseline.computed_at)
        baseline_finding_ids = {f.id for f in baseline_findings}

        new_findings = list(current_finding_ids - baseline_finding_ids)
        fixed_findings = list(baseline_finding_ids - current_finding_ids)
        regressed_findings = []

        comparison = PostureComparison(
            target_id=target_id,
            baseline_snapshot=baseline,
            current_snapshot=current,
            score_delta=score_delta,
            posture_changed=posture_changed,
            new_critical=len([f for f in current_findings if f.id in new_findings and f.severity == SeverityLevel.CRITICAL]),
            new_high=len([f for f in current_findings if f.id in new_findings and f.severity == SeverityLevel.HIGH]),
            fixed_critical=len([f for f in baseline_findings if f.id in fixed_findings and f.severity == SeverityLevel.CRITICAL]),
            fixed_high=len([f for f in baseline_findings if f.id in fixed_findings and f.severity == SeverityLevel.HIGH]),
            regressed_findings=regressed_findings,
            new_findings=new_findings,
            fixed_findings=fixed_findings,
        )

        await self.db.posture_comparisons.insert_one(comparison.model_dump())
        return comparison

    async def _get_findings_for_target_at(self, target_id: UUID, at_time: datetime) -> list[Finding]:
        target = await self.get_target(target_id)
        if not target:
            return []
        cursor = self.findings_collection.find({"target_id": target_id, "created_at": {"$lte": at_time}})
        return [Finding(**doc) async for doc in cursor]