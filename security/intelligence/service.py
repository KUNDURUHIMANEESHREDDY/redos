from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from security.database import get_database
from security.intelligence.models import (
    RegressionIntelligence,
    RegressionType,
    AttackCoverageAnalytics,
    RiskTrendAnalysis,
    EvidenceLineage,
    ModelVersionComparison,
    TargetComparison,
    RemediationVerification,
    IntelligenceReport,
    IntelligenceType,
    IntelligencePriority,
)
from security.findings.models import Finding, FindingStatus
from security.regression.models import RegressionRun, RegressionTest
from security.evidence.models import Evidence
from security.remediation.models import RemediationAction
import structlog

logger = structlog.get_logger()


class RegressionIntelligenceService:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.intelligence_collection = self.db.regression_intelligence
        self.attack_coverage_collection = self.db.attack_coverage_analytics
        self.risk_trend_collection = self.db.risk_trend_analysis
        self.evidence_lineage_collection = self.db.evidence_lineage
        self.model_comparison_collection = self.db.model_version_comparisons
        self.target_comparison_collection = self.db.target_comparisons
        self.remediation_verification_collection = self.db.remediation_verifications
        self.intelligence_reports_collection = self.db.intelligence_reports
        self.findings_collection = self.db.findings
        self.regression_runs_collection = self.db.regression_runs
        self.regression_tests_collection = self.db.regression_tests
        self.evidence_collection = self.db.evidence
        self.remediation_collection = self.db.remediation_actions

    async def analyze_regression(self, finding_id: UUID, execution_a_id: UUID, execution_b_id: UUID) -> RegressionIntelligence:
        finding = await self._get_finding(finding_id)
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        runs_a = await self._get_regression_runs(finding_id, execution_a_id)
        runs_b = await self._get_regression_runs(finding_id, execution_b_id)

        result_a = runs_a[0].get("result") if runs_a else None
        result_b = runs_b[0].get("result") if runs_b else None

        regression_type = self._determine_regression_type(result_a, result_b)
        what_changed = self._describe_change(finding, result_a, result_b)
        why_changed = await self._analyze_why_changed(finding, execution_a_id, execution_b_id)
        affected_vectors = await self._get_affected_attack_vectors(finding)
        recommended_reruns = await self._get_recommended_reruns(finding, regression_type)
        severity_delta = self._calculate_severity_delta(finding, execution_a_id, execution_b_id)

        intelligence = RegressionIntelligence(
            target_id=finding.target_id,
            execution_a_id=execution_a_id,
            execution_b_id=execution_b_id,
            finding_id=finding_id,
            regression_type=regression_type,
            what_changed=what_changed,
            why_changed=why_changed,
            affected_attack_vectors=affected_vectors,
            recommended_reruns=recommended_reruns,
            severity_delta=severity_delta,
            confidence=0.9 if result_b == "regression" else 0.7,
            evidence={
                "runs_a": len(runs_a),
                "runs_b": len(runs_b),
                "result_a": result_a,
                "result_b": result_b,
            },
        )

        await self.intelligence_collection.insert_one(intelligence.model_dump())
        logger.info("Regression intelligence generated", finding_id=str(finding_id), type=regression_type.value)
        return intelligence

    def _determine_regression_type(self, result_a: Optional[str], result_b: Optional[str]) -> RegressionType:
        if result_a == "fixed" and result_b == "regression":
            return RegressionType.REGRESSION
        elif result_a == "regression" and result_b == "fixed":
            return RegressionType.FIXED
        elif result_a != result_b:
            return RegressionType.CHANGED
        elif result_a is None and result_b == "fixed":
            return RegressionType.NEW
        return RegressionType.UNCHANGED

    def _describe_change(self, finding: Finding, result_a: Optional[str], result_b: Optional[str]) -> str:
        if result_a == "fixed" and result_b == "regression":
            return f"Previously fixed {finding.vulnerability_type.value} has regressed"
        elif result_a == "regression" and result_b == "fixed":
            return f"Previously regressed {finding.vulnerability_type.value} is now fixed"
        elif result_a != result_b:
            return f"Finding status changed from {result_a} to {result_b}"
        return "Finding status unchanged"

    async def _analyze_why_changed(self, finding: Finding, execution_a_id: UUID, execution_b_id: UUID) -> str:
        changes = await self.db.change_events.find({
            "target_id": finding.target_id,
            "detected_at": {"$gte": execution_a_id, "$lte": execution_b_id}
        }).to_list(None)

        if changes:
            change_types = [c["change_type"] for c in changes]
            return f"System changes detected: {', '.join(set(change_types))}"
        return "No system changes detected; may be environmental or test flakiness"

    async def _get_affected_attack_vectors(self, finding: Finding) -> list[str]:
        return [finding.attack_id, finding.vulnerability_type.value]

    async def _get_recommended_reruns(self, finding: Finding, regression_type: RegressionType) -> list[str]:
        if regression_type == RegressionType.REGRESSION:
            return [
                f"Rerun {finding.vulnerability_type.value} attack variants",
                "Run full regression suite",
                "Verify remediation steps",
            ]
        return []

    def _calculate_severity_delta(self, finding: Finding, execution_a_id: UUID, execution_b_id: UUID) -> float:
        return 0.0

    async def _get_finding(self, finding_id: UUID) -> Optional[Finding]:
        doc = await self.findings_collection.find_one({"id": str(finding_id)})
        return Finding(**doc) if doc else None

    async def _get_regression_runs(self, finding_id: UUID, execution_id: UUID) -> list[dict]:
        cursor = self.regression_runs_collection.find({"finding_id": str(finding_id), "execution_id": str(execution_id)})
        return await cursor.to_list(None)

    async def generate_attack_coverage(self, target_id: UUID, execution_id: UUID) -> AttackCoverageAnalytics:
        findings = await self._get_findings_for_execution(target_id, execution_id)
        evidence = await self._get_evidence_for_execution(execution_id)

        total_vectors = await self._get_total_attack_vectors(target_id)
        covered = len(set(f.attack_id for f in findings))
        uncovered = self._get_uncovered_vectors(target_id, findings)

        tactic_coverage = self._calculate_tactic_coverage(findings)

        analytics = AttackCoverageAnalytics(
            target_id=target_id,
            execution_id=execution_id,
            total_attack_vectors=total_vectors,
            covered_vectors=covered,
            coverage_percentage=(covered / total_vectors * 100) if total_vectors > 0 else 0,
            uncovered_vectors=uncovered,
            tested_vectors=[{"attack_id": f.attack_id, "severity": f.severity.value} for f in findings],
            mitre_tactics_covered=tactic_coverage["covered"],
            mitre_tactics_missing=tactic_coverage["missing"],
            coverage_by_tactic=tactic_coverage["by_tactic"],
            evidence_ids=[e.id for e in evidence],
        )

        await self.attack_coverage_collection.insert_one(analytics.model_dump())
        return analytics

    async def _get_total_attack_vectors(self, target_id: UUID) -> int:
        return 50

    def _get_uncovered_vectors(self, target_id: UUID, findings: list[Finding]) -> list[str]:
        all_vectors = ["sql_injection", "command_injection", "xss", "path_traversal", "ssrf", "broken_auth", "broken_access_control"]
        covered = set(f.attack_id for f in findings)
        return [v for v in all_vectors if v not in covered]

    def _calculate_tactic_coverage(self, findings: list[Finding]) -> dict[str, Any]:
        tactic_map = {
            "sql_injection": "initial_access",
            "command_injection": "execution",
            "xss": "client_side",
            "path_traversal": "credential_access",
            "ssrf": "initial_access",
            "broken_auth": "credential_access",
            "broken_access_control": "privilege_escalation",
        }
        covered = set()
        for f in findings:
            if f.vulnerability_type.value in tactic_map:
                covered.add(tactic_map[f.vulnerability_type.value])
        all_tactics = ["initial_access", "execution", "credential_access", "privilege_escalation", "client_side"]
        return {
            "covered": list(covered),
            "missing": [t for t in all_tactics if t not in covered],
            "by_tactic": {t: 1 if t in covered else 0 for t in all_tactics},
        }

    async def _get_findings_for_execution(self, target_id: UUID, execution_id: UUID) -> list[Finding]:
        cursor = self.findings_collection.find({"target_id": target_id, "execution_id": str(execution_id)})
        return [Finding(**doc) async for doc in cursor]

    async def _get_evidence_for_execution(self, execution_id: UUID) -> list[Evidence]:
        cursor = self.evidence_collection.find({"execution_id": str(execution_id)})
        return [Evidence(**doc) async for doc in cursor]

    async def analyze_risk_trend(self, target_id: UUID, days: int = 30) -> RiskTrendAnalysis:
        end = datetime.utcnow()
        start = end - timedelta(days=days)

        snapshots = await self._get_posture_snapshots(target_id, start, end)
        if not snapshots:
            raise ValueError("No posture snapshots for period")

        trend_points = [{"timestamp": s.computed_at.isoformat(), "score": s.overall_score} for s in snapshots]
        trend_direction = self._calculate_trend_direction(trend_points)
        risk_velocity = self._calculate_risk_velocity(trend_points)

        posture_changes = sum(1 for i in range(1, len(snapshots)) if snapshots[i].posture_level != snapshots[i-1].posture_level)
        critical_changes = sum(1 for s in snapshots if s.critical_findings_count > 0)
        regression_events = await self._count_regression_events(target_id, start, end)
        remediation_events = await self._count_remediation_events(target_id, start, end)
        net_risk_change = snapshots[-1].overall_score - snapshots[0].overall_score

        return RiskTrendAnalysis(
            target_id=target_id,
            period_start=start,
            period_end=end,
            trend_direction=trend_direction,
            risk_velocity=risk_velocity,
            posture_changes=posture_changes,
            critical_changes=critical_changes,
            regression_events=regression_events,
            remediation_events=remediation_events,
            net_risk_change=net_risk_change,
            trend_points=trend_points,
        )

    def _calculate_trend_direction(self, points: list[dict]) -> str:
        if len(points) < 2:
            return "stable"
        first = points[0]["score"]
        last = points[-1]["score"]
        if last > first + 10:
            return "deteriorating"
        elif last < first - 10:
            return "improving"
        return "stable"

    def _calculate_risk_velocity(self, points: list[dict]) -> float:
        if len(points) < 2:
            return 0.0
        return (points[-1]["score"] - points[0]["score"]) / len(points)

    async def _get_posture_snapshots(self, target_id: UUID, start: datetime, end: datetime) -> list:
        cursor = self.db.posture_snapshots.find({
            "target_id": str(target_id),
            "computed_at": {"$gte": start, "$lte": end}
        }).sort("computed_at", 1)
        return [doc async for doc in cursor]

    async def _count_regression_events(self, target_id: UUID, start: datetime, end: datetime) -> int:
        return 0

    async def _count_remediation_events(self, target_id: UUID, start: datetime, end: datetime) -> int:
        return 0

    async def create_evidence_lineage(self, evidence_id: UUID) -> EvidenceLineage:
        finding = await self._get_finding_by_evidence(evidence_id)
        if not finding:
            raise ValueError(f"No finding for evidence {evidence_id}")

        lineage = EvidenceLineage(
            evidence_id=evidence_id,
            finding_id=finding.id,
            finding_correlations=[],
            attack_paths=[],
            remediation_actions=[],
            regression_tests=[],
            attack_graph_nodes=[],
            severity_assessments=[],
            root_causes=[],
        )
        await self.evidence_lineage_collection.insert_one(lineage.model_dump())
        return lineage

    async def _get_finding_by_evidence(self, evidence_id: UUID) -> Optional[Finding]:
        doc = await self.findings_collection.find_one({"evidence_ids": str(evidence_id)})
        return Finding(**doc) if doc else None

    async def compare_versions(self, target_id: UUID, version_a: str, version_b: str, scan_a_id: UUID, scan_b_id: UUID) -> ModelVersionComparison:
        findings_a = await self._get_findings_for_scan(scan_a_id)
        findings_b = await self._get_findings_for_scan(scan_b_id)

        ids_a = {f.id for f in findings_a}
        ids_b = {f.id for f in findings_b}

        new_vulns = list(ids_b - ids_a)
        fixed_vulns = list(ids_a - ids_b)
        regressed = []

        comparison = ModelVersionComparison(
            target_id=target_id,
            version_a=version_a,
            version_b=version_b,
            scan_a_id=scan_a_id,
            scan_b_id=scan_b_id,
            new_vulnerabilities=new_vulns,
            fixed_vulnerabilities=fixed_vulns,
            regressions=regressed,
            changed_attack_surface=[],
            risk_delta=0.0,
            posture_changed=False,
        )
        await self.model_comparison_collection.insert_one(comparison.model_dump())
        return comparison

    async def _get_findings_for_scan(self, scan_id: UUID) -> list[Finding]:
        cursor = self.findings_collection.find({"execution_id": str(scan_id)})
        return [Finding(**doc) async for doc in cursor]

    async def compare_targets(self, target_a_id: UUID, target_b_id: UUID) -> TargetComparison:
        posture_a = await self._get_latest_posture(target_a_id)
        posture_b = await self._get_latest_posture(target_b_id)

        findings_a = await self._get_findings_for_target(target_a_id)
        findings_b = await self._get_findings_for_target(target_b_id)

        ids_a = {f.id for f in findings_a}
        ids_b = {f.id for f in findings_b}

        comparison = TargetComparison(
            target_a_id=target_a_id,
            target_b_id=target_b_id,
            posture_a=posture_a.posture_level.value if posture_a else "unknown",
            posture_b=posture_b.posture_level.value if posture_b else "unknown",
            risk_delta=posture_b.overall_score - posture_a.overall_score if posture_a and posture_b else 0,
            shared_vulnerabilities=list(ids_a & ids_b),
            unique_to_a=list(ids_a - ids_b),
            unique_to_b=list(ids_b - ids_a),
        )
        await self.target_comparison_collection.insert_one(comparison.model_dump())
        return comparison

    async def _get_latest_posture(self, target_id: UUID) -> Optional[PostureSnapshot]:
        doc = await self.db.posture_snapshots.find_one({"target_id": str(target_id)}, sort=[("computed_at", -1)])
        return PostureSnapshot(**doc) if doc else None

    async def _get_findings_for_target(self, target_id: UUID) -> list[Finding]:
        cursor = self.findings_collection.find({"target_id": target_id})
        return [Finding(**doc) async for doc in cursor]

    async def verify_remediation(self, finding_id: UUID, remediation_id: UUID, test_id: UUID, execution_id: UUID) -> RemediationVerification:
        run = await self.regression_runs_collection.find_one({"test_id": str(test_id), "execution_id": str(execution_id)})
        verified = run.get("result") == "fixed" if run else False

        verification = RemediationVerification(
            finding_id=finding_id,
            remediation_id=remediation_id,
            regression_test_id=test_id,
            test_execution_id=execution_id,
            verified=verified,
            verification_evidence=[run["evidence_ids"]] if run else [],
            details=f"Remediation verified: {verified}",
            verified_at=datetime.utcnow() if verified else None,
        )
        await self.remediation_verification_collection.insert_one(verification.model_dump())
        return verification

    async def create_intelligence_report(self, target_id: UUID, intelligence_type: IntelligenceType, priority: IntelligencePriority, title: str, summary: str, findings: list[UUID], correlations: list[UUID], regressions: list[UUID], recommendations: list[str]) -> IntelligenceReport:
        report = IntelligenceReport(
            target_id=target_id,
            intelligence_type=intelligence_type,
            priority=priority,
            title=title,
            summary=summary,
            findings=findings,
            correlations=correlations,
            regressions=regressions,
            recommendations=recommendations,
        )
        await self.intelligence_reports_collection.insert_one(report.model_dump())
        return report

    async def get_intelligence_reports(self, target_id: UUID) -> list[IntelligenceReport]:
        cursor = self.intelligence_reports_collection.find({"target_id": str(target_id)})
        return [IntelligenceReport(**doc) async for doc in cursor]