from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from security.database import get_database
from security.correlation.models import (
    FindingCorrelation,
    CorrelationType,
    CorrelationSeverity,
    CorrelationStatus,
    CompositeAttackPath,
    SystemicRiskAssessment,
    CorrelationRule,
    CorrelationResult,
)
from security.findings.models import Finding, FindingStatus
from security.posture.models import Target
from security.evidence.models import Evidence
import structlog

logger = structlog.get_logger()


class CorrelationEngine:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.correlations_collection = self.db.finding_correlations
        self.composite_paths_collection = self.db.composite_attack_paths
        self.systemic_risk_collection = self.db.systemic_risk_assessments
        self.correlation_rules_collection = self.db.correlation_rules
        self.correlation_results_collection = self.db.correlation_results
        self.findings_collection = self.db.findings
        self.evidence_collection = self.db.evidence

    async def analyze_correlations(self, target_id: UUID, days: int = 30) -> CorrelationResult:
        start_time = datetime.utcnow()
        cutoff = datetime.utcnow() - timedelta(days=days)

        findings = await self._get_findings_for_target(target_id, cutoff)
        correlations = []

        for i, finding_a in enumerate(findings):
            for finding_b in findings[i+1:]:
                correlation = await self._check_correlation(finding_a, finding_b, target_id)
                if correlation:
                    correlations.append(correlation)
                    await self.correlations_collection.insert_one(correlation.model_dump())

        composite_paths = await self._build_composite_paths(target_id, correlations)
        for path in composite_paths:
            await self.composite_paths_collection.insert_one(path.model_dump())

        systemic_risk = await self._assess_systemic_risk(target_id, composite_paths, findings)
        if systemic_risk:
            await self.systemic_risk_collection.insert_one(systemic_risk.model_dump())

        result = CorrelationResult(
            target_id=target_id,
            correlations=correlations,
            composite_paths=composite_paths,
            systemic_risk=systemic_risk.assessment_id if systemic_risk else None,
            total_correlations=len(correlations),
            critical_correlations=len([c for c in correlations if c.severity == CorrelationSeverity.CRITICAL]),
            high_correlations=len([c for c in correlations if c.severity == CorrelationSeverity.HIGH]),
            new_correlations=len(correlations),
            analyzed_at=datetime.utcnow(),
            analysis_duration_ms=int((datetime.utcnow() - datetime.utcnow()).total_seconds() * 1000),
        )

        await self.correlation_results_collection.insert_one(result.model_dump())
        logger.info("Correlation analysis completed", target_id=str(target_id), correlations=len(correlations), paths=len(composite_paths))
        return result

    async def _check_correlation(self, finding_a: Finding, finding_b: Finding, target_id: UUID) -> Optional[FindingCorrelation]:
        shared_evidence = set(finding_a.evidence_ids) & set(finding_b.evidence_ids)
        if shared_evidence:
            return FindingCorrelation(
                correlation_type=CorrelationType.SHARED_EVIDENCE,
                severity=self._calculate_severity(finding_a, finding_b),
                finding_ids=[finding_a.id, finding_b.id],
                description=f"Findings share {len(shared_evidence)} evidence items",
                shared_evidence_ids=list(shared_evidence),
                risk_score=max(finding_a.risk_score, finding_b.risk_score),
                systemic_risk_score=self._calculate_systemic_risk(finding_a, finding_b),
            )

        if finding_a.target_id == finding_b.target_id:
            if self._can_chain(finding_a, finding_b):
                return FindingCorrelation(
                    correlation_type=CorrelationType.CHAINED_VULNERABILITY,
                    severity=self._calculate_severity(finding_a, finding_b),
                    finding_ids=[finding_a.id, finding_b.id],
                    description=f"{finding_a.vulnerability_type.value} can chain to {finding_b.vulnerability_type.value}",
                    attack_path=[finding_a.attack_id, finding_b.attack_id],
                    risk_score=finding_a.risk_score + finding_b.risk_score,
                    systemic_risk_score=self._calculate_systemic_risk(finding_a, finding_b) * 1.5,
                )

        if self._same_attack_vector(finding_a, finding_b):
            return FindingCorrelation(
                correlation_type=CorrelationType.SHARED_ATTACK_VECTOR,
                severity=CorrelationSeverity.MEDIUM,
                finding_ids=[finding_a.id, finding_b.id],
                description=f"Both findings use {finding_a.attack_id} attack vector",
                attack_path=[finding_a.attack_id],
                risk_score=max(finding_a.risk_score, finding_b.risk_score),
            )

        return None

    def _calculate_severity(self, finding_a: Finding, finding_b: Finding) -> CorrelationSeverity:
        max_risk = max(finding_a.risk_score, finding_b.risk_score)
        if max_risk >= 9.0:
            return CorrelationSeverity.CRITICAL
        elif max_risk >= 7.0:
            return CorrelationSeverity.HIGH
        elif max_risk >= 4.0:
            return CorrelationSeverity.MEDIUM
        return CorrelationSeverity.LOW

    def _calculate_systemic_risk(self, finding_a: Finding, finding_b: Finding) -> float:
        base = max(finding_a.risk_score, finding_b.risk_score)
        return min(10.0, base * 1.2)

    def _can_chain(self, finding_a: Finding, finding_b: Finding) -> bool:
        chain_map = {
            "sql_injection": ["command_injection", "path_traversal", "broken_access_control"],
            "xss": ["csrf", "open_redirect", "broken_access_control"],
            "command_injection": ["path_traversal", "broken_access_control"],
            "path_traversal": ["broken_access_control", "sensitive_data_exposure"],
            "broken_auth": ["broken_access_control", "sensitive_data_exposure"],
            "ssrf": ["broken_access_control", "sensitive_data_exposure"],
        }
        return finding_b.vulnerability_type.value in chain_map.get(finding_a.vulnerability_type.value, [])

    def _same_attack_vector(self, finding_a: Finding, finding_b: Finding) -> bool:
        return finding_a.attack_id == finding_b.attack_id

    async def _build_composite_paths(self, target_id: UUID, correlations: list[FindingCorrelation]) -> list[CompositeAttackPath]:
        paths = []
        chains = [c for c in correlations if c.correlation_type == CorrelationType.CHAINED_VULNERABILITY]

        for chain in chains:
            findings = await self._get_findings_by_ids(chain.finding_ids)
            if len(findings) >= 2:
                path = CompositeAttackPath(
                    name=f"Composite: {' -> '.join(f.attack_id for f in findings)}",
                    description=f"Chained attack path: {' -> '.join(f.attack_id for f in findings)}",
                    finding_correlations=[chain.correlation_id],
                    attack_steps=[{"finding_id": str(f.id), "attack": f.attack_id, "technique": f.vulnerability_type.value} for f in findings],
                    entry_points=[findings[0].attack_id],
                    target_assets=[f.target_id for f in findings],
                    mitre_techniques=list(set(t for f in findings for t in self._get_mitre_techniques(f))),
                    overall_risk_score=sum(f.risk_score for f in findings),
                    exploitability=max(f.risk_score for f in findings),
                    impact=sum(f.risk_score for f in findings) / len(findings),
                    evidence_ids=list(set(e for f in findings for e in f.evidence_ids)),
                )
                paths.append(path)

        return paths

    def _get_mitre_techniques(self, finding: Finding) -> list[str]:
        technique_map = {
            "sql_injection": ["T1190"],
            "command_injection": ["T1059"],
            "xss": ["T1059.007"],
            "path_traversal": ["T1005"],
            "ssrf": ["T1190"],
            "broken_auth": ["T1078"],
            "broken_access_control": ["T1078"],
        }
        return technique_map.get(finding.vulnerability_type.value, [])

    async def _assess_systemic_risk(self, target_id: UUID, composite_paths: list[CompositeAttackPath], findings: list[Finding]) -> Optional[SystemicRiskAssessment]:
        if not composite_paths:
            return None

        critical_paths = len([p for p in composite_paths if p.overall_risk_score >= 9.0])
        exploitable_chains = len([p for p in composite_paths if p.exploitability >= 7.0])

        blast_radius = {}
        for path in composite_paths:
            for asset in path.target_assets:
                blast_radius[asset] = blast_radius.get(asset, 0) + 1

        return SystemicRiskAssessment(
            target_id=target_id,
            composite_paths=[p.path_id for p in composite_paths],
            overall_systemic_risk=max(p.overall_risk_score for p in composite_paths),
            risk_factors={
                "critical_paths": critical_paths,
                "exploitable_chains": exploitable_chains,
                "total_findings": len(findings),
                "avg_risk": sum(f.risk_score for f in findings) / len(findings) if findings else 0,
            },
            critical_attack_paths=critical_paths,
            exploitable_chains=exploitable_chains,
            blast_radius=blast_radius,
            recommendations=self._generate_recommendations(composite_paths, findings),
        )

    def _generate_recommendations(self, paths: list[CompositeAttackPath], findings: list[Finding]) -> list[str]:
        recs = []
        if paths:
            recs.append(f"Prioritize remediation of {len(paths)} composite attack paths")
        critical = [f for f in findings if f.severity.value == "critical"]
        if critical:
            recs.append(f"Address {len(critical)} critical findings immediately")
        return recs

    async def _get_findings_for_target(self, target_id: UUID, cutoff: datetime) -> list[Finding]:
        cursor = self.findings_collection.find({
            "target_id": target_id,
            "created_at": {"$gte": cutoff},
            "status": {"$nin": ["duplicate", "false_positive", "wont_fix"]},
        })
        return [Finding(**doc) async for doc in cursor]

    async def _get_findings_by_ids(self, finding_ids: list[UUID]) -> list[Finding]:
        cursor = self.findings_collection.find({"id": {"$in": [str(f) for f in finding_ids]}})
        return [Finding(**doc) async for doc in cursor]

    async def get_correlation_history(self, target_id: UUID, days: int = 30) -> list[FindingCorrelation]:
        cutoff = datetime.utcnow() - timedelta(days=days)
        cursor = self.correlations_collection.find({"finding_ids": {"$in": [str(f) for f in await self._get_findings_for_target(target_id, cutoff)]}})
        return [FindingCorrelation(**doc) async for doc in cursor]

    async def validate_correlation(self, correlation_id: UUID, validated: bool = True) -> Optional[FindingCorrelation]:
        update = {
            "status": CorrelationStatus.VALIDATED if validated else CorrelationStatus.FALSE_POSITIVE,
            "validated_at": datetime.utcnow(),
        }
        doc = await self.correlations_collection.find_one_and_update(
            {"correlation_id": str(correlation_id)},
            {"$set": update},
            return_document=True,
        )
        return FindingCorrelation(**doc) if doc else None

    async def mitigate_correlation(self, correlation_id: UUID) -> Optional[FindingCorrelation]:
        update = {
            "status": CorrelationStatus.MITIGATED,
            "mitigated_at": datetime.utcnow(),
        }
        doc = await self.correlations_collection.find_one_and_update(
            {"correlation_id": str(correlation_id)},
            {"$set": update},
            return_document=True,
        )
        return FindingCorrelation(**doc) if doc else None

    async def create_correlation_rule(self, rule: CorrelationRule) -> CorrelationRule:
        await self.correlation_rules_collection.insert_one(rule.model_dump())
        return rule

    async def list_correlation_rules(self) -> list[CorrelationRule]:
        cursor = self.correlation_rules_collection.find({"enabled": True})
        return [CorrelationRule(**doc) async for doc in cursor]