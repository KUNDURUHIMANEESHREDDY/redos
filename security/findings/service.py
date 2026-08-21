from datetime import datetime
from typing import Any
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from security.models.finding import (
    Finding,
    FindingStatus,
    VulnerabilityType,
    SeverityLevel,
    ConfidenceLevel,
    ImpactLevel,
    ExploitabilityLevel,
    AttackPath,
    RootCause,
    RemediationAction,
    RegressionTest,
)
from security.models.evidence import Evidence
from security.database import get_database
from security.severity.service import SeverityCalculationService
from security.remediation.service import RemediationService
import structlog

logger = structlog.get_logger()


class FindingService:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.findings_collection = self.db.findings
        self.evidence_collection = self.db.evidence
        self.severity_service = SeverityCalculationService(db)
        self.remediation_service = RemediationService(db)

    async def create_finding(
        self,
        target_id: str,
        attack_id: str,
        execution_id: UUID,
        vulnerability_type: VulnerabilityType,
        evidence_ids: list[UUID],
        severity: SeverityLevel | None = None,
        confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
        impact: ImpactLevel = ImpactLevel.MEDIUM,
        exploitability: ExploitabilityLevel = ExploitabilityLevel.MEDIUM,
    ) -> Finding:
        if not evidence_ids:
            raise ValueError("Finding must have at least one evidence reference")

        for ev_id in evidence_ids:
            evidence = await self._get_evidence(ev_id)
            if not evidence:
                raise ValueError(f"Evidence {ev_id} does not exist")
            if evidence.status.value not in ("normalized", "correlated"):
                raise ValueError(f"Evidence {ev_id} not in valid state (must be normalized or correlated)")

        finding = Finding(
            target_id=target_id,
            attack_id=attack_id,
            execution_id=execution_id,
            vulnerability_type=vulnerability_type,
            severity=SeverityLevel.INFO,  # Will be recalculated
            confidence=confidence,
            impact=impact,
            exploitability=exploitability,
            evidence_ids=evidence_ids,
            status=FindingStatus.NEW,
        )

        # Always recalculate severity from evidence (never trust input)
        severity_assessment = await self.severity_service.assess_finding(finding)
        finding.severity = severity_assessment.severity
        finding.cvss_vector = severity_assessment.cvss_vector.to_vector_string()
        finding.cvss_score = severity_assessment.base_score

        duplicate = await self._check_duplicate(finding)
        if duplicate:
            finding.status = FindingStatus.DUPLICATE
            finding.metadata["duplicate_of"] = str(duplicate.id)
            logger.info("Finding marked as duplicate", finding_id=str(finding.id), duplicate_of=str(duplicate.id))

        await self.findings_collection.insert_one(finding.model_dump())
        logger.info("Finding created", finding_id=str(finding.id), status=finding.status.value)
        return finding

    async def _check_duplicate(self, finding: Finding) -> Finding | None:
        cursor = self.findings_collection.find({
            "execution_id": str(finding.execution_id),
            "vulnerability_type": finding.vulnerability_type.value,
            "target_id": finding.target_id,
            "attack_id": finding.attack_id,
            "status": {"$nin": ["duplicate", "false_positive", "wont_fix"]},
        })
        existing = await cursor.to_list(length=1)
        return Finding(**existing[0]) if existing else None

    async def get_finding(self, finding_id: UUID) -> Finding | None:
        doc = await self.findings_collection.find_one({"id": str(finding_id)})
        return Finding(**doc) if doc else None

    async def get_findings_by_execution(self, execution_id: UUID) -> list[Finding]:
        cursor = self.findings_collection.find({"execution_id": str(execution_id)})
        return [Finding(**doc) async for doc in cursor]

    async def transition_status(self, finding_id: UUID, new_status: FindingStatus) -> Finding | None:
        from security.models.finding import can_transition

        finding = await self.get_finding(finding_id)
        if not finding:
            return None

        if not can_transition(finding.status, new_status):
            raise ValueError(f"Invalid status transition: {finding.status.value} -> {new_status.value}")

        if new_status == FindingStatus.REMEDIATED and not finding.remediation:
            raise ValueError("Cannot transition to REMEDIATED without remediation actions")

        if new_status == FindingStatus.REGRESSION_TESTED and not finding.regression_tests:
            raise ValueError("Cannot transition to REGRESSION_TESTED without regression tests")

        finding.status = new_status
        finding.updated_at = datetime.utcnow()

        if new_status == FindingStatus.FIXED:
            finding.closed_at = datetime.utcnow()

        await self.findings_collection.replace_one(
            {"id": str(finding_id)},
            finding.model_dump(),
        )
        logger.info("Finding status transitioned", finding_id=str(finding_id), new_status=new_status.value)
        return finding

    async def add_remediation(self, finding_id: UUID, actions: list[RemediationAction]) -> Finding | None:
        finding = await self.get_finding(finding_id)
        if not finding:
            return None

        finding.remediation = actions
        finding.updated_at = datetime.utcnow()
        await self.findings_collection.replace_one(
            {"id": str(finding_id)},
            finding.model_dump(),
        )
        return finding

    async def add_regression_test(self, finding_id: UUID, test: RegressionTest) -> Finding | None:
        finding = await self.get_finding(finding_id)
        if not finding:
            return None

        test.created_from_finding = finding_id
        finding.regression_tests.append(test)
        finding.updated_at = datetime.utcnow()
        await self.findings_collection.replace_one(
            {"id": str(finding_id)},
            finding.model_dump(),
        )
        return finding

    async def set_attack_path(self, finding_id: UUID, attack_path: AttackPath) -> Finding | None:
        finding = await self.get_finding(finding_id)
        if not finding:
            return None

        finding.attack_path = attack_path
        finding.updated_at = datetime.utcnow()
        await self.findings_collection.replace_one(
            {"id": str(finding_id)},
            finding.model_dump(),
        )
        return finding

    async def set_root_cause(self, finding_id: UUID, root_cause: RootCause) -> Finding | None:
        finding = await self.get_finding(finding_id)
        if not finding:
            return None

        finding.root_cause = root_cause
        finding.updated_at = datetime.utcnow()
        await self.findings_collection.replace_one(
            {"id": str(finding_id)},
            finding.model_dump(),
        )
        return finding

    async def set_reproduction(self, finding_id: UUID, reproduction: dict[str, Any]) -> Finding | None:
        finding = await self.get_finding(finding_id)
        if not finding:
            return None

        finding.reproduction = reproduction
        finding.updated_at = datetime.utcnow()
        await self.findings_collection.replace_one(
            {"id": str(finding_id)},
            finding.model_dump(),
        )
        return finding

    async def deduplicate_findings(self, execution_id: UUID) -> dict[str, Any]:
        findings = await self.get_findings_by_execution(execution_id)
        groups: dict[str, list[Finding]] = {}

        for finding in findings:
            key = f"{finding.target_id}:{finding.vulnerability_type.value}:{finding.attack_id}"
            if key not in groups:
                groups[key] = []
            groups[key].append(finding)

        duplicates_found = 0
        for key, group in groups.items():
            if len(group) > 1:
                primary = group[0]
                for dup in group[1:]:
                    dup.status = FindingStatus.DUPLICATE
                    dup.metadata["duplicate_of"] = str(primary.id)
                    await self.findings_collection.replace_one(
                        {"id": str(dup.id)},
                        dup.model_dump(),
                    )
                    duplicates_found += 1

        logger.info("Deduplication completed", execution_id=str(execution_id), duplicates_found=duplicates_found)
        return {"duplicates_found": duplicates_found, "groups_checked": len(groups)}

    async def correlate_findings(self, execution_id: UUID) -> dict[str, Any]:
        findings = await self.get_findings_by_execution(execution_id)
        correlations = []

        for i, finding_a in enumerate(findings):
            for finding_b in findings[i+1:]:
                shared_evidence = set(finding_a.evidence_ids) & set(finding_b.evidence_ids)
                if shared_evidence:
                    correlations.append({
                        "finding_a": str(finding_a.id),
                        "finding_b": str(finding_b.id),
                        "shared_evidence": [str(e) for e in shared_evidence],
                        "correlation_type": "shared_evidence",
                    })

        logger.info("Correlation completed", execution_id=str(execution_id), correlations_found=len(correlations))
        return {"correlations_found": len(correlations), "correlations": correlations}

    async def _get_evidence(self, evidence_id: UUID) -> Evidence | None:
        doc = await self.evidence_collection.find_one({"_id": str(evidence_id)})
        from security.models.evidence import Evidence
        return Evidence(**doc) if doc else None