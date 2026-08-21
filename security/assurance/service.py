from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from security.database import get_database
from security.assurance.models import (
    AssuranceLevel,
    VerificationStatus,
    AssuranceMetric,
    ContinuousAssurance,
    AssurancePolicy,
    AssuranceVerification,
)
from security.findings.models import Finding, FindingStatus
from security.regression.models import RegressionRun
from security.evidence.models import Evidence
from security.posture.models import PostureSnapshot
import structlog

logger = structlog.get_logger()


class AssuranceEngine:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.assurance_collection = self.db.continuous_assurance
        self.policies_collection = self.db.assurance_policies
        self.verifications_collection = self.db.assurance_verifications
        self.findings_collection = self.db.findings
        self.regression_runs_collection = self.db.regression_runs
        self.evidence_collection = self.db.evidence
        self.posture_snapshots_collection = self.db.posture_snapshots

    async def compute_assurance(self, target_id: UUID) -> ContinuousAssurance:
        metrics = []

        findings = await self._get_findings_for_target(target_id)
        verified_findings = len([f for f in findings if f.status in (FindingStatus.FIXED, FindingStatus.VERIFIED)])
        total_findings = len(findings)

        verification_rate = verified_findings / total_findings if total_findings > 0 else 1.0

        metrics.append(AssuranceMetric(
            name="finding_verification_rate",
            value=verification_rate,
            threshold=0.8,
            unit="ratio",
            assurance_level=self._rate_to_assurance(verification_rate),
            description="Percentage of findings verified as fixed",
            computed_at=datetime.utcnow(),
        ))

        regression_runs = await self._get_regression_runs(target_id)
        passing = len([r for r in regression_runs if r.get("result") == "fixed"])
        total_runs = len(regression_runs)
        regression_pass_rate = passing / total_runs if total_runs > 0 else 1.0

        metrics.append(AssuranceMetric(
            name="regression_pass_rate",
            value=regression_pass_rate,
            threshold=0.9,
            unit="ratio",
            assurance_level=self._rate_to_assurance(regression_pass_rate),
            description="Percentage of regression tests passing",
            computed_at=datetime.utcnow(),
        ))

        evidence = await self._get_evidence_for_target(target_id)
        normalized = len([e for e in evidence if e.get("status") == "normalized"])
        total_evidence = len(evidence)
        evidence_completeness = normalized / total_evidence if total_evidence > 0 else 1.0

        metrics.append(AssuranceMetric(
            name="evidence_completeness",
            value=evidence_completeness,
            threshold=0.7,
            unit="ratio",
            assurance_level=self._rate_to_assurance(evidence_completeness),
            description="Percentage of evidence normalized",
            computed_at=datetime.utcnow(),
        ))

        latest_posture = await self._get_latest_posture(target_id)
        attack_coverage = latest_posture.attack_coverage if latest_posture else 0.0

        metrics.append(AssuranceMetric(
            name="attack_coverage",
            value=attack_coverage / 100,
            threshold=0.6,
            unit="ratio",
            assurance_level=self._rate_to_assurance(attack_coverage / 100),
            description="Percentage of attack vectors covered",
            computed_at=datetime.utcnow(),
        ))

        remediated = len([f for f in findings if f.status in (FindingStatus.FIXED, FindingStatus.VERIFIED, FindingStatus.REMEDIATED)])
        remediation_completeness = remediated / total_findings if total_findings > 0 else 1.0

        metrics.append(AssuranceMetric(
            name="remediation_completeness",
            value=remediation_completeness,
            threshold=0.8,
            unit="ratio",
            assurance_level=self._rate_to_assurance(remediation_completeness),
            description="Percentage of findings remediated",
            computed_at=datetime.utcnow(),
        ))

        overall = self._calculate_overall_assurance(metrics)

        assurance = ContinuousAssurance(
            target_id=target_id,
            overall_assurance=overall,
            metrics=metrics,
            verified_findings=verified_findings,
            total_findings=total_findings,
            verification_rate=verification_rate,
            regression_tests_passing=passing,
            regression_tests_total=total_runs,
            regression_pass_rate=regression_pass_rate,
            evidence_completeness=evidence_completeness,
            attack_coverage=attack_coverage,
            remediation_completeness=remediation_completeness,
        )

        await self.assurance_collection.insert_one(assurance.model_dump())
        logger.info("Assurance computed", target_id=str(target_id), level=overall.value)
        return assurance

    def _rate_to_assurance(self, rate: float) -> AssuranceLevel:
        if rate >= 0.9:
            return AssuranceLevel.HIGH
        elif rate >= 0.7:
            return AssuranceLevel.MEDIUM
        elif rate >= 0.5:
            return AssuranceLevel.LOW
        return AssuranceLevel.UNKNOWN

    def _calculate_overall_assurance(self, metrics: list[AssuranceMetric]) -> AssuranceLevel:
        high_count = len([m for m in metrics if m.assurance_level == AssuranceLevel.HIGH])
        medium_count = len([m for m in metrics if m.assurance_level == AssuranceLevel.MEDIUM])
        low_count = len([m for m in metrics if m.assurance_level == AssuranceLevel.LOW])
        unknown_count = len([m for m in metrics if m.assurance_level == AssuranceLevel.UNKNOWN])

        if low_count > 0 or unknown_count > 0:
            return AssuranceLevel.LOW
        elif medium_count > 0:
            return AssuranceLevel.MEDIUM
        elif high_count >= len(metrics) * 0.8:
            return AssuranceLevel.HIGH
        return AssuranceLevel.MEDIUM

    async def create_policy(self, policy: AssurancePolicy) -> AssurancePolicy:
        await self.policies_collection.insert_one(policy.model_dump())
        return policy

    async def get_policies(self) -> list[AssurancePolicy]:
        cursor = self.policies_collection.find({"enabled": True})
        return [AssurancePolicy(**doc) async for doc in cursor]

    async def run_verification(self, target_id: UUID, policy_id: UUID) -> AssuranceVerification:
        policy = await self.policies_collection.find_one({"policy_id": str(policy_id)})
        if not policy:
            raise ValueError(f"Policy {policy_id} not found")

        verification = AssuranceVerification(
            assurance_id=UUID("00000000-0000-0000-0000-000000000000"),
            policy_id=policy_id,
            status=VerificationStatus.PENDING,
        )
        await self.verifications_collection.insert_one(verification.model_dump())

        findings = await self._get_findings_for_target(target_id)
        verified = []
        failed = []
        skipped = []

        for finding in findings:
            if finding.status in (FindingStatus.FIXED, FindingStatus.VERIFIED):
                verified.append(finding.id)
            elif finding.status in (FindingStatus.NEW, FindingStatus.CONFIRMED):
                failed.append(finding.id)
            else:
                skipped.append(finding.id)

        verification.status = VerificationStatus.VERIFIED if not failed else VerificationStatus.FAILED
        verification.findings_verified = verified
        verification.findings_failed = failed
        verification.findings_skipped = skipped
        verification.completed_at = datetime.utcnow()
        verification.details = {
            "policy_name": policy.name,
            "target_id": str(target_id),
        }

        await self.verifications_collection.replace_one(
            {"verification_id": str(verification.verification_id)},
            verification.model_dump(),
        )
        return verification

    async def get_verifications(self, target_id: UUID) -> list[AssuranceVerification]:
        cursor = self.verifications_collection.find({"details.target_id": str(target_id)})
        return [AssuranceVerification(**doc) async for doc in cursor]

    async def _get_findings_for_target(self, target_id: UUID) -> list:
        cursor = self.findings_collection.find({"target_id": target_id})
        return [Finding(**doc) async for doc in cursor]

    async def _get_regression_runs(self, target_id: UUID) -> list:
        findings = await self._get_findings_for_target(target_id)
        finding_ids = [str(f.id) for f in findings]
        if not finding_ids:
            return []
        cursor = self.regression_runs_collection.find({"finding_id": {"$in": finding_ids}})
        return [doc async for doc in cursor]

    async def _get_evidence_for_target(self, target_id: UUID) -> list:
        cursor = self.evidence_collection.find({"target_id": target_id})
        return [Evidence(**doc) async for doc in cursor]

    async def _get_latest_posture(self, target_id: UUID):
        doc = await self.posture_snapshots_collection.find_one(
            {"target_id": str(target_id)},
            sort=[("computed_at", -1)]
        )
        return PostureSnapshot(**doc) if doc else None

    async def get_assurance_history(self, target_id: UUID, days: int = 30) -> list[ContinuousAssurance]:
        cutoff = datetime.utcnow() - timedelta(days=days)
        cursor = self.assurance_collection.find({"target_id": str(target_id), "computed_at": {"$gte": cutoff}}).sort("computed_at", 1)
        return [ContinuousAssurance(**doc) async for doc in cursor]

    async def get_latest_assurance(self, target_id: UUID) -> Optional[ContinuousAssurance]:
        doc = await self.assurance_collection.find_one({"target_id": str(target_id)}, sort=[("computed_at", -1)])
        return ContinuousAssurance(**doc) if doc else None