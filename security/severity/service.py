from datetime import datetime
from typing import Any
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field, ConfigDict
from security.database import get_database
from security.models.finding import Finding, VulnerabilityType, ImpactLevel, ExploitabilityLevel, ConfidenceLevel
from security.models.severity import (
    SeverityLevel,
    CVSSVersion,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    ImpactLevel as CVSSImpactLevel,
    ExploitCodeMaturity,
    RemediationLevel,
    ReportConfidence,
    CVSSv31BaseMetrics,
    CVSSv31TemporalMetrics,
    CVSSv31EnvironmentalMetrics,
    CVSSVector,
    SeverityAssessment,
    SeverityRule,
)
import structlog
import math

logger = structlog.get_logger()


class SeverityCalculationService:
    CVSS_V31_WEIGHTS = {
        "attack_vector": {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2},
        "attack_complexity": {"low": 0.77, "high": 0.44},
        "privileges_required": {
            "none": {"unchanged": 0.85, "changed": 0.85},
            "low": {"unchanged": 0.62, "changed": 0.68},
            "high": {"unchanged": 0.27, "changed": 0.50},
        },
        "user_interaction": {"none": 0.85, "required": 0.62},
        "scope": {"unchanged": 1.0, "changed": 1.08},
        "impact": {"none": 0.0, "low": 0.22, "high": 0.56},
    }

    TEMPORAL_WEIGHTS = {
        "exploit_code_maturity": {
            "unproven": 0.91,
            "proof_of_concept": 0.94,
            "functional": 0.97,
            "high": 1.0,
            "not_defined": 1.0,
        },
        "remediation_level": {
            "official_fix": 0.95,
            "temporary_fix": 0.96,
            "workaround": 0.97,
            "unavailable": 1.0,
            "not_defined": 1.0,
        },
        "report_confidence": {
            "unknown": 0.92,
            "reasonable": 0.96,
            "confirmed": 1.0,
            "not_defined": 1.0,
        },
    }

    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.assessments_collection = self.db.severity_assessments
        self.rules_collection = self.db.severity_rules

    def calculate_base_score(self, metrics: CVSSv31BaseMetrics) -> float:
        av = self.CVSS_V31_WEIGHTS["attack_vector"][metrics.attack_vector.value]
        ac = self.CVSS_V31_WEIGHTS["attack_complexity"][metrics.attack_complexity.value]
        pr = self.CVSS_V31_WEIGHTS["privileges_required"][metrics.privileges_required.value][metrics.scope.value]
        ui = self.CVSS_V31_WEIGHTS["user_interaction"][metrics.user_interaction.value]
        scope = self.CVSS_V31_WEIGHTS["scope"][metrics.scope.value]

        c = self.CVSS_V31_WEIGHTS["impact"][metrics.confidentiality.value]
        i = self.CVSS_V31_WEIGHTS["impact"][metrics.integrity.value]
        a = self.CVSS_V31_WEIGHTS["impact"][metrics.availability.value]

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        if metrics.scope == Scope.UNCHANGED:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            base_score = 0.0
        elif metrics.scope == Scope.UNCHANGED:
            base_score = min(10.0, impact + exploitability)
        else:
            base_score = min(10.0, 1.08 * (impact + exploitability))

        return round(base_score * 10) / 10

    def calculate_temporal_score(self, base_score: float, metrics: CVSSv31TemporalMetrics) -> float:
        e = self.TEMPORAL_WEIGHTS["exploit_code_maturity"][metrics.exploit_code_maturity.value]
        rl = self.TEMPORAL_WEIGHTS["remediation_level"][metrics.remediation_level.value]
        rc = self.TEMPORAL_WEIGHTS["report_confidence"][metrics.report_confidence.value]

        temporal = base_score * e * rl * rc
        return round(temporal * 10) / 10

    def calculate_environmental_score(
        self,
        base_score: float,
        base_metrics: CVSSv31BaseMetrics,
        env_metrics: CVSSv31EnvironmentalMetrics,
    ) -> float:
        modified = CVSSv31BaseMetrics(
            attack_vector=env_metrics.modified_attack_vector or base_metrics.attack_vector,
            attack_complexity=env_metrics.modified_attack_complexity or base_metrics.attack_complexity,
            privileges_required=env_metrics.modified_privileges_required or base_metrics.privileges_required,
            user_interaction=env_metrics.modified_user_interaction or base_metrics.user_interaction,
            scope=env_metrics.modified_scope or base_metrics.scope,
            confidentiality=env_metrics.modified_confidentiality or base_metrics.confidentiality,
            integrity=env_metrics.modified_integrity or base_metrics.integrity,
            availability=env_metrics.modified_availability or base_metrics.availability,
        )

        modified_base = self.calculate_base_score(modified)

        cr = self.CVSS_V31_WEIGHTS["impact"][env_metrics.confidentiality_requirement.value]
        ir = self.CVSS_V31_WEIGHTS["impact"][env_metrics.integrity_requirement.value]
        ar = self.CVSS_V31_WEIGHTS["impact"][env_metrics.availability_requirement.value]

        if modified_base <= 0:
            return 0.0

        if modified.scope == Scope.UNCHANGED:
            environmental = min(10.0, modified_base * (cr + ir + ar) / 3)
        else:
            environmental = min(10.0, modified_base * (cr + ir + ar) / 3 * 1.08)

        return round(environmental * 10) / 10

    def score_to_severity(self, score: float) -> SeverityLevel:
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        elif score >= 7.0:
            return SeverityLevel.HIGH
        elif score >= 4.0:
            return SeverityLevel.MEDIUM
        elif score >= 0.1:
            return SeverityLevel.LOW
        return SeverityLevel.INFO

    def map_finding_to_cvss(self, finding: Finding) -> CVSSVector:
        base_metrics = CVSSv31BaseMetrics(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW if finding.exploitability in [ExploitabilityLevel.HIGH, ExploitabilityLevel.CRITICAL] else AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=self._map_impact(finding.impact),
            integrity=self._map_impact(finding.impact),
            availability=self._map_impact(finding.impact),
        )

        temporal_metrics = CVSSv31TemporalMetrics(
            exploit_code_maturity=self._map_exploitability(finding.exploitability),
            remediation_level=RemediationLevel.NOT_DEFINED,
            report_confidence=self._map_confidence(finding.confidence),
        )

        return CVSSVector(
            version=CVSSVersion.V3_1,
            base_metrics=base_metrics,
            temporal_metrics=temporal_metrics,
        )

    def _map_impact(self, impact: ImpactLevel) -> CVSSImpactLevel:
        mapping = {
            ImpactLevel.NONE: CVSSImpactLevel.NONE,
            ImpactLevel.LOW: CVSSImpactLevel.LOW,
            ImpactLevel.MEDIUM: CVSSImpactLevel.LOW,
            ImpactLevel.HIGH: CVSSImpactLevel.HIGH,
            ImpactLevel.CRITICAL: CVSSImpactLevel.HIGH,
        }
        return mapping.get(impact, CVSSImpactLevel.NONE)

    def _map_exploitability(self, exploitability: ExploitabilityLevel) -> ExploitCodeMaturity:
        mapping = {
            ExploitabilityLevel.NONE: ExploitCodeMaturity.UNPROVEN,
            ExploitabilityLevel.LOW: ExploitCodeMaturity.PROOF_OF_CONCEPT,
            ExploitabilityLevel.MEDIUM: ExploitCodeMaturity.FUNCTIONAL,
            ExploitabilityLevel.HIGH: ExploitCodeMaturity.HIGH,
            ExploitabilityLevel.CRITICAL: ExploitCodeMaturity.HIGH,
        }
        return mapping.get(exploitability, ExploitCodeMaturity.NOT_DEFINED)

    def _map_confidence(self, confidence: ConfidenceLevel) -> ReportConfidence:
        mapping = {
            ConfidenceLevel.LOW: ReportConfidence.UNKNOWN,
            ConfidenceLevel.MEDIUM: ReportConfidence.REASONABLE,
            ConfidenceLevel.HIGH: ReportConfidence.CONFIRMED,
            ConfidenceLevel.VERY_HIGH: ReportConfidence.CONFIRMED,
        }
        return mapping.get(confidence, ReportConfidence.NOT_DEFINED)

    async def assess_finding(self, finding: Finding, evidence_ids: list[UUID] | None = None) -> SeverityAssessment:
        cvss_vector = self.map_finding_to_cvss(finding)
        base_score = self.calculate_base_score(cvss_vector.base_metrics)
        temporal_score = self.calculate_temporal_score(base_score, cvss_vector.temporal_metrics)
        environmental_score = self.calculate_environmental_score(base_score, cvss_vector.base_metrics, cvss_vector.environmental_metrics)
        final_score = environmental_score or temporal_score or base_score
        severity = self.score_to_severity(final_score)

        assessment = SeverityAssessment(
            finding_id=finding.id,
            cvss_vector=cvss_vector,
            base_score=base_score,
            temporal_score=temporal_score,
            environmental_score=environmental_score,
            severity=severity,
            rationale=f"Calculated from finding {finding.vulnerability_type.value} with impact {finding.impact.value} and exploitability {finding.exploitability.value}",
            evidence_ids=evidence_ids or finding.evidence_ids,
        )

        await self.assessments_collection.insert_one(assessment.model_dump())
        logger.info("Severity assessed", finding_id=str(finding.id), severity=severity.value, score=final_score)
        return assessment

    async def get_assessment(self, assessment_id: UUID) -> SeverityAssessment | None:
        doc = await self.assessments_collection.find_one({"assessment_id": str(assessment_id)})
        return SeverityAssessment(**doc) if doc else None

    async def get_assessments_for_finding(self, finding_id: UUID) -> list[SeverityAssessment]:
        cursor = self.assessments_collection.find({"finding_id": str(finding_id)})
        return [SeverityAssessment(**doc) async for doc in cursor]


class SeverityRuleService:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.rules_collection = self.db.severity_rules
        self._load_default_rules()

    def _load_default_rules(self) -> None:
        self.default_rules = [
            SeverityRule(
                name="SQL Injection - High",
                description="SQL Injection with high impact",
                vulnerability_type="sql_injection",
                cvss_vector=CVSSVector(
                    base_metrics=CVSSv31BaseMetrics(
                        attack_vector=AttackVector.NETWORK,
                        attack_complexity=AttackComplexity.LOW,
                        privileges_required=PrivilegesRequired.NONE,
                        user_interaction=UserInteraction.NONE,
                        confidentiality=CVSSImpactLevel.HIGH,
                        integrity=CVSSImpactLevel.HIGH,
                        availability=CVSSImpactLevel.LOW,
                    )
                ),
                min_score=7.0,
                max_score=10.0,
            ),
            SeverityRule(
                name="XSS - Medium",
                description="Cross-site scripting",
                vulnerability_type="cross_site_scripting",
                cvss_vector=CVSSVector(
                    base_metrics=CVSSv31BaseMetrics(
                        attack_vector=AttackVector.NETWORK,
                        attack_complexity=AttackComplexity.LOW,
                        privileges_required=PrivilegesRequired.NONE,
                        user_interaction=UserInteraction.REQUIRED,
                        confidentiality=CVSSImpactLevel.LOW,
                        integrity=CVSSImpactLevel.LOW,
                        availability=CVSSImpactLevel.NONE,
                    )
                ),
                min_score=4.0,
                max_score=6.9,
            ),
            SeverityRule(
                name="Command Injection - Critical",
                description="Command injection with full impact",
                vulnerability_type="command_injection",
                cvss_vector=CVSSVector(
                    base_metrics=CVSSv31BaseMetrics(
                        attack_vector=AttackVector.NETWORK,
                        attack_complexity=AttackComplexity.LOW,
                        privileges_required=PrivilegesRequired.NONE,
                        user_interaction=UserInteraction.NONE,
                        confidentiality=CVSSImpactLevel.HIGH,
                        integrity=CVSSImpactLevel.HIGH,
                        availability=CVSSImpactLevel.HIGH,
                    )
                ),
                min_score=9.0,
                max_score=10.0,
            ),
        ]

    async def create_rule(self, rule: SeverityRule) -> SeverityRule:
        await self.rules_collection.insert_one(rule.model_dump())
        return rule

    async def get_rule(self, rule_id: UUID) -> SeverityRule | None:
        doc = await self.rules_collection.find_one({"rule_id": str(rule_id)})
        return SeverityRule(**doc) if doc else None

    async def list_rules(self, vulnerability_type: str | None = None) -> list[SeverityRule]:
        query = {"vulnerability_type": vulnerability_type} if vulnerability_type else {}
        cursor = self.rules_collection.find(query)
        return [SeverityRule(**doc) async for doc in cursor]

    async def evaluate_finding(self, finding: Finding) -> list[SeverityRule]:
        rules = await self.list_rules(finding.vulnerability_type.value)
        matched = []
        for rule in rules:
            if not rule.enabled:
                continue
            calc_service = SeverityCalculationService(self.db)
            base_score = calc_service.calculate_base_score(rule.cvss_vector.base_metrics)
            if rule.min_score <= base_score <= rule.max_score:
                matched.append(rule)
        return matched