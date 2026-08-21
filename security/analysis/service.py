from datetime import datetime
from typing import Any
from uuid import UUID
try:
    from motor.motor_asyncio import AsyncIOMotorDatabase
except ImportError:
    AsyncIOMotorDatabase = Any  # type: ignore
from security.models.analysis import (
    AnalysisPipeline,
    AnalysisStage,
    AnalysisStatus,
    StageResult,
    BehaviorPattern,
    SecurityRule,
    ImpactAssessment,
    ExploitabilityAssessment,
    RiskScore,
)
from security.models.finding import Finding, VulnerabilityType, SeverityLevel, ConfidenceLevel, ImpactLevel, ExploitabilityLevel, FindingStatus
from security.models.evidence import Evidence
try:
    from security.database import get_database
except ImportError:
    get_database = lambda: None  # type: ignore
try:
    from security.severity.service import SeverityCalculationService
except ImportError:
    SeverityCalculationService = Any  # type: ignore
try:
    import structlog
    logger = structlog.get_logger()
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


class AnalysisPipelineService:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.pipeline_collection = self.db.analysis_pipelines
        self.evidence_collection = self.db.evidence
        self.findings_collection = self.db.findings
        self.rules_collection = self.db.security_rules
        self.patterns_collection = self.db.behavior_patterns
        self.severity_service = SeverityCalculationService(db)

    async def create_pipeline(self, execution_id: UUID, target_id: str) -> AnalysisPipeline:
        pipeline = AnalysisPipeline(execution_id=execution_id, target_id=target_id)
        await self.pipeline_collection.insert_one(pipeline.model_dump())
        logger.info("Analysis pipeline created", pipeline_id=str(pipeline.pipeline_id), execution_id=str(execution_id))
        return pipeline

    async def run_pipeline(self, pipeline_id: UUID) -> AnalysisPipeline:
        pipeline = await self.get_pipeline(pipeline_id)
        if not pipeline:
            raise ValueError(f"Pipeline {pipeline_id} not found")

        pipeline.overall_status = AnalysisStatus.RUNNING
        await self._save_pipeline(pipeline)

        stages = [
            AnalysisStage.EVIDENCE_VALIDATION,
            AnalysisStage.BEHAVIOR_EXTRACTION,
            AnalysisStage.SECURITY_RULES,
            AnalysisStage.IMPACT_ANALYSIS,
            AnalysisStage.EXPLOITABILITY_ANALYSIS,
            AnalysisStage.RISK_CALCULATION,
            AnalysisStage.FINDING_GENERATION,
        ]

        for stage in stages:
            pipeline.current_stage = stage
            result = await self._run_stage(pipeline, stage)
            pipeline.add_stage_result(result)
            await self._save_pipeline(pipeline)

            if result.status == AnalysisStatus.FAILED:
                pipeline.overall_status = AnalysisStatus.FAILED
                await self._save_pipeline(pipeline)
                return pipeline

        pipeline.overall_status = AnalysisStatus.COMPLETED
        await self._save_pipeline(pipeline)
        logger.info("Pipeline completed", pipeline_id=str(pipeline_id), findings=len(pipeline.findings_generated))
        return pipeline

    async def _run_stage(self, pipeline: AnalysisPipeline, stage: AnalysisStage) -> StageResult:
        started = datetime.utcnow()
        result = StageResult(stage=stage, status=AnalysisStatus.RUNNING, started_at=started)

        try:
            if stage == AnalysisStage.EVIDENCE_VALIDATION:
                result.output = await self._validate_evidence(pipeline)
            elif stage == AnalysisStage.BEHAVIOR_EXTRACTION:
                result.output = await self._extract_behaviors(pipeline)
            elif stage == AnalysisStage.SECURITY_RULES:
                result.output = await self._apply_security_rules(pipeline)
            elif stage == AnalysisStage.IMPACT_ANALYSIS:
                result.output = await self._analyze_impact(pipeline)
            elif stage == AnalysisStage.EXPLOITABILITY_ANALYSIS:
                result.output = await self._analyze_exploitability(pipeline)
            elif stage == AnalysisStage.RISK_CALCULATION:
                result.output = await self._calculate_risk(pipeline)
            elif stage == AnalysisStage.FINDING_GENERATION:
                result.output = await self._generate_findings(pipeline)

            result.status = AnalysisStatus.COMPLETED
        except Exception as e:
            result.status = AnalysisStatus.FAILED
            result.errors.append(str(e))
            logger.error("Stage failed", stage=stage.value, error=str(e))

        result.completed_at = datetime.utcnow()
        return result

    async def _validate_evidence(self, pipeline: AnalysisPipeline) -> dict[str, Any]:
        # This stage performs integrity verification: stored content -> recalculate -> compare -> ACCEPT/REJECT
        # Tampered evidence must not proceed to analysis/finding
        from engine.model.errors import EvidenceTamperedError

        try:
            evidence_list = await self._get_evidence(pipeline.execution_id)
        except EvidenceTamperedError as e:
            # Tampered evidence detected at read - fail validation, do not proceed
            return {"total": 0, "validated": 0, "errors": [f"integrity failure: {e}"], "tampered": True}

        validated = 0
        errors = []
        tampered_detected = []

        for evidence in evidence_list:
            # Double-check integrity via model helper if present
            if evidence.content_hash:
                import hashlib, hmac, json
                canonical = json.dumps(evidence.raw_data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")
                computed = hashlib.new(evidence.content_hash_algorithm or "sha256", canonical).hexdigest()
                if not hmac.compare_digest(computed, evidence.content_hash):
                    tampered_detected.append(str(evidence.id))
                    errors.append(f"Evidence {evidence.id}: tampering detected - checksum mismatch")
                    continue
            if evidence.status.value == "raw":
                if not evidence.raw_data:
                    errors.append(f"Evidence {evidence.id}: empty raw_data")
                elif evidence.normalized_data is None:
                    errors.append(f"Evidence {evidence.id}: not normalized")
                else:
                    validated += 1

        if tampered_detected:
            # Prevent downstream stages from using tampered evidence
            raise EvidenceTamperedError(f"Tampered evidence detected {tampered_detected} - pipeline aborted, no finding will be generated")

        return {"total": len(evidence_list), "validated": validated, "errors": errors}

    async def _extract_behaviors(self, pipeline: AnalysisPipeline) -> dict[str, Any]:
        evidence_list = await self._get_evidence(pipeline.execution_id)
        patterns = await self._get_patterns()

        behaviors = []
        for evidence in evidence_list:
            if evidence.normalized_data:
                for pattern in patterns:
                    if self._matches_pattern(evidence.normalized_data, pattern):
                        behaviors.append({
                            "pattern_id": str(pattern.pattern_id),
                            "evidence_id": str(evidence.id),
                            "confidence": pattern.confidence,
                        })

        return {"behaviors_detected": len(behaviors), "behaviors": behaviors}

    async def _apply_security_rules(self, pipeline: AnalysisPipeline) -> dict[str, Any]:
        evidence_list = await self._get_evidence(pipeline.execution_id)
        rules = await self._get_rules()

        matches = []
        for rule in rules:
            if not rule.enabled:
                continue
            for evidence in evidence_list:
                if evidence.normalized_data and self._evaluate_rule(evidence.normalized_data, rule):
                    matches.append({
                        "rule_id": str(rule.rule_id),
                        "evidence_id": str(evidence.id),
                        "vulnerability_type": rule.vulnerability_type,
                        "severity": rule.severity,
                    })

        return {"rule_matches": len(matches), "matches": matches}

    async def _analyze_impact(self, pipeline: AnalysisPipeline) -> dict[str, Any]:
        rule_matches = pipeline.get_stage(AnalysisStage.SECURITY_RULES)
        if not rule_matches or not rule_matches.output.get("matches"):
            return {"impact_assessments": []}

        assessments = []
        for match in rule_matches.output["matches"]:
            assessment = ImpactAssessment(
                finding_id=None,
                confidentiality=self._assess_confidentiality(match),
                integrity=self._assess_integrity(match),
                availability=self._assess_availability(match),
                affected_assets=[pipeline.target_id],
                business_impact=self._assess_business_impact(match),
                evidence_ids=[UUID(match["evidence_id"])],
                rationale=f"Rule {match['rule_id']} matched: {match['vulnerability_type']}",
            )
            assessments.append(assessment.model_dump())

        return {"impact_assessments": assessments}

    async def _analyze_exploitability(self, pipeline: AnalysisPipeline) -> dict[str, Any]:
        rule_matches = pipeline.get_stage(AnalysisStage.SECURITY_RULES)
        if not rule_matches or not rule_matches.output.get("matches"):
            return {"exploitability_assessments": []}

        assessments = []
        for match in rule_matches.output["matches"]:
            assessment = ExploitabilityAssessment(
                finding_id=None,
                attack_vector=self._assess_attack_vector(match),
                attack_complexity=self._assess_complexity(match),
                privileges_required=self._assess_privileges(match),
                user_interaction=self._assess_user_interaction(match),
                exploit_maturity=self._assess_maturity(match),
                evidence_ids=[UUID(match["evidence_id"])],
                rationale=f"Exploitability for {match['vulnerability_type']}",
            )
            assessments.append(assessment.model_dump())

        return {"exploitability_assessments": assessments}

    async def _calculate_risk(self, pipeline: AnalysisPipeline) -> dict[str, Any]:
        impact_stage = pipeline.get_stage(AnalysisStage.IMPACT_ANALYSIS)
        exploit_stage = pipeline.get_stage(AnalysisStage.EXPLOITABILITY_ANALYSIS)

        if not impact_stage or not exploit_stage:
            return {"risk_scores": []}

        impact_assessments = impact_stage.output.get("impact_assessments", [])
        exploit_assessments = exploit_stage.output.get("exploitability_assessments", [])

        risk_scores = []
        for i, (impact, exploit) in enumerate(zip(impact_assessments, exploit_assessments)):
            base_score = self._calculate_cvss_base(impact, exploit)
            risk_score = RiskScore(
                finding_id=None,
                base_score=base_score,
                final_score=base_score,
                severity=self._score_to_severity(base_score),
                components={"impact": impact, "exploitability": exploit},
            )
            risk_scores.append(risk_score.model_dump())

        return {"risk_scores": risk_scores}

    async def _generate_findings(self, pipeline: AnalysisPipeline) -> dict[str, Any]:
        rule_matches = pipeline.get_stage(AnalysisStage.SECURITY_RULES)
        risk_stage = pipeline.get_stage(AnalysisStage.RISK_CALCULATION)

        if not rule_matches or not risk_stage:
            return {"findings_created": 0}

        matches = rule_matches.output.get("matches", [])
        risk_scores = risk_stage.output.get("risk_scores", [])

        findings = []
        for i, (match, risk) in enumerate(zip(matches, risk_scores)):
            finding = Finding(
                target_id=pipeline.target_id,
                attack_id=match["vulnerability_type"],
                execution_id=pipeline.execution_id,
                vulnerability_type=VulnerabilityType(match["vulnerability_type"]),
                severity=SeverityLevel(risk["severity"]),
                confidence=ConfidenceLevel.HIGH,
                impact=ImpactLevel.HIGH if risk["final_score"] >= 7.0 else ImpactLevel.MEDIUM,
                exploitability=ExploitabilityLevel.HIGH if risk["final_score"] >= 7.0 else ExploitabilityLevel.MEDIUM,
                evidence_ids=[UUID(match["evidence_id"])],
                risk_score=risk["final_score"],
                status=FindingStatus.NEW,
            )

            severity_assessment = await self.severity_service.assess_finding(finding)
            finding.severity = severity_assessment.severity
            finding.cvss_vector = severity_assessment.cvss_vector.to_vector_string()
            finding.cvss_score = severity_assessment.base_score

            await self.findings_collection.insert_one(finding.model_dump())
            pipeline.findings_generated.append(finding.id)
            findings.append(str(finding.id))

        return {"findings_created": len(findings), "finding_ids": findings}

    def _matches_pattern(self, data: dict[str, Any], pattern: BehaviorPattern) -> bool:
        for indicator in pattern.indicators:
            if indicator in str(data).lower():
                return True
        return False

    def _evaluate_rule(self, data: dict[str, Any], rule: SecurityRule) -> bool:
        condition = rule.condition
        if "field" in condition and "value" in condition:
            field_value = data.get(condition["field"])
            if condition.get("operator") == "contains":
                return condition["value"].lower() in str(field_value).lower()
            elif condition.get("operator") == "equals":
                return field_value == condition["value"]
            elif condition.get("operator") == "regex":
                import re
                return bool(re.search(condition["value"], str(field_value)))
        return False

    def _assess_confidentiality(self, match: dict[str, Any]) -> str:
        high_impact_types = ["injection", "sensitive_data_exposure", "broken_access_control"]
        return "high" if any(t in match["vulnerability_type"] for t in high_impact_types) else "low"

    def _assess_integrity(self, match: dict[str, Any]) -> str:
        return "high" if "injection" in match["vulnerability_type"] else "low"

    def _assess_availability(self, match: dict[str, Any]) -> str:
        return "high" if "dos" in match["vulnerability_type"].lower() else "none"

    def _assess_business_impact(self, match: dict[str, Any]) -> str:
        critical_types = ["sql_injection", "command_injection", "broken_authentication"]
        return "critical" if any(t in match["vulnerability_type"] for t in critical_types) else "medium"

    def _assess_attack_vector(self, match: dict[str, Any]) -> str:
        return "network"

    def _assess_complexity(self, match: dict[str, Any]) -> str:
        return "low" if "injection" in match["vulnerability_type"] else "high"

    def _assess_privileges(self, match: dict[str, Any]) -> str:
        return "none" if "injection" in match["vulnerability_type"] else "high"

    def _assess_user_interaction(self, match: dict[str, Any]) -> str:
        return "none" if "xss" in match["vulnerability_type"] else "required"

    def _assess_maturity(self, match: dict[str, Any]) -> str:
        return "functional" if "injection" in match["vulnerability_type"] else "poc"

    def _calculate_cvss_base(self, impact: dict[str, Any], exploit: dict[str, Any]) -> float:
        impact_score = {"high": 0.56, "low": 0.22, "none": 0}.get(impact.get("confidentiality", "none"), 0)
        exploit_score = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2}.get(exploit.get("attack_vector", "network"), 0.85)
        complexity_mod = {"low": 0.77, "high": 0.44}.get(exploit.get("attack_complexity", "high"), 0.44)
        return min(10.0, round((impact_score + exploit_score) * complexity_mod * 10, 1))

    def _score_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 0.1:
            return "low"
        return "info"

    async def _get_evidence(self, execution_id: UUID) -> list[Evidence]:
        # Every read verifies integrity; tampered evidence raises and aborts pipeline
        from engine.model.errors import EvidenceTamperedError
        import hashlib, hmac, json

        cursor = self.evidence_collection.find({"execution_id": str(execution_id)})
        out: list[Evidence] = []
        async for doc in cursor:
            evidence = Evidence(**doc)
            if evidence.content_hash:
                canonical = json.dumps(evidence.raw_data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")
                computed = hashlib.new(evidence.content_hash_algorithm or "sha256", canonical).hexdigest()
                if not hmac.compare_digest(computed, evidence.content_hash):
                    raise EvidenceTamperedError(f"Evidence {evidence.id} tampered - rejected before analysis")
            out.append(evidence)
        return out

    async def _get_patterns(self) -> list[BehaviorPattern]:
        cursor = self.patterns_collection.find({"enabled": True})
        return [BehaviorPattern(**doc) async for doc in cursor]

    async def _get_rules(self) -> list[SecurityRule]:
        cursor = self.rules_collection.find({"enabled": True})
        return [SecurityRule(**doc) async for doc in cursor]

    async def _save_pipeline(self, pipeline: AnalysisPipeline) -> None:
        await self.pipeline_collection.replace_one(
            {"pipeline_id": str(pipeline.pipeline_id)},
            pipeline.model_dump(),
            upsert=True,
        )

    async def get_pipeline(self, pipeline_id: UUID) -> AnalysisPipeline | None:
        doc = await self.pipeline_collection.find_one({"pipeline_id": str(pipeline_id)})
        return AnalysisPipeline(**doc) if doc else None