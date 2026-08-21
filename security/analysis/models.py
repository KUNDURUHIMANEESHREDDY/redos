from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class AnalysisStage(str, Enum):
    EVIDENCE_VALIDATION = "evidence_validation"
    BEHAVIOR_EXTRACTION = "behavior_extraction"
    SECURITY_RULES = "security_rules"
    IMPACT_ANALYSIS = "impact_analysis"
    EXPLOITABILITY_ANALYSIS = "exploitability_analysis"
    RISK_CALCULATION = "risk_calculation"
    FINDING_GENERATION = "finding_generation"


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class StageResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    stage: AnalysisStage
    status: AnalysisStatus
    started_at: datetime
    completed_at: datetime | None = None
    output: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metrics: dict[str, float] = Field(default_factory=dict)


class AnalysisPipeline(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    pipeline_id: UUID = Field(default_factory=uuid4)
    execution_id: UUID
    target: str
    stages: list[StageResult] = Field(default_factory=list)
    current_stage: AnalysisStage | None = None
    overall_status: AnalysisStatus = AnalysisStatus.PENDING
    findings_generated: list[UUID] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def get_stage(self, stage: AnalysisStage) -> StageResult | None:
        for s in self.stages:
            if s.stage == stage:
                return s
        return None

    def add_stage_result(self, result: StageResult) -> None:
        self.stages.append(result)
        self.updated_at = datetime.utcnow()


class BehaviorPattern(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    pattern_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    category: str
    indicators: list[str] = Field(default_factory=list)
    evidence_types: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityRule(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    rule_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    category: str
    vulnerability_type: str
    severity: str
    condition: dict[str, Any] = Field(default_factory=dict)
    patterns: list[UUID] = Field(default_factory=list)
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class ImpactAssessment(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    assessment_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID | None = None
    confidentiality: str = "none"
    integrity: str = "none"
    availability: str = "none"
    scope: str = "unchanged"
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: int = 0
    data_classification: str = "public"
    business_impact: str = "low"
    regulatory_impact: list[str] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    rationale: str = ""


class ExploitabilityAssessment(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    assessment_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID | None = None
    attack_vector: str = "network"
    attack_complexity: str = "high"
    privileges_required: str = "high"
    user_interaction: str = "required"
    scope: str = "unchanged"
    exploit_maturity: str = "unproven"
    exploit_code_available: bool = False
    evidence_ids: list[UUID] = Field(default_factory=list)
    rationale: str = ""


class RiskScore(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    score_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID | None = None
    base_score: float = 0.0
    temporal_score: float | None = None
    environmental_score: float | None = None
    final_score: float = 0.0
    severity: str = "info"
    calculation_method: str = "cvss_v3.1"
    components: dict[str, float] = Field(default_factory=dict)
    calculated_at: datetime = Field(default_factory=datetime.utcnow)