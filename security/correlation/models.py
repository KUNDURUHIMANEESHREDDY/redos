from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class CorrelationType(str, Enum):
    SHARED_EVIDENCE = "shared_evidence"
    SHARED_TARGET = "shared_target"
    SHARED_ATTACK_VECTOR = "shared_attack_vector"
    CHAINED_VULNERABILITY = "chained_vulnerability"
    COMPOSITE_ATTACK = "composite_attack"
    DEPENDENCY_CHAIN = "dependency_chain"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"


class CorrelationSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CorrelationStatus(str, Enum):
    DETECTED = "detected"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    EXPLOITED = "exploited"
    MITIGATED = "mitigated"


class FindingCorrelation(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    correlation_id: UUID = Field(default_factory=uuid4)
    correlation_type: CorrelationType
    severity: CorrelationSeverity
    status: CorrelationStatus = CorrelationStatus.DETECTED
    finding_ids: list[UUID] = Field(default_factory=list)
    description: str
    attack_path: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    shared_evidence_ids: list[UUID] = Field(default_factory=list)
    risk_score: float = 0.0
    systemic_risk_score: float = 0.0
    evidence: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    validated_at: Optional[datetime] = None
    mitigated_at: Optional[datetime] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["correlation_id"] = str(data["correlation_id"])
        data["finding_ids"] = [str(f) for f in data["finding_ids"]]
        data["shared_evidence_ids"] = [str(e) for e in data["shared_evidence_ids"]]
        if "detected_at" in data and isinstance(data["detected_at"], datetime):
            data["detected_at"] = data["detected_at"].isoformat()
        if "validated_at" in data and data["validated_at"] and isinstance(data["validated_at"], datetime):
            data["validated_at"] = data["validated_at"].isoformat()
        if "mitigated_at" in data and data["mitigated_at"] and isinstance(data["mitigated_at"], datetime):
            data["mitigated_at"] = data["mitigated_at"].isoformat()
        return data


class CompositeAttackPath(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    path_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    finding_correlations: list[UUID] = Field(default_factory=list)
    attack_steps: list[dict[str, Any]] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    target_assets: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    overall_risk_score: float = 0.0
    exploitability: float = 0.0
    impact: float = 0.0
    evidence_ids: list[UUID] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    validated_at: Optional[datetime] = None

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["path_id"] = str(data["path_id"])
        data["finding_correlations"] = [str(f) for f in data["finding_correlations"]]
        data["evidence_ids"] = [str(e) for e in data["evidence_ids"]]
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "validated_at" in data and data["validated_at"] and isinstance(data["validated_at"], datetime):
            data["validated_at"] = data["validated_at"].isoformat()
        return data


class SystemicRiskAssessment(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    assessment_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    composite_paths: list[UUID] = Field(default_factory=list)
    overall_systemic_risk: float = 0.0
    risk_factors: dict[str, float] = Field(default_factory=dict)
    critical_attack_paths: int = 0
    exploitable_chains: int = 0
    blast_radius: dict[str, Any] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    assessed_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["assessment_id"] = str(data["assessment_id"])
        data["target_id"] = str(data["target_id"])
        data["composite_paths"] = [str(p) for p in data["composite_paths"]]
        if "assessed_at" in data and isinstance(data["assessed_at"], datetime):
            data["assessed_at"] = data["assessed_at"].isoformat()
        return data


class CorrelationRule(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    rule_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    correlation_type: CorrelationType
    conditions: dict[str, Any] = Field(default_factory=dict)
    min_findings: int = 2
    severity_threshold: str = "medium"
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class CorrelationResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    result_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    correlations: list[FindingCorrelation] = Field(default_factory=list)
    composite_paths: list[CompositeAttackPath] = Field(default_factory=list)
    systemic_risk: Optional[UUID] = None
    total_correlations: int = 0
    critical_correlations: int = 0
    high_correlations: int = 0
    new_correlations: int = 0
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    analysis_duration_ms: int = 0

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["result_id"] = str(data["result_id"])
        data["target_id"] = str(data["target_id"])
        if "systemic_risk" in data and data["systemic_risk"]:
            data["systemic_risk"] = str(data["systemic_risk"])
        if "analyzed_at" in data and isinstance(data["analyzed_at"], datetime):
            data["analyzed_at"] = data["analyzed_at"].isoformat()
        return data