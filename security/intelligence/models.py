from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class RegressionType(str, Enum):
    FIXED = "fixed"
    REGRESSION = "regression"
    CHANGED = "changed"
    NEW = "new"
    UNCHANGED = "unchanged"


class IntelligenceType(str, Enum):
    REGRESSION_ANALYSIS = "regression_analysis"
    ATTACK_COVERAGE = "attack_coverage"
    RISK_TREND = "risk_trend"
    EVIDENCE_LINEAGE = "evidence_lineage"
    MODEL_COMPARISON = "model_comparison"
    TARGET_COMPARISON = "target_comparison"
    REMEDIATION_VERIFICATION = "remediation_verification"


class IntelligencePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RegressionIntelligence(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    intelligence_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    execution_a_id: UUID
    execution_b_id: UUID
    finding_id: UUID
    regression_type: RegressionType
    what_changed: str
    why_changed: str
    affected_attack_vectors: list[str] = Field(default_factory=list)
    recommended_reruns: list[str] = Field(default_factory=list)
    severity_delta: float = 0.0
    confidence: float = 1.0
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["intelligence_id"] = str(data["intelligence_id"])
        data["target_id"] = str(data["target_id"])
        data["execution_a_id"] = str(data["execution_a_id"])
        data["execution_b_id"] = str(data["execution_b_id"])
        data["finding_id"] = str(data["finding_id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        return data


class AttackCoverageAnalytics(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    analytics_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    execution_id: UUID
    total_attack_vectors: int = 0
    covered_vectors: int = 0
    coverage_percentage: float = 0.0
    uncovered_vectors: list[str] = Field(default_factory=list)
    tested_vectors: list[dict[str, Any]] = Field(default_factory=list)
    mitre_tactics_covered: list[str] = Field(default_factory=list)
    mitre_tactics_missing: list[str] = Field(default_factory=list)
    coverage_by_tactic: dict[str, float] = Field(default_factory=dict)
    evidence_ids: list[UUID] = Field(default_factory=list)
    computed_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["analytics_id"] = str(data["analytics_id"])
        data["target_id"] = str(data["target_id"])
        data["execution_id"] = str(data["execution_id"])
        data["evidence_ids"] = [str(e) for e in data["evidence_ids"]]
        if "computed_at" in data and isinstance(data["computed_at"], datetime):
            data["computed_at"] = data["computed_at"].isoformat()
        return data


class RiskTrendAnalysis(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    trend_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    period_start: datetime
    period_end: datetime
    trend_direction: str
    risk_velocity: float
    posture_changes: int = 0
    critical_changes: int = 0
    regression_events: int = 0
    remediation_events: int = 0
    net_risk_change: float = 0.0
    trend_points: list[dict[str, Any]] = Field(default_factory=list)
    computed_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["trend_id"] = str(data["trend_id"])
        data["target_id"] = str(data["target_id"])
        if "period_start" in data and isinstance(data["period_start"], datetime):
            data["period_start"] = data["period_start"].isoformat()
        if "period_end" in data and isinstance(data["period_end"], datetime):
            data["period_end"] = data["period_end"].isoformat()
        if "computed_at" in data and isinstance(data["computed_at"], datetime):
            data["computed_at"] = data["computed_at"].isoformat()
        return data


class EvidenceLineage(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    lineage_id: UUID = Field(default_factory=uuid4)
    evidence_id: UUID
    finding_id: UUID
    finding_correlations: list[UUID] = Field(default_factory=list)
    attack_paths: list[UUID] = Field(default_factory=list)
    remediation_actions: list[UUID] = Field(default_factory=list)
    regression_tests: list[UUID] = Field(default_factory=list)
    attack_graph_nodes: list[UUID] = Field(default_factory=list)
    severity_assessments: list[UUID] = Field(default_factory=list)
    root_causes: list[UUID] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["lineage_id"] = str(data["lineage_id"])
        data["evidence_id"] = str(data["evidence_id"])
        data["finding_id"] = str(data["finding_id"])
        data["finding_correlations"] = [str(f) for f in data["finding_correlations"]]
        data["attack_paths"] = [str(a) for a in data["attack_paths"]]
        data["remediation_actions"] = [str(r) for r in data["remediation_actions"]]
        data["regression_tests"] = [str(r) for r in data["regression_tests"]]
        data["attack_graph_nodes"] = [str(n) for n in data["attack_graph_nodes"]]
        data["severity_assessments"] = [str(s) for s in data["severity_assessments"]]
        data["root_causes"] = [str(r) for r in data["root_causes"]]
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data


class ModelVersionComparison(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    comparison_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    version_a: str
    version_b: str
    scan_a_id: UUID
    scan_b_id: UUID
    new_vulnerabilities: list[UUID] = Field(default_factory=list)
    fixed_vulnerabilities: list[UUID] = Field(default_factory=list)
    regressions: list[UUID] = Field(default_factory=list)
    changed_attack_surface: list[str] = Field(default_factory=list)
    risk_delta: float = 0.0
    posture_changed: bool = False
    change_summary: str = ""
    compared_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["comparison_id"] = str(data["comparison_id"])
        data["target_id"] = str(data["target_id"])
        data["scan_a_id"] = str(data["scan_a_id"])
        data["scan_b_id"] = str(data["scan_b_id"])
        data["new_vulnerabilities"] = [str(f) for f in data["new_vulnerabilities"]]
        data["fixed_vulnerabilities"] = [str(f) for f in data["fixed_vulnerabilities"]]
        data["regressions"] = [str(r) for r in data["regressions"]]
        if "compared_at" in data and isinstance(data["compared_at"], datetime):
            data["compared_at"] = data["compared_at"].isoformat()
        return data


class TargetComparison(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    comparison_id: UUID = Field(default_factory=uuid4)
    target_a_id: UUID
    target_b_id: UUID
    posture_a: str
    posture_b: str
    risk_delta: float
    shared_vulnerabilities: list[UUID] = Field(default_factory=list)
    unique_to_a: list[UUID] = Field(default_factory=list)
    unique_to_b: list[UUID] = Field(default_factory=list)
    compared_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["comparison_id"] = str(data["comparison_id"])
        data["target_a_id"] = str(data["target_a_id"])
        data["target_b_id"] = str(data["target_b_id"])
        data["shared_vulnerabilities"] = [str(v) for v in data["shared_vulnerabilities"]]
        data["unique_to_a"] = [str(v) for v in data["unique_to_a"]]
        data["unique_to_b"] = [str(v) for v in data["unique_to_b"]]
        if "compared_at" in data and isinstance(data["compared_at"], datetime):
            data["compared_at"] = data["compared_at"].isoformat()
        return data


class RemediationVerification(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    verification_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    remediation_id: UUID
    regression_test_id: UUID
    test_execution_id: UUID
    verified: bool = False
    verification_evidence: list[UUID] = Field(default_factory=list)
    details: str = ""
    verified_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["verification_id"] = str(data["verification_id"])
        data["finding_id"] = str(data["finding_id"])
        data["remediation_id"] = str(data["remediation_id"])
        data["regression_test_id"] = str(data["regression_test_id"])
        data["test_execution_id"] = str(data["test_execution_id"])
        data["verification_evidence"] = [str(e) for e in data["verification_evidence"]]
        if "verified_at" in data and data["verified_at"] and isinstance(data["verified_at"], datetime):
            data["verified_at"] = data["verified_at"].isoformat()
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        return data


class IntelligenceReport(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    report_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    intelligence_type: IntelligenceType
    priority: IntelligencePriority
    title: str
    summary: str
    findings: list[UUID] = Field(default_factory=list)
    correlations: list[UUID] = Field(default_factory=list)
    regressions: list[UUID] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["report_id"] = str(data["report_id"])
        data["target_id"] = str(data["target_id"])
        data["findings"] = [str(f) for f in data["findings"]]
        data["correlations"] = [str(c) for c in data["correlations"]]
        data["regressions"] = [str(r) for r in data["regressions"]]
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "acknowledged_at" in data and data["acknowledged_at"] and isinstance(data["acknowledged_at"], datetime):
            data["acknowledged_at"] = data["acknowledged_at"].isoformat()
        return data