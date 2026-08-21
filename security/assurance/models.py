from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class AssuranceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class VerificationStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    SKIPPED = "skipped"


class AssuranceMetric(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    metric_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    value: float
    threshold: float
    unit: str
    assurance_level: AssuranceLevel
    computed_at: datetime = Field(default_factory=datetime.utcnow)


class ContinuousAssurance(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    assurance_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    overall_assurance: AssuranceLevel
    metrics: list[AssuranceMetric] = Field(default_factory=list)
    verified_findings: int = 0
    total_findings: int = 0
    verification_rate: float = 0.0
    regression_tests_passing: int = 0
    regression_tests_total: int = 0
    regression_pass_rate: float = 0.0
    evidence_completeness: float = 0.0
    attack_coverage: float = 0.0
    remediation_completeness: float = 0.0
    computed_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["assurance_id"] = str(data["assurance_id"])
        data["target_id"] = str(data["target_id"])
        if "computed_at" in data and isinstance(data["computed_at"], datetime):
            data["computed_at"] = data["computed_at"].isoformat()
        return data


class AssurancePolicy(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    policy_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    target_types: list[str] = Field(default_factory=list)
    required_metrics: list[str] = Field(default_factory=list)
    minimum_assurance: AssuranceLevel = AssuranceLevel.MEDIUM
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class AssuranceVerification(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    verification_id: UUID = Field(default_factory=uuid4)
    assurance_id: UUID
    policy_id: UUID
    status: VerificationStatus = VerificationStatus.PENDING
    findings_verified: list[UUID] = Field(default_factory=list)
    findings_failed: list[UUID] = Field(default_factory=list)
    findings_skipped: list[UUID] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    details: dict[str, Any] = Field(default_factory=dict)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["verification_id"] = str(data["verification_id"])
        data["assurance_id"] = str(data["assurance_id"])
        data["policy_id"] = str(data["policy_id"])
        data["findings_verified"] = [str(f) for f in data["findings_verified"]]
        data["findings_failed"] = [str(f) for f in data["findings_failed"]]
        data["findings_skipped"] = [str(f) for f in data["findings_skipped"]]
        if "started_at" in data and isinstance(data["started_at"], datetime):
            data["started_at"] = data["started_at"].isoformat()
        if "completed_at" in data and data["completed_at"] and isinstance(data["completed_at"], datetime):
            data["completed_at"] = data["completed_at"].isoformat()
        return data