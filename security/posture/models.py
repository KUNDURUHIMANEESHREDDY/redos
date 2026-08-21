from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class PostureLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class TargetType(str, Enum):
    AI_AGENT = "ai_agent"
    LLM_MODEL = "llm_model"
    RAG_SYSTEM = "rag_system"
    TOOL_CHAIN = "tool_chain"
    API_ENDPOINT = "api_endpoint"
    DOCUMENT_STORE = "document_store"
    PROMPT_TEMPLATE = "prompt_template"
    SYSTEM_PROMPT = "system_prompt"
    POLICY_ENGINE = "policy_engine"
    DEPENDENCY = "dependency"


class TargetStatus(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    TESTING = "testing"
    ARCHIVED = "archived"


class Target(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    name: str
    target_type: TargetType
    version: str
    description: Optional[str] = None
    status: TargetStatus = TargetStatus.ACTIVE
    configuration: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    owner: Optional[str] = None
    environment: str = "production"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["id"] = str(data["id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data


class TargetVersion(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    version: str
    configuration_snapshot: dict[str, Any]
    change_summary: str
    changed_by: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["id"] = str(data["id"])
        data["target_id"] = str(data["target_id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        return data


class PostureMetric(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    metric_id: UUID = Field(default_factory=uuid4)
    name: str
    value: float
    unit: str
    threshold_critical: Optional[float] = None
    threshold_high: Optional[float] = None
    threshold_medium: Optional[float] = None
    threshold_low: Optional[float] = None
    description: str
    computed_at: datetime = Field(default_factory=datetime.utcnow)


class PostureSnapshot(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    snapshot_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    posture_level: PostureLevel
    overall_score: float
    metrics: list[PostureMetric] = Field(default_factory=list)
    critical_findings_count: int = 0
    high_findings_count: int = 0
    medium_findings_count: int = 0
    low_findings_count: int = 0
    total_findings_count: int = 0
    attack_coverage: float = 0.0
    remediation_rate: float = 0.0
    regression_rate: float = 0.0
    unresolved_risk_score: float = 0.0
    computed_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["snapshot_id"] = str(data["snapshot_id"])
        data["target_id"] = str(data["target_id"])
        if "computed_at" in data and isinstance(data["computed_at"], datetime):
            data["computed_at"] = data["computed_at"].isoformat()
        return data


class RiskHistoryEntry(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    entry_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    timestamp: datetime
    posture_snapshot: PostureSnapshot
    trigger: str
    finding_ids: list[UUID] = Field(default_factory=list)
    change_type: str
    description: str

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["entry_id"] = str(data["entry_id"])
        data["target_id"] = str(data["target_id"])
        if "timestamp" in data and isinstance(data["timestamp"], datetime):
            data["timestamp"] = data["timestamp"].isoformat()
        return data


class TargetRiskHistory(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    target_id: UUID
    entries: list[RiskHistoryEntry] = Field(default_factory=list)
    current_posture: Optional[PostureSnapshot] = None
    trend: str = "stable"
    risk_velocity: float = 0.0

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["target_id"] = str(data["target_id"])
        return data


class PostureComparison(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    comparison_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    baseline_snapshot: PostureSnapshot
    current_snapshot: PostureSnapshot
    score_delta: float
    posture_changed: bool
    new_critical: int = 0
    new_high: int = 0
    fixed_critical: int = 0
    fixed_high: int = 0
    regressed_findings: list[UUID] = Field(default_factory=list)
    new_findings: list[UUID] = Field(default_factory=list)
    fixed_findings: list[UUID] = Field(default_factory=list)
    compared_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["comparison_id"] = str(data["comparison_id"])
        data["target_id"] = str(data["target_id"])
        if "compared_at" in data and isinstance(data["compared_at"], datetime):
            data["compared_at"] = data["compared_at"].isoformat()
        return data