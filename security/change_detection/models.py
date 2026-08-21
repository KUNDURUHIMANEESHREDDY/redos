from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class ChangeType(str, Enum):
    MODEL_CHANGE = "model_change"
    SYSTEM_PROMPT_CHANGE = "system_prompt_change"
    TOOL_CHANGE = "tool_change"
    TOOL_PERMISSION_CHANGE = "tool_permission_change"
    RAG_INDEX_CHANGE = "rag_index_change"
    DOCUMENT_CHANGE = "document_change"
    AGENT_CONFIG_CHANGE = "agent_config_change"
    POLICY_CHANGE = "policy_change"
    DEPENDENCY_CHANGE = "dependency_change"
    PROMPT_TEMPLATE_CHANGE = "prompt_template_change"
    PERMISSION_CHANGE = "permission_change"
    CONFIGURATION_CHANGE = "configuration_change"


class ChangeSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ChangeCategory(str, Enum):
    SECURITY_RELEVANT = "security_relevant"
    FUNCTIONAL = "functional"
    PERFORMANCE = "performance"
    UNKNOWN = "unknown"


class ChangeSource(str, Enum):
    GIT = "git"
    CONFIG_FILE = "config_file"
    API = "api"
    MANUAL = "manual"
    SCHEDULED_SCAN = "scheduled_scan"


class ChangeEvent(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    event_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    change_type: ChangeType
    severity: ChangeSeverity
    category: ChangeCategory = ChangeCategory.UNKNOWN
    source: ChangeSource = ChangeSource.MANUAL
    description: str
    details: dict[str, Any] = Field(default_factory=dict)
    before: Optional[dict[str, Any]] = None
    after: Optional[dict[str, Any]] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    detected_by: str = "system"
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["event_id"] = str(data["event_id"])
        data["target_id"] = str(data["target_id"])
        if "detected_at" in data and isinstance(data["detected_at"], datetime):
            data["detected_at"] = data["detected_at"].isoformat()
        return data


class AssumptionChange(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    assumption_id: UUID = Field(default_factory=uuid4)
    change_event_id: UUID
    assumption: str
    was_valid: bool
    is_valid: bool
    evidence: list[str] = Field(default_factory=list)
    impact: str
    description: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["assumption_id"] = str(data["assumption_id"])
        data["change_event_id"] = str(data["change_event_id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        return data


class AttackSurfaceChange(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    change_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    change_event_id: UUID
    attack_vector: str
    before_coverage: float
    after_coverage: float
    new_attack_paths: list[str] = Field(default_factory=list)
    removed_attack_paths: list[str] = Field(default_factory=list)
    risk_delta: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["change_id"] = str(data["change_id"])
        data["target_id"] = str(data["target_id"])
        data["change_event_id"] = str(data["change_event_id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        return data


class ChangeDetectionRule(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    rule_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    change_types: list[ChangeType] = Field(default_factory=list)
    target_types: list[str] = Field(default_factory=list)
    condition: dict[str, Any] = Field(default_factory=dict)
    severity: ChangeSeverity = ChangeSeverity.MEDIUM
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ChangeDetectionResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    detection_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    change_events: list[ChangeEvent] = Field(default_factory=list)
    assumption_changes: list[AssumptionChange] = Field(default_factory=list)
    attack_surface_changes: list[AttackSurfaceChange] = Field(default_factory=list)
    security_assumptions_broken: list[str] = Field(default_factory=list)
    new_attack_vectors: list[str] = Field(default_factory=list)
    risk_increase: float = 0.0
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    scan_duration_ms: int = 0

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["detection_id"] = str(data["detection_id"])
        data["target_id"] = str(data["target_id"])
        if "scanned_at" in data and isinstance(data["scanned_at"], datetime):
            data["scanned_at"] = data["scanned_at"].isoformat()
        return data