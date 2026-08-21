from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class ComponentType(str, Enum):
    MODEL = "model"
    PROMPT = "prompt"
    TOOL = "tool"
    PERMISSION = "permission"
    RAG = "rag"
    DOCUMENT = "document"
    MEMORY = "memory"
    AGENT = "agent"
    API = "api"
    DATA = "data"
    DEPENDENCY = "dependency"
    PIPELINE = "pipeline"


class ComponentStatus(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    TESTING = "testing"
    DISABLED = "disabled"


class TwinComponent(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    component_id: UUID = Field(default_factory=uuid4)
    twin_id: UUID
    component_type: ComponentType
    name: str
    version: str
    description: str
    status: ComponentStatus = ComponentStatus.ACTIVE
    configuration: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    parent_id: Optional[UUID] = None
    dependencies: list[UUID] = Field(default_factory=list)
    dependents: list[UUID] = Field(default_factory=list)
    risk_score: float = 0.0
    last_scanned: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["component_id"] = str(data["component_id"])
        data["twin_id"] = str(data["twin_id"])
        if data.get("parent_id"):
            data["parent_id"] = str(data["parent_id"])
        data["dependencies"] = [str(d) for d in data["dependencies"]]
        data["dependents"] = [str(d) for d in data["dependents"]]
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        if "last_scanned" in data and data["last_scanned"] and isinstance(data["last_scanned"], datetime):
            data["last_scanned"] = data["last_scanned"].isoformat()
        return data


class TwinEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    edge_id: UUID = Field(default_factory=uuid4)
    twin_id: UUID
    source_id: UUID
    target_id: UUID
    relationship: str
    weight: float = 1.0
    evidence_ids: list[UUID] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["edge_id"] = str(data["edge_id"])
        data["twin_id"] = str(data["twin_id"])
        data["source_id"] = str(data["source_id"])
        data["target_id"] = str(data["target_id"])
        data["evidence_ids"] = [str(e) for e in data["evidence_ids"]]
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        return data


class DigitalTwin(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    twin_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    name: str
    description: str = ""
    components: list[TwinComponent] = Field(default_factory=list)
    edges: list[TwinEdge] = Field(default_factory=list)
    version: str = "1.0"
    last_synced: Optional[datetime] = None
    sync_status: str = "pending"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["twin_id"] = str(data["twin_id"])
        data["target_id"] = str(data["target_id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        if "last_synced" in data and data["last_synced"] and isinstance(data["last_synced"], datetime):
            data["last_synced"] = data["last_synced"].isoformat()
        return data


class TwinSnapshot(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    snapshot_id: UUID = Field(default_factory=uuid4)
    twin_id: UUID
    version: str
    components_snapshot: dict[str, Any]
    edges_snapshot: list[dict[str, Any]]
    captured_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["snapshot_id"] = str(data["snapshot_id"])
        data["twin_id"] = str(data["twin_id"])
        if "captured_at" in data and isinstance(data["captured_at"], datetime):
            data["captured_at"] = data["captured_at"].isoformat()
        return data


class ComponentChange(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    change_id: UUID = Field(default_factory=uuid4)
    twin_id: UUID
    component_id: UUID
    change_type: str
    before: Optional[dict[str, Any]] = None
    after: Optional[dict[str, Any]] = None
    diff: dict[str, Any] = Field(default_factory=dict)
    security_impact: Optional[str] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["change_id"] = str(data["change_id"])
        data["twin_id"] = str(data["twin_id"])
        data["component_id"] = str(data["component_id"])
        if "detected_at" in data and isinstance(data["detected_at"], datetime):
            data["detected_at"] = data["detected_at"].isoformat()
        return data


class AssumptionImpact(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    impact_id: UUID = Field(default_factory=uuid4)
    twin_id: UUID
    assumption: str
    was_valid: bool
    is_valid: bool
    affected_components: list[UUID] = Field(default_factory=list)
    affected_findings: list[UUID] = Field(default_factory=list)
    risk_delta: float = 0.0
    description: str
    detected_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["impact_id"] = str(data["impact_id"])
        data["twin_id"] = str(data["twin_id"])
        data["affected_components"] = [str(c) for c in data["affected_components"]]
        data["affected_findings"] = [str(f) for f in data["affected_findings"]]
        if "detected_at" in data and isinstance(data["detected_at"], datetime):
            data["detected_at"] = data["detected_at"].isoformat()
        return data


class DigitalTwinSyncRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    target_id: UUID
    force_full_sync: bool = False
    components_to_sync: Optional[list[str]] = None