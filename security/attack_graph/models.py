from datetime import datetime
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class AttackNode(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    node_id: UUID = Field(default_factory=uuid4)
    finding_id: Optional[UUID] = None
    type: str  # "vulnerability", "asset", "entry_point", "tool", "permission", "data_store"
    label: str
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    severity: str = "info"


class AttackEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    edge_id: UUID = Field(default_factory=uuid4)
    source_id: UUID
    target_id: UUID
    relationship: str  # "exploits", "accesses", "calls", "contains", "flows_to", "depends_on"
    weight: float = 1.0
    evidence_ids: list[UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackGraph(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    graph_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    execution_id: Optional[UUID] = None
    nodes: list[AttackNode] = Field(default_factory=list)
    edges: list[AttackEdge] = Field(default_factory=list)
    entry_points: list[UUID] = Field(default_factory=list)
    critical_paths: list[list[UUID]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["graph_id"] = str(data["graph_id"])
        data["target_id"] = str(data["target_id"])
        if data.get("execution_id"):
            data["execution_id"] = str(data["execution_id"])
        return data


class AttackGraphBuildRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    target_id: UUID
    execution_id: Optional[UUID] = None
    include_findings: bool = True
    include_assets: bool = True
    include_permissions: bool = True