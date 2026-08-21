from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class NodeType(str, Enum):
    MODEL = "model"
    PROMPT = "prompt"
    TOOL = "tool"
    PERMISSION = "permission"
    RAG_INDEX = "rag_index"
    DOCUMENT = "document"
    MEMORY = "memory"
    AGENT = "agent"
    API = "api"
    DATA_STORE = "data_store"
    USER = "user"
    ENTRY_POINT = "entry_point"
    VULNERABILITY = "vulnerability"
    ATTACK_STEP = "attack_step"


class EdgeType(str, Enum):
    CALLS = "calls"
    ACCESSES = "accesses"
    CONTAINS = "contains"
    FLOWS_TO = "flows_to"
    DEPENDS_ON = "depends_on"
    EXPLOITS = "exploits"
    CHAINS_TO = "chains_to"
    LEADS_TO = "leads_to"
    RELATED_TO = "related_to"
    PERMITS = "permits"
    READS = "reads"
    WRITES = "writes"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class GraphNode(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    node_id: UUID = Field(default_factory=uuid4)
    graph_id: UUID
    node_type: NodeType
    label: str
    description: str
    target_id: Optional[UUID] = None
    finding_id: Optional[UUID] = None
    execution_id: Optional[UUID] = None
    risk_level: RiskLevel = RiskLevel.INFO
    risk_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)
    properties: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["node_id"] = str(data["node_id"])
        data["graph_id"] = str(data["graph_id"])
        if data.get("target_id"):
            data["target_id"] = str(data["target_id"])
        if data.get("finding_id"):
            data["finding_id"] = str(data["finding_id"])
        if data.get("execution_id"):
            data["execution_id"] = str(data["execution_id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data


class GraphEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    edge_id: UUID = Field(default_factory=uuid4)
    graph_id: UUID
    source_id: UUID
    target_id: UUID
    edge_type: EdgeType
    weight: float = 1.0
    evidence_ids: list[UUID] = Field(default_factory=list)
    finding_ids: list[UUID] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["edge_id"] = str(data["edge_id"])
        data["graph_id"] = str(data["graph_id"])
        data["source_id"] = str(data["source_id"])
        data["target_id"] = str(data["target_id"])
        data["evidence_ids"] = [str(e) for e in data["evidence_ids"]]
        data["finding_ids"] = [str(f) for f in data["finding_ids"]]
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        return data


class RiskGraph(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    graph_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    name: str
    description: str = ""
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    entry_points: list[UUID] = Field(default_factory=list)
    critical_paths: list[list[UUID]] = Field(default_factory=list)
    risk_score: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["graph_id"] = str(data["graph_id"])
        data["target_id"] = str(data["target_id"])
        data["entry_points"] = [str(e) for e in data["entry_points"]]
        data["critical_paths"] = [[str(n) for n in path] for path in data["critical_paths"]]
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data


class RiskPropagationEvent(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    event_id: UUID = Field(default_factory=uuid4)
    graph_id: UUID
    source_node_id: UUID
    affected_node_ids: list[UUID] = Field(default_factory=list)
    trigger_type: str
    trigger_details: dict[str, Any] = Field(default_factory=dict)
    risk_delta: float = 0.0
    propagated: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["event_id"] = str(data["event_id"])
        data["graph_id"] = str(data["graph_id"])
        data["source_node_id"] = str(data["source_node_id"])
        data["affected_node_ids"] = [str(n) for n in data["affected_node_ids"]]
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        return data


class BlastRadiusAssessment(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    assessment_id: UUID = Field(default_factory=uuid4)
    graph_id: UUID
    source_node_id: UUID
    affected_nodes: list[UUID] = Field(default_factory=list)
    blast_radius_score: float = 0.0
    max_depth: int = 0
    affected_assets: list[str] = Field(default_factory=list)
    affected_data_stores: list[str] = Field(default_factory=list)
    critical_paths: list[list[UUID]] = Field(default_factory=list)
    assessed_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["assessment_id"] = str(data["assessment_id"])
        data["graph_id"] = str(data["graph_id"])
        data["source_node_id"] = str(data["source_node_id"])
        data["affected_nodes"] = [str(n) for n in data["affected_nodes"]]
        data["critical_paths"] = [[str(n) for n in path] for path in data["critical_paths"]]
        if "assessed_at" in data and isinstance(data["assessed_at"], datetime):
            data["assessed_at"] = data["assessed_at"].isoformat()
        return data


class RiskGraphBuildRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    target_id: UUID
    execution_id: Optional[UUID] = None
    include_findings: bool = True
    include_assets: bool = True
    include_permissions: bool = True
    include_change_history: bool = True