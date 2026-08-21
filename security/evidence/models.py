from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class EvidenceType(str, Enum):
    NETWORK_TRAFFIC = "network_traffic"
    LOG_ENTRY = "log_entry"
    FILE_SYSTEM = "file_system"
    MEMORY_DUMP = "memory_dump"
    PROCESS_TRACE = "process_trace"
    API_CALL = "api_call"
    USER_ACTION = "user_action"
    CONFIGURATION = "configuration"
    VULNERABILITY_SCAN = "vulnerability_scan"
    CUSTOM = "custom"


class EvidenceStatus(str, Enum):
    RAW = "raw"
    VALIDATED = "validated"
    NORMALIZED = "normalized"
    CORRELATED = "correlated"
    ARCHIVED = "archived"


class Evidence(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: UUID = Field(default_factory=uuid4)
    execution_id: UUID
    type: EvidenceType
    source: str
    timestamp: datetime
    raw_data: dict[str, Any]
    normalized_data: dict[str, Any] | None = None
    status: EvidenceStatus = EvidenceStatus.RAW
    validation_errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["id"] = str(data["id"])
        data["execution_id"] = str(data["execution_id"])
        if "timestamp" in data and isinstance(data["timestamp"], datetime):
            data["timestamp"] = data["timestamp"].isoformat()
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data