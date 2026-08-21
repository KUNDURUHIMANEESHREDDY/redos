from datetime import datetime
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class SecurityPolicy(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    policy_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    category: str
    rules: list[dict[str, Any]] = Field(default_factory=list)
    severity_threshold: str = "medium"
    enabled: bool = True
    applies_to: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class PolicyEvaluation(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    evaluation_id: UUID = Field(default_factory=uuid4)
    policy_id: UUID
    execution_id: UUID
    passed: bool
    violations: list[dict[str, Any]] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)