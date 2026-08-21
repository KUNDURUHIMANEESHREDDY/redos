from datetime import datetime
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class RegressionTest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    test_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    name: str
    description: str
    test_type: str = "automated"
    input_data: dict[str, Any] = Field(default_factory=dict)
    expected_outcome: dict[str, Any] = Field(default_factory=dict)
    validation_criteria: list[str] = Field(default_factory=list)
    environment_requirements: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class RegressionRun(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    run_id: UUID = Field(default_factory=uuid4)
    test_id: UUID
    finding_id: UUID
    execution_id: UUID
    status: str = "pending"  # pending, running, completed, failed
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    result: Optional[str] = None  # fixed, regression, error
    details: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[UUID] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)