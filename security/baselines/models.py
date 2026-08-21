from datetime import datetime
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class Baseline(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    baseline_id: UUID = Field(default_factory=uuid4)
    target: str
    name: str
    description: str
    metrics: dict[str, float] = Field(default_factory=dict)
    findings_summary: dict[str, int] = Field(default_factory=dict)
    period_start: datetime
    period_end: datetime
    execution_ids: list[UUID] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class BaselineComparison(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    comparison_id: UUID = Field(default_factory=uuid4)
    baseline_id: UUID
    execution_id: UUID
    metric_changes: dict[str, float] = Field(default_factory=dict)
    new_findings: int = 0
    resolved_findings: int = 0
    regressed_findings: int = 0
    risk_score_delta: float = 0.0
    compared_at: datetime = Field(default_factory=datetime.utcnow)