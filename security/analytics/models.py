from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class AnalyticsType(str, Enum):
    ATTACK_COVERAGE = "attack_coverage"
    RISK_TREND = "risk_trend"
    FINDING_DISTRIBUTION = "finding_distribution"
    REMEDIATION_EFFECTIVENESS = "remediation_effectiveness"
    REGRESSION_ANALYSIS = "regression_analysis"
    EVIDENCE_QUALITY = "evidence_quality"
    TARGET_COMPARISON = "target_comparison"
    MODEL_PERFORMANCE = "model_performance"


class TimeGranularity(str, Enum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class AnalyticsQuery(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    query_id: UUID = Field(default_factory=uuid4)
    analytics_type: AnalyticsType
    target_ids: list[UUID] = Field(default_factory=list)
    time_range_start: datetime
    time_range_end: datetime
    granularity: TimeGranularity = TimeGranularity.DAILY
    filters: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AnalyticsResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    result_id: UUID = Field(default_factory=uuid4)
    query_id: UUID
    analytics_type: AnalyticsType
    target_id: UUID
    data_points: list[dict[str, Any]] = Field(default_factory=list)
    aggregations: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    computed_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["result_id"] = str(data["result_id"])
        data["query_id"] = str(data["query_id"])
        data["target_id"] = str(data["target_id"])
        if "computed_at" in data and isinstance(data["computed_at"], datetime):
            data["computed_at"] = data["computed_at"].isoformat()
        return data


class DashboardWidget(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    widget_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    analytics_type: AnalyticsType
    target_ids: list[UUID] = Field(default_factory=list)
    time_range: str = "30d"
    granularity: TimeGranularity = TimeGranularity.DAILY
    config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class AnalyticsReport(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    report_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    target_ids: list[UUID] = Field(default_factory=list)
    widgets: list[UUID] = Field(default_factory=list)
    schedule: Optional[str] = None
    recipients: list[str] = Field(default_factory=list)
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["report_id"] = str(data["report_id"])
        data["target_ids"] = [str(t) for t in data["target_ids"]]
        data["widgets"] = [str(w) for w in data["widgets"]]
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data