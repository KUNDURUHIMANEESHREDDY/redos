from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class KnowledgeType(str, Enum):
    ATTACK_PATTERN = "attack_pattern"
    VULNERABILITY_PATTERN = "vulnerability_pattern"
    EXPLOIT_TECHNIQUE = "exploit_technique"
    REMEDIATION_PATTERN = "remediation_pattern"
    REGRESSION_PATTERN = "regression_pattern"
    TARGET_PROFILE = "target_profile"
    CAMPAIGN_STRATEGY = "campaign_strategy"
    EVASION_TECHNIQUE = "evasion_technique"
    DETECTION_RULE = "detection_rule"
    THREAT_INTEL = "threat_intel"


class KnowledgeStatus(str, Enum):
    DRAFT = "draft"
    VERIFIED = "verified"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class KnowledgeEntry(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    entry_id: UUID = Field(default_factory=uuid4)
    knowledge_type: KnowledgeType
    title: str
    description: str
    content: dict[str, Any] = Field(default_factory=dict)
    status: KnowledgeStatus = KnowledgeStatus.DRAFT
    confidence: float = 0.0
    source: str = "system"
    tags: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    vulnerability_types: list[str] = Field(default_factory=list)
    affected_targets: list[UUID] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    finding_ids: list[UUID] = Field(default_factory=list)
    related_entries: list[UUID] = Field(default_factory=list)
    created_by: Optional[str] = None
    verified_by: Optional[str] = None
    verified_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["entry_id"] = str(data["entry_id"])
        data["affected_targets"] = [str(t) for t in data["affected_targets"]]
        data["evidence_ids"] = [str(e) for e in data["evidence_ids"]]
        data["finding_ids"] = [str(f) for f in data["finding_ids"]]
        data["related_entries"] = [str(r) for r in data["related_entries"]]
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        if "verified_at" in data and data["verified_at"] and isinstance(data["verified_at"], datetime):
            data["verified_at"] = data["verified_at"].isoformat()
        return data


class AttackPattern(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    pattern_id: UUID = Field(default_factory=uuid4)
    entry_id: UUID
    name: str
    description: str
    attack_vector: str
    prerequisites: list[str] = Field(default_factory=list)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    detection_difficulty: str = "medium"
    exploitability: float = 0.0
    impact: float = 0.0
    countermeasures: list[str] = Field(default_factory=list)
    examples: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["pattern_id"] = str(data["pattern_id"])
        data["entry_id"] = str(data["entry_id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data


class VulnerabilityPattern(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    pattern_id: UUID = Field(default_factory=uuid4)
    entry_id: UUID
    vulnerability_type: str
    root_cause_pattern: str
    common_locations: list[str] = Field(default_factory=list)
    trigger_conditions: list[str] = Field(default_factory=list)
    exploit_patterns: list[str] = Field(default_factory=list)
    detection_signatures: list[str] = Field(default_factory=list)
    remediation_patterns: list[str] = Field(default_factory=list)
    false_positive_patterns: list[str] = Field(default_factory=list)
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    confidence: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["pattern_id"] = str(data["pattern_id"])
        data["entry_id"] = str(data["entry_id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data


class RemediationPattern(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    pattern_id: UUID = Field(default_factory=uuid4)
    entry_id: UUID
    vulnerability_type: str
    title: str
    description: str
    remediation_steps: list[str] = Field(default_factory=list)
    code_examples: dict[str, str] = Field(default_factory=dict)
    configuration_changes: list[dict[str, Any]] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    effectiveness: float = 0.0
    effort_estimate: str = "medium"
    prerequisites: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["pattern_id"] = str(data["pattern_id"])
        data["entry_id"] = str(data["entry_id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data


class RegressionPattern(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    pattern_id: UUID = Field(default_factory=uuid4)
    entry_id: UUID
    vulnerability_type: str
    regression_triggers: list[str] = Field(default_factory=list)
    detection_patterns: list[str] = Field(default_factory=list)
    recurrence_rate: float = 0.0
    typical_time_to_regression: int = 0
    prevention_strategies: list[str] = Field(default_factory=list)
    detection_rules: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["pattern_id"] = str(data["pattern_id"])
        data["entry_id"] = str(data["entry_id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data


class TargetProfile(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    profile_id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    target_type: str
    attack_surface_summary: dict[str, Any] = Field(default_factory=dict)
    common_vulnerabilities: list[str] = Field(default_factory=list)
    common_attack_vectors: list[str] = Field(default_factory=list)
    risk_profile: str = "unknown"
    defense_posture: dict[str, Any] = Field(default_factory=dict)
    historical_regressions: int = 0
    remediation_velocity: float = 0.0
    attack_success_rate: float = 0.0
    last_updated: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["profile_id"] = str(data["profile_id"])
        data["target_id"] = str(data["target_id"])
        if "last_updated" in data and isinstance(data["last_updated"], datetime):
            data["last_updated"] = data["last_updated"].isoformat()
        return data


class CampaignStrategy(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    strategy_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    target_types: list[str] = Field(default_factory=list)
    attack_vectors: list[str] = Field(default_factory=list)
    phases: list[dict[str, Any]] = Field(default_factory=list)
    success_rate: float = 0.0
    avg_findings_per_run: float = 0.0
    avg_critical_findings: float = 0.0
    recommended_targets: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    estimated_duration: int = 0
    success_criteria: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["strategy_id"] = str(data["strategy_id"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data


class KnowledgeEntrySearch(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    query: Optional[str] = None
    knowledge_types: list[KnowledgeType] = Field(default_factory=list)
    statuses: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    vulnerability_types: list[str] = Field(default_factory=list)
    target_ids: list[UUID] = Field(default_factory=list)
    min_confidence: float = 0.0
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    limit: int = 50
    offset: int = 0