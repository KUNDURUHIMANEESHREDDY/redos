from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class VulnerabilityType(str, Enum):
    INJECTION = "injection"
    BROKEN_AUTH = "broken_authentication"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    XML_EXTERNAL_ENTITIES = "xml_external_entities"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    XSS = "cross_site_scripting"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    INSUFFICIENT_LOGGING = "insufficient_logging"
    SSRF = "server_side_request_forgery"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    HEADER_INJECTION = "header_injection"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    CSRF = "cross_site_request_forgery"
    OPEN_REDIRECT = "open_redirect"
    RACE_CONDITION = "race_condition"
    BUSINESS_LOGIC = "business_logic"
    CRYPTOGRAPHIC_FAILURE = "cryptographic_failure"
    CUSTOM = "custom"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    REMEDIATED = "remediated"
    REGRESSION_TESTED = "regression_tested"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    DUPLICATE = "duplicate"


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class ImpactLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExploitabilityLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackStep(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    step_id: int
    description: str
    evidence_ids: list[UUID] = Field(default_factory=list)
    technique: str | None = None
    tactic: str | None = None
    timestamp: datetime | None = None
    success: bool = True
    details: dict[str, Any] = Field(default_factory=dict)


class AttackPath(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    path_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    steps: list[AttackStep] = Field(default_factory=list)
    entry_point: str
    target: str
    mitre_techniques: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class RemediationAction(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    action_id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    priority: int = 1
    effort: str = "medium"
    category: str = "code_change"
    references: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)


class RegressionTest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    test_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    test_type: str = "automated"
    input_data: dict[str, Any] = Field(default_factory=dict)
    expected_outcome: dict[str, Any] = Field(default_factory=dict)
    validation_criteria: list[str] = Field(default_factory=list)
    environment_requirements: dict[str, Any] = Field(default_factory=dict)
    created_from_finding: UUID | None = None


class RootCause(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    cause_id: UUID = Field(default_factory=uuid4)
    description: str
    category: str
    evidence_ids: list[UUID] = Field(default_factory=list)
    contributing_factors: list[str] = Field(default_factory=list)
    code_location: str | None = None
    configuration_issue: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    target_id: str
    attack_id: str
    execution_id: UUID
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    confidence: ConfidenceLevel
    impact: ImpactLevel
    exploitability: ExploitabilityLevel
    attack_path: AttackPath | None = None
    evidence_ids: list[UUID] = Field(default_factory=list)
    root_cause: RootCause | None = None
    remediation: list[RemediationAction] = Field(default_factory=list)
    reproduction: dict[str, Any] = Field(default_factory=dict)
    regression_tests: list[RegressionTest] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.NEW
    risk_score: float = 0.0
    cvss_vector: str | None = None
    cvss_score: float | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    closed_at: datetime | None = None

    def model_dump(self, **kwargs) -> dict[str, Any]:
        data = super().model_dump(**kwargs)
        data["id"] = str(data["id"])
        data["execution_id"] = str(data["execution_id"])
        data["evidence_ids"] = [str(e) for e in data["evidence_ids"]]
        if data.get("attack_path"):
            data["attack_path"]["path_id"] = str(data["attack_path"]["path_id"])
            for step in data["attack_path"]["steps"]:
                step["evidence_ids"] = [str(e) for e in step["evidence_ids"]]
        if data.get("root_cause"):
            data["root_cause"]["cause_id"] = str(data["root_cause"]["cause_id"])
            data["root_cause"]["evidence_ids"] = [str(e) for e in data["root_cause"]["evidence_ids"]]
        for rem in data.get("remediation", []):
            rem["action_id"] = str(rem["action_id"])
        for test in data.get("regression_tests", []):
            test["test_id"] = str(test["test_id"])
            if test.get("created_from_finding"):
                test["created_from_finding"] = str(test["created_from_finding"])
        if "created_at" in data and isinstance(data["created_at"], datetime):
            data["created_at"] = data["created_at"].isoformat()
        if "updated_at" in data and isinstance(data["updated_at"], datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        if "closed_at" in data and data["closed_at"] and isinstance(data["closed_at"], datetime):
            data["closed_at"] = data["closed_at"].isoformat()
        return data


VALID_STATUS_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.NEW: {FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE, FindingStatus.DUPLICATE},
    FindingStatus.CONFIRMED: {FindingStatus.REMEDIATED, FindingStatus.FALSE_POSITIVE, FindingStatus.WONT_FIX},
    FindingStatus.REMEDIATED: {FindingStatus.REGRESSION_TESTED, FindingStatus.CONFIRMED},
    FindingStatus.REGRESSION_TESTED: {FindingStatus.FIXED, FindingStatus.REMEDIATED},
    FindingStatus.FIXED: set(),
    FindingStatus.FALSE_POSITIVE: set(),
    FindingStatus.WONT_FIX: set(),
    FindingStatus.DUPLICATE: set(),
}


def can_transition(from_status: FindingStatus, to_status: FindingStatus) -> bool:
    return to_status in VALID_STATUS_TRANSITIONS.get(from_status, set())