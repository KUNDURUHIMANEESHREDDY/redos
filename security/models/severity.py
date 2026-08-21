from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class CVSSVersion(str, Enum):
    V3_0 = "3.0"
    V3_1 = "3.1"
    V4_0 = "4.0"


class AttackVector(str, Enum):
    NETWORK = "network"
    ADJACENT = "adjacent"
    LOCAL = "local"
    PHYSICAL = "physical"


class AttackComplexity(str, Enum):
    LOW = "low"
    HIGH = "high"


class PrivilegesRequired(str, Enum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"


class UserInteraction(str, Enum):
    NONE = "none"
    REQUIRED = "required"


class Scope(str, Enum):
    UNCHANGED = "unchanged"
    CHANGED = "changed"


class ImpactLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"


class ExploitCodeMaturity(str, Enum):
    UNPROVEN = "unproven"
    PROOF_OF_CONCEPT = "proof_of_concept"
    FUNCTIONAL = "functional"
    HIGH = "high"
    NOT_DEFINED = "not_defined"


class RemediationLevel(str, Enum):
    OFFICIAL_FIX = "official_fix"
    TEMPORARY_FIX = "temporary_fix"
    WORKAROUND = "workaround"
    UNAVAILABLE = "unavailable"
    NOT_DEFINED = "not_defined"


class ReportConfidence(str, Enum):
    UNKNOWN = "unknown"
    REASONABLE = "reasonable"
    CONFIRMED = "confirmed"
    NOT_DEFINED = "not_defined"


class CVSSv31BaseMetrics(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.HIGH
    privileges_required: PrivilegesRequired = PrivilegesRequired.HIGH
    user_interaction: UserInteraction = UserInteraction.REQUIRED
    scope: Scope = Scope.UNCHANGED
    confidentiality: ImpactLevel = ImpactLevel.NONE
    integrity: ImpactLevel = ImpactLevel.NONE
    availability: ImpactLevel = ImpactLevel.NONE


class CVSSv31TemporalMetrics(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    exploit_code_maturity: ExploitCodeMaturity = ExploitCodeMaturity.NOT_DEFINED
    remediation_level: RemediationLevel = RemediationLevel.NOT_DEFINED
    report_confidence: ReportConfidence = ReportConfidence.NOT_DEFINED


class CVSSv31EnvironmentalMetrics(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    confidentiality_requirement: ImpactLevel = ImpactLevel.NONE
    integrity_requirement: ImpactLevel = ImpactLevel.NONE
    availability_requirement: ImpactLevel = ImpactLevel.NONE
    modified_attack_vector: AttackVector | None = None
    modified_attack_complexity: AttackComplexity | None = None
    modified_privileges_required: PrivilegesRequired | None = None
    modified_user_interaction: UserInteraction | None = None
    modified_scope: Scope | None = None
    modified_confidentiality: ImpactLevel | None = None
    modified_integrity: ImpactLevel | None = None
    modified_availability: ImpactLevel | None = None


class CVSSVector(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    version: CVSSVersion = CVSSVersion.V3_1
    base_metrics: CVSSv31BaseMetrics = Field(default_factory=CVSSv31BaseMetrics)
    temporal_metrics: CVSSv31TemporalMetrics = Field(default_factory=CVSSv31TemporalMetrics)
    environmental_metrics: CVSSv31EnvironmentalMetrics = Field(default_factory=CVSSv31EnvironmentalMetrics)

    def to_vector_string(self) -> str:
        base = self.base_metrics
        parts = [
            f"AV:{base.attack_vector.value[0].upper()}",
            f"AC:{base.attack_complexity.value[0].upper()}",
            f"PR:{base.privileges_required.value[0].upper()}",
            f"UI:{base.user_interaction.value[0].upper()}",
            f"S:{base.scope.value[0].upper()}",
            f"C:{base.confidentiality.value[0].upper()}",
            f"I:{base.integrity.value[0].upper()}",
            f"A:{base.availability.value[0].upper()}",
        ]
        vector = f"CVSS:{self.version.value}/" + "/".join(parts)

        temporal = self.temporal_metrics
        if temporal.exploit_code_maturity != ExploitCodeMaturity.NOT_DEFINED:
            vector += f"/E:{temporal.exploit_code_maturity.value[0].upper()}"
        if temporal.remediation_level != RemediationLevel.NOT_DEFINED:
            vector += f"/RL:{temporal.remediation_level.value[0].upper()}"
        if temporal.report_confidence != ReportConfidence.NOT_DEFINED:
            vector += f"/RC:{temporal.report_confidence.value[0].upper()}"

        return vector


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SeverityAssessment(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    assessment_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID | None = None
    cvss_vector: CVSSVector
    base_score: float
    temporal_score: float | None = None
    environmental_score: float | None = None
    severity: SeverityLevel
    calculated_at: datetime = Field(default_factory=datetime.utcnow)
    rationale: str = ""
    evidence_ids: list[UUID] = Field(default_factory=list)


class SeverityRule(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    rule_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    vulnerability_type: str
    cvss_vector: CVSSVector
    min_score: float = 0.0
    max_score: float = 10.0
    enabled: bool = True