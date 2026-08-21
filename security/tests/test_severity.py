import pytest
from uuid import uuid4
from datetime import datetime
from security.severity.models import (
    SeverityLevel,
    CVSSVersion,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    ImpactLevel as SeverityImpactLevel,
    ExploitCodeMaturity,
    RemediationLevel,
    ReportConfidence,
    CVSSv31BaseMetrics,
    CVSSv31TemporalMetrics,
    CVSSv31EnvironmentalMetrics,
    CVSSVector,
    SeverityAssessment,
    SeverityRule,
)
from security.findings.models import (
    Finding,
    VulnerabilityType,
    SeverityLevel as FindingSeverityLevel,
    ConfidenceLevel,
    ImpactLevel,
    ExploitabilityLevel,
    FindingStatus,
)


def test_severity_level_enum():
    assert SeverityLevel.CRITICAL.value == "critical"
    assert SeverityLevel.HIGH.value == "high"
    assert SeverityLevel.MEDIUM.value == "medium"
    assert SeverityLevel.LOW.value == "low"
    assert SeverityLevel.INFO.value == "info"


def test_cvss_vector_creation():
    base_metrics = CVSSv31BaseMetrics(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=SeverityImpactLevel.HIGH,
        integrity=SeverityImpactLevel.HIGH,
        availability=SeverityImpactLevel.LOW,
    )
    vector = CVSSVector(base_metrics=base_metrics)
    vector_str = vector.to_vector_string()
    assert vector_str.startswith("CVSS:3.1/")
    assert "AV:N" in vector_str
    assert "AC:L" in vector_str
    assert "PR:N" in vector_str
    assert "UI:N" in vector_str
    assert "S:U" in vector_str
    assert "C:H" in vector_str
    assert "I:H" in vector_str
    assert "A:L" in vector_str


def test_severity_assessment_model():
    base_metrics = CVSSv31BaseMetrics(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=SeverityImpactLevel.HIGH,
        integrity=SeverityImpactLevel.HIGH,
        availability=SeverityImpactLevel.LOW,
    )
    vector = CVSSVector(base_metrics=base_metrics)
    
    assessment = SeverityAssessment(
        finding_id=uuid4(),
        cvss_vector=vector,
        base_score=8.5,
        temporal_score=8.0,
        environmental_score=7.5,
        severity=SeverityLevel.HIGH,
        rationale="SQL injection with high impact",
        evidence_ids=[uuid4()],
    )
    assert assessment.base_score == 8.5
    assert assessment.severity == SeverityLevel.HIGH
    assert len(assessment.evidence_ids) == 1


def test_severity_rule_model():
    base_metrics = CVSSv31BaseMetrics(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        confidentiality=SeverityImpactLevel.HIGH,
        integrity=SeverityImpactLevel.HIGH,
        availability=SeverityImpactLevel.HIGH,
    )
    vector = CVSSVector(base_metrics=base_metrics)
    
    rule = SeverityRule(
        name="Test Rule",
        description="Test rule for SQL injection",
        vulnerability_type="sql_injection",
        cvss_vector=vector,
        min_score=7.0,
        max_score=10.0,
    )
    assert rule.vulnerability_type == "sql_injection"
    assert rule.min_score == 7.0
    assert rule.max_score == 10.0


def test_cvss_temporal_metrics():
    temporal = CVSSv31TemporalMetrics(
        exploit_code_maturity=ExploitCodeMaturity.FUNCTIONAL,
        remediation_level=RemediationLevel.OFFICIAL_FIX,
        report_confidence=ReportConfidence.CONFIRMED,
    )
    assert temporal.exploit_code_maturity == ExploitCodeMaturity.FUNCTIONAL
    assert temporal.remediation_level == RemediationLevel.OFFICIAL_FIX


def test_cvss_environmental_metrics():
    environmental = CVSSv31EnvironmentalMetrics(
        confidentiality_requirement=SeverityImpactLevel.HIGH,
        integrity_requirement=SeverityImpactLevel.HIGH,
        availability_requirement=SeverityImpactLevel.LOW,
    )
    assert environmental.confidentiality_requirement == SeverityImpactLevel.HIGH