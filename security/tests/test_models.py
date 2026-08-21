import pytest
from uuid import uuid4
from datetime import datetime
from security.evidence.models import Evidence, EvidenceType, EvidenceStatus
from security.findings.models import (
    Finding,
    VulnerabilityType,
    SeverityLevel,
    ConfidenceLevel,
    ImpactLevel,
    ExploitabilityLevel,
    FindingStatus,
    AttackPath,
    AttackStep,
    RootCause,
    RemediationAction,
    RegressionTest,
)


def test_evidence_model():
    evidence = Evidence(
        execution_id=uuid4(),
        type=EvidenceType.NETWORK_TRAFFIC,
        source="test",
        timestamp=datetime.utcnow(),
        raw_data={"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1"},
    )
    assert evidence.id is not None
    assert evidence.status == EvidenceStatus.RAW
    assert evidence.type == EvidenceType.NETWORK_TRAFFIC


def test_finding_model():
    finding = Finding(
        target="api.example.com",
        attack="SQL Injection in login",
        execution_id=uuid4(),
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        impact=ImpactLevel.HIGH,
        exploitability=ExploitabilityLevel.HIGH,
        evidence=[],
        risk_score=8.5,
    )
    assert finding.id is not None
    assert finding.vulnerability_type == VulnerabilityType.SQL_INJECTION
    assert finding.severity == SeverityLevel.HIGH
    assert finding.status == FindingStatus.OPEN


def test_attack_path_model():
    step = AttackStep(
        step_id=1,
        description="Send malicious payload",
        evidence_ids=[uuid4()],
        technique="T1190",
        tactic="Initial Access",
    )
    path = AttackPath(
        name="SQL Injection Path",
        description="Exploit path for SQL injection",
        steps=[step],
        entry_point="/login",
        target="database",
    )
    assert len(path.steps) == 1
    assert path.steps[0].technique == "T1190"


def test_root_cause_model():
    cause = RootCause(
        description="User input not validated",
        category="input_validation",
        evidence_ids=[uuid4()],
        contributing_factors=["No parameterized queries", "No input sanitization"],
        code_location="auth/login.py:42",
    )
    assert cause.category == "input_validation"
    assert len(cause.contributing_factors) == 2


def test_remediation_action_model():
    action = RemediationAction(
        title="Use parameterized queries",
        description="Replace string concatenation with prepared statements",
        priority=1,
        effort="low",
        category="code_change",
        verification_steps=["Test with SQL injection payloads", "Verify query execution"],
    )
    assert action.priority == 1
    assert action.category == "code_change"


def test_regression_test_model():
    test = RegressionTest(
        name="SQL Injection Regression Test",
        description="Verify SQL injection is fixed",
        input_data={"payload": "' OR '1'='1", "endpoint": "/api/login"},
        expected_outcome={"vulnerability_present": False},
        validation_criteria=["No database errors in response", "No unauthorized data returned"],
    )
    assert test.test_type == "automated"
    assert test.input_data["payload"] == "' OR '1'='1"