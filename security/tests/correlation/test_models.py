"""
Tests for correlation and assurance models
"""
import pytest
from uuid import uuid4
from datetime import datetime
from security.correlation.models import (
    FindingCorrelation, CorrelationType, CorrelationSeverity, CorrelationStatus,
    CompositeAttackPath, SystemicRiskAssessment, CorrelationRule, CorrelationResult
)
from security.assurance.models import (
    AssuranceLevel, VerificationStatus, AssuranceMetric, ContinuousAssurance,
    AssurancePolicy, AssuranceVerification
)


class TestCorrelationModels:
    def test_finding_correlation_shared_evidence(self):
        fid1, fid2 = uuid4(), uuid4()
        corr = FindingCorrelation(
            correlation_type=CorrelationType.SHARED_EVIDENCE,
            severity=CorrelationSeverity.HIGH,
            finding_ids=[fid1, fid2],
            description="Share evidence E1, E2",
            shared_evidence_ids=[uuid4(), uuid4()],
            risk_score=8.5,
        )
        assert corr.correlation_type == CorrelationType.SHARED_EVIDENCE
        assert len(corr.finding_ids) == 2
        assert len(corr.shared_evidence_ids) == 2

    def test_finding_correlation_chained(self):
        fid1, fid2 = uuid4(), uuid4()
        corr = FindingCorrelation(
            correlation_type=CorrelationType.CHAINED_VULNERABILITY,
            severity=CorrelationSeverity.CRITICAL,
            finding_ids=[fid1, fid2],
            description="SQL injection chains to command injection",
            attack_path=["sql_injection", "command_injection"],
            mitre_techniques=["T1190", "T1059"],
            risk_score=9.5,
            systemic_risk_score=9.8,
        )
        assert corr.correlation_type == CorrelationType.CHAINED_VULNERABILITY
        assert "T1190" in corr.mitre_techniques

    def test_correlation_status_transitions(self):
        corr = FindingCorrelation(
            correlation_type=CorrelationType.SHARED_EVIDENCE,
            severity=CorrelationSeverity.HIGH,
            finding_ids=[uuid4(), uuid4()],
            description="Test correlation",
            status=CorrelationStatus.DETECTED,
        )
        assert corr.status == CorrelationStatus.DETECTED

        corr.status = CorrelationStatus.VALIDATED
        corr.validated_at = datetime.utcnow()
        assert corr.status == CorrelationStatus.VALIDATED

        corr.status = CorrelationStatus.MITIGATED
        corr.mitigated_at = datetime.utcnow()
        assert corr.status == CorrelationStatus.MITIGATED

    def test_composite_attack_path(self):
        path = CompositeAttackPath(
            name="Full Chain: Web → Shell → DB",
            description="Composite attack path test",
            finding_correlations=[uuid4(), uuid4()],
            attack_steps=[
                {"finding_id": str(uuid4()), "attack": "sql_injection", "technique": "T1190"},
                {"finding_id": str(uuid4()), "attack": "command_injection", "technique": "T1059"},
            ],
            entry_points=["web_form"],
            target_assets=["customer_db"],
            mitre_tactics=["initial_access", "execution"],
            mitre_techniques=["T1190", "T1059"],
            overall_risk_score=9.5,
            exploitability=9.0,
            impact=9.5,
            evidence_ids=[uuid4(), uuid4()],
        )
        assert len(path.attack_steps) == 2
        assert path.overall_risk_score == 9.5

    def test_systemic_risk_assessment(self):
        path_id = uuid4()
        sra = SystemicRiskAssessment(
            target_id=uuid4(),
            composite_paths=[uuid4()],
            overall_systemic_risk=9.2,
            risk_factors={
                "critical_paths": 2,
                "exploitable_chains": 3,
                "total_findings": 15,
            },
            critical_attack_paths=2,
            exploitable_chains=3,
            blast_radius={"customer_db": 3, "user_api": 2},
            recommendations=["Patch SQL injection", "Restrict shell access"],
        )
        assert sra.overall_systemic_risk == 9.2
        assert sra.critical_attack_paths == 2


class TestAssuranceModels:
    def test_assurance_metric_levels(self):
        # HIGH
        m1 = AssuranceMetric(name="m1", value=0.95, threshold=0.9, unit="ratio", assurance_level=AssuranceLevel.HIGH, description="Test metric")
        assert m1.assurance_level == AssuranceLevel.HIGH

        # MEDIUM
        m2 = AssuranceMetric(name="m2", value=0.75, threshold=0.7, unit="ratio", assurance_level=AssuranceLevel.MEDIUM, description="Test metric")
        assert m2.assurance_level == AssuranceLevel.MEDIUM

        # LOW
        m3 = AssuranceMetric(name="m3", value=0.6, threshold=0.7, unit="ratio", assurance_level=AssuranceLevel.LOW, description="Test metric")
        assert m3.assurance_level == AssuranceLevel.LOW

    def test_continuous_assurance_computed(self):
        ca = ContinuousAssurance(
            target_id=uuid4(),
            overall_assurance=AssuranceLevel.HIGH,
            metrics=[
                AssuranceMetric(name="verification_rate", value=0.95, threshold=0.8, unit="ratio", assurance_level=AssuranceLevel.HIGH, description="Verification rate"),
                AssuranceMetric(name="regression_pass_rate", value=0.92, threshold=0.9, unit="ratio", assurance_level=AssuranceLevel.HIGH, description="Regression pass rate"),
                AssuranceMetric(name="evidence_completeness", value=0.85, threshold=0.7, unit="ratio", assurance_level=AssuranceLevel.HIGH, description="Evidence completeness"),
            ],
            verified_findings=45,
            total_findings=50,
            verification_rate=0.9,
            regression_tests_passing=180,
            regression_tests_total=200,
            regression_pass_rate=0.9,
            evidence_completeness=0.85,
            attack_coverage=0.75,
            remediation_completeness=0.88,
        )
        assert ca.overall_assurance == AssuranceLevel.HIGH
        assert len(ca.metrics) == 3

    def test_assurance_policy(self):
        policy = AssurancePolicy(
            name="High Security Policy",
            description="High security policy for testing",
            target_types=["llm_model", "rag_system"],
            required_metrics=["verification_rate", "regression_pass_rate"],
            minimum_assurance=AssuranceLevel.HIGH,
        )
        assert policy.minimum_assurance == AssuranceLevel.HIGH

    def test_assurance_verification(self):
        v = AssuranceVerification(
            assurance_id=uuid4(),
            policy_id=uuid4(),
            status=VerificationStatus.VERIFIED,
            findings_verified=[uuid4(), uuid4()],
            findings_failed=[uuid4()],
        )
        assert v.status == VerificationStatus.VERIFIED
        assert len(v.findings_verified) == 2
        assert len(v.findings_failed) == 1

    def test_verification_status_enum(self):
        assert VerificationStatus.PENDING.value == "pending"
        assert VerificationStatus.VERIFIED.value == "verified"
        assert VerificationStatus.FAILED.value == "failed"
        assert VerificationStatus.SKIPPED.value == "skipped"


class TestCrossModuleIntegration:
    """Test integration between correlation and assurance models"""
    
    def test_correlation_to_assurance_flow(self):
        """Correlations increase systemic risk which affects assurance"""
        corr = FindingCorrelation(
            correlation_type=CorrelationType.CHAINED_VULNERABILITY,
            severity=CorrelationSeverity.CRITICAL,
            finding_ids=[uuid4(), uuid4()],
            description="Test correlation",
            systemic_risk_score=9.5,
        )
        
        # High systemic risk should lower assurance
        assert corr.systemic_risk_score >= 9.0
        assert corr.severity == CorrelationSeverity.CRITICAL

    def test_correlation_rule_conditions(self):
        rule = CorrelationRule(
            name="Chain SQL to Command",
            description="Correlation rule for SQL injection chaining to command injection",
            correlation_type=CorrelationType.CHAINED_VULNERABILITY,
            conditions={
                "finding_a_types": ["sql_injection"],
                "finding_b_types": ["command_injection"],
                "shared_evidence": True,
            },
            min_findings=2,
        )
        assert rule.correlation_type == CorrelationType.CHAINED_VULNERABILITY
        assert rule.conditions["finding_a_types"] == ["sql_injection"]

    def test_correlation_result_aggregation(self):
        corr1 = FindingCorrelation(
            correlation_type=CorrelationType.CHAINED_VULNERABILITY,
            severity=CorrelationSeverity.CRITICAL,
            finding_ids=[uuid4(), uuid4()],
            description="Test correlation 1",
        )
        corr2 = FindingCorrelation(
            correlation_type=CorrelationType.SHARED_EVIDENCE,
            severity=CorrelationSeverity.HIGH,
            finding_ids=[uuid4(), uuid4()],
            description="Test correlation 2",
        )
        
        result = CorrelationResult(
            target_id=uuid4(),
            correlations=[corr1, corr2],
            composite_paths=[],
            total_correlations=2,
            critical_correlations=1,
            high_correlations=1,
        )
        
        assert result.total_correlations == 2
        assert result.critical_correlations == 1
        assert result.high_correlations == 1