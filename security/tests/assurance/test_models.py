"""
Tests for assurance models
"""
import pytest
from uuid import uuid4
from datetime import datetime
from security.assurance.models import (
    AssuranceLevel, VerificationStatus, AssuranceMetric, ContinuousAssurance,
    AssurancePolicy, AssuranceVerification
)


class TestAssuranceModels:
    def test_assurance_metric_creation(self):
        metric = AssuranceMetric(
            name="test_metric",
            value=0.85,
            threshold=0.8,
            unit="ratio",
            assurance_level=AssuranceLevel.HIGH,
            description="Test metric",
        )
        assert metric.value == 0.85
        assert metric.threshold == 0.8
        assert metric.assurance_level == AssuranceLevel.HIGH

    def test_continuous_assurance_computation(self):
        ca = ContinuousAssurance(
            target_id=uuid4(),
            overall_assurance=AssuranceLevel.HIGH,
            metrics=[
                AssuranceMetric(
                    name="finding_verification_rate",
                    value=0.9,
                    threshold=0.8,
                    unit="ratio",
                    assurance_level=AssuranceLevel.HIGH,
                    description="Finding verification rate",
                ),
                AssuranceMetric(
                    name="regression_pass_rate",
                    value=0.95,
                    threshold=0.9,
                    unit="ratio",
                    assurance_level=AssuranceLevel.HIGH,
                    description="Regression pass rate",
                ),
            ],
            verified_findings=90,
            total_findings=100,
            verification_rate=0.9,
            regression_tests_passing=180,
            regression_tests_total=200,
            regression_pass_rate=0.9,
            evidence_completeness=0.85,
            attack_coverage=0.7,
            remediation_completeness=0.85,
        )
        
        assert ca.overall_assurance == AssuranceLevel.HIGH
        assert ca.verified_findings == 90
        assert ca.total_findings == 100
        assert ca.verification_rate == 0.9

    def test_assurance_policy(self):
        policy = AssurancePolicy(
            name="High Security Policy",
            description="Policy for critical AI systems",
            target_types=["llm_model", "rag_system"],
            required_metrics=["finding_verification_rate", "regression_pass_rate"],
            minimum_assurance=AssuranceLevel.HIGH,
        )
        assert policy.minimum_assurance == AssuranceLevel.HIGH
        assert "llm_model" in policy.target_types

    def test_assurance_verification_flow(self):
        verification = AssuranceVerification(
            assurance_id=uuid4(),
            policy_id=uuid4(),
            status=VerificationStatus.VERIFIED,
            findings_verified=[uuid4(), uuid4()],
            findings_failed=[uuid4()],
            findings_skipped=[uuid4()],
        )
        
        assert verification.status == VerificationStatus.VERIFIED
        assert len(verification.findings_verified) == 2
        assert len(verification.findings_failed) == 1

    def test_assurance_levels(self):
        assert AssuranceLevel.HIGH.value == "high"
        assert AssuranceLevel.MEDIUM.value == "medium"
        assert AssuranceLevel.LOW.value == "low"
        assert AssuranceLevel.UNKNOWN.value == "unknown"

    def test_verification_status(self):
        assert VerificationStatus.PENDING.value == "pending"
        assert VerificationStatus.VERIFIED.value == "verified"
        assert VerificationStatus.FAILED.value == "failed"
        assert VerificationStatus.SKIPPED.value == "skipped"


class TestAssuranceIntegration:
    """Test assurance integration with other modules"""
    
    def test_assurance_from_findings(self):
        """Assurance should be computable from findings data"""
        # This would be computed by the AssuranceEngine
        metrics = [
            AssuranceMetric(
                name="finding_verification_rate",
                value=0.9,
                threshold=0.8,
                unit="ratio",
                assurance_level=AssuranceLevel.HIGH,
                description="Finding verification rate",
            ),
            AssuranceMetric(
                name="regression_pass_rate",
                value=0.85,
                threshold=0.9,
                unit="ratio",
                assurance_level=AssuranceLevel.MEDIUM,
                description="Regression pass rate",
            ),
        ]
        
        ca = ContinuousAssurance(
            target_id=uuid4(),
            overall_assurance=AssuranceLevel.MEDIUM,
            metrics=metrics,
            verified_findings=85,
            total_findings=100,
            verification_rate=0.85,
            regression_tests_passing=85,
            regression_tests_total=100,
            regression_pass_rate=0.85,
            evidence_completeness=0.8,
            attack_coverage=0.65,
            remediation_completeness=0.8,
        )
        
        assert ca.overall_assurance == AssuranceLevel.MEDIUM
        assert len(ca.metrics) == 2

    def test_policy_target_types(self):
        policy = AssurancePolicy(
            name="Critical Systems Policy",
            description="Policy for critical AI systems",
            target_types=["llm_model", "rag_system", "tool_chain"],
            required_metrics=["finding_verification_rate", "regression_pass_rate", "evidence_completeness"],
            minimum_assurance=AssuranceLevel.HIGH,
        )
        
        assert "llm_model" in policy.target_types
        assert "rag_system" in policy.target_types
        assert len(policy.required_metrics) == 3