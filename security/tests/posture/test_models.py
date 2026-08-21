"""
Tests for the intelligence layer modules
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
from datetime import datetime, timedelta
from security.posture.models import (
    Target, TargetVersion, TargetType, TargetStatus, PostureLevel,
    PostureSnapshot, PostureMetric, RiskHistoryEntry, TargetRiskHistory, PostureComparison
)
from security.change_detection.models import (
    ChangeEvent, ChangeType, ChangeSeverity, ChangeCategory, ChangeSource,
    AssumptionChange, AttackSurfaceChange, ChangeDetectionRule, ChangeDetectionResult
)
from security.correlation.models import (
    FindingCorrelation, CorrelationType, CorrelationSeverity, CorrelationStatus,
    CompositeAttackPath, SystemicRiskAssessment, CorrelationRule, CorrelationResult
)
from security.intelligence.models import (
    RegressionIntelligence, RegressionType, AttackCoverageAnalytics,
    RiskTrendAnalysis, EvidenceLineage, ModelVersionComparison,
    TargetComparison, RemediationVerification, IntelligenceReport,
    IntelligenceType, IntelligencePriority
)
from security.assurance.models import (
    AssuranceLevel, VerificationStatus, AssuranceMetric, ContinuousAssurance,
    AssurancePolicy, AssuranceVerification
)
from security.analytics.models import (
    AnalyticsQuery, AnalyticsResult, DashboardWidget, AnalyticsReport,
    AnalyticsType, TimeGranularity
)
from security.attack_graph.models import AttackGraph, AttackNode, AttackEdge, AttackGraphBuildRequest


class TestPostureModels:
    def test_target_creation(self):
        target = Target(
            name="Test LLM",
            target_type=TargetType.LLM_MODEL,
            version="1.0.0",
            description="Test model"
        )
        assert target.id is not None
        assert target.name == "Test LLM"
        assert target.target_type == TargetType.LLM_MODEL
        assert target.status == TargetStatus.ACTIVE

    def test_target_version(self):
        tv = TargetVersion(
            target_id=uuid4(),
            version="2.0.0",
            configuration_snapshot={"model": "gpt-4"},
            change_summary="Upgraded to GPT-4"
        )
        assert tv.version == "2.0.0"

    def test_posture_snapshot(self):
        snapshot = PostureSnapshot(
            target_id=uuid4(),
            posture_level=PostureLevel.HIGH,
            overall_score=65.0,
            metrics=[
                PostureMetric(name="critical_findings", value=3, unit="count", threshold_critical=5, description="Critical findings count"),
            ],
            critical_findings_count=2,
            high_findings_count=5,
        )
        assert snapshot.posture_level == PostureLevel.HIGH
        assert len(snapshot.metrics) == 1

    def test_risk_history(self):
        history = TargetRiskHistory(
            target_id=uuid4(),
            trend="deteriorating",
            risk_velocity=2.5
        )
        assert history.trend == "deteriorating"
        assert history.risk_velocity == 2.5


class TestChangeDetectionModels:
    def test_change_event(self):
        event = ChangeEvent(
            target_id=uuid4(),
            change_type=ChangeType.MODEL_CHANGE,
            severity=ChangeSeverity.CRITICAL,
            category=ChangeCategory.SECURITY_RELEVANT,
            description="Model upgraded from v1 to v2",
            details={"old": "gpt-3.5", "new": "gpt-4"},
        )
        assert event.change_type == ChangeType.MODEL_CHANGE
        assert event.severity == ChangeSeverity.CRITICAL

    def test_assumption_change(self):
        ac = AssumptionChange(
            change_event_id=uuid4(),
            assumption="Model cannot execute arbitrary code",
            was_valid=True,
            is_valid=False,
            impact="Security boundary potentially bypassed",
            description="Test assumption change",
        )
        assert ac.was_valid is True
        assert ac.is_valid is False

    def test_attack_surface_change(self):
        asc = AttackSurfaceChange(
            target_id=uuid4(),
            change_event_id=uuid4(),
            attack_vector="tool_permission",
            before_coverage=0.0,
            after_coverage=1.0,
            risk_delta=5.0,
        )
        assert asc.risk_delta == 5.0


class TestCorrelationModels:
    def test_finding_correlation(self):
        fid1, fid2 = uuid4(), uuid4()
        corr = FindingCorrelation(
            correlation_type=CorrelationType.CHAINED_VULNERABILITY,
            severity=CorrelationSeverity.HIGH,
            finding_ids=[fid1, fid2],
            description="SQL injection can chain to command injection",
            attack_path=["sql_injection", "command_injection"],
            risk_score=9.0,
        )
        assert len(corr.finding_ids) == 2
        assert corr.severity == CorrelationSeverity.HIGH

    def test_composite_attack_path(self):
        path = CompositeAttackPath(
            name="SQL → Command Injection Chain",
            description="Composite attack path test",
            finding_correlations=[uuid4()],
            attack_steps=[{"attack": "sql_injection"}, {"attack": "command_injection"}],
            overall_risk_score=9.5,
        )
        assert path.overall_risk_score == 9.5


class TestIntelligenceModels:
    def test_regression_intelligence(self):
        ri = RegressionIntelligence(
            target_id=uuid4(),
            execution_a_id=uuid4(),
            execution_b_id=uuid4(),
            finding_id=uuid4(),
            regression_type=RegressionType.REGRESSION,
            what_changed="Finding regressed from fixed to vulnerable",
            why_changed="System prompt changed",
            affected_attack_vectors=["sql_injection"],
            recommended_reruns=["Run SQL injection variants"],
            severity_delta=2.5,
        )
        assert ri.regression_type == RegressionType.REGRESSION

    def test_attack_coverage(self):
        ac = AttackCoverageAnalytics(
            target_id=uuid4(),
            execution_id=uuid4(),
            total_attack_vectors=50,
            covered_vectors=30,
            coverage_percentage=60.0,
            uncovered_vectors=["xss", "ssrf"],
            mitre_tactics_covered=["initial_access", "execution"],
            mitre_tactics_missing=["persistence"],
        )
        assert ac.coverage_percentage == 60.0

    def test_model_version_comparison(self):
        mvc = ModelVersionComparison(
            target_id=uuid4(),
            version_a="1.0",
            version_b="2.0",
            scan_a_id=uuid4(),
            scan_b_id=uuid4(),
            new_vulnerabilities=[uuid4()],
            fixed_vulnerabilities=[uuid4()],
            risk_delta=5.0,
            posture_changed=True,
        )
        assert mvc.posture_changed is True


class TestAssuranceModels:
    def test_assurance_metric(self):
        am = AssuranceMetric(
            name="test_metric",
            value=0.95,
            threshold=0.9,
            unit="ratio",
            assurance_level=AssuranceLevel.HIGH,
            description="Test metric",
        )
        assert am.assurance_level == AssuranceLevel.HIGH

    def test_continuous_assurance(self):
        ca = ContinuousAssurance(
            target_id=uuid4(),
            overall_assurance=AssuranceLevel.HIGH,
            metrics=[
                AssuranceMetric(name="m1", value=0.95, threshold=0.9, unit="ratio", assurance_level=AssuranceLevel.HIGH, description="Test metric"),
            ],
            verified_findings=10,
            total_findings=10,
            verification_rate=1.0,
        )
        assert ca.overall_assurance == AssuranceLevel.HIGH


class TestAnalyticsModels:
    def test_analytics_query(self):
        query = AnalyticsQuery(
            analytics_type=AnalyticsType.ATTACK_COVERAGE,
            target_ids=[uuid4()],
            time_range_start=datetime.utcnow() - timedelta(days=30),
            time_range_end=datetime.utcnow(),
            granularity=TimeGranularity.DAILY,
        )
        assert query.analytics_type == AnalyticsType.ATTACK_COVERAGE

    def test_dashboard_widget(self):
        widget = DashboardWidget(
            name="Attack Coverage",
            description="Dashboard widget for attack coverage",
            analytics_type=AnalyticsType.ATTACK_COVERAGE,
            target_ids=[uuid4()],
        )
        assert widget.analytics_type == AnalyticsType.ATTACK_COVERAGE


class TestAttackGraphModels:
    def test_attack_node(self):
        node = AttackNode(
            type="vulnerability",
            label="SQL Injection",
            description="SQL injection in login",
            risk_score=9.0,
        )
        assert node.type == "vulnerability"
        assert node.risk_score == 9.0

    def test_attack_edge(self):
        edge = AttackEdge(
            source_id=uuid4(),
            target_id=uuid4(),
            relationship="exploits",
            weight=1.0,
        )
        assert edge.relationship == "exploits"

    def test_attack_graph(self):
        graph = AttackGraph(
            target_id=uuid4(),
            nodes=[AttackNode(type="vulnerability", label="test", description="test")],
            edges=[],
        )
        assert len(graph.nodes) == 1
        assert graph.target_id is not None


class TestModelRelationships:
    """Test that models can reference each other correctly"""
    
    def test_target_version_relationship(self):
        target = Target(
            name="Test",
            target_type=TargetType.LLM_MODEL,
            version="1.0"
        )
        version = TargetVersion(
            target_id=target.id,
            version="2.0",
            configuration_snapshot={},
            change_summary="Upgrade"
        )
        assert version.target_id == target.id

    def test_correlation_references_findings(self):
        fid1, fid2 = uuid4(), uuid4()
        corr = FindingCorrelation(
            correlation_type=CorrelationType.CHAINED_VULNERABILITY,
            severity=CorrelationSeverity.HIGH,
            finding_ids=[fid1, fid2],
            description="Chain",
        )
        assert len(corr.finding_ids) == 2
        assert fid1 in corr.finding_ids

    def test_composite_path_references_correlations(self):
        corr_id = uuid4()
        path = CompositeAttackPath(
            name="Test Path",
            description="Test composite path",
            finding_correlations=[corr_id],
            attack_steps=[],
        )
        assert corr_id in path.finding_correlations

    def test_intelligence_references_finding(self):
        finding_id = uuid4()
        ri = RegressionIntelligence(
            target_id=uuid4(),
            execution_a_id=uuid4(),
            execution_b_id=uuid4(),
            finding_id=finding_id,
            regression_type=RegressionType.FIXED,
            what_changed="Fixed",
            why_changed="Patch applied",
        )
        assert ri.finding_id == finding_id

    def test_evidence_lineage_references(self):
        lineage = EvidenceLineage(
            evidence_id=uuid4(),
            finding_id=uuid4(),
            finding_correlations=[uuid4()],
            attack_paths=[uuid4()],
        )
        assert lineage.evidence_id is not None
        assert lineage.finding_id is not None


class TestEnumValues:
    """Test that all enum values are valid"""
    
    def test_target_types(self):
        assert TargetType.LLM_MODEL.value == "llm_model"
        assert TargetType.RAG_SYSTEM.value == "rag_system"
        assert TargetType.TOOL_CHAIN.value == "tool_chain"

    def test_change_types(self):
        assert ChangeType.MODEL_CHANGE.value == "model_change"
        assert ChangeType.TOOL_PERMISSION_CHANGE.value == "tool_permission_change"
        assert ChangeType.RAG_INDEX_CHANGE.value == "rag_index_change"

    def test_correlation_types(self):
        assert CorrelationType.CHAINED_VULNERABILITY.value == "chained_vulnerability"
        assert CorrelationType.COMPOSITE_ATTACK.value == "composite_attack"

    def test_regression_types(self):
        assert RegressionType.FIXED.value == "fixed"
        assert RegressionType.REGRESSION.value == "regression"
        assert RegressionType.NEW.value == "new"

    def test_assurance_levels(self):
        assert AssuranceLevel.HIGH.value == "high"
        assert AssuranceLevel.MEDIUM.value == "medium"
        assert AssuranceLevel.LOW.value == "low"

    def test_posture_levels(self):
        assert PostureLevel.CRITICAL.value == "critical"
        assert PostureLevel.HIGH.value == "high"
        assert PostureLevel.MINIMAL.value == "minimal"

    def test_analytics_types(self):
        assert AnalyticsType.ATTACK_COVERAGE.value == "attack_coverage"
        assert AnalyticsType.RISK_TREND.value == "risk_trend"
        assert AnalyticsType.FINDING_DISTRIBUTION.value == "finding_distribution"