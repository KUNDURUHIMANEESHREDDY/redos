import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from datetime import datetime
from security.models.evidence import Evidence, EvidenceType, EvidenceStatus, EvidenceIngestRequest
from security.evidence.service import EvidenceIngestionBoundary, EvidenceNormalizer
from security.models.finding import Finding, VulnerabilityType, SeverityLevel, ConfidenceLevel, ImpactLevel, ExploitabilityLevel, FindingStatus
from security.remediation.service import RemediationService, RootCauseAnalyzer
from security.models.analysis import AnalysisStage, AnalysisStatus, StageResult, AnalysisPipeline
from security.models.severity import CVSSVector, CVSSv31BaseMetrics, AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, ImpactLevel as CVSSImpactLevel


@pytest.fixture
def mock_db():
    return AsyncMock()


@pytest.fixture
def mock_evidence_collection():
    collection = AsyncMock()
    collection.insert_one = AsyncMock()
    collection.insert_many = AsyncMock()
    collection.find_one = AsyncMock()
    collection.find_one_and_update = AsyncMock()
    collection.find = MagicMock(return_value=AsyncMock(__aiter__=AsyncMock(return_value=iter([]))))
    return collection


class TestEvidenceIngestionBoundary:
    @pytest.mark.asyncio
    async def test_ingest_evidence(self, mock_db, mock_evidence_collection):
        mock_db.evidence = mock_evidence_collection
        boundary = EvidenceIngestionBoundary(mock_db)

        execution_id = uuid4()
        request = EvidenceIngestRequest(
            execution_id=execution_id,
            type=EvidenceType.NETWORK_TRAFFIC,
            source="test",
            raw_data={"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1"},
        )
        evidence = await boundary.ingest(request)

        assert evidence.execution_id == execution_id
        assert evidence.type == EvidenceType.NETWORK_TRAFFIC
        assert evidence.status == EvidenceStatus.RAW
        mock_evidence_collection.insert_one.assert_called_once()

    @pytest.mark.asyncio
    async def test_ingest_evidence_missing_required_fields(self, mock_db, mock_evidence_collection):
        mock_db.evidence = mock_evidence_collection
        boundary = EvidenceIngestionBoundary(mock_db)

        execution_id = uuid4()
        request = EvidenceIngestRequest(
            execution_id=execution_id,
            type=EvidenceType.NETWORK_TRAFFIC,
            source="test",
            raw_data={},
        )
        with pytest.raises(Exception) as exc_info:
            await boundary.ingest(request)
        assert "validation" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_ingest_batch(self, mock_db, mock_evidence_collection):
        mock_db.evidence = mock_evidence_collection
        boundary = EvidenceIngestionBoundary(mock_db)

        execution_id = uuid4()
        requests = [
            EvidenceIngestRequest(
                execution_id=execution_id,
                type=EvidenceType.NETWORK_TRAFFIC,
                source="test",
                raw_data={"src_ip": "1.1.1.1", "dst_ip": "10.0.0.1"},
            ),
            EvidenceIngestRequest(
                execution_id=execution_id,
                type=EvidenceType.LOG_ENTRY,
                source="test",
                raw_data={"message": "test", "level": "info"},
            ),
        ]
        evidence_list = await boundary.ingest_batch(requests)

        assert len(evidence_list) == 2
        mock_evidence_collection.insert_many.assert_called_once()


class TestEvidenceNormalizer:
    @pytest.mark.asyncio
    async def test_normalize_network_evidence(self, mock_db, mock_evidence_collection):
        mock_db.evidence = mock_evidence_collection
        normalizer = EvidenceNormalizer(mock_db)

        evidence_id = uuid4()
        mock_evidence_collection.find_one.return_value = {
            "_id": str(evidence_id),
            "execution_id": str(uuid4()),
            "type": "network_traffic",
            "source": "test",
            "timestamp": datetime.utcnow().isoformat(),
            "raw_data": {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 443},
            "status": "raw",
        }
        mock_evidence_collection.find_one_and_update.return_value = {
            "_id": str(evidence_id),
            "execution_id": str(uuid4()),
            "type": "network_traffic",
            "source": "test",
            "timestamp": datetime.utcnow().isoformat(),
            "raw_data": {"src_ip": "192.168.1.1"},
            "normalized_data": {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 443},
            "status": "normalized",
        }

        result = await normalizer.normalize(evidence_id)
        assert result is not None
        assert result.status == EvidenceStatus.NORMALIZED
        assert result.normalized_data["src_ip"] == "192.168.1.1"


class TestRemediationService:
    @pytest.mark.asyncio
    async def test_generate_remediation_sql_injection(self, mock_db):
        mock_db.remediation_templates = AsyncMock()
        service = RemediationService(mock_db)

        finding = Finding(
            target_id="api.example.com",
            attack_id="SQL Injection",
            execution_id=uuid4(),
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
            impact=ImpactLevel.HIGH,
            exploitability=ExploitabilityLevel.HIGH,
            evidence_ids=[],
            risk_score=8.5,
        )

        actions = await service.generate_remediation(finding)
        assert len(actions) >= 2
        assert any("parameterized" in a.title.lower() for a in actions)


class TestRootCauseAnalyzer:
    @pytest.mark.asyncio
    async def test_analyze_sql_injection(self, mock_db):
        class MockAsyncIterator:
            def __init__(self):
                self._items = []
                self._index = 0
            
            def __aiter__(self):
                return self
            
            async def __anext__(self):
                if self._index >= len(self._items):
                    raise StopAsyncIteration
                item = self._items[self._index]
                self._index += 1
                return item
        
        mock_cursor = MockAsyncIterator()
        mock_db.evidence = AsyncMock()
        mock_db.evidence.find = MagicMock(return_value=mock_cursor)
        analyzer = RootCauseAnalyzer(mock_db)

        finding = Finding(
            target_id="api.example.com",
            attack_id="SQL Injection",
            execution_id=uuid4(),
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
            impact=ImpactLevel.HIGH,
            exploitability=ExploitabilityLevel.HIGH,
            evidence_ids=[uuid4()],
            risk_score=8.5,
        )

        cause = await analyzer.analyze(finding)
        assert "parameterization" in cause.description.lower() or "concatenated" in cause.description.lower()
        assert cause.category == "input_validation"


class TestAnalysisPipeline:
    @pytest.mark.asyncio
    async def test_pipeline_creation(self, mock_db):
        mock_db.analysis_pipelines = AsyncMock()
        mock_db.evidence = AsyncMock()
        mock_db.findings = AsyncMock()
        mock_db.security_rules = AsyncMock()
        mock_db.behavior_patterns = AsyncMock()

        from security.analysis.service import AnalysisPipelineService
        service = AnalysisPipelineService(mock_db)

        execution_id = uuid4()
        pipeline = await service.create_pipeline(execution_id, "api.example.com")

        assert pipeline.execution_id == execution_id
        assert pipeline.target_id == "api.example.com"
        assert pipeline.overall_status == AnalysisStatus.PENDING


class TestSeverityCalculation:
    @pytest.mark.asyncio
    async def test_calculate_base_score(self, mock_db):
        from security.severity.service import SeverityCalculationService
        service = SeverityCalculationService(mock_db)

        metrics = CVSSv31BaseMetrics(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=CVSSImpactLevel.HIGH,
            integrity=CVSSImpactLevel.HIGH,
            availability=CVSSImpactLevel.LOW,
        )
        score = service.calculate_base_score(metrics)
        assert score >= 7.0
        assert score <= 10.0

    @pytest.mark.asyncio
    async def test_score_to_severity(self, mock_db):
        from security.severity.service import SeverityCalculationService
        service = SeverityCalculationService(mock_db)

        assert service.score_to_severity(9.5) == SeverityLevel.CRITICAL
        assert service.score_to_severity(7.5) == SeverityLevel.HIGH
        assert service.score_to_severity(5.0) == SeverityLevel.MEDIUM
        assert service.score_to_severity(2.0) == SeverityLevel.LOW
        assert service.score_to_severity(0.0) == SeverityLevel.INFO


class TestFindingLifecycle:
    @pytest.mark.asyncio
    async def test_valid_status_transitions(self):
        from security.models.finding import can_transition, FindingStatus

        assert can_transition(FindingStatus.NEW, FindingStatus.CONFIRMED) is True
        assert can_transition(FindingStatus.NEW, FindingStatus.FALSE_POSITIVE) is True
        assert can_transition(FindingStatus.NEW, FindingStatus.REMEDIATED) is False

        assert can_transition(FindingStatus.CONFIRMED, FindingStatus.REMEDIATED) is True
        assert can_transition(FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE) is True
        assert can_transition(FindingStatus.CONFIRMED, FindingStatus.NEW) is False

        assert can_transition(FindingStatus.REMEDIATED, FindingStatus.REGRESSION_TESTED) is True
        assert can_transition(FindingStatus.REMEDIATED, FindingStatus.CONFIRMED) is True

        assert can_transition(FindingStatus.REGRESSION_TESTED, FindingStatus.FIXED) is True
        assert can_transition(FindingStatus.REGRESSION_TESTED, FindingStatus.REMEDIATED) is True
        assert can_transition(FindingStatus.REGRESSION_TESTED, FindingStatus.CONFIRMED) is False

        assert can_transition(FindingStatus.FIXED, FindingStatus.FIXED) is False