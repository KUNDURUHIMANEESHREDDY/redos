"""
Integrity Tests - Proving the platform rejects fabricated evidence and accepts real evidence.

Test Categories:
1. MOCK evidence → REJECTED
2. Missing evidence → REJECTED
3. Invalid execution → REJECTED
4. Fabricated finding → REJECTED
5. Real evidence → ACCEPTED
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4, UUID
from datetime import datetime
from security.models.evidence import Evidence, EvidenceType, EvidenceStatus, EvidenceIngestRequest
from security.evidence.service import EvidenceIngestionBoundary, EvidenceNormalizer, EvidenceValidationError
from security.models.finding import Finding, FindingStatus, VulnerabilityType, SeverityLevel, ConfidenceLevel, ImpactLevel, ExploitabilityLevel
from security.findings.service import FindingService
from security.models.severity import CVSSVector, CVSSv31BaseMetrics, AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, ImpactLevel as CVSSImpactLevel
from security.severity.service import SeverityCalculationService
from security.remediation.service import RootCauseAnalyzer


class MockAsyncIterator:
    def __init__(self, items=None):
        self._items = items or []
        self._index = 0
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        if self._index >= len(self._items):
            raise StopAsyncIteration
        item = self._items[self._index]
        self._index += 1
        return item
    
    async def to_list(self, length=None):
        return self._items[:length] if length else self._items


def make_evidence_dict(evidence_id: UUID, execution_id: UUID, etype: EvidenceType, status: str = "normalized") -> dict:
    """Create a valid evidence dict for mocking"""
    base = {
        "_id": str(evidence_id),
        "id": str(evidence_id),
        "execution_id": str(execution_id),
        "type": etype.value,
        "source": "test",
        "timestamp": datetime.utcnow().isoformat(),
        "raw_data": {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
        "normalized_data": {"src_ip": "1.1.1.1"},
        "status": status,
        "validation_errors": [],
        "metadata": {},
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }
    if etype == EvidenceType.LOG_ENTRY:
        base["raw_data"] = {"level": "info", "message": "test"}
        base["normalized_data"] = {"level": "info", "message": "test"}
    elif etype == EvidenceType.API_CALL:
        base["raw_data"] = {"method": "POST", "path": "/api/test"}
        base["normalized_data"] = {"method": "POST", "path": "/api/test"}
    elif etype == EvidenceType.PROCESS_TRACE:
        base["raw_data"] = {"pid": 123, "command": "test"}
        base["normalized_data"] = {"pid": 123, "command": "test"}
    return base


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
    collection.find = MagicMock(return_value=MockAsyncIterator([]))
    return collection


class TestMockEvidenceRejected:
    """MOCK evidence → REJECTED"""

    @pytest.mark.asyncio
    async def test_empty_raw_data_rejected(self, mock_db, mock_evidence_collection):
        mock_db.evidence = mock_evidence_collection
        boundary = EvidenceIngestionBoundary(mock_db)

        request = EvidenceIngestRequest(
            execution_id=uuid4(),
            type=EvidenceType.NETWORK_TRAFFIC,
            source="test",
            raw_data={},  # Empty - should be rejected
        )
        
        with pytest.raises(EvidenceValidationError) as exc_info:
            await boundary.ingest(request)
        
        assert "validation" in str(exc_info.value).lower()
        mock_evidence_collection.insert_one.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_required_fields_rejected(self, mock_db, mock_evidence_collection):
        mock_db.evidence = mock_evidence_collection
        boundary = EvidenceIngestionBoundary(mock_db)

        # Network traffic requires src_ip and dst_ip
        request = EvidenceIngestRequest(
            execution_id=uuid4(),
            type=EvidenceType.NETWORK_TRAFFIC,
            source="test",
            raw_data={"src_ip": "192.168.1.1"},  # Missing dst_ip
        )
        
        with pytest.raises(EvidenceValidationError) as exc_info:
            await boundary.ingest(request)
        
        assert "dst_ip" in str(exc_info.value).lower()
        mock_evidence_collection.insert_one.assert_not_called()

    @pytest.mark.asyncio
    async def test_log_entry_missing_message_rejected(self, mock_db, mock_evidence_collection):
        mock_db.evidence = mock_evidence_collection
        boundary = EvidenceIngestionBoundary(mock_db)

        request = EvidenceIngestRequest(
            execution_id=uuid4(),
            type=EvidenceType.LOG_ENTRY,
            source="test",
            raw_data={"level": "info"},  # Missing message
        )
        
        with pytest.raises(EvidenceValidationError) as exc_info:
            await boundary.ingest(request)
        
        assert "message" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_api_call_missing_method_path_rejected(self, mock_db, mock_evidence_collection):
        mock_db.evidence = mock_evidence_collection
        boundary = EvidenceIngestionBoundary(mock_db)

        request = EvidenceIngestRequest(
            execution_id=uuid4(),
            type=EvidenceType.API_CALL,
            source="test",
            raw_data={"headers": {}},  # Missing method and path
        )
        
        with pytest.raises(EvidenceValidationError) as exc_info:
            await boundary.ingest(request)
        
        assert "method" in str(exc_info.value).lower() or "path" in str(exc_info.value).lower()


class TestMissingEvidenceRejected:
    """Missing evidence → REJECTED"""

    @pytest.mark.asyncio
    async def test_finding_without_evidence_rejected(self, mock_db):
        mock_db.findings = AsyncMock()
        mock_db.evidence = AsyncMock()
        mock_db.evidence.find_one = AsyncMock(return_value=None)
        mock_db.severity_assessments = AsyncMock()
        
        service = FindingService(mock_db)
        
        with pytest.raises(ValueError) as exc_info:
            await service.create_finding(
                target_id="api.example.com",
                attack_id="sql_injection",
                execution_id=uuid4(),
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                evidence_ids=[],  # Empty evidence
            )
        
        assert "at least one evidence" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_finding_with_nonexistent_evidence_rejected(self, mock_db):
        mock_db.findings = AsyncMock()
        mock_db.evidence = AsyncMock()
        mock_db.evidence.find_one = AsyncMock(return_value=None)
        mock_db.severity_assessments = AsyncMock()
        
        service = FindingService(mock_db)
        
        with pytest.raises(ValueError) as exc_info:
            await service.create_finding(
                target_id="api.example.com",
                attack_id="sql_injection",
                execution_id=uuid4(),
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                evidence_ids=[uuid4()],  # Non-existent evidence
            )
        
        assert "does not exist" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_finding_with_invalid_evidence_state_rejected(self, mock_db):
        mock_db.findings = AsyncMock()
        mock_db.evidence = AsyncMock()
        mock_db.severity_assessments = AsyncMock()
        
        # Evidence in RAW state (not normalized)
        evidence_id = uuid4()
        mock_db.evidence.find_one = AsyncMock(return_value={
            "_id": str(evidence_id),
            "id": str(evidence_id),
            "execution_id": str(uuid4()),
            "type": "network_traffic",
            "source": "test",
            "timestamp": datetime.utcnow().isoformat(),
            "raw_data": {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
            "normalized_data": None,
            "status": "raw",
            "validation_errors": [],
            "metadata": {},
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        })
        
        service = FindingService(mock_db)
        
        with pytest.raises(ValueError) as exc_info:
            await service.create_finding(
                target_id="api.example.com",
                attack_id="sql_injection",
                execution_id=uuid4(),
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                evidence_ids=[evidence_id],
            )
        
        assert "valid state" in str(exc_info.value).lower()


class TestFabricatedFindingRejected:
    """Fabricated finding → REJECTED"""

    @pytest.mark.asyncio
    async def test_finding_without_evidence_rejected(self, mock_db):
        """Finding created without evidence references should fail"""
        mock_db.findings = AsyncMock()
        mock_db.evidence = AsyncMock()
        mock_db.evidence.find_one = AsyncMock(return_value=None)
        mock_db.severity_assessments = AsyncMock()
        
        service = FindingService(mock_db)
        
        with pytest.raises(ValueError):
            await service.create_finding(
                target_id="test",
                attack_id="test",
                execution_id=uuid4(),
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                evidence_ids=[],
            )

    @pytest.mark.asyncio
    async def test_finding_with_fake_severity_rejected(self, mock_db):
        """Finding with fabricated severity (not from evidence) should be recalculated"""
        mock_db.findings = AsyncMock()
        mock_db.findings.find = MagicMock(return_value=MockAsyncIterator([]))
        mock_db.findings.insert_one = AsyncMock()
        mock_db.evidence = AsyncMock()
        mock_db.evidence.find_one = AsyncMock(return_value={
            "_id": str(uuid4()),
            "id": str(uuid4()),
            "execution_id": str(uuid4()),
            "type": "network_traffic",
            "source": "test",
            "timestamp": datetime.utcnow().isoformat(),
            "raw_data": {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
            "normalized_data": {"src_ip": "1.1.1.1"},
            "status": "normalized",
            "validation_errors": [],
            "metadata": {},
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        })
        mock_db.severity_assessments = AsyncMock()
        
        service = FindingService(mock_db)
        
        evidence_id = uuid4()
        
        # Create finding - severity will be recalculated by severity service
        finding = await service.create_finding(
            target_id="api.example.com",
            attack_id="sql_injection",
            execution_id=uuid4(),
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            evidence_ids=[evidence_id],
            severity=SeverityLevel.INFO,  # Intentionally wrong - should be recalculated
            confidence=ConfidenceLevel.HIGH,  # High confidence
            impact=ImpactLevel.HIGH,  # High impact
            exploitability=ExploitabilityLevel.HIGH,  # High exploitability
        )
        
        # Severity should be recalculated to HIGH/CRITICAL for SQL injection
        assert finding.severity != SeverityLevel.INFO
        assert finding.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        assert finding.cvss_vector is not None
        assert finding.cvss_score is not None


class TestRealEvidenceAccepted:
    """Real evidence → ACCEPTED"""

    @pytest.mark.asyncio
    async def test_valid_network_evidence_accepted(self, mock_db, mock_evidence_collection):
        mock_db.evidence = mock_evidence_collection
        boundary = EvidenceIngestionBoundary(mock_db)

        request = EvidenceIngestRequest(
            execution_id=uuid4(),
            type=EvidenceType.NETWORK_TRAFFIC,
            source="firewall",
            raw_data={
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.50",
                "src_port": 54321,
                "dst_port": 443,
                "protocol": "TCP",
            },
        )
        
        evidence = await boundary.ingest(request)
        
        assert evidence.id is not None
        assert evidence.type == EvidenceType.NETWORK_TRAFFIC
        assert evidence.status == EvidenceStatus.RAW
        assert evidence.raw_data["src_ip"] == "192.168.1.100"
        mock_evidence_collection.insert_one.assert_called_once()

    @pytest.mark.asyncio
    async def test_valid_log_entry_accepted(self, mock_db, mock_evidence_collection):
        mock_db.evidence = mock_evidence_collection
        boundary = EvidenceIngestionBoundary(mock_db)

        request = EvidenceIngestRequest(
            execution_id=uuid4(),
            type=EvidenceType.LOG_ENTRY,
            source="app-server",
            raw_data={
                "level": "error",
                "message": "SQL syntax error near 'union select'",
                "logger": "security.audit",
            },
        )
        
        evidence = await boundary.ingest(request)
        
        assert evidence.type == EvidenceType.LOG_ENTRY
        assert evidence.raw_data["message"] == "SQL syntax error near 'union select'"

    @pytest.mark.asyncio
    async def test_valid_api_call_accepted(self, mock_db, mock_evidence_collection):
        mock_db.evidence = mock_evidence_collection
        boundary = EvidenceIngestionBoundary(mock_db)

        request = EvidenceIngestRequest(
            execution_id=uuid4(),
            type=EvidenceType.API_CALL,
            source="api-gateway",
            raw_data={
                "method": "POST",
                "path": "/api/login",
                "query_params": {},
                "headers": {"content-type": "application/json"},
                "request_body": '{"username": "admin", "password": "admin\'--"}',
            },
        )
        
        evidence = await boundary.ingest(request)
        
        assert evidence.type == EvidenceType.API_CALL
        assert evidence.raw_data["method"] == "POST"


class TestSeverityCalculationFromEvidence:
    """Verify severity is calculated from evidence, not fabricated"""

    @pytest.mark.asyncio
    async def test_severity_recalculated_not_fabricated(self, mock_db):
        """Finding severity should come from CVSS calculation, not input"""
        mock_db.severity_assessments = AsyncMock()
        mock_db.severity_rules = AsyncMock()
        
        service = SeverityCalculationService(mock_db)
        
        # Finding with LOW severity input but HIGH impact evidence
        finding = Finding(
            target_id="api.example.com",
            attack_id="sql_injection",
            execution_id=uuid4(),
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=SeverityLevel.LOW,  # Wrong - should be recalculated
            confidence=ConfidenceLevel.HIGH,
            impact=ImpactLevel.HIGH,
            exploitability=ExploitabilityLevel.HIGH,
            evidence_ids=[uuid4()],
            risk_score=0.0,
        )
        
        assessment = await service.assess_finding(finding)
        
        # Severity should be recalculated to HIGH/CRITICAL
        assert assessment.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        assert assessment.base_score >= 7.0
        assert assessment.evidence_ids == finding.evidence_ids
        assert assessment.rationale != ""


class TestEndToEndTraceability:
    """Test complete traceability chain"""

    @pytest.mark.asyncio
    async def test_root_cause_uses_evidence(self, mock_db):
        """Verify root cause analyzer uses actual evidence"""
        mock_cursor = MockAsyncIterator([
            {
                "_id": str(uuid4()),
                "id": str(uuid4()),
                "execution_id": str(uuid4()),
                "type": "api_call",
                "source": "test",
                "timestamp": datetime.utcnow().isoformat(),
                "raw_data": {"method": "POST", "path": "/api/test", "request_body": "test"},
                "normalized_data": {"method": "POST", "path": "/api/test", "request_body": "test"},
                "status": "normalized",
                "validation_errors": [],
                "metadata": {},
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
            },
        ])
        mock_db.evidence = AsyncMock()
        mock_db.evidence.find = MagicMock(return_value=mock_cursor)
        
        analyzer = RootCauseAnalyzer(mock_db)
        
        finding = Finding(
            target_id="api.example.com",
            attack_id="sql_injection",
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
        
        assert cause.evidence_ids == finding.evidence_ids
        assert "concatenated" in cause.description.lower() or "parameterization" in cause.description.lower()
        assert cause.category == "input_validation"


# Run a quick sanity check
if __name__ == "__main__":
    pytest.main([__file__, "-v"])