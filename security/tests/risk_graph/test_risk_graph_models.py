"""
Tests for risk_graph models
"""
import pytest
from uuid import uuid4
from datetime import datetime
from security.risk_graph.models import (
    GraphNode,
    GraphEdge,
    RiskGraph,
    NodeType,
    EdgeType,
    RiskLevel,
    RiskGraphBuildRequest,
    RiskPropagationEvent,
    BlastRadiusAssessment,
)


class TestRiskGraphModels:
    def test_graph_node_creation(self):
        node = GraphNode(
            graph_id=uuid4(),
            node_type=NodeType.VULNERABILITY,
            label="SQL Injection",
            description="SQL injection in login",
            risk_level=RiskLevel.CRITICAL,
            risk_score=9.5,
        )
        assert node.node_id is not None
        assert node.node_type == NodeType.VULNERABILITY
        assert node.risk_level == RiskLevel.CRITICAL
        assert node.risk_score == 9.5

    def test_graph_node_with_finding(self):
        finding_id = uuid4()
        node = GraphNode(
            graph_id=uuid4(),
            node_type=NodeType.VULNERABILITY,
            label="SQL Injection",
            description="SQL injection in login",
            finding_id=finding_id,
            risk_score=9.0,
        )
        assert node.finding_id == finding_id

    def test_graph_edge_creation(self):
        source_id = uuid4()
        target_id = uuid4()
        edge = GraphEdge(
            graph_id=uuid4(),
            source_id=source_id,
            target_id=target_id,
            edge_type=EdgeType.EXPLOITS,
            weight=1.0,
            evidence_ids=[uuid4()],
        )
        assert edge.source_id == source_id
        assert edge.target_id == target_id
        assert edge.edge_type == EdgeType.EXPLOITS

    def test_risk_graph_creation(self):
        target_id = uuid4()
        graph = RiskGraph(
            target_id=target_id,
            name="Test Risk Graph",
            description="Test graph",
        )
        assert graph.graph_id is not None
        assert graph.target_id == target_id
        assert graph.risk_score == 0.0
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_risk_graph_with_nodes_and_edges(self):
        target_id = uuid4()
        node1 = GraphNode(
            graph_id=uuid4(),
            node_type=NodeType.VULNERABILITY,
            label="SQL Injection",
            description="SQL injection",
            risk_score=9.0,
        )
        node2 = GraphNode(
            graph_id=uuid4(),
            node_type=NodeType.TOOL,
            label="Database Tool",
            description="Database tool",
            risk_score=5.0,
        )
        edge = GraphEdge(
            graph_id=uuid4(),
            source_id=node1.node_id,
            target_id=node2.node_id,
            edge_type=EdgeType.EXPLOITS,
            weight=1.0,
        )
        graph = RiskGraph(
            target_id=uuid4(),
            name="Test Graph",
            nodes=[node1, node2],
            edges=[edge],
            risk_score=9.0,
        )
        assert len(graph.nodes) == 2
        assert len(graph.edges) == 1
        assert graph.risk_score == 9.0

    def test_risk_propagation_event(self):
        graph_id = uuid4()
        source_id = uuid4()
        event = RiskPropagationEvent(
            graph_id=graph_id,
            source_node_id=source_id,
            affected_node_ids=[uuid4(), uuid4()],
            trigger_type="permission_change",
            trigger_details={"tool": "database", "permission": "write"},
            risk_delta=3.5,
            propagated=True,
        )
        assert event.trigger_type == "permission_change"
        assert event.risk_delta == 3.5
        assert event.propagated is True

    def test_blast_radius_assessment(self):
        graph_id = uuid4()
        source_id = uuid4()
        assessment = BlastRadiusAssessment(
            graph_id=graph_id,
            source_node_id=source_id,
            affected_nodes=[uuid4(), uuid4(), uuid4()],
            blast_radius_score=7.5,
            max_depth=3,
            affected_assets=["database", "api"],
            affected_data_stores=["customer_db"],
            critical_paths=[[uuid4(), uuid4()], [uuid4(), uuid4()]],
        )
        assert len(assessment.affected_nodes) == 3
        assert assessment.blast_radius_score == 7.5
        assert assessment.max_depth == 3

    def test_risk_graph_build_request(self):
        request = RiskGraphBuildRequest(
            target_id=uuid4(),
            execution_id=uuid4(),
            include_findings=True,
            include_assets=True,
            include_permissions=True,
            include_change_history=True,
        )
        assert request.include_findings is True
        assert request.include_assets is True

    def test_node_type_enum(self):
        assert NodeType.MODEL.value == "model"
        assert NodeType.TOOL.value == "tool"
        assert NodeType.VULNERABILITY.value == "vulnerability"
        assert NodeType.ENTRY_POINT.value == "entry_point"

    def test_edge_type_enum(self):
        assert EdgeType.EXPLOITS.value == "exploits"
        assert EdgeType.CHAINS_TO.value == "chains_to"
        assert EdgeType.LEADS_TO.value == "leads_to"
        assert EdgeType.READS.value == "reads"
        assert EdgeType.WRITES.value == "writes"

    def test_risk_level_enum(self):
        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.INFO.value == "info"