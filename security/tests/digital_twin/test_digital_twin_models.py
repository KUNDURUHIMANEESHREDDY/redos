"""
Tests for digital_twin models
"""
import pytest
from uuid import uuid4
from datetime import datetime
from security.digital_twin.models import (
    TwinComponent,
    TwinEdge,
    DigitalTwin,
    TwinSnapshot,
    ComponentType,
    ComponentStatus,
    ComponentChange,
    AssumptionImpact,
    DigitalTwinSyncRequest,
)


class TestDigitalTwinModels:
    def test_twin_component_creation(self):
        component = TwinComponent(
            twin_id=uuid4(),
            component_type=ComponentType.MODEL,
            name="gpt-4",
            version="1.0",
            description="GPT-4 model",
            configuration={"provider": "openai", "parameters": {}},
            risk_score=3.5,
        )
        assert component.component_id is not None
        assert component.component_type == ComponentType.MODEL
        assert component.name == "gpt-4"
        assert component.risk_score == 3.5

    def test_twin_component_with_dependencies(self):
        dep1 = uuid4()
        dep2 = uuid4()
        component = TwinComponent(
            twin_id=uuid4(),
            component_type=ComponentType.AGENT,
            name="main_agent",
            version="1.0",
            description="Main agent",
            dependencies=[dep1, dep2],
            dependents=[uuid4()],
        )
        assert len(component.dependencies) == 2
        assert len(component.dependents) == 1

    def test_twin_edge_creation(self):
        source_id = uuid4()
        target_id = uuid4()
        edge = TwinEdge(
            twin_id=uuid4(),
            source_id=source_id,
            target_id=target_id,
            relationship="uses_tool",
            weight=1.0,
        )
        assert edge.source_id == source_id
        assert edge.target_id == target_id
        assert edge.relationship == "uses_tool"

    def test_digital_twin_creation(self):
        target_id = uuid4()
        twin = DigitalTwin(
            target_id=target_id,
            name="Test Twin",
            description="Test digital twin",
        )
        assert twin.twin_id is not None
        assert twin.target_id == target_id
        assert twin.version == "1.0"
        assert twin.sync_status == "pending"

    def test_digital_twin_with_components_and_edges(self):
        target_id = uuid4()
        component = TwinComponent(
            twin_id=uuid4(),
            component_type=ComponentType.MODEL,
            name="model",
            version="1.0",
            description="Test model",
            risk_score=3.0,
        )
        twin = DigitalTwin(
            target_id=target_id,
            name="Test Twin",
            components=[component],
        )
        assert len(twin.components) == 1
        assert twin.components[0].name == "model"

    def test_twin_snapshot(self):
        twin_id = uuid4()
        component_id = uuid4()
        snapshot = TwinSnapshot(
            twin_id=twin_id,
            version="1.0",
            components_snapshot={str(component_id): {"name": "model"}},
            edges_snapshot=[],
        )
        assert snapshot.twin_id == twin_id
        assert snapshot.version == "1.0"

    def test_component_change(self):
        twin_id = uuid4()
        component_id = uuid4()
        change = ComponentChange(
            twin_id=twin_id,
            component_id=component_id,
            change_type="modified",
            before={"version": "1.0", "risk_score": 3.0},
            after={"version": "2.0", "risk_score": 4.0},
            diff={"version": {"old": "1.0", "new": "2.0"}, "risk_score": {"old": 3.0, "new": 4.0}},
            security_impact="Medium-risk component modified: model (risk: 4.0)",
        )
        assert change.change_type == "modified"
        assert "version" in change.diff
        assert change.security_impact is not None

    def test_assumption_impact(self):
        twin_id = uuid4()
        impact = AssumptionImpact(
            twin_id=twin_id,
            assumption="Model cannot execute arbitrary code",
            was_valid=True,
            is_valid=False,
            affected_components=[uuid4()],
            affected_findings=[uuid4()],
            risk_delta=2.5,
            description="Change to model may invalidate assumption: Model cannot execute arbitrary code",
        )
        assert impact.was_valid is True
        assert impact.is_valid is False
        assert impact.risk_delta == 2.5

    def test_digital_twin_sync_request(self):
        request = DigitalTwinSyncRequest(
            target_id=uuid4(),
            force_full_sync=False,
            components_to_sync=["model", "tools"],
        )
        assert request.force_full_sync is False
        assert "model" in request.components_to_sync

    def test_component_type_enum(self):
        assert ComponentType.MODEL.value == "model"
        assert ComponentType.TOOL.value == "tool"
        assert ComponentType.PROMPT.value == "prompt"
        assert ComponentType.RAG.value == "rag"

    def test_component_status_enum(self):
        assert ComponentStatus.ACTIVE.value == "active"
        assert ComponentStatus.DEPRECATED.value == "deprecated"
        assert ComponentStatus.TESTING.value == "testing"