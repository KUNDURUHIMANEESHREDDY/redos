from datetime import datetime
from typing import Any
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field, ConfigDict
from security.database import get_database
from security.models.finding import Finding
import structlog
import networkx as nx

logger = structlog.get_logger()


class AttackNode(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    node_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID | None = None
    type: str
    label: str
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0


class AttackEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    edge_id: UUID = Field(default_factory=uuid4)
    source_id: UUID
    target_id: UUID
    relationship: str
    weight: float = 1.0
    evidence_ids: list[UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackGraph(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    graph_id: UUID = Field(default_factory=uuid4)
    execution_id: UUID
    target_id: str
    nodes: list[AttackNode] = Field(default_factory=list)
    edges: list[AttackEdge] = Field(default_factory=list)
    entry_points: list[UUID] = Field(default_factory=list)
    critical_paths: list[list[UUID]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class AttackGraphService:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.graph_collection = self.db.attack_graphs
        self.findings_collection = self.db.findings
        self.evidence_collection = self.db.evidence

    async def build_graph(self, execution_id: UUID, target_id: str) -> AttackGraph:
        graph = AttackGraph(execution_id=execution_id, target_id=target_id)
        findings = await self._get_findings(execution_id)

        for finding in findings:
            node = AttackNode(
                finding_id=finding.id,
                type="vulnerability",
                label=finding.vulnerability_type.value,
                description=finding.attack_id,
                risk_score=finding.risk_score,
            )
            graph.nodes.append(node)

            if finding.attack_path:
                await self._add_attack_path_to_graph(graph, finding)

        await self._infer_edges(graph, findings)
        await self._find_critical_paths(graph)
        await self._save_graph(graph)

        logger.info("Attack graph built", graph_id=str(graph.graph_id), nodes=len(graph.nodes), edges=len(graph.edges))
        return graph

    async def _add_attack_path_to_graph(self, graph: AttackGraph, finding: Finding) -> None:
        if not finding.attack_path:
            return

        prev_node_id = None
        for step in finding.attack_path.steps:
            node = AttackNode(
                type="attack_step",
                label=step.description,
                description=f"Step {step.step_id}: {step.description}",
                metadata={"technique": step.technique, "tactic": step.tactic},
            )
            graph.nodes.append(node)

            if prev_node_id:
                edge = AttackEdge(
                    source_id=prev_node_id,
                    target_id=node.node_id,
                    relationship="leads_to",
                    evidence_ids=step.evidence_ids,
                )
                graph.edges.append(edge)

            prev_node_id = node.node_id

        vuln_node = next((n for n in graph.nodes if n.finding_id == finding.id), None)
        if vuln_node and prev_node_id:
            edge = AttackEdge(
                source_id=prev_node_id,
                target_id=vuln_node.node_id,
                relationship="exploits",
                evidence_ids=finding.evidence_ids,
            )
            graph.edges.append(edge)

    async def _infer_edges(self, graph: AttackGraph, findings: list[Finding]) -> None:
        for i, node_a in enumerate(graph.nodes):
            for node_b in graph.nodes[i+1:]:
                if node_a.finding_id and node_b.finding_id:
                    finding_a = next((f for f in findings if f.id == node_a.finding_id), None)
                    finding_b = next((f for f in findings if f.id == node_b.finding_id), None)

                    if finding_a and finding_b:
                        if self._can_chain(finding_a, finding_b):
                            edge = AttackEdge(
                                source_id=node_a.node_id,
                                target_id=node_b.node_id,
                                relationship="chains_to",
                                weight=0.7,
                            )
                            graph.edges.append(edge)
                        elif self._shares_evidence(finding_a, finding_b):
                            edge = AttackEdge(
                                source_id=node_a.node_id,
                                target_id=node_b.node_id,
                                relationship="related_to",
                                weight=0.3,
                            )
                            graph.edges.append(edge)

    def _can_chain(self, finding_a: Finding, finding_b: Finding) -> bool:
        chainable = {
            VulnerabilityType.SQL_INJECTION: [VulnerabilityType.COMMAND_INJECTION, VulnerabilityType.PATH_TRAVERSAL],
            VulnerabilityType.XSS: [VulnerabilityType.CSRF, VulnerabilityType.OPEN_REDIRECT],
            VulnerabilityType.BROKEN_AUTH: [VulnerabilityType.BROKEN_ACCESS_CONTROL, VulnerabilityType.SENSITIVE_DATA_EXPOSURE],
        }
        return finding_b.vulnerability_type in chainable.get(finding_a.vulnerability_type, [])

    def _shares_evidence(self, finding_a: Finding, finding_b: Finding) -> bool:
        return bool(set(finding_a.evidence_ids) & set(finding_b.evidence_ids))

    async def _find_critical_paths(self, graph: AttackGraph) -> None:
        if not graph.nodes or not graph.edges:
            return

        nx_graph = nx.DiGraph()
        for node in graph.nodes:
            nx_graph.add_node(str(node.node_id), risk=node.risk_score)
        for edge in graph.edges:
            nx_graph.add_edge(str(edge.source_id), str(edge.target_id), weight=edge.weight)

        try:
            entry_nodes = [str(n.node_id) for n in graph.nodes if n.type == "attack_step"]
            vuln_nodes = [str(n.node_id) for n in graph.nodes if n.type == "vulnerability"]

            for entry in entry_nodes:
                for vuln in vuln_nodes:
                    if nx.has_path(nx_graph, entry, vuln):
                        path = nx.shortest_path(nx_graph, entry, vuln, weight="weight")
                        if len(path) > 1:
                            path_uuids = [UUID(p) for p in path]
                            if path_uuids not in graph.critical_paths:
                                graph.critical_paths.append(path_uuids)
        except Exception as e:
            logger.warning("Failed to find critical paths", error=str(e))

    async def _get_findings(self, execution_id: UUID) -> list[Finding]:
        cursor = self.findings_collection.find({"execution_id": str(execution_id)})
        return [Finding(**doc) async for doc in cursor]

    async def _save_graph(self, graph: AttackGraph) -> None:
        await self.graph_collection.replace_one(
            {"graph_id": str(graph.graph_id)},
            graph.model_dump(),
            upsert=True,
        )

    async def get_graph(self, graph_id: UUID) -> AttackGraph | None:
        doc = await self.graph_collection.find_one({"graph_id": str(graph_id)})
        return AttackGraph(**doc) if doc else None

    async def get_graph_by_execution(self, execution_id: UUID) -> AttackGraph | None:
        doc = await self.graph_collection.find_one({"execution_id": str(execution_id)})
        return AttackGraph(**doc) if doc else None

    async def export_graph(self, graph_id: UUID, format: str = "json") -> dict[str, Any] | str:
        graph = await self.get_graph(graph_id)
        if not graph:
            return {}

        if format == "json":
            return graph.model_dump()
        elif format == "graphml":
            nx_graph = nx.DiGraph()
            for node in graph.nodes:
                nx_graph.add_node(str(node.node_id), **node.model_dump())
            for edge in graph.edges:
                nx_graph.add_edge(str(edge.source_id), str(edge.target_id), **edge.model_dump())
            import io
            buffer = io.StringIO()
            nx.write_graphml(nx_graph, buffer)
            return buffer.getvalue()
        return {}