from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
import networkx as nx
from security.database import get_database
from security.risk_graph.models import (
    GraphNode,
    GraphEdge,
    RiskGraph,
    NodeType,
    EdgeType,
    RiskLevel,
    EdgeType,
    RiskPropagationEvent,
    BlastRadiusAssessment,
    RiskGraphBuildRequest,
)
from security.posture.models import Target
from security.findings.models import Finding, FindingStatus
from security.evidence.models import Evidence
from security.attack_graph.service import AttackGraphService
from security.change_detection.service import ChangeDetector
import structlog

logger = structlog.get_logger()


class RiskGraphEngine:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.graphs_collection = self.db.risk_graphs
        self.nodes_collection = self.db.risk_graph_nodes
        self.edges_collection = self.db.risk_graph_edges
        self.propagation_events_collection = self.db.risk_propagation_events
        self.blast_radius_collection = self.db.blast_radius_assessments
        self.targets_collection = self.db.targets
        self.findings_collection = self.db.findings
        self.evidence_collection = self.db.evidence
        self.attack_graph_service = AttackGraphService(db)
        self.change_detector = ChangeDetector(db)

    async def build_risk_graph(self, request: RiskGraphBuildRequest) -> RiskGraph:
        target = await self._get_target(request.target_id)
        if not target:
            raise ValueError(f"Target {request.target_id} not found")

        existing = await self.graphs_collection.find_one({"target_id": str(request.target_id)})
        if existing:
            await self.graphs_collection.delete_one({"graph_id": existing["graph_id"]})
            await self.nodes_collection.delete_many({"graph_id": existing["graph_id"]})
            await self.edges_collection.delete_many({"graph_id": existing["graph_id"]})

        graph = RiskGraph(
            target_id=request.target_id,
            name=f"Risk Graph for {target.name}",
            description=f"Risk graph for {target.name} ({target.target_type.value})",
        )
        await self.graphs_collection.insert_one(graph.model_dump())

        await self._add_target_nodes(graph, target)
        
        if request.include_findings:
            await self._add_finding_nodes(graph, request.target_id)
        
        if request.include_assets:
            await self._add_asset_nodes(graph, target)
        
        if request.include_permissions:
            await self._add_permission_nodes(graph, target)

        if request.include_change_history:
            await self._add_change_history_nodes(graph, request.target_id)

        await self._add_edges_from_attack_graph(graph, request.target_id)
        await self._add_permission_edges(graph, target)
        await self._add_data_flow_edges(graph, target)

        await self._compute_risk_scores(graph)
        await self._find_critical_paths(graph)
        await self._identify_entry_points(graph)

        graph.updated_at = datetime.utcnow()
        await self.graphs_collection.replace_one({"graph_id": str(graph.graph_id)}, graph.model_dump())

        logger.info("Risk graph built", graph_id=str(graph.graph_id), nodes=len(graph.nodes), edges=len(graph.edges))
        return graph

    async def _add_target_nodes(self, graph: RiskGraph, target: Any) -> None:
        node = GraphNode(
            graph_id=graph.graph_id,
            node_type=NodeType(target.target_type.value),
            label=target.name,
            description=f"{target.target_type.value}: {target.name} (v{target.version})",
            target_id=target.id,
            risk_level=RiskLevel.INFO,
            properties={"version": target.version, "status": target.status.value},
        )
        graph.nodes.append(node)
        await self.nodes_collection.insert_one(node.model_dump())

    async def _add_finding_nodes(self, graph: RiskGraph, target_id: UUID) -> None:
        findings = await self._get_findings_for_target(target_id)
        for finding in findings:
            if finding.status in (FindingStatus.FIXED, FindingStatus.VERIFIED, FindingStatus.FALSE_POSITIVE, FindingStatus.WONT_FIX):
                continue
            node = GraphNode(
                graph_id=graph.graph_id,
                node_type=NodeType.VULNERABILITY,
                label=finding.vulnerability_type.value,
                description=f"{finding.attack_id}: {finding.vulnerability_type.value}",
                target_id=finding.target_id,
                finding_id=finding.id,
                execution_id=finding.execution_id,
                risk_level=self._severity_to_risk_level(finding.severity),
                risk_score=finding.risk_score,
                properties={
                    "vulnerability_type": finding.vulnerability_type.value,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "attack_id": finding.attack_id,
                    "evidence_ids": [str(e) for e in finding.evidence_ids],
                },
            )
            graph.nodes.append(node)
            await self.nodes_collection.insert_one(node.model_dump())

    async def _add_asset_nodes(self, graph: RiskGraph, target: Any) -> None:
        config = target.configuration
        
        if "tools" in config:
            for tool in config["tools"]:
                node = GraphNode(
                    graph_id=graph.graph_id,
                    node_type=NodeType.TOOL,
                    label=tool.get("name", "unknown_tool"),
                    description=f"Tool: {tool.get('name', 'unknown')}",
                    target_id=target.id,
                    properties={
                        "tool_type": tool.get("type"),
                        "permissions": tool.get("permissions", []),
                        "enabled": tool.get("enabled", True),
                    },
                    risk_level=RiskLevel.MEDIUM if tool.get("permissions") else RiskLevel.LOW,
                )
                graph.nodes.append(node)
                await self.nodes_collection.insert_one(node.model_dump())

        if "rag" in config:
            rag = config["rag"]
            node = GraphNode(
                graph_id=graph.graph_id,
                node_type=NodeType.RAG_INDEX,
                label="RAG Index",
                description=f"RAG Index: {rag.get('name', 'default')}",
                target_id=target.id,
                properties={
                    "embedding_model": rag.get("embedding_model"),
                    "chunk_size": rag.get("chunk_size"),
                    "top_k": rag.get("top_k"),
                },
                risk_level=RiskLevel.LOW,
            )
            graph.nodes.append(node)
            await self.nodes_collection.insert_one(node.model_dump())

        if "documents" in config:
            for doc in config["documents"]:
                node = GraphNode(
                    graph_id=graph.graph_id,
                    node_type=NodeType.DOCUMENT,
                    label=doc.get("name", "document"),
                    description=f"Document: {doc.get('name', 'unknown')}",
                    target_id=target.id,
                    properties={
                        "classification": doc.get("classification", "internal"),
                        "sensitive": doc.get("sensitive", False),
                    },
                    risk_level=RiskLevel.HIGH if doc.get("sensitive") else RiskLevel.LOW,
                )
                graph.nodes.append(node)
                await self.nodes_collection.insert_one(node.model_dump())

    async def _add_permission_nodes(self, graph: RiskGraph, target: Any) -> None:
        config = target.configuration
        if "permissions" in config:
            for perm in config["permissions"]:
                node = GraphNode(
                    graph_id=graph.graph_id,
                    node_type=NodeType.PERMISSION,
                    label=perm.get("name", "permission"),
                    description=f"Permission: {perm.get('resource', 'unknown')}",
                    target_id=target.id,
                    properties={
                        "resource": perm.get("resource"),
                        "actions": perm.get("actions", []),
                        "principal": perm.get("principal"),
                    },
                    risk_level=RiskLevel.HIGH if "write" in perm.get("actions", []) or "delete" in perm.get("actions", []) else RiskLevel.MEDIUM,
                )
                graph.nodes.append(node)
                await self.nodes_collection.insert_one(node.model_dump())

    async def _add_change_history_nodes(self, graph: RiskGraph, target_id: UUID) -> None:
        changes = await self.db.change_events.find({"target_id": str(target_id)}).sort("detected_at", -1).limit(10).to_list(None)
        for change in changes:
            node = GraphNode(
                graph_id=graph.graph_id,
                node_type=NodeType.CONFIGURATION_CHANGE if "CONFIGURATION" in change["change_type"] else NodeType.PERMISSION,
                label=change["change_type"].replace("_", " ").title(),
                description=change["description"],
                target_id=target_id,
                execution_id=UUID(change["execution_id"]) if change.get("execution_id") else None,
                properties={
                    "change_type": change["change_type"],
                    "severity": change["severity"],
                    "before": change.get("before"),
                    "after": change.get("after"),
                },
                risk_level=self._change_severity_to_risk(change["severity"]),
            )
            graph.nodes.append(node)
            await self.nodes_collection.insert_one(node.model_dump())

    def _severity_to_risk_level(self, severity: Any) -> RiskLevel:
        if hasattr(severity, 'value'):
            sev = severity.value
        else:
            sev = str(severity).lower()
        mapping = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
            "info": RiskLevel.INFO,
        }
        return mapping.get(sev, RiskLevel.INFO)

    def _change_severity_to_risk(self, severity: str) -> RiskLevel:
        mapping = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
            "info": RiskLevel.INFO,
        }
        return mapping.get(severity.lower(), RiskLevel.INFO)

    async def _add_edges_from_attack_graph(self, graph: RiskGraph, target_id: UUID) -> None:
        attack_graph = await self.attack_graph_service.get_graph_by_execution(target_id)
        if not attack_graph:
            return

        for edge in attack_graph.edges:
            source_node = next((n for n in graph.nodes if n.node_id == edge.source_id), None)
            target_node = next((n for n in graph.nodes if n.node_id == edge.target_id), None)
            if source_node and target_node:
                edge = GraphEdge(
                    graph_id=graph.graph_id,
                    source_id=edge.source_id,
                    target_id=edge.target_id,
                    edge_type=self._map_attack_edge_type(edge.relationship),
                    weight=edge.weight,
                    evidence_ids=edge.evidence_ids,
                    finding_ids=[edge.source_id, edge.target_id] if edge.relationship == "exploits" else [],
                )
                graph.edges.append(edge)
                await self.edges_collection.insert_one(edge.model_dump())

    def _map_attack_edge_type(self, relationship: str) -> EdgeType:
        mapping = {
            "exploits": EdgeType.EXPLOITS,
            "chains_to": EdgeType.CHAINS_TO,
            "leads_to": EdgeType.LEADS_TO,
            "related_to": EdgeType.RELATED_TO,
        }
        return mapping.get(relationship, EdgeType.RELATED_TO)

    async def _add_permission_edges(self, graph: RiskGraph, target: Any) -> None:
        config = target.configuration
        if "permissions" not in config:
            return

        tool_nodes = [n for n in graph.nodes if n.node_type == NodeType.TOOL]
        permission_nodes = [n for n in graph.nodes if n.node_type == NodeType.PERMISSION]
        doc_nodes = [n for n in graph.nodes if n.node_type == NodeType.DOCUMENT]

        for perm in config.get("permissions", []):
            perm_actions = perm.get("actions", [])
            for tool_node in tool_nodes:
                if perm.get("resource") == tool_node.properties.get("tool_type"):
                    edge = GraphEdge(
                        graph_id=graph.graph_id,
                        source_id=tool_node.node_id,
                        target_id=next((p.node_id for p in permission_nodes if p.label == perm.get("name")), None),
                        edge_type=EdgeType.PERMITS,
                        weight=1.0,
                        properties={"actions": perm_actions},
                    )
                    if edge.target_id:
                        graph.edges.append(edge)
                        await self.edges_collection.insert_one(edge.model_dump())

            for doc_node in doc_nodes:
                if perm.get("resource") == "documents" or perm.get("resource") == doc_node.label:
                    edge = GraphEdge(
                        graph_id=graph.graph_id,
                        source_id=next((p.node_id for p in permission_nodes if p.label == perm.get("name")), None),
                        target_id=doc_node.node_id,
                        edge_type=EdgeType.ACCESSES if "read" in perm_actions else EdgeType.WRITES,
                        weight=1.0,
                        properties={"actions": perm_actions},
                    )
                    if edge.source_id:
                        graph.edges.append(edge)
                        await self.edges_collection.insert_one(edge.model_dump())

    async def _add_data_flow_edges(self, graph: RiskGraph, target: Any) -> None:
        config = target.configuration
        
        agent_nodes = [n for n in graph.nodes if n.node_type == NodeType.AGENT]
        tool_nodes = [n for n in graph.nodes if n.node_type == NodeType.TOOL]
        rag_nodes = [n for n in graph.nodes if n.node_type == NodeType.RAG_INDEX]
        doc_nodes = [n for n in graph.nodes if n.node_type == NodeType.DOCUMENT]
        api_nodes = [n for n in graph.nodes if n.node_type == NodeType.API]
        data_store_nodes = [n for n in graph.nodes if n.node_type == NodeType.DATA_STORE]

        for agent in agent_nodes:
            for tool in tool_nodes:
                edge = GraphEdge(
                    graph_id=graph.graph_id,
                    source_id=agent.node_id,
                    target_id=tool.node_id,
                    edge_type=EdgeType.CALLS,
                    weight=0.8,
                )
                graph.edges.append(edge)
                await self.edges_collection.insert_one(edge.model_dump())

            for rag in rag_nodes:
                edge = GraphEdge(
                    graph_id=graph.graph_id,
                    source_id=agent.node_id,
                    target_id=rag.node_id,
                    edge_type=EdgeType.CALLS,
                    weight=0.7,
                )
                graph.edges.append(edge)
                await self.edges_collection.insert_one(edge.model_dump())

        for rag in rag_nodes:
            for doc in doc_nodes:
                edge = GraphEdge(
                    graph_id=graph.graph_id,
                    source_id=rag.node_id,
                    target_id=doc.node_id,
                    edge_type=EdgeType.READS,
                    weight=0.9,
                )
                graph.edges.append(edge)
                await self.edges_collection.insert_one(edge.model_dump())

    async def _compute_risk_scores(self, graph: RiskGraph) -> None:
        nx_graph = nx.DiGraph()
        for node in graph.nodes:
            nx_graph.add_node(str(node.node_id), risk=node.risk_score)
        for edge in graph.edges:
            nx_graph.add_edge(str(edge.source_id), str(edge.target_id), weight=edge.weight)

        vuln_nodes = [n for n in graph.nodes if n.node_type == NodeType.VULNERABILITY]
        
        for vuln in vuln_nodes:
            try:
                entry_points = [str(n.node_id) for n in graph.nodes if n.node_type == NodeType.ENTRY_POINT]
                paths = list(nx.all_simple_paths(nx_graph, source=entry_points, target=str(vuln.node_id), cutoff=5))
                if paths:
                    max_risk = max(vuln.risk_score, max(sum(nx_graph.nodes[p]["risk"] for p in path) / len(path) for path in paths))
                    vuln.risk_score = max(vuln.risk_score, max_risk)
                    vuln.risk_level = self._score_to_risk(vuln.risk_score)
                    await self.nodes_collection.replace_one({"node_id": str(vuln.node_id)}, vuln.model_dump())
            except:
                pass

        graph.risk_score = sum(n.risk_score for n in graph.nodes if n.node_type == NodeType.VULNERABILITY) / max(1, len([n for n in graph.nodes if n.node_type == NodeType.VULNERABILITY]))
        await self.graphs_collection.replace_one({"graph_id": str(graph.graph_id)}, graph.model_dump())

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 9.0:
            return RiskLevel.CRITICAL
        elif score >= 7.0:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        elif score >= 1.0:
            return RiskLevel.LOW
        return RiskLevel.INFO

    async def _find_critical_paths(self, graph: RiskGraph) -> None:
        nx_graph = nx.DiGraph()
        for node in graph.nodes:
            nx_graph.add_node(str(node.node_id), risk=node.risk_score)
        for edge in graph.edges:
            nx_graph.add_edge(str(edge.source_id), str(edge.target_id), weight=edge.weight)

        entry_nodes = [n.node_id for n in graph.nodes if n.node_type == NodeType.ENTRY_POINT]
        vuln_nodes = [n.node_id for n in graph.nodes if n.node_type == NodeType.VULNERABILITY]

        for entry in entry_nodes:
            for vuln in vuln_nodes:
                try:
                    if nx.has_path(nx_graph, str(entry), str(vuln)):
                        path = nx.shortest_path(nx_graph, str(entry), str(vuln), weight="weight")
                        if len(path) > 1:
                            path_uuids = [UUID(p) for p in path]
                            if path_uuids not in graph.critical_paths:
                                graph.critical_paths.append(path_uuids)
                except:
                    pass

    async def _identify_entry_points(self, graph: RiskGraph) -> None:
        for node in graph.nodes:
            if node.node_type in (NodeType.ENTRY_POINT, NodeType.API, NodeType.USER):
                if node.node_id not in graph.entry_points:
                    graph.entry_points.append(node.node_id)

    async def propagate_risk(self, graph_id: UUID, source_node_id: UUID, trigger_type: str, trigger_details: dict[str, Any]) -> RiskPropagationEvent:
        graph = await self.get_risk_graph(graph_id)
        if not graph:
            raise ValueError(f"Graph {graph_id} not found")

        source_node = next((n for n in graph.nodes if n.node_id == source_node_id), None)
        if not source_node:
            raise ValueError(f"Source node {source_node_id} not found")

        affected = await self._propagate_risk(graph, source_node_id, set())
        affected = [n for n in affected if n != source_node_id]

        event = RiskPropagationEvent(
            graph_id=graph_id,
            source_node_id=source_node_id,
            affected_node_ids=affected,
            trigger_type=trigger_type,
            trigger_details=trigger_details,
            risk_delta=sum(n.risk_score for n in graph.nodes if n.node_id in affected) - sum(n.risk_score for n in graph.nodes if n.node_id in affected),
            propagated=True,
        )
        await self.propagation_events_collection.insert_one(event.model_dump())

        for node_id in affected:
            node = next((n for n in graph.nodes if n.node_id == n), None)
            if node:
                node.risk_score = min(10.0, node.risk_score + 0.5)
                node.risk_level = self._score_to_risk(node.risk_score)
                node.updated_at = datetime.utcnow()
                await self.nodes_collection.replace_one({"node_id": str(node.node_id)}, node.model_dump())

        graph.updated_at = datetime.utcnow()
        await self.graphs_collection.replace_one({"graph_id": str(graph_id)}, graph.model_dump())

        logger.info("Risk propagated", graph_id=str(graph_id), source=str(source_node_id), affected=len(affected))
        return event

    async def _propagate_risk(self, graph: RiskGraph, node_id: UUID, visited: set[UUID]) -> list[UUID]:
        if node_id in visited:
            return []
        visited.add(node_id)

        affected = [node_id]
        edges = [e for e in graph.edges if e.source_id == node_id]
        for edge in edges:
            affected.extend(await self._propagate_risk(graph, edge.target_id, visited))
        return affected

    async def assess_blast_radius(self, graph_id: UUID, source_node_id: UUID) -> BlastRadiusAssessment:
        graph = await self.get_risk_graph(graph_id)
        if not graph:
            raise ValueError(f"Graph {graph_id} not found")

        affected = await self._propagate_risk(graph, source_node_id, set())
        affected = [n for n in affected if n != source_node_id]

        affected_nodes = [n for n in graph.nodes if n.node_id in affected]
        max_depth = self._calculate_max_depth(graph, source_node_id)

        affected_assets = set()
        affected_data_stores = set()
        for node in affected_nodes:
            if node.node_type in (NodeType.DATA_STORE, NodeType.DOCUMENT):
                affected_data_stores.add(node.label)
            else:
                affected_assets.add(node.label)

        critical_paths = [p for p in graph.critical_paths if source_node_id in p]

        assessment = BlastRadiusAssessment(
            graph_id=graph_id,
            source_node_id=source_node_id,
            affected_nodes=affected,
            blast_radius_score=sum(n.risk_score for n in graph.nodes if n.node_id in affected) / max(1, len(affected)),
            max_depth=max_depth,
            affected_assets=list(affected_assets),
            affected_data_stores=list(affected_data_stores),
            critical_paths=critical_paths,
        )
        await self.blast_radius_collection.insert_one(assessment.model_dump())
        return assessment

    def _calculate_max_depth(self, graph: RiskGraph, start_node_id: UUID) -> int:
        nx_graph = nx.DiGraph()
        for node in graph.nodes:
            nx_graph.add_node(str(node.node_id))
        for edge in graph.edges:
            nx_graph.add_edge(str(edge.source_id), str(edge.target_id))

        try:
            lengths = nx.single_source_shortest_path_length(nx_graph, str(start_node_id))
            return max(lengths.values()) if lengths else 0
        except:
            return 0

    async def get_risk_graph(self, graph_id: UUID) -> Optional[RiskGraph]:
        doc = await self.graphs_collection.find_one({"graph_id": str(graph_id)})
        if not doc:
            return None
        graph = RiskGraph(**doc)
        graph.nodes = [GraphNode(**n) async for n in self.nodes_collection.find({"graph_id": str(graph_id)})]
        graph.edges = [GraphEdge(**e) async for e in self.edges_collection.find({"graph_id": str(graph_id)})]
        return graph

    async def get_risk_graph_by_target(self, target_id: UUID) -> Optional[RiskGraph]:
        doc = await self.graphs_collection.find_one({"target_id": str(target_id)})
        if not doc:
            return None
        return await self.get_risk_graph(doc["graph_id"])

    async def get_risk_graph_by_target_id(self, target_id: UUID) -> Optional[RiskGraph]:
        return await self.get_risk_graph_by_target(target_id)

    async def _get_target(self, target_id: UUID):
        doc = await self.targets_collection.find_one({"id": str(target_id)})
        from security.posture.models import Target
        return Target(**doc) if doc else None

    async def _get_findings_for_target(self, target_id: UUID) -> list:
        cursor = self.findings_collection.find({"target_id": str(target_id)})
        from security.findings.models import Finding
        return [Finding(**doc) async for doc in cursor]