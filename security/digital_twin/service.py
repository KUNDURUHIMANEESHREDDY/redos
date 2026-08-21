from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from security.database import get_database
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
from security.posture.models import Target
from security.findings.models import Finding
from security.evidence.models import Evidence
from security.risk_graph.models import RiskGraph
import structlog

logger = structlog.get_logger()


class DigitalTwinEngine:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.twins_collection = self.db.digital_twins
        self.components_collection = self.db.twin_components
        self.edges_collection = self.db.twin_edges
        self.snapshots_collection = self.db.twin_snapshots
        self.changes_collection = self.db.component_changes
        self.assumptions_collection = self.db.assumption_impacts
        self.targets_collection = self.db.targets
        self.findings_collection = self.db.findings
        self.evidence_collection = self.db.evidence
        self.risk_graphs_collection = self.db.risk_graphs

    async def create_twin(self, target_id: UUID, name: str, description: str = "") -> DigitalTwin:
        target = await self._get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id} not found")

        existing = await self.twins_collection.find_one({"target_id": str(target_id)})
        if existing:
            return DigitalTwin(**existing)

        twin = DigitalTwin(
            target_id=target_id,
            name=name,
            description=description,
        )
        await self.twins_collection.insert_one(twin.model_dump())
        
        await self._sync_twin(twin.twin_id, target_id)
        
        logger.info("Digital twin created", twin_id=str(twin.twin_id), target_id=str(target_id))
        return twin

    async def sync_twin(self, request: DigitalTwinSyncRequest) -> DigitalTwin:
        twin = await self._get_twin_by_target(request.target_id)
        if not twin:
            raise ValueError(f"No twin found for target {request.target_id}")

        if request.force_full_sync:
            await self._full_sync(twin, request.target_id)
        else:
            await self._incremental_sync(twin, request.target_id, request.components_to_sync)

        twin.last_synced = datetime.utcnow()
        twin.sync_status = "synced"
        twin.updated_at = datetime.utcnow()
        await self.twins_collection.replace_one({"twin_id": str(twin.twin_id)}, twin.model_dump())

        logger.info("Digital twin synced", twin_id=str(twin.twin_id), target_id=str(request.target_id))
        return twin

    async def _full_sync(self, twin: DigitalTwin, target_id: UUID) -> None:
        target = await self._get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id} not found")

        await self.components_collection.delete_many({"twin_id": str(twin.twin_id)})
        await self.edges_collection.delete_many({"twin_id": str(twin.twin_id)})

        components = await self._build_components_from_target(target)
        edges = await self._build_edges_from_components(components, target_id)

        for component in components:
            component.twin_id = twin.twin_id
            await self.components_collection.insert_one(component.model_dump())

        for edge in edges:
            edge.twin_id = twin.twin_id
            await self.edges_collection.insert_one(edge.model_dump())

        twin.components = components
        twin.edges = edges
        twin.version = str(int(twin.version.split(".")[0]) + 1) + ".0"
        twin.updated_at = datetime.utcnow()

        snapshot = TwinSnapshot(
            twin_id=twin.twin_id,
            version=twin.version,
            components_snapshot={c.component_id: c.model_dump() for c in components},
            edges_snapshot=[e.model_dump() for e in twin.edges],
        )
        await self.snapshots_collection.insert_one(snapshot.model_dump())

    async def _incremental_sync(self, twin: DigitalTwin, target_id: UUID, components_to_sync: Optional[list[str]] = None) -> None:
        target = await self._get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id} not found")

        new_components = await self._build_components_from_target(target)
        existing_components = {c.name: c for c in twin.components}
        new_components_map = {c.name: c for c in new_components}

        changes = []
        for name, new_comp in new_components_map.items():
            if name not in existing_components:
                changes.append(ComponentChange(
                    twin_id=twin.twin_id,
                    component_id=new_comp.component_id,
                    change_type="added",
                    after=new_comp.model_dump(),
                    security_impact=self._assess_security_impact(new_comp, "added"),
                ))
            elif components_to_sync is None or name in components_to_sync:
                old_comp = existing_components[name]
                if old_comp.version != new_comp.version or old_comp.configuration != new_comp.configuration:
                    diff = self._compute_diff(old_comp, new_comp)
                    changes.append(ComponentChange(
                        twin_id=twin.twin_id,
                        component_id=new_comp.component_id,
                        change_type="modified",
                        before=old_comp.model_dump(),
                        after=new_comp.model_dump(),
                        diff=diff,
                        security_impact=self._assess_security_impact(new_comp, "modified"),
                    ))

        for name, old_comp in existing_components.items():
            if name not in new_components_map:
                changes.append(ComponentChange(
                    twin_id=twin.twin_id,
                    component_id=old_comp.component_id,
                    change_type="removed",
                    before=old_comp.model_dump(),
                    security_impact=self._assess_security_impact(old_comp, "removed"),
                ))

        for change in changes:
            await self.changes_collection.insert_one(change.model_dump())
            await self._assess_assumption_impact(twin.twin_id, change)

        twin.components = list(new_components_map.values())
        twin.edges = await self._build_edges_from_components(twin.components, twin.target_id)
        twin.version = f"{int(twin.version.split('.')[0]) + 1}.0"
        twin.updated_at = datetime.utcnow()

        snapshot = TwinSnapshot(
            twin_id=twin.twin_id,
            version=twin.version,
            components_snapshot={c.component_id: c.model_dump() for c in twin.components},
            edges_snapshot=[e.model_dump() for e in twin.edges],
        )
        await self.snapshots_collection.insert_one(snapshot.model_dump())

    async def _build_components_from_target(self, target: Target) -> list[TwinComponent]:
        components = []
        config = target.configuration

        if "model" in config:
            model = config["model"]
            components.append(TwinComponent(
                twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                component_type=ComponentType.MODEL,
                name=model.get("name", "model"),
                version=model.get("version", "1.0"),
                description=f"Model: {model.get('name', 'unknown')}",
                configuration=model,
                metadata={"provider": model.get("provider"), "parameters": model.get("parameters", {})},
                risk_score=self._calculate_model_risk(model),
            ))

        if "system_prompt" in config:
            prompt = config["system_prompt"]
            components.append(TwinComponent(
                twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                component_type=ComponentType.PROMPT,
                name="system_prompt",
                version=prompt.get("version", "1.0"),
                description="System prompt",
                configuration=prompt,
                risk_score=self._calculate_prompt_risk(prompt),
            ))

        if "prompt_templates" in config:
            for tmpl in config["prompt_templates"]:
                components.append(TwinComponent(
                    twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                    component_type=ComponentType.PROMPT,
                    name=tmpl.get("name", "template"),
                    version=tmpl.get("version", "1.0"),
                    description=f"Prompt template: {tmpl.get('name')}",
                    configuration=tmpl,
                    risk_score=self._calculate_prompt_risk(tmpl),
                ))

        if "tools" in config:
            for tool in config["tools"]:
                components.append(TwinComponent(
                    twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                    component_type=ComponentType.TOOL,
                    name=tool.get("name", "tool"),
                    version=tool.get("version", "1.0"),
                    description=f"Tool: {tool.get('name', 'unknown')}",
                    configuration=tool,
                    metadata={"tool_type": tool.get("type")},
                    risk_score=self._calculate_tool_risk(tool),
                ))

        if "permissions" in config:
            for perm in config["permissions"]:
                components.append(TwinComponent(
                    twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                    component_type=ComponentType.PERMISSION,
                    name=perm.get("name", "permission"),
                    version="1.0",
                    description=f"Permission: {perm.get('resource', 'unknown')}",
                    configuration=perm,
                    metadata={"resource": perm.get("resource"), "actions": perm.get("actions", [])},
                    risk_score=self._calculate_permission_risk(perm),
                ))

        if "rag" in config:
            rag = config["rag"]
            components.append(TwinComponent(
                twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                component_type=ComponentType.RAG,
                name=rag.get("name", "rag"),
                version=rag.get("version", "1.0"),
                description="RAG Index",
                configuration=rag,
                metadata={
                    "embedding_model": rag.get("embedding_model"),
                    "chunk_size": rag.get("chunk_size"),
                    "top_k": rag.get("top_k"),
                },
                risk_score=self._calculate_rag_risk(rag),
            ))

        if "documents" in config:
            for doc in config["documents"]:
                components.append(TwinComponent(
                    twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                    component_type=ComponentType.DOCUMENT,
                    name=doc.get("name", "document"),
                    version="1.0",
                    description=f"Document: {doc.get('name', 'unknown')}",
                    configuration=doc,
                    metadata={
                        "classification": doc.get("classification", "internal"),
                        "sensitive": doc.get("sensitive", False),
                    },
                    risk_score=self._calculate_document_risk(doc),
                ))

        if "agents" in config:
            for agent in config["agents"]:
                components.append(TwinComponent(
                    twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                    component_type=ComponentType.AGENT,
                    name=agent.get("name", "agent"),
                    version=agent.get("version", "1.0"),
                    description=f"Agent: {agent.get('name', 'unknown')}",
                    configuration=agent,
                    metadata={"agent_type": agent.get("type")},
                    risk_score=self._calculate_agent_risk(agent),
                ))

        if "apis" in config:
            for api in config["apis"]:
                components.append(TwinComponent(
                    twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                    component_type=ComponentType.API,
                    name=api.get("name", "api"),
                    version=api.get("version", "1.0"),
                    description=f"API: {api.get('name', 'unknown')}",
                    configuration=api,
                    metadata={"endpoint": api.get("endpoint"), "auth": api.get("auth")},
                    risk_score=self._calculate_api_risk(api),
                ))

        return components

    def _calculate_model_risk(self, model: dict) -> float:
        risk = 0.0
        if model.get("provider") in ["openai", "anthropic"]:
            risk += 2.0
        if "fine_tuned" in model.get("parameters", {}):
            risk += 3.0
        if model.get("provider") == "custom":
            risk += 4.0
        return min(10.0, risk)

    def _calculate_prompt_risk(self, prompt: dict) -> float:
        risk = 1.0
        if "injection" in str(prompt).lower():
            risk += 3.0
        if "override" in str(prompt).lower():
            risk += 2.0
        return min(10.0, risk)

    def _calculate_tool_risk(self, tool: dict) -> float:
        risk = 2.0
        permissions = tool.get("permissions", [])
        if "write" in permissions or "delete" in permissions or "execute" in permissions:
            risk += 4.0
        if "shell" in tool.get("type", "").lower():
            risk += 5.0
        if "database" in tool.get("type", "").lower() and "write" in tool.get("permissions", []):
            risk += 4.0
        return min(10.0, risk)

    def _calculate_permission_risk(self, perm: dict) -> float:
        risk = 1.0
        actions = perm.get("actions", [])
        if "write" in actions or "delete" in actions:
            risk += 3.0
        if "admin" in perm.get("principal", "").lower():
            risk += 3.0
        return min(10.0, risk)

    def _calculate_rag_risk(self, rag: dict) -> float:
        risk = 1.0
        if rag.get("allow_external", False):
            risk += 3.0
        if "public" in rag.get("name", "").lower():
            risk += 2.0
        return min(10.0, risk)

    def _calculate_document_risk(self, doc: dict) -> float:
        risk = 1.0
        if doc.get("sensitive", False):
            risk += 4.0
        if doc.get("classification") in ["confidential", "secret", "top_secret"]:
            risk += 5.0
        return min(10.0, risk)

    def _calculate_agent_risk(self, agent: dict) -> float:
        risk = 2.0
        if agent.get("autonomous", False):
            risk += 3.0
        if agent.get("can_delegate", False):
            risk += 2.0
        return min(10.0, risk)

    def _calculate_api_risk(self, api: dict) -> float:
        risk = 1.0
        if not api.get("auth", False):
            risk += 3.0
        if api.get("public", False):
            risk += 2.0
        return min(10.0, risk)

    def _compute_diff(self, old: TwinComponent, new: TwinComponent) -> dict[str, Any]:
        diff = {}
        if old.version != new.version:
            diff["version"] = {"old": old.version, "new": new.version}
        if old.configuration != new.configuration:
            diff["configuration"] = {"old": old.configuration, "new": new.configuration}
        if old.status != new.status:
            diff["status"] = {"old": old.status.value, "new": new.status.value}
        if old.risk_score != new.risk_score:
            diff["risk_score"] = {"old": old.risk_score, "new": new.risk_score}
        return diff

    def _assess_security_impact(self, component: TwinComponent, change_type: str) -> Optional[str]:
        if component.risk_score >= 7.0:
            return f"High-risk component {change_type}: {component.name} (risk: {component.risk_score})"
        elif component.risk_score >= 4.0:
            return f"Medium-risk component {change_type}: {component.name} (risk: {component.risk_score})"
        return None

    async def _assess_assumption_impact(self, twin_id: UUID, change: ComponentChange) -> None:
        assumptions = [
            "Model cannot execute arbitrary code",
            "System prompt prevents harmful outputs",
            "Tools have restricted permissions",
            "RAG index contains only approved documents",
            "Agent follows configured policies",
            "Dependencies are vetted",
        ]

        for assumption in assumptions:
            affected = self._assumption_affected_by_change(assumption, change)
            if affected:
                impact = AssumptionImpact(
                    twin_id=twin_id,
                    assumption=assumption,
                    was_valid=True,
                    is_valid=False,
                    affected_components=[c.component_id for c in change.after] if change.after else [],
                    affected_findings=[],
                    risk_delta=0.0,
                    description=f"Change to {change.change_type} component may invalidate assumption: {assumption}",
                )
                await self.assumptions_collection.insert_one(impact.model_dump())

    def _assumption_affected_by_change(self, assumption: str, change: ComponentChange) -> bool:
        if "Model cannot execute arbitrary code" == assumption:
            return change.change_type in ("modified", "added") and any(
                c.component_type == ComponentType.MODEL or 
                c.component_type == ComponentType.PROMPT 
                for c in [change.before, change.after] if c
            )
        if "System prompt prevents harmful outputs" == assumption:
            return change.change_type in ("modified", "added") and any(
                c.component_type == ComponentType.PROMPT 
                for c in [change.before, change.after] if c
            )
        if "Tools have restricted permissions" == assumption:
            return change.change_type in ("modified", "added") and any(
                c.component_type == ComponentType.TOOL or 
                c.component_type == ComponentType.PERMISSION 
                for c in [change.before, change.after] if c
            )
        if "RAG index contains only approved documents" == assumption:
            return change.change_type in ("modified", "added") and any(
                c.component_type in (ComponentType.RAG, ComponentType.DOCUMENT) 
                for c in [change.before, change.after] if c
            )
        if "Agent follows configured policies" == assumption:
            return change.change_type in ("modified", "added") and any(
                c.component_type == ComponentType.AGENT 
                for c in [change.before, change.after] if c
            )
        if "Dependencies are vetted" == assumption:
            return change.change_type in ("modified", "added") and any(
                c.component_type == ComponentType.DEPENDENCY 
                for c in [change.before, change.after] if c
            )
        return False

    async def _build_edges_from_components(self, components: list[TwinComponent], target_id: UUID) -> list[TwinEdge]:
        edges = []
        components_map = {c.name: c for c in components}

        for comp in components:
            if comp.component_type == ComponentType.AGENT:
                for tool_name in comp.configuration.get("tools", []):
                    if tool_name in components_map:
                        edges.append(TwinEdge(
                            twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                            source_id=components_map[comp.name].component_id,
                            target_id=components_map[tool_name].component_id,
                            relationship="uses_tool",
                            weight=1.0,
                        ))

                if "rag" in comp.configuration:
                    rag_name = comp.configuration["rag"]
                    if rag_name in components_map:
                        edges.append(TwinEdge(
                            twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                            source_id=components_map[comp.name].component_id,
                            target_id=components_map[rag_name].component_id,
                            relationship="queries",
                            weight=1.0,
                        ))

            if comp.component_type == ComponentType.TOOL:
                for perm_name, perm in comp.configuration.get("permissions", {}).items():
                    if perm_name in components_map:
                        edges.append(TwinEdge(
                            twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                            source_id=components_map[comp.name].component_id,
                            target_id=components_map[perm_name].component_id,
                            relationship="requires_permission",
                            weight=1.0,
                        ))

            if comp.component_type == ComponentType.RAG:
                for doc_name in comp.configuration.get("documents", []):
                    if doc_name in components_map:
                        edges.append(TwinEdge(
                            twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                            source_id=components_map[comp.name].component_id,
                            target_id=components_map[doc_name].component_id,
                            relationship="indexes",
                            weight=1.0,
                        ))

            if comp.component_type == ComponentType.DOCUMENT:
                for tool_name in components_map:
                    if components_map[tool_name].component_type == ComponentType.TOOL:
                        if "read" in components_map[tool_name].configuration.get("permissions", []):
                            edges.append(TwinEdge(
                                twin_id=UUID("00000000-0000-0000-0000-000000000000"),
                                source_id=components_map[tool_name].component_id,
                                target_id=comp.component_id,
                                relationship="reads",
                                weight=0.8,
                            ))

        return edges

    async def get_twin(self, twin_id: UUID) -> Optional[DigitalTwin]:
        doc = await self.twins_collection.find_one({"twin_id": str(twin_id)})
        if not doc:
            return None
        twin = DigitalTwin(**doc)
        twin.components = [TwinComponent(**c) async for c in self.components_collection.find({"twin_id": str(twin_id)})]
        twin.edges = [TwinEdge(**e) async for e in self.edges_collection.find({"twin_id": str(twin.twin_id)})]
        return twin

    async def get_twin_by_target(self, target_id: UUID) -> Optional[DigitalTwin]:
        doc = await self.twins_collection.find_one({"target_id": str(target_id)})
        if not doc:
            return None
        return await self.get_twin(doc["twin_id"])

    async def _get_twin_by_target(self, target_id: UUID) -> Optional[DigitalTwin]:
        return await self.get_twin_by_target(target_id)

    async def _get_target(self, target_id: UUID) -> Optional[Target]:
        doc = await self.targets_collection.find_one({"id": str(target_id)})
        return Target(**doc) if doc else None

    async def get_twin_snapshot(self, twin_id: UUID, snapshot_id: UUID) -> Optional[TwinSnapshot]:
        doc = await self.snapshots_collection.find_one({"snapshot_id": str(snapshot_id)})
        return TwinSnapshot(**doc) if doc else None

    async def get_twin_history(self, twin_id: UUID, days: int = 30) -> list[TwinSnapshot]:
        cutoff = datetime.utcnow() - timedelta(days=days)
        cursor = self.snapshots_collection.find({"twin_id": str(twin_id), "captured_at": {"$gte": cutoff}}).sort("captured_at", -1)
        return [TwinSnapshot(**doc) async for doc in cursor]

    async def get_component_changes(self, twin_id: UUID, days: int = 30) -> list[ComponentChange]:
        cutoff = datetime.utcnow() - timedelta(days=days)
        cursor = self.changes_collection.find({"twin_id": str(twin_id), "detected_at": {"$gte": cutoff}}).sort("detected_at", -1)
        return [ComponentChange(**doc) async for doc in cursor]

    async def get_assumption_impacts(self, twin_id: UUID, days: int = 30) -> list[AssumptionImpact]:
        cutoff = datetime.utcnow() - timedelta(days=days)
        cursor = self.assumptions_collection.find({"twin_id": str(twin_id), "detected_at": {"$gte": cutoff}}).sort("detected_at", -1)
        return [AssumptionImpact(**doc) async for doc in cursor]

    async def compare_twins(self, twin_a_id: UUID, twin_b_id: UUID) -> list[ComponentChange]:
        twin_a = await self.get_twin(twin_a_id)
        twin_b = await self.get_twin(twin_b_id)
        if not twin_a or not twin_b:
            raise ValueError("One or both twins not found")

        comps_a = {c.name: c for c in twin_a.components}
        comps_b = {c.name: c for c in twin_b.components}

        changes = []
        for name, comp_a in comps_a.items():
            if name not in comps_b:
                changes.append(ComponentChange(
                    twin_id=twin_a_id,
                    component_id=comp_a.component_id,
                    change_type="removed",
                    before=comp_a.model_dump(),
                ))
            else:
                comp_b = comps_b[name]
                if comp_a.version != comp_b.version or comp_a.configuration != comp_b.configuration:
                    changes.append(ComponentChange(
                        twin_id=twin_a_id,
                        component_id=comp_a.component_id,
                        change_type="modified",
                        before=comp_a.model_dump(),
                        after=comp_b.model_dump(),
                        diff=self._compute_diff(comp_a, comp_b),
                    ))

        for name, comp_b in comps_b.items():
            if name not in comps_a:
                changes.append(ComponentChange(
                    twin_id=twin_b_id,
                    component_id=comp_b.component_id,
                    change_type="added",
                    after=comp_b.model_dump(),
                ))

        return changes