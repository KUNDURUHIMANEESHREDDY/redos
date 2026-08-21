from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from security.database import get_database
from security.change_detection.models import (
    ChangeEvent,
    ChangeType,
    ChangeSeverity,
    ChangeCategory,
    ChangeSource,
    AssumptionChange,
    AttackSurfaceChange,
    ChangeDetectionRule,
    ChangeDetectionResult,
)
from security.posture.models import Target
from security.findings.models import Finding
from security.attack_graph.service import AttackGraph
import structlog

logger = structlog.get_logger()


class ChangeDetector:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.change_events_collection = self.db.change_events
        self.assumption_changes_collection = self.db.assumption_changes
        self.attack_surface_changes_collection = self.db.attack_surface_changes
        self.detection_rules_collection = self.db.change_detection_rules
        self.detection_results_collection = self.db.change_detection_results
        self.targets_collection = self.db.targets
        self.findings_collection = self.db.findings
        self.attack_graphs_collection = self.db.attack_graphs

    async def detect_changes(self, target_id: UUID, source: str = "scheduled_scan") -> ChangeDetectionResult:
        start_time = datetime.utcnow()
        target = await self._get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id} not found")

        previous_version = await self._get_previous_version(target_id)
        current_version = await self._get_current_version(target_id)

        change_events = await self._detect_change_events(target_id, previous_version, current_version, source)
        assumption_changes = await self._analyze_assumption_changes(target_id, change_events)
        attack_surface_changes = await self._analyze_attack_surface_changes(target_id, change_events)

        broken_assumptions = [a.assumption for a in assumption_changes if a.was_valid and not a.is_valid]
        new_vectors = [a.attack_vector for a in attack_surface_changes if a.after_coverage > a.before_coverage]
        risk_increase = sum(a.risk_delta for a in attack_surface_changes)

        result = ChangeDetectionResult(
            target_id=target_id,
            change_events=change_events,
            assumption_changes=assumption_changes,
            attack_surface_changes=attack_surface_changes,
            security_assumptions_broken=broken_assumptions,
            new_attack_vectors=new_vectors,
            risk_increase=risk_increase,
            scanned_at=datetime.utcnow(),
            scan_duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000),
        )

        await self._save_detection_result(result)
        await self._save_change_events(change_events)
        await self._save_assumption_changes(assumption_changes)
        await self._save_attack_surface_changes(attack_surface_changes)

        if change_events:
            logger.info("Changes detected", target_id=str(target_id), count=len(change_events), risk_increase=risk_increase)
        return result

    async def _detect_change_events(self, target_id: UUID, previous: Optional[dict], current: Optional[dict], source: str) -> list[ChangeEvent]:
        events = []
        if not previous or not current:
            return events

        for change_type in ChangeType:
            events.extend(await self._detect_specific_change(target_id, change_type, previous, current, source))

        return events

    async def _detect_specific_change(self, target_id: UUID, change_type: ChangeType, previous: dict, current: dict, source: str) -> list[ChangeEvent]:
        events = []
        key = change_type.value

        if key in current and key in previous:
            if current[key] != previous[key]:
                events.append(ChangeEvent(
                    target_id=target_id,
                    change_type=change_type,
                    severity=self._assess_severity(change_type, previous[key], current[key]),
                    category=self._categorize_change(change_type),
                    source=ChangeSource(source),
                    description=f"{change_type.value.replace('_', ' ').title()} changed",
                    details={"field": key, "old": previous[key], "new": current[key]},
                    before={key: previous[key]},
                    after={key: current[key]},
                ))
        elif key in current and key not in previous:
            events.append(ChangeEvent(
                target_id=target_id,
                change_type=change_type,
                severity=self._assess_severity(change_type, None, current[key]),
                category=self._categorize_change(change_type),
                source=ChangeSource(source),
                description=f"{change_type.value.replace('_', ' ').title()} added",
                details={"field": key, "new": current[key]},
                after={key: current[key]},
            ))
        elif key not in current and key in previous:
            events.append(ChangeEvent(
                target_id=target_id,
                change_type=change_type,
                severity=ChangeSeverity.HIGH,
                category=self._categorize_change(change_type),
                source=ChangeSource(source),
                description=f"{change_type.value.replace('_', ' ').title()} removed",
                details={"field": key, "old": previous[key]},
                before={key: previous[key]},
            ))

        return events

    def _assess_severity(self, change_type: ChangeType, old: Any, new: Any) -> ChangeSeverity:
        critical_changes = {
            ChangeType.MODEL_CHANGE,
            ChangeType.SYSTEM_PROMPT_CHANGE,
            ChangeType.TOOL_PERMISSION_CHANGE,
            ChangeType.POLICY_CHANGE,
            ChangeType.RAG_INDEX_CHANGE,
        }
        high_changes = {
            ChangeType.TOOL_CHANGE,
            ChangeType.RAG_INDEX_CHANGE,
            ChangeType.DOCUMENT_CHANGE,
            ChangeType.AGENT_CONFIG_CHANGE,
            ChangeType.PERMISSION_CHANGE,
        }

        if change_type in critical_changes:
            return ChangeSeverity.CRITICAL
        elif change_type in high_changes:
            return ChangeSeverity.HIGH
        return ChangeSeverity.MEDIUM

    def _categorize_change(self, change_type: ChangeType) -> ChangeCategory:
        security_relevant = {
            ChangeType.MODEL_CHANGE,
            ChangeType.SYSTEM_PROMPT_CHANGE,
            ChangeType.TOOL_PERMISSION_CHANGE,
            ChangeType.RAG_INDEX_CHANGE,
            ChangeType.POLICY_CHANGE,
            ChangeType.PERMISSION_CHANGE,
            ChangeType.DEPENDENCY_CHANGE,
        }
        if change_type in security_relevant:
            return ChangeCategory.SECURITY_RELEVANT
        return ChangeCategory.FUNCTIONAL

    async def _analyze_assumption_changes(self, target_id: UUID, change_events: list[ChangeEvent]) -> list[AssumptionChange]:
        assumptions = [
            "Model cannot execute arbitrary code",
            "System prompt prevents harmful outputs",
            "Tools have restricted permissions",
            "RAG index contains only approved documents",
            "Agent follows configured policies",
            "Dependencies are vetted",
        ]

        changes = []
        for event in change_events:
            if event.change_type in (ChangeType.MODEL_CHANGE, ChangeType.SYSTEM_PROMPT_CHANGE, ChangeType.TOOL_PERMISSION_CHANGE):
                for assumption in assumptions:
                    if self._assumption_affected(assumption, event):
                        changes.append(AssumptionChange(
                            change_event_id=event.event_id,
                            assumption=assumption,
                            was_valid=True,
                            is_valid=False,
                            evidence=[event.description],
                            impact="Security boundary potentially bypassed",
                            description=f"Change to {event.change_type.value} may invalidate assumption: {assumption}",
                        ))
        return changes

    def _assumption_affected(self, assumption: str, event: ChangeEvent) -> bool:
        mapping = {
            "Model cannot execute arbitrary code": [ChangeType.MODEL_CHANGE, ChangeType.SYSTEM_PROMPT_CHANGE],
            "System prompt prevents harmful outputs": [ChangeType.SYSTEM_PROMPT_CHANGE, ChangeType.POLICY_CHANGE],
            "Tools have restricted permissions": [ChangeType.TOOL_PERMISSION_CHANGE, ChangeType.TOOL_CHANGE],
            "RAG index contains only approved documents": [ChangeType.RAG_INDEX_CHANGE, ChangeType.DOCUMENT_CHANGE],
            "Agent follows configured policies": [ChangeType.AGENT_CONFIG_CHANGE, ChangeType.POLICY_CHANGE],
            "Dependencies are vetted": [ChangeType.DEPENDENCY_CHANGE],
        }
        return event.change_type in mapping.get(assumption, [])

    async def _analyze_attack_surface_changes(self, target_id: UUID, change_events: list[ChangeEvent]) -> list[AttackSurfaceChange]:
        changes = []
        for event in change_events:
            if event.severity in (ChangeSeverity.CRITICAL, ChangeSeverity.HIGH):
                before_coverage = 0.0
                after_coverage = 0.0
                risk_delta = 5.0 if event.severity == ChangeSeverity.CRITICAL else 2.0

                if event.change_type in (ChangeType.TOOL_PERMISSION_CHANGE, ChangeType.TOOL_CHANGE, ChangeType.AGENT_CONFIG_CHANGE):
                    changes.append(AttackSurfaceChange(
                        target_id=target_id,
                        change_event_id=event.event_id,
                        attack_vector=event.change_type.value,
                        before_coverage=before_coverage,
                        after_coverage=after_coverage,
                        new_attack_paths=[event.description],
                        risk_delta=risk_delta,
                    ))
        return changes

    async def _get_target(self, target_id: UUID) -> Optional[Target]:
        doc = await self.targets_collection.find_one({"id": str(target_id)})
        return Target(**doc) if doc else None

    async def _get_previous_version(self, target_id: UUID) -> Optional[dict]:
        cursor = self.db.target_versions.find({"target_id": str(target_id)}).sort("created_at", -1).limit(2)
        versions = await cursor.to_list(2)
        if len(versions) >= 2:
            return versions[1].get("configuration_snapshot", {})
        return None

    async def _get_current_version(self, target_id: UUID) -> Optional[dict]:
        target = await self._get_target(target_id)
        return target.configuration if target else None

    async def _save_detection_result(self, result: ChangeDetectionResult) -> None:
        await self.detection_results_collection.insert_one(result.model_dump())

    async def _save_change_events(self, events: list[ChangeEvent]) -> None:
        if events:
            await self.change_events_collection.insert_many([e.model_dump() for e in events])

    async def _save_assumption_changes(self, changes: list[AssumptionChange]) -> None:
        if changes:
            await self.assumption_changes_collection.insert_many([c.model_dump() for c in changes])

    async def _save_attack_surface_changes(self, changes: list[AttackSurfaceChange]) -> None:
        if changes:
            await self.attack_surface_changes_collection.insert_many([c.model_dump() for c in changes])

    async def get_change_history(self, target_id: UUID, days: int = 30) -> list[ChangeEvent]:
        cutoff = datetime.utcnow() - timedelta(days=days)
        cursor = self.change_events_collection.find({"target_id": str(target_id), "detected_at": {"$gte": cutoff}}).sort("detected_at", -1)
        return [ChangeEvent(**doc) async for doc in cursor]

    async def create_detection_rule(self, rule: ChangeDetectionRule) -> ChangeDetectionRule:
        await self.detection_rules_collection.insert_one(rule.model_dump())
        return rule

    async def list_detection_rules(self) -> list[ChangeDetectionRule]:
        cursor = self.detection_rules_collection.find({"enabled": True})
        return [ChangeDetectionRule(**doc) async for doc in cursor]