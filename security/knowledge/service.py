from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from security.database import get_database
from security.knowledge.models import (
    KnowledgeEntry,
    KnowledgeType,
    KnowledgeStatus,
    AttackPattern,
    VulnerabilityPattern,
    RemediationPattern,
    RegressionPattern,
    TargetProfile,
    CampaignStrategy,
    KnowledgeEntrySearch,
    AttackPattern,
    VulnerabilityPattern,
    RemediationPattern,
    RegressionPattern,
    TargetProfile,
    CampaignStrategy,
)
from security.findings.models import Finding
from security.evidence.models import Evidence
from security.remediation.models import RemediationAction
from security.regression.models import RegressionRun
from security.posture.models import Target
import structlog

logger = structlog.get_logger()


class KnowledgeBase:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.entries_collection = self.db.knowledge_entries
        self.attack_patterns_collection = self.db.attack_patterns
        self.vuln_patterns_collection = self.db.vulnerability_patterns
        self.remediation_patterns_collection = self.db.remediation_patterns
        self.regression_patterns_collection = self.db.regression_patterns
        self.target_profiles_collection = self.db.target_profiles
        self.campaign_strategies_collection = self.db.campaign_strategies
        self.findings_collection = self.db.findings
        self.evidence_collection = self.db.evidence
        self.remediation_collection = self.db.remediation_actions
        self.regression_runs_collection = self.db.regression_runs
        self.targets_collection = self.db.targets

    async def create_entry(self, entry: KnowledgeEntry) -> KnowledgeEntry:
        await self.entries_collection.insert_one(entry.model_dump())
        logger.info("Knowledge entry created", entry_id=str(entry.entry_id), type=entry.knowledge_type.value)
        return entry

    async def get_entry(self, entry_id: UUID) -> Optional[KnowledgeEntry]:
        doc = await self.entries_collection.find_one({"entry_id": str(entry_id)})
        return KnowledgeEntry(**doc) if doc else None

    async def search_entries(self, search: KnowledgeEntrySearch) -> list[KnowledgeEntry]:
        query = {}
        if search.query:
            query["$or"] = [
                {"title": {"$regex": search.query, "$options": "i"}},
                {"description": {"$regex": search.query, "$options": "i"}},
            ]
        if search.knowledge_types:
            query["knowledge_type"] = {"$in": [t.value for t in search.knowledge_types]}
        if search.statuses:
            query["status"] = {"$in": search.statuses}
        if search.tags:
            query["tags"] = {"$in": search.tags}
        if search.mitre_techniques:
            query["mitre_techniques"] = {"$in": search.mitre_techniques}
        if search.vulnerability_types:
            query["vulnerability_types"] = {"$in": search.vulnerability_types}
        if search.target_ids:
            query["affected_targets"] = {"$in": [str(t) for t in search.target_ids]}
        if search.min_confidence > 0:
            query["confidence"] = {"$gte": search.min_confidence}
        if search.date_from or search.date_to:
            date_query = {}
            if search.date_from:
                date_query["$gte"] = search.date_from
            if search.date_to:
                date_query["$lte"] = search.date_to
            query["created_at"] = date_query

        cursor = self.entries_collection.find(query).skip(search.offset).limit(search.limit).sort("created_at", -1)
        return [KnowledgeEntry(**doc) async for doc in cursor]

    async def update_entry(self, entry_id: UUID, updates: dict[str, Any]) -> Optional[KnowledgeEntry]:
        updates["updated_at"] = datetime.utcnow()
        doc = await self.entries_collection.find_one_and_update(
            {"entry_id": str(entry_id)},
            {"$set": updates},
            return_document=True,
        )
        return KnowledgeEntry(**doc) if doc else None

    async def verify_entry(self, entry_id: UUID, verified_by: str) -> Optional[KnowledgeEntry]:
        return await self.update_entry(entry_id, {
            "status": KnowledgeStatus.VERIFIED,
            "verified_by": verified_by,
            "verified_at": datetime.utcnow(),
        })

    async def create_attack_pattern(self, pattern: AttackPattern) -> AttackPattern:
        await self.attack_patterns_collection.insert_one(pattern.model_dump())
        return pattern

    async def create_vulnerability_pattern(self, pattern: VulnerabilityPattern) -> VulnerabilityPattern:
        await self.vuln_patterns_collection.insert_one(pattern.model_dump())
        return pattern

    async def create_remediation_pattern(self, pattern: RemediationPattern) -> RemediationPattern:
        await self.remediation_patterns_collection.insert_one(pattern.model_dump())
        return pattern

    async def create_regression_pattern(self, pattern: RegressionPattern) -> RegressionPattern:
        await self.regression_patterns_collection.insert_one(pattern.model_dump())
        return pattern

    async def search_attack_patterns(self, vulnerability_type: Optional[str] = None, mitre_technique: Optional[str] = None) -> list[AttackPattern]:
        query = {}
        if vulnerability_type:
            query["vulnerability_type"] = vulnerability_type
        if mitre_technique:
            query["mitre_techniques"] = mitre_technique
        cursor = self.attack_patterns_collection.find(query)
        return [AttackPattern(**doc) async for doc in cursor]

    async def search_vulnerability_patterns(self, vulnerability_type: Optional[str] = None) -> list[VulnerabilityPattern]:
        query = {}
        if vulnerability_type:
            query["vulnerability_type"] = vulnerability_type
        cursor = self.vuln_patterns_collection.find(query)
        return [VulnerabilityPattern(**doc) async for doc in cursor]

    async def search_remediation_patterns(self, vulnerability_type: Optional[str] = None) -> list[RemediationPattern]:
        query = {}
        if vulnerability_type:
            query["vulnerability_type"] = vulnerability_type
        cursor = self.remediation_patterns_collection.find(query)
        return [RemediationPattern(**doc) async for doc in cursor]

    async def search_regression_patterns(self, vulnerability_type: Optional[str] = None) -> list[RegressionPattern]:
        query = {}
        if vulnerability_type:
            query["vulnerability_type"] = vulnerability_type
        cursor = self.regression_patterns_collection.find(query)
        return [RegressionPattern(**doc) async for doc in cursor]

    async def create_or_update_target_profile(self, profile: TargetProfile) -> TargetProfile:
        existing = await self.target_profiles_collection.find_one({"target_id": str(profile.target_id)})
        if existing:
            profile.profile_id = UUID(existing["profile_id"])
            profile.last_updated = datetime.utcnow()
            await self.target_profiles_collection.replace_one(
                {"profile_id": str(profile.profile_id)},
                profile.model_dump(),
            )
        else:
            await self.target_profiles_collection.insert_one(profile.model_dump())
        return profile

    async def get_target_profile(self, target_id: UUID) -> Optional[TargetProfile]:
        doc = await self.target_profiles_collection.find_one({"target_id": str(target_id)})
        return TargetProfile(**doc) if doc else None

    async def create_campaign_strategy(self, strategy: CampaignStrategy) -> CampaignStrategy:
        await self.campaign_strategies_collection.insert_one(strategy.model_dump())
        return strategy

    async def get_campaign_strategies(self, target_type: Optional[str] = None) -> list[CampaignStrategy]:
        query = {}
        if target_type:
            query["target_types"] = target_type
        cursor = self.campaign_strategies_collection.find(query)
        return [CampaignStrategy(**doc) async for doc in cursor]

    async def get_best_strategy_for_target(self, target_id: UUID) -> Optional[CampaignStrategy]:
        target = await self._get_target(target_id)
        if not target:
            return None
        strategies = await self.get_campaign_strategies(target.target_type.value)
        if not strategies:
            return None
        return max(strategies, key=lambda s: s.success_rate)

    async def extract_knowledge_from_finding(self, finding: Finding) -> list[KnowledgeEntry]:
        entries = []

        vuln_pattern = VulnerabilityPattern(
            entry_id=uuid4(),
            vulnerability_type=finding.vulnerability_type.value,
            root_cause_pattern=finding.root_cause.description if finding.root_cause else "Unknown",
            common_locations=[finding.target_id] if finding.target_id else [],
            trigger_conditions=[finding.attack_id],
            exploit_patterns=[finding.attack_id],
            detection_signatures=[finding.attack_id],
            remediation_patterns=[r.title for r in finding.remediation] if finding.remediation else [],
            false_positive_patterns=[],
            severity_distribution={finding.severity.value: 1},
            confidence=finding.confidence.value if hasattr(finding.confidence, 'value') else 0.8,
        )
        await self.create_vulnerability_pattern(vuln_pattern)

        entry = KnowledgeEntry(
            knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
            title=f"{finding.vulnerability_type.value} pattern",
            description=f"Pattern extracted from finding {finding.id}",
            content=vuln_pattern.model_dump(),
            status=KnowledgeStatus.DRAFT,
            confidence=finding.confidence.value if hasattr(finding.confidence, 'value') else 0.8,
            tags=[finding.vulnerability_type.value, "auto-extracted"],
            mitre_techniques=finding.attack_path.mitre_techniques if finding.attack_path else [],
            vulnerability_types=[finding.vulnerability_type.value],
            affected_targets=[finding.target_id] if finding.target_id else [],
            evidence_ids=finding.evidence_ids,
            finding_ids=[finding.id],
        )
        entries.append(entry)
        await self.create_entry(entry)

        if finding.remediation:
            remediation_pattern = RemediationPattern(
                entry_id=uuid4(),
                vulnerability_type=finding.vulnerability_type.value,
                title=f"Remediation for {finding.vulnerability_type.value}",
                description="Auto-extracted remediation pattern",
                remediation_steps=[r.description for r in finding.remediation],
                code_examples={r.title: r.description for r in finding.remediation},
                configuration_changes=[],
                verification_steps=[r.verification_steps for r in finding.remediation if r.verification_steps],
                effectiveness=0.8,
                effort_estimate="medium",
                prerequisites=[],
            )
            await self.create_remediation_pattern(remediation_pattern)

            entry = KnowledgeEntry(
                knowledge_type=KnowledgeType.REMEDIATION_PATTERN,
                title=f"Remediation for {finding.vulnerability_type.value}",
                description="Auto-extracted remediation pattern",
                content=remediation_pattern.model_dump(),
                status=KnowledgeStatus.DRAFT,
                confidence=0.8,
                tags=[finding.vulnerability_type.value, "remediation", "auto-extracted"],
                vulnerability_types=[finding.vulnerability_type.value],
                affected_targets=[finding.target_id] if finding.target_id else [],
                evidence_ids=finding.evidence_ids,
                finding_ids=[finding.id],
            )
            entries.append(entry)
            await self.create_entry(entry)

        return entries

    async def extract_regression_pattern(self, finding: Finding, execution_a: UUID, execution_b: UUID) -> Optional[KnowledgeEntry]:
        runs_a = await self.db.regression_runs.find({"finding_id": str(finding.id), "execution_id": str(execution_a)}).to_list(None)
        runs_b = await self.db.regression_runs.find({"finding_id": str(finding.id), "execution_id": str(execution_b)}).to_list(None)

        result_a = runs_a[0].get("result") if runs_a else None
        result_b = runs_b[0].get("result") if runs_b else None

        if result_a == "fixed" and result_b == "regression":
            pattern = RegressionPattern(
                entry_id=uuid4(),
                vulnerability_type=finding.vulnerability_type.value,
                regression_triggers=["system_prompt_change", "tool_permission_change", "model_change"],
                detection_patterns=[finding.attack_id],
                recurrence_rate=0.0,
                typical_time_to_regression=0,
                prevention_strategies=["Monitor for system prompt changes", "Validate tool permissions after changes"],
                detection_rules=[f"Check for {finding.attack_id} regression"],
                confidence=0.8,
            )
            await self.create_regression_pattern(pattern)

            entry = KnowledgeEntry(
                knowledge_type=KnowledgeType.REGRESSION_PATTERN,
                title=f"Regression pattern for {finding.vulnerability_type.value}",
                description=f"Regression pattern detected for {finding.attack_id}",
                content=pattern.model_dump(),
                status=KnowledgeStatus.DRAFT,
                confidence=0.8,
                tags=[finding.vulnerability_type.value, "regression", "auto-extracted"],
                mitre_techniques=finding.attack_path.mitre_techniques if finding.attack_path else [],
                vulnerability_types=[finding.vulnerability_type.value],
                affected_targets=[finding.target_id] if finding.target_id else [],
                evidence_ids=finding.evidence_ids,
                finding_ids=[finding.id],
            )
            await self.create_entry(entry)
            return entry
        return None

    async def update_target_profile(self, target_id: UUID) -> TargetProfile:
        findings = await self._get_findings_for_target(target_id)
        
        if not findings:
            return TargetProfile(target_id=target_id, target_type="unknown")

        vuln_counts = {}
        attack_vectors = set()
        for f in findings:
            vuln_counts[f.vulnerability_type.value] = vuln_counts.get(f.vulnerability_type.value, 0) + 1
            attack_vectors.add(f.attack_id)

        regressions = await self.db.regression_runs.find({"finding_id": {"$in": [str(f.id) for f in findings]}, "result": "regression"}).to_list(None)
        
        fixed_count = len([f for f in findings if f.status.value in ("fixed", "verified")])
        remediation_velocity = fixed_count / max(1, len(findings))

        attack_success_rate = len([r for r in regressions if r.get("result") == "regression"]) / max(1, len(regressions))

        profile = TargetProfile(
            target_id=target_id,
            target_type="unknown",
            attack_surface_summary={
                "total_findings": len(findings),
                "by_type": vuln_counts,
                "attack_vectors": list(attack_vectors),
            },
            common_vulnerabilities=sorted(vuln_counts.keys(), key=lambda k: vuln_counts[k], reverse=True)[:5],
            common_attack_vectors=list(attack_vectors)[:5],
            risk_profile=self._determine_risk_profile(findings),
            defense_posture={
                "remediation_velocity": remediation_velocity,
                "regression_rate": len(regressions) / max(1, len(findings)),
            },
            historical_regressions=len(regressions),
            remediation_velocity=remediation_velocity,
            attack_success_rate=attack_success_rate,
        )
        
        await self.create_or_update_target_profile(profile)
        return profile

    def _determine_risk_profile(self, findings: list) -> str:
        if not findings:
            return "unknown"
        critical = len([f for f in findings if f.severity.value == "critical"])
        high = len([f for f in findings if f.severity.value == "high"])
        if critical > 0:
            return "critical"
        elif high > 2:
            return "high"
        elif high > 0 or len(findings) > 5:
            return "medium"
        return "low"

    async def _get_target(self, target_id: UUID) -> Optional[Target]:
        doc = await self.targets_collection.find_one({"id": str(target_id)})
        return Target(**doc) if doc else None

    async def _get_findings_for_target(self, target_id: UUID) -> list[Finding]:
        cursor = self.findings_collection.find({"target_id": str(target_id)})
        return [Finding(**doc) async for doc in cursor]