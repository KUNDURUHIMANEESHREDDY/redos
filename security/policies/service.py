from datetime import datetime
from typing import Any
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field, ConfigDict
from security.database import get_database
from security.policies.models import SecurityPolicy, PolicyEvaluation
import structlog

logger = structlog.get_logger()


class SecurityPolicy(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    policy_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    category: str
    rules: list[dict[str, Any]] = Field(default_factory=list)
    severity_threshold: str = "medium"
    enabled: bool = True
    applies_to: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class PolicyEvaluation(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    evaluation_id: UUID = Field(default_factory=uuid4)
    policy_id: UUID
    execution_id: UUID
    passed: bool
    violations: list[dict[str, Any]] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)


class PolicyService:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.policies_collection = self.db.security_policies
        self.evaluations_collection = self.db.policy_evaluations
        self._load_default_policies()

    def _load_default_policies(self) -> None:
        self.default_policies = [
            SecurityPolicy(
                name="OWASP Top 10 Compliance",
                description="Enforce protection against OWASP Top 10 vulnerabilities",
                category="compliance",
                rules=[
                    {"vulnerability_type": "injection", "max_severity": "high"},
                    {"vulnerability_type": "broken_authentication", "max_severity": "high"},
                    {"vulnerability_type": "sensitive_data_exposure", "max_severity": "medium"},
                ],
                severity_threshold="high",
            ),
            SecurityPolicy(
                name="PCI DSS Requirements",
                description="Payment Card Industry Data Security Standard",
                category="compliance",
                rules=[
                    {"requirement": "encryption_in_transit", "enabled": True},
                    {"requirement": "encryption_at_rest", "enabled": True},
                    {"requirement": "access_control", "enabled": True},
                ],
                severity_threshold="critical",
            ),
            SecurityPolicy(
                name="Zero Critical Vulnerabilities",
                description="No critical severity findings allowed in production",
                category="release_gate",
                rules=[
                    {"max_critical_findings": 0},
                    {"max_high_findings": 5},
                ],
                severity_threshold="critical",
            ),
        ]

    async def create_policy(self, policy: SecurityPolicy) -> SecurityPolicy:
        await self.policies_collection.insert_one(policy.model_dump())
        return policy

    async def get_policy(self, policy_id: UUID) -> SecurityPolicy | None:
        doc = await self.policies_collection.find_one({"policy_id": str(policy_id)})
        return SecurityPolicy(**doc) if doc else None

    async def list_policies(self, category: str | None = None) -> list[SecurityPolicy]:
        query = {"category": category} if category else {}
        cursor = self.policies_collection.find(query)
        return [SecurityPolicy(**doc) async for doc in cursor]

    async def evaluate_policy(self, policy_id: UUID, execution_id: UUID, findings: list[dict[str, Any]]) -> PolicyEvaluation:
        policy = await self.get_policy(policy_id)
        if not policy:
            raise ValueError(f"Policy {policy_id} not found")

        violations = []
        for rule in policy.rules:
            violation = self._check_rule(rule, findings)
            if violation:
                violations.append(violation)

        passed = len(violations) == 0
        evaluation = PolicyEvaluation(
            policy_id=policy_id,
            execution_id=execution_id,
            passed=passed,
            violations=violations,
        )
        await self.evaluations_collection.insert_one(evaluation.model_dump())
        return evaluation

    def _check_rule(self, rule: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any] | None:
        if "vulnerability_type" in rule:
            max_severity = rule.get("max_severity", "critical")
            severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            max_level = severity_order.get(max_severity, 4)

            for finding in findings:
                if finding.get("vulnerability_type") == rule["vulnerability_type"]:
                    finding_level = severity_order.get(finding.get("severity", "info"), 0)
                    if finding_level > max_level:
                        return {
                            "rule": rule,
                            "finding": finding,
                            "message": f"Finding exceeds max severity {max_severity}",
                        }
        return None

    async def get_evaluations(self, execution_id: UUID) -> list[PolicyEvaluation]:
        cursor = self.evaluations_collection.find({"execution_id": str(execution_id)})
        return [PolicyEvaluation(**doc) async for doc in cursor]