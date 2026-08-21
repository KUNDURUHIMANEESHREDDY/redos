from datetime import datetime
from typing import Any
from uuid import UUID, uuid4
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field, ConfigDict
from security.models.finding import Finding, RemediationAction, RootCause, VulnerabilityType
from security.database import get_database
import structlog

logger = structlog.get_logger()


class RemediationTemplate(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    template_id: UUID = Field(default_factory=uuid4)
    vulnerability_type: VulnerabilityType
    title: str
    description: str
    default_actions: list[RemediationAction] = Field(default_factory=list)
    code_examples: dict[str, str] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class RemediationService:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.templates_collection = self.db.remediation_templates
        self.findings_collection = self.db.findings
        self._load_default_templates()

    def _load_default_templates(self) -> None:
        self.default_templates = {
            VulnerabilityType.SQL_INJECTION: RemediationTemplate(
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                title="Prevent SQL Injection",
                description="Use parameterized queries and prepared statements",
                default_actions=[
                    RemediationAction(
                        title="Use Parameterized Queries",
                        description="Replace string concatenation with parameterized queries",
                        category="code_change",
                        priority=1,
                        effort="low",
                        verification_steps=["Verify all database queries use parameters", "Test with SQL injection payloads"],
                    ),
                    RemediationAction(
                        title="Implement Input Validation",
                        description="Add allowlist validation for all user inputs",
                        category="code_change",
                        priority=2,
                        effort="medium",
                    ),
                ],
                code_examples={
                    "python_bad": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
                    "python_good": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
                },
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            ),
            VulnerabilityType.COMMAND_INJECTION: RemediationTemplate(
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                title="Prevent Command Injection",
                description="Avoid shell commands; use safe APIs",
                default_actions=[
                    RemediationAction(
                        title="Use Safe APIs",
                        description="Replace shell commands with language-native libraries",
                        category="code_change",
                        priority=1,
                        effort="medium",
                    ),
                    RemediationAction(
                        title="Input Sanitization",
                        description="Strict allowlist validation for any command arguments",
                        category="code_change",
                        priority=2,
                        effort="low",
                    ),
                ],
                references=["https://owasp.org/www-community/attacks/Command_Injection"],
            ),
            VulnerabilityType.XSS: RemediationTemplate(
                vulnerability_type=VulnerabilityType.XSS,
                title="Prevent Cross-Site Scripting",
                description="Encode output and implement CSP",
                default_actions=[
                    RemediationAction(
                        title="Output Encoding",
                        description="Context-aware output encoding for all user data",
                        category="code_change",
                        priority=1,
                        effort="low",
                    ),
                    RemediationAction(
                        title="Content Security Policy",
                        description="Implement strict CSP headers",
                        category="configuration",
                        priority=2,
                        effort="low",
                    ),
                ],
                references=["https://owasp.org/www-community/attacks/xss/"],
            ),
            VulnerabilityType.PATH_TRAVERSAL: RemediationTemplate(
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                title="Prevent Path Traversal",
                description="Validate and sanitize file paths",
                default_actions=[
                    RemediationAction(
                        title="Path Normalization",
                        description="Use os.path.realpath() and validate against allowed directories",
                        category="code_change",
                        priority=1,
                        effort="low",
                    ),
                ],
                references=["https://owasp.org/www-community/attacks/Path_Traversal"],
            ),
            VulnerabilityType.BROKEN_AUTH: RemediationTemplate(
                vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                title="Fix Authentication Issues",
                description="Implement secure authentication practices",
                default_actions=[
                    RemediationAction(
                        title="Multi-Factor Authentication",
                        description="Enable MFA for all user accounts",
                        category="configuration",
                        priority=1,
                        effort="medium",
                    ),
                    RemediationAction(
                        title="Secure Session Management",
                        description="Use secure, HttpOnly, SameSite cookies; implement rotation",
                        category="code_change",
                        priority=2,
                        effort="medium",
                    ),
                ],
                references=["https://owasp.org/www-community/attacks/Authentication_bypass"],
            ),
        }

    async def generate_remediation(self, finding: Finding) -> list[RemediationAction]:
        template = self.default_templates.get(finding.vulnerability_type)
        if not template:
            logger.warning("No remediation template for vulnerability type", type=finding.vulnerability_type.value)
            return []

        actions = []
        for default_action in template.default_actions:
            action = RemediationAction(
                title=default_action.title,
                description=default_action.description,
                category=default_action.category,
                priority=default_action.priority,
                effort=default_action.effort,
                verification_steps=default_action.verification_steps.copy(),
                references=template.references.copy(),
            )
            actions.append(action)

        if finding.root_cause:
            root_action = RemediationAction(
                title="Address Root Cause",
                description=f"Fix the root cause: {finding.root_cause.description}",
                category="code_change",
                priority=1,
                effort="high",
                verification_steps=[f"Verify fix at {finding.root_cause.code_location or 'unknown location'}"],
            )
            actions.insert(0, root_action)

        return actions

    async def apply_remediation(self, finding_id: UUID, actions: list[RemediationAction]) -> Finding | None:
        finding = await self._get_finding(finding_id)
        if not finding:
            return None

        finding.remediation = actions
        finding.status = FindingStatus.REMEDIATED
        finding.updated_at = datetime.utcnow()

        await self.findings_collection.replace_one(
            {"id": str(finding_id)},
            finding.model_dump(),
        )
        return finding

    async def verify_remediation(self, finding_id: UUID) -> Finding | None:
        finding = await self._get_finding(finding_id)
        if not finding:
            return None

        all_verified = all(
            action.verification_steps and len(action.verification_steps) > 0
            for action in finding.remediation
        )

        if all_verified:
            finding.status = FindingStatus.REGRESSION_TESTED
        else:
            finding.status = FindingStatus.REMEDIATED

        finding.updated_at = datetime.utcnow()
        await self.findings_collection.replace_one(
            {"id": str(finding_id)},
            finding.model_dump(),
        )
        return finding

    async def _get_finding(self, finding_id: UUID) -> Finding | None:
        doc = await self.findings_collection.find_one({"id": str(finding_id)})
        return Finding(**doc) if doc else None


class RootCauseAnalyzer:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.evidence_collection = self.db.evidence

    async def analyze(self, finding: Finding) -> RootCause:
        evidence_list = await self._get_evidence(finding.evidence_ids)

        cause = RootCause(
            description=self._determine_cause(finding, evidence_list),
            category=self._categorize_cause(finding),
            evidence_ids=finding.evidence_ids,
            contributing_factors=self._identify_factors(finding, evidence_list),
            code_location=self._locate_code(finding, evidence_list),
        )
        return cause

    def _determine_cause(self, finding: Finding, evidence: list) -> str:
        causes = {
            VulnerabilityType.SQL_INJECTION: "User input directly concatenated into SQL query without parameterization",
            VulnerabilityType.COMMAND_INJECTION: "User input passed directly to shell command execution",
            VulnerabilityType.XSS: "User input rendered in HTML without proper output encoding",
            VulnerabilityType.PATH_TRAVERSAL: "User-controlled file path used without validation",
            VulnerabilityType.BROKEN_AUTH: "Weak or missing authentication controls",
            VulnerabilityType.BROKEN_ACCESS_CONTROL: "Missing authorization checks for sensitive operations",
            VulnerabilityType.SENSITIVE_DATA_EXPOSURE: "Sensitive data transmitted or stored without encryption",
        }
        return causes.get(finding.vulnerability_type, "Unknown root cause")

    def _categorize_cause(self, finding: Finding) -> str:
        categories = {
            VulnerabilityType.SQL_INJECTION: "input_validation",
            VulnerabilityType.COMMAND_INJECTION: "input_validation",
            VulnerabilityType.XSS: "output_encoding",
            VulnerabilityType.PATH_TRAVERSAL: "input_validation",
            VulnerabilityType.BROKEN_AUTH: "authentication",
            VulnerabilityType.BROKEN_ACCESS_CONTROL: "authorization",
            VulnerabilityType.SENSITIVE_DATA_EXPOSURE: "cryptography",
        }
        return categories.get(finding.vulnerability_type, "unknown")

    def _identify_factors(self, finding: Finding, evidence: list) -> list[str]:
        factors = []
        for ev in evidence:
            if ev.normalized_data:
                if ev.type.value == "api_call" and ev.normalized_data.get("request_body"):
                    factors.append("Unvalidated API input")
                if ev.type.value == "process_trace" and "shell" in str(ev.normalized_data).lower():
                    factors.append("Shell command execution")
                if ev.type.value == "log_entry" and "error" in ev.normalized_data.get("level", ""):
                    factors.append("Error information disclosure")
        return list(set(factors))

    def _locate_code(self, finding: Finding, evidence: list) -> str | None:
        for ev in evidence:
            if ev.normalized_data and ev.type.value == "process_trace":
                return ev.normalized_data.get("command")
        return None

    async def _get_evidence(self, evidence_ids: list[UUID]) -> list:
        if not evidence_ids:
            return []
        cursor = self.evidence_collection.find({"_id": {"$in": [str(e) for e in evidence_ids]}})
        from security.models.evidence import Evidence
        return [Evidence(**doc) async for doc in cursor]