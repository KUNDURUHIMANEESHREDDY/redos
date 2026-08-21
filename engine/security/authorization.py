"""
Centralized authorization with tenant isolation.

This module replaces scattered permission checks with a single
authorization engine that every request must pass through.

Tenant identity is derived from the authenticated JWT context, NOT
from the frontend. Every request resolves: User -> Organization ->
Project -> Resource, and authorization is verified before the resource
is retrieved.

RBAC roles:
  super_admin: full access across all tenants
  org_admin: full access within organization
  project_admin: full access within project
  user: read access within authorized project
  viewer: read-only limited access
  service_account: scoped to specific resources only

All sensitive operations are verified against RBAC. IDOR tests
must pass for every resource type.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Optional, Set

from engine.model.errors import AuthorizationError, TenantIsolationError


class ResourceType(str, Enum):
    """All resource types subject to authorization."""
    ORGANIZATION = "organization"
    PROJECT = "project"
    TARGET = "target"
    CAMPAIGN = "campaign"
    EXECUTION = "execution"
    FINDING = "finding"
    EVIDENCE = "evidence"
    ATTACK_GRAPH = "attack_graph"
    REGRESSION_TEST = "regression_test"
    REPORT = "report"
    KNOWLEDGE = "knowledge"
    DIGITAL_TWIN = "digital_twin"
    RISK_GRAPH = "risk_graph"
    ANALYTICS = "analytics"
    AUDIT_LOG = "audit_log"


class EvidencePermission(str, Enum):
    """Evidence access permissions (subset of global Permission set)."""
    READ = "evidence:read"
    DOWNLOAD = "evidence:download"
    EXPORT = "evidence:export"
    REPORT = "evidence:report"
    LINEAGE = "evidence:lineage"
    ARCHIVE_READ = "evidence:archive:read"
    ARCHIVE_WRITE = "evidence:archive:write"
    LEGAL_HOLD_READ = "evidence:legal_hold:read"
    LEGAL_HOLD_WRITE = "evidence:legal_hold:write"
    ADMIN = "evidence:admin"
ORG_READ = "org:read"
ORG_WRITE = "org:write"
ORG_DELETE = "org:delete"

PROJECT_READ = "project:read"
PROJECT_WRITE = "project:write"
PROJECT_DELETE = "project:delete"
PROJECT_MEMBERS = "project:members"

TARGET_READ = "target:read"
TARGET_WRITE = "target:write"
TARGET_DELETE = "target:delete"

CAMPAIGN_READ = "campaign:read"
CAMPAIGN_WRITE = "campaign:write"
CAMPAIGN_DELETE = "campaign:delete"
CAMPAIGN_EXECUTE = "campaign:execute"

EXECUTION_READ = "execution:read"
EXECUTION_WRITE = "execution:write"
EXECUTION_CANCEL = "execution:cancel"

FINDING_READ = "finding:read"
FINDING_WRITE = "finding:write"
FINDING_RESOLVE = "finding:resolve"

EVIDENCE_READ = "evidence:read"
EVIDENCE_DOWNLOAD = "evidence:download"
EVIDENCE_EXPORT = "evidence:export"
EVIDENCE_LINEAGE = "evidence:lineage"

ATTACK_GRAPH_VIEW = "attack_graph:view"
ATTACK_GRAPH_MODIFY = "attack_graph:modify"

REGRESSION_VIEW = "regression:view"
REGRESSION_RUN = "regression:run"

REPORT_VIEW = "report:view"
REPORT_GENERATE = "report:generate"

KNOWLEDGE_VIEW = "knowledge:view"
KNOWLEDGE_CONTRIBUTE = "knowledge:contribute"

DIGITAL_TWIN_VIEW = "digital_twin:view"
DIGITAL_TWIN_MODIFY = "digital_twin:modify"

RISK_GRAPH_VIEW = "risk_graph:view"
RISK_GRAPH_ANALYZE = "risk_graph:analyze"

ANALYTICS_VIEW = "analytics:view"

AUDIT_LOG_VIEW = "audit_log:view"


class Role(str, Enum):
    """RBAC roles with hierarchical permissions."""

    SUPER_ADMIN = "super_admin"
    ORG_ADMIN = "org_admin"
    PROJECT_ADMIN = "project_admin"
    USER = "user"
    VIEWER = "viewer"
    SERVICE_ACCOUNT = "service_account"


# Role -> Permission sets
ROLE_PERMISSIONS: dict = {
    Role.SUPER_ADMIN: set(
        [
            ORG_READ,
            ORG_WRITE,
            ORG_DELETE,
            PROJECT_READ,
            PROJECT_WRITE,
            PROJECT_DELETE,
            PROJECT_MEMBERS,
            TARGET_READ,
            TARGET_WRITE,
            CAMPAIGN_READ,
            CAMPAIGN_WRITE,
            CAMPAIGN_EXECUTE,
            EXECUTION_READ,
            EXECUTION_WRITE,
            EXECUTION_CANCEL,
            FINDING_READ,
            FINDING_WRITE,
            FINDING_RESOLVE,
            EVIDENCE_READ,
            EVIDENCE_DOWNLOAD,
            EVIDENCE_EXPORT,
            EVIDENCE_LINEAGE,
            ATTACK_GRAPH_VIEW,
            ATTACK_GRAPH_MODIFY,
            REGRESSION_VIEW,
            REGRESSION_RUN,
            REPORT_VIEW,
            REPORT_GENERATE,
            KNOWLEDGE_VIEW,
            KNOWLEDGE_CONTRIBUTE,
            DIGITAL_TWIN_VIEW,
            DIGITAL_TWIN_MODIFY,
            RISK_GRAPH_VIEW,
            RISK_GRAPH_ANALYZE,
            ANALYTICS_VIEW,
            AUDIT_LOG_VIEW,
        ]
    ),
    Role.ORG_ADMIN: set(
        [
            ORG_READ,
            ORG_WRITE,
            PROJECT_READ,
            PROJECT_WRITE,
            PROJECT_DELETE,
            PROJECT_MEMBERS,
            TARGET_READ,
            TARGET_WRITE,
            CAMPAIGN_READ,
            CAMPAIGN_WRITE,
            CAMPAIGN_EXECUTE,
            EXECUTION_READ,
            EXECUTION_WRITE,
            EXECUTION_CANCEL,
            FINDING_READ,
            FINDING_WRITE,
            FINDING_RESOLVE,
            EVIDENCE_READ,
            EVIDENCE_DOWNLOAD,
            EVIDENCE_EXPORT,
            ATTACK_GRAPH_VIEW,
            REGRESSION_VIEW,
            REGRESSION_RUN,
            REPORT_VIEW,
            REPORT_GENERATE,
            KNOWLEDGE_VIEW,
            DIGITAL_TWIN_VIEW,
            RISK_GRAPH_VIEW,
            ANALYTICS_VIEW,
            AUDIT_LOG_VIEW,
        ]
    ),
    Role.PROJECT_ADMIN: set(
        [
            PROJECT_READ,
            PROJECT_WRITE,
            PROJECT_DELETE,
            PROJECT_MEMBERS,
            TARGET_READ,
            TARGET_WRITE,
            CAMPAIGN_READ,
            CAMPAIGN_WRITE,
            CAMPAIGN_EXECUTE,
            EXECUTION_READ,
            EXECUTION_WRITE,
            EXECUTION_CANCEL,
            FINDING_READ,
            FINDING_WRITE,
            FINDING_RESOLVE,
            EVIDENCE_READ,
            EVIDENCE_DOWNLOAD,
            ATTACK_GRAPH_VIEW,
            REGRESSION_VIEW,
            REGRESSION_RUN,
            REPORT_VIEW,
            REPORT_GENERATE,
            KNOWLEDGE_VIEW,
            DIGITAL_TWIN_VIEW,
            RISK_GRAPH_VIEW,
            ANALYTICS_VIEW,
        ]
    ),
    Role.USER: set(
        [
            PROJECT_READ,
            TARGET_READ,
            EXECUTION_READ,
            EXECUTION_CANCEL,
            FINDING_READ,
            EVIDENCE_READ,
            ATTACK_GRAPH_VIEW,
            REGRESSION_VIEW,
            REPORT_VIEW,
            KNOWLEDGE_VIEW,
            DIGITAL_TWIN_VIEW,
            RISK_GRAPH_VIEW,
            ANALYTICS_VIEW,
        ]
    ),
    Role.VIEWER: set(
        [
            ORG_READ,
            PROJECT_READ,
            TARGET_READ,
            EXECUTION_READ,
            FINDING_READ,
            EVIDENCE_READ,
            ATTACK_GRAPH_VIEW,
            REGRESSION_VIEW,
            REPORT_VIEW,
            KNOWLEDGE_VIEW,
            DIGITAL_TWIN_VIEW,
            RISK_GRAPH_VIEW,
            ANALYTICS_VIEW,
        ]
    ),
    Role.SERVICE_ACCOUNT: set(),
}


def get_permissions(role: Role) -> set:
    """Return the permission set for a role."""
    return ROLE_PERMISSIONS.get(role, set())


def has_permission(role: Role, permission: str) -> bool:
    """Check if a role has a specific permission string."""
    return permission in ROLE_PERMISSIONS.get(role, set())


@dataclass(frozen=True, slots=True)
class UserContext:
    """Authentication context derived from JWT.

    This is what the backend constructs from the authenticated token.
    The frontend must NOT send org_id or project_id; those are derived
    from the user's organization membership and project assignments.
    """

    user_id: str
    email: str
    role: Role
    organization_id: str
    project_ids: Set[str] = field(default_factory=set)
    # Resource-specific scopes for service accounts
    authorized_resource_ids: Set[str] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class ResourceContext:
    """Context for a resource authorization check."""

    resource_type: ResourceType
    resource_id: str
    organization_id: str
    project_id: Optional[str] = None
    owner_tenant_id: Optional[str] = None  # For cross-tenant checks


@dataclass(frozen=True, slots=True)
class AccessRequest:
    """Request to access a resource."""

    user: UserContext
    resource: ResourceContext
    action: str  # permission string, not enum


class AuthorizationEngine:
    """Centralized authorization engine.

    Every request must pass through this engine before a resource is retrieved.
    It enforces tenant isolation and RBAC.

    The authorization flow:
    1. Resolve user's organization and projects from their context
    2. Verify tenant isolation (user cannot access another tenant's resources)
    3. Check RBAC permissions for the role
    4. For service accounts, verify authorized_resource_ids
    5. Return decision with reason
    """

    def __init__(self) -> None:
        self._access_log: list[dict] = []

    def authenticate(self, token_payload: dict[str, Any]) -> UserContext:
        """Construct a UserContext from a JWT token payload.

        The token MUST contain: sub, email, role, organization_id.
        Project IDs are optional (user may belong to multiple).
        """
        role_name = token_payload.get("role", "viewer")
        try:
            role = Role(role_name)
        except ValueError:
            role = Role.VIEWER

        return UserContext(
            user_id=token_payload["sub"],
            email=token_payload["email"],
            role=role,
            organization_id=token_payload["organization_id"],
            project_ids=set(token_payload.get("project_ids", [])),
            authorized_resource_ids=set(token_payload.get("authorized_resource_ids", [])),
        )

    def authorize(self, request: AccessRequest) -> dict[str, Any]:
        """Authorize an access request.

        Returns a dict with keys: allowed, reason, resource_type, resource_id.
        """
        # Step 1: Tenant isolation check
        if request.user.organization_id != request.resource.organization_id:
            self._log_access(request, False, "cross_tenant")
            return {
                "allowed": False,
                "reason": "cross-tenant access denied",
                "resource_type": request.resource.resource_type.value,
                "resource_id": request.resource.resource_id,
            }

        # Step 2: Role-based permission check
        permitted = has_permission(request.user.role, request.action)
        if not permitted:
            # Service account with specific resource IDs
            if (
                request.user.role == Role.SERVICE_ACCOUNT
                and request.user.authorized_resource_ids
                and request.resource.resource_id in request.user.authorized_resource_ids
            ):
                permitted = True

        if not permitted:
            self._log_access(request, False, "permission_denied")
            return {
                "allowed": False,
                "reason": f"permission denied: {request.action} for {request.user.role.value}",
                "resource_type": request.resource.resource_type.value,
                "resource_id": request.resource.resource_id,
            }

        # Step 3: Project-level check (if applicable)
        if request.resource.project_id and request.resource.project_id not in request.user.project_ids:
            if request.user.role not in (Role.SUPER_ADMIN, Role.ORG_ADMIN):
                self._log_access(request, False, "project_not_owned")
                return {
                    "allowed": False,
                    "reason": f"project {request.resource.project_id} not owned by user's organization",
                    "resource_type": request.resource.resource_type.value,
                    "resource_id": request.resource.resource_id,
                }

        # Step 4: Resource-specific checks can be added here

        self._log_access(request, True, "allowed")
        return {
            "allowed": True,
            "reason": "authorized",
            "resource_type": request.resource.resource_type.value,
            "resource_id": request.resource.resource_id,
        }

    def _log_access(self, request: AccessRequest, allowed: bool, reason: str) -> None:
        self._access_log.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_id": request.user.user_id,
                "email": request.user.email,
                "role": request.user.role.value,
                "organization_id": request.user.organization_id,
                "resource_type": request.resource.resource_type.value,
                "resource_id": request.resource.resource_id,
                "project_id": request.resource.project_id,
                "action": request.action,
                "allowed": allowed,
                "reason": reason,
            }
        )

    def get_access_log(self, user_id: str | None = None) -> list[dict]:
        """Get access log, optionally filtered by user."""
        logs = self._access_log
        if user_id:
            logs = [l for l in logs if l["user_id"] == user_id]
        return logs


# Global authorization engine instance
_authorization_engine: AuthorizationEngine | None = None


def get_authorization_engine() -> AuthorizationEngine:
    """Get the global authorization engine instance."""
    global _authorization_engine
    if _authorization_engine is None:
        _authorization_engine = AuthorizationEngine()
    return _authorization_engine


def authenticate_user(token_payload: dict[str, Any]) -> UserContext:
    """Convenience function to authenticate a user from JWT payload."""
    return get_authorization_engine().authenticate(token_payload)


def authorize_resource(
    user: UserContext,
    resource_type: ResourceType,
    resource_id: str,
    organization_id: str,
    project_id: Optional[str] = None,
    action: str = EVIDENCE_READ,
) -> dict[str, Any]:
    """Convenience function to authorize a resource access request."""
    from engine.security.authorization import ResourceContext

    resource = ResourceContext(
        resource_type=resource_type,
        resource_id=resource_id,
        organization_id=organization_id,
        project_id=project_id,
    )
    request = AccessRequest(user=user, resource=resource, action=action)
    return get_authorization_engine().authorize(request)


# ---- IDOR test cases ----

# To register IDOR tests, call: register_idor_tests()
# The test cases verify that a user from Org A cannot access Org B's resources.
# Expected statuses: "401" = unauthenticated, "403" = forbidden, "404" = hidden.

IDOR_TEST_CASES: list = []


def register_idor_tests() -> None:
    """Register comprehensive IDOR test cases for all resource types.

    This must be called after the engine.security module is fully loaded.
    """
    global IDOR_TEST_CASES

    def add(ri: dict) -> None:
        IDOR_TEST_CASES.append(ri)

    # Organization-level IDOR
    add(
        {
            "resource_type": ResourceType.ORGANIZATION,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "org_b",
            "action": ORG_READ,
            "expected_status": "403",
        }
    )

    # Project-level IDOR
    add(
        {
            "resource_type": ResourceType.PROJECT,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "project_b",
            "action": PROJECT_READ,
            "expected_status": "403",
        }
    )

    # Target-level IDOR (most critical)
    add(
        {
            "resource_type": ResourceType.TARGET,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "target_b",
            "action": TARGET_READ,
            "expected_status": "403",
        }
    )

    # Campaign-level IDOR
    add(
        {
            "resource_type": ResourceType.CAMPAIGN,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "campaign_b",
            "action": CAMPAIGN_READ,
            "expected_status": "403",
        }
    )

    # Execution-level IDOR
    add(
        {
            "resource_type": ResourceType.EXECUTION,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "execution_b",
            "action": EXECUTION_READ,
            "expected_status": "403",
        }
    )

    # Finding-level IDOR
    add(
        {
            "resource_type": ResourceType.FINDING,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "finding_b",
            "action": FINDING_READ,
            "expected_status": "403",
        }
    )

    # Evidence-level IDOR
    add(
        {
            "resource_type": ResourceType.EVIDENCE,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "evidence_b",
            "action": EVIDENCE_READ,
            "expected_status": "403",
        }
    )

    # Attack graph IDOR
    add(
        {
            "resource_type": ResourceType.ATTACK_GRAPH,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "attack_graph_b",
            "action": ATTACK_GRAPH_VIEW,
            "expected_status": "403",
        }
    )

    # Regression test IDOR
    add(
        {
            "resource_type": ResourceType.REGRESSION_TEST,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "regression_b",
            "action": REGRESSION_VIEW,
            "expected_status": "403",
        }
    )

    # Report IDOR
    add(
        {
            "resource_type": ResourceType.REPORT,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "report_b",
            "action": REPORT_VIEW,
            "expected_status": "403",
        }
    )

    # Knowledge IDOR
    add(
        {
            "resource_type": ResourceType.KNOWLEDGE,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "knowledge_b",
            "action": KNOWLEDGE_VIEW,
            "expected_status": "403",
        }
    )

    # Digital twin IDOR
    add(
        {
            "resource_type": ResourceType.DIGITAL_TWIN,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "digital_twin_b",
            "action": DIGITAL_TWIN_VIEW,
            "expected_status": "403",
        }
    )

    # Risk graph IDOR
    add(
        {
            "resource_type": ResourceType.RISK_GRAPH,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "risk_graph_b",
            "action": RISK_GRAPH_VIEW,
            "expected_status": "403",
        }
    )

    # Analytics IDOR
    add(
        {
            "resource_type": ResourceType.ANALYTICS,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "analytics_b",
            "action": ANALYTICS_VIEW,
            "expected_status": "403",
        }
    )

    # Audit log IDOR (should be 404 - intentionally hidden for other tenants)
    add(
        {
            "resource_type": ResourceType.AUDIT_LOG,
            "requesting_org": "org_a",
            "target_org": "org_b",
            "resource_id": "audit_log_b",
            "action": AUDIT_LOG_VIEW,
            "expected_status": "404",
        }
    )


# ---- End of module ----

__all__ = [
    "ResourceType",
    "ORG_READ",
    "ORG_WRITE",
    "ORG_DELETE",
    "PROJECT_READ",
    "PROJECT_WRITE",
    "PROJECT_DELETE",
    "PROJECT_MEMBERS",
    "TARGET_READ",
    "TARGET_WRITE",
    "TARGET_DELETE",
    "CAMPAIGN_READ",
    "CAMPAIGN_WRITE",
    "CAMPAIGN_DELETE",
    "CAMPAIGN_EXECUTE",
    "EXECUTION_READ",
    "EXECUTION_WRITE",
    "EXECUTION_CANCEL",
    "FINDING_READ",
    "FINDING_WRITE",
    "FINDING_RESOLVE",
    "EVIDENCE_READ",
    "EVIDENCE_DOWNLOAD",
    "EVIDENCE_EXPORT",
    "EVIDENCE_LINEAGE",
    "ATTACK_GRAPH_VIEW",
    "ATTACK_GRAPH_MODIFY",
    "REGRESSION_VIEW",
    "REGRESSION_RUN",
    "REPORT_VIEW",
    "REPORT_GENERATE",
    "KNOWLEDGE_VIEW",
    "KNOWLEDGE_CONTRIBUTE",
    "DIGITAL_TWIN_VIEW",
    "DIGITAL_TWIN_MODIFY",
    "RISK_GRAPH_VIEW",
    "RISK_GRAPH_ANALYZE",
    "ANALYTICS_VIEW",
    "AUDIT_LOG_VIEW",
    "Role",
    "UserContext",
    "ResourceContext",
    "AccessRequest",
    "AuthorizationEngine",
    "get_authorization_engine",
    "authenticate_user",
    "authorize_resource",
    "register_idor_tests",
    "IDOR_TEST_CASES",
    "has_permission",
    "get_permissions",
]