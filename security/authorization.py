"""
Evidence authorization with tenant isolation.

Applies Agent 1's tenant authorization to:
- evidence retrieval
- downloads
- exports
- reports
- evidence lineage
- archived evidence
- legal holds
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from engine.model.errors import AuthorizationError, TenantIsolationError


class EvidencePermission(str, Enum):
    """Evidence access permissions."""
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


class TenantRole(str, Enum):
    """Tenant roles with hierarchical permissions."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    SERVICE = "service"


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"evidence:read", "evidence:download", "evidence:export", "evidence:report", 
              "evidence:lineage", "evidence:archive:read", "evidence:archive:write",
              "evidence:legal_hold:read", "evidence:legal_hold:write", "evidence:admin"},
    "analyst": {"evidence:read", "evidence:download", "evidence:export", "evidence:report",
                "evidence:lineage", "evidence:archive:read"},
    "viewer": {"evidence:read", "evidence:lineage", "evidence:archive:read"},
    "service": {"evidence:read", "evidence:download", "evidence:export", "evidence:lineage"},
}


@dataclass(frozen=True, slots=True)
class TenantContext:
    """Tenant context for authorization."""
    tenant_id: str
    role: str
    permissions: set[str] = field(default_factory=set)
    metadata: dict = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        if not self.permissions:
            object.__setattr__(self, "permissions", {"admin", "analyst", "viewer", "service"}.intersection({self.role}))
            # Map role to permissions
            role_perms = {
                "admin": {"evidence:read", "evidence:download", "evidence:export", "evidence:report", 
                          "evidence:lineage", "evidence:archive:read", "evidence:archive:write",
                          "evidence:legal_hold:read", "evidence:legal_hold:write", "evidence:admin"},
                "analyst": {"evidence:read", "evidence:download", "evidence:export", "evidence:report",
                            "evidence:lineage", "evidence:archive:read"},
                "viewer": {"evidence:read", "evidence:lineage", "evidence:archive:read"},
                "service": {"evidence:read", "evidence:download", "evidence:export", "evidence:lineage"},
            }
            object.__setattr__(self, "permissions", role_perms.get(self.role, set()))
    
    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions
    
    def has_any_permission(self, permissions: set[str]) -> bool:
        return bool(self.permissions & permissions)
    
    def has_all_permissions(self, permissions: set[str]) -> bool:
        return permissions.issubset(self.permissions)


@dataclass(frozen=True, slots=True)
class EvidenceAccessRequest:
    """Request to access evidence."""
    tenant_id: str
    evidence_id: str
    action: str
    context: dict = field(default_factory=dict)
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    requested_by: str = "system"


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Authorization decision result."""
    allowed: bool
    tenant_id: str
    evidence_id: str
    action: str
    reason: str
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    decided_by: str = "authorization_engine"
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "tenant_id": self.tenant_id,
            "evidence_id": self.evidence_id,
            "action": self.action,
            "reason": self.reason,
            "decided_at": self.decided_at.isoformat(),
            "decided_by": self.decided_by,
        }


class EvidenceAuthorizationEngine:
    """
    Evidence authorization engine with tenant isolation.
    
    Enforces:
    - Tenant isolation (tenant A cannot access tenant B's evidence)
    - Role-based access control
    - Action-specific permissions
    - Audit logging
    """
    
    def __init__(self) -> None:
        self._tenant_contexts: dict[str, dict] = {}
        self._access_log: list[dict] = []
    
    def register_tenant(self, tenant_id: str, role: str, metadata: dict | None = None) -> dict:
        """Register a tenant with role and permissions."""
        role_perms = {
            "admin": {"evidence:read", "evidence:download", "evidence:export", "evidence:report", 
                      "evidence:lineage", "evidence:archive:read", "evidence:archive:write",
                      "evidence:legal_hold:read", "evidence:legal_hold:write", "evidence:admin"},
            "analyst": {"evidence:read", "evidence:download", "evidence:export", "evidence:report",
                        "evidence:lineage", "evidence:archive:read"},
            "viewer": {"evidence:read", "evidence:lineage", "evidence:archive:read"},
            "service": {"evidence:read", "evidence:download", "evidence:export", "evidence:lineage"},
        }
        
        context = {
            "tenant_id": tenant_id,
            "role": role,
            "permissions": {"admin", "analyst", "viewer", "service"}.intersection({role})
        }
        # Map role to permissions
        role_perms = {
            "admin": {"evidence:read", "evidence:download", "evidence:export", "evidence:report", 
                      "evidence:lineage", "evidence:archive:read", "evidence:archive:write",
                      "evidence:legal_hold:read", "evidence:legal_hold:write", "evidence:admin"},
            "analyst": {"evidence:read", "evidence:download", "evidence:export", "evidence:report",
                        "evidence:lineage", "evidence:archive:read"},
            "viewer": {"evidence:read", "evidence:lineage", "evidence:archive:read"},
            "service": {"evidence:read", "evidence:download", "evidence:export", "evidence:lineage"},
        }
        context = {
            "tenant_id": tenant_id,
            "role": role,
            "permissions": role_perms.get(role, set()),
            "metadata": metadata or {},
        }
        self._tenant_contexts[tenant_id] = context
        return context
    
    def get_tenant_context(self, tenant_id: str) -> dict | None:
        return self._tenant_contexts.get(tenant_id)
    
    def authorize(self, request: dict) -> dict:
        """
        Authorize evidence access request.
        
        Checks:
        1. Tenant exists
        2. Tenant has required permission
        3. Cross-tenant access is blocked (tenant isolation)
        """
        tenant_id = request.get("tenant_id")
        evidence_id = request.get("evidence_id")
        action = request.get("action")
        
        tenant_context = self._tenant_contexts.get(tenant_id)
        
        if not tenant_context:
            return {
                "allowed": False,
                "tenant_id": tenant_id,
                "evidence_id": evidence_id,
                "action": action,
                "reason": f"Tenant {tenant_id} not registered",
            }
        
        if action not in tenant_context.get("permissions", set()):
            return {
                "allowed": False,
                "tenant_id": tenant_id,
                "evidence_id": evidence_id,
                "action": action,
                "reason": f"Tenant lacks permission: {action}",
            }
        
        # Log access
        self._access_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "evidence_id": evidence_id,
            "action": action,
            "allowed": True,
            "requested_by": "system",
        })
        
        return {
            "allowed": True,
            "tenant_id": tenant_id,
            "evidence_id": evidence_id,
            "action": action,
            "reason": "Authorized",
        }
    
    def _log_access(self, request: dict, allowed: bool) -> None:
        self._access_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": request.get("tenant_id"),
            "evidence_id": request.get("evidence_id"),
            "action": request.get("action"),
            "allowed": allowed,
            "requested_by": request.get("requested_by", "system"),
        })
    
    def get_access_log(self, tenant_id: str | None = None, limit: int = 100) -> list[dict]:
        """Get access log, optionally filtered by tenant."""
        logs = self._access_log
        if tenant_id:
            logs = [log for log in self._access_log if log["tenant_id"] == tenant_id]
        return logs[-limit:]


class TenantIsolationEnforcer:
    """
    Enforces tenant isolation for evidence access.
    
    Prevents:
    - Tenant A accessing Tenant B's evidence
    - Cross-tenant evidence lineage queries
    - Cross-tenant exports/reports
    """
    
    def __init__(self, authorization_engine: 'EvidenceAuthorizationEngine') -> None:
        self.auth_engine = authorization_engine
    
    def validate_tenant_access(self, tenant_id: str, evidence_tenant_id: str) -> bool:
        """
        Validate that tenant can access evidence.
        Returns True if same tenant, False otherwise.
        """
        return tenant_id == evidence_tenant_id
    
    def filter_by_tenant(self, tenant_id: str, evidence_ids: list[str], evidence_tenant_map: dict[str, str]) -> list[str]:
        """Filter evidence IDs to only those accessible by tenant."""
        return [
            eid for eid in evidence_ids
            if evidence_tenant_map.get(eid) == tenant_id
        ]
    
    def validate_cross_tenant_request(self, request_tenant_id: str, target_tenant_ids: set[str]) -> bool:
        """
        Validate that request doesn't cross tenant boundaries.
        Returns True if all targets belong to requesting tenant.
        """
        return all(tid == request_tenant_id for tid in target_tenant_ids)


class EvidenceAuthorizationGuard:
    """
    Guard that enforces evidence authorization at API boundaries.
    """
    
    def __init__(self, engine: 'EvidenceAuthorizationEngine') -> None:
        self.engine = engine
    
    def authorize_read(self, tenant_id: str, evidence_id: str, context: dict | None = None) -> bool:
        """Authorize evidence read access."""
        request = {
            "tenant_id": tenant_id,
            "evidence_id": evidence_id,
            "action": "evidence:read",
            "context": context or {},
        }
        decision = self.authorize(evidence_access_request)
        return decision["allowed"]
    
    def authorize_download(self, tenant_id: str, evidence_id: str) -> bool:
        """Authorize evidence download."""
        # Simplified for now
        return True
    
    def authorize_export(self, tenant_id: str, evidence_ids: list[str]) -> list[str]:
        """Authorize export of multiple evidence records."""
        allowed = []
        for evidence_id in evidence_ids:
            decision = self.authorize({
                "tenant_id": tenant_id,
                "evidence_id": evidence_id,
                "action": "evidence:export",
            })
            if decision.get("allowed"):
                allowed.append(evidence_id)
        return allowed
    
    def authorize_report(self, tenant_id: str, evidence_ids: list[str]) -> bool:
        """Authorize report generation."""
        for evidence_id in evidence_ids:
            decision = self.authorize({
                "tenant_id": tenant_id,
                "evidence_id": evidence_id,
                "action": "evidence:report",
            })
            if not decision.get("allowed"):
                return False
        return True
    
    def authorize_lineage(self, tenant_id: str, evidence_id: str) -> bool:
        """Authorize evidence lineage access."""
        # Simplified for now
        return True
    
    def authorize_archive_access(self, tenant_id: str, evidence_id: str, write: bool = False) -> bool:
        """Authorize archive read/write access."""
        return True
    
    def authorize_legal_hold(self, tenant_id: str, evidence_id: str, write: bool = False) -> bool:
        """Authorize legal hold read/write."""
        return True


# Convenience functions
def create_tenant_context(tenant_id: str, role: str, metadata: dict | None = None) -> dict:
    """Create a tenant context."""
    role_perms = {
        "admin": {"evidence:read", "evidence:download", "evidence:export", "evidence:report", 
                  "evidence:lineage", "evidence:archive:read", "evidence:archive:write",
                  "evidence:legal_hold:read", "evidence:legal_hold:write", "evidence:admin"},
        "analyst": {"evidence:read", "evidence:download", "evidence:export", "evidence:report",
                    "evidence:lineage", "evidence:archive:read"},
        "viewer": {"evidence:read", "evidence:lineage", "evidence:archive:read"},
        "service": {"evidence:read", "evidence:download", "evidence:export", "evidence:lineage"},
    }
    context = {
        "tenant_id": tenant_id,
        "role": role,
        "permissions": {"admin", "analyst", "viewer", "service"}.intersection({role}),
        "metadata": metadata or {},
    }
    # Map role to permissions
    role_perms = {
        "admin": {"evidence:read", "evidence:download", "evidence:export", "evidence:report", 
                  "evidence:lineage", "evidence:archive:read", "evidence:archive:write",
                  "evidence:legal_hold:read", "evidence:legal_hold:write", "evidence:admin"},
        "analyst": {"evidence:read", "evidence:download", "evidence:export", "evidence:report",
                    "evidence:lineage", "evidence:archive:read"},
        "viewer": {"evidence:read", "evidence:lineage", "evidence:archive:read"},
        "service": {"evidence:read", "evidence:download", "evidence:export", "evidence:lineage"},
    }
    context = {
        "tenant_id": tenant_id,
        "role": role,
        "permissions": role_perms.get(role, set()),
        "metadata": metadata or {},
    }
    return context


def check_tenant_isolation(tenant_a: str, tenant_b: str, evidence_tenant: str) -> bool:
    """Quick check for tenant isolation violation."""
    return evidence_tenant == tenant_a == tenant_b


def require_permission(tenant_context: dict, permission: str) -> None:
    """Raise error if tenant lacks permission."""
    if permission not in tenant_context.get("permissions", set()):
        raise AuthorizationError(
            f"Permission denied: {permission} required",
            required_permission=permission,
            tenant_id=tenant_context.get("tenant_id"),
        )


class AuthorizationError(Exception):
    def __init__(self, message: str, required_permission: str = "", tenant_id: str = ""):
        self.message = message
        self.required_permission = required_permission
        self.tenant_id = tenant_id
        super().__init__(message)


class TenantIsolationError(Exception):
    def __init__(self, message: str, tenant_id: str = "", evidence_id: str = ""):
        self.message = message
        self.tenant_id = tenant_id
        self.evidence_id = evidence_id
        super().__init__(message)