"""Standalone permission definitions.

This module defines Role and Permission enums and the ROLE_PERMISSIONS mapping
without importing from engine.* modules. It can be imported before the full
engine pipeline is set up.

All values are plain strings; no engine model references.
"""

from __future__ import annotations

from enum import Enum, auto
from typing import Any, Dict, FrozenSet, Set


class Role(str, Enum):
    """RBAC roles with hierarchical permissions."""
    SUPER_ADMIN = "super_admin"
    ORG_ADMIN = "org_admin"
    PROJECT_ADMIN = "project_admin"
    USER = "user"
    VIEWER = "viewer"
    SERVICE_ACCOUNT = "service_account"


# Permission actions as strings (resource:type/verb format)
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


def get_permissions(role: Role) -> FrozenSet[str]:
    """Return the permission frozenset for a role.

    This is a standalone function that does NOT import from engine modules.
    The full ROLE_PERMISSIONS mapping is defined separately.
    """
    try:
        from engine.security.authorization import ROLE_PERMISSIONS
    except ImportError:
        return frozenset()
    return frozenset(ROLE_PERMISSIONS.get(role, set()))


def has_permission(role: Role, permission: str) -> bool:
    """Check if a role has a specific permission string.

    Standalone version — does not import ROLE_PERMISSIONS eagerly.
    """
    try:
        from engine.security.authorization import ROLE_PERMISSIONS
    except ImportError:
        return False
    return permission in ROLE_PERMISSIONS.get(role, set())