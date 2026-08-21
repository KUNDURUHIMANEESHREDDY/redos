from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Annotated
from uuid import UUID
from motor.motor_asyncio import AsyncIOMotorDatabase
from security.database import get_database
from security.auth.service import AuthService, PermissionService, get_current_user
from security.auth.models import User, Permission, UserRole, TokenPayload
import structlog

logger = structlog.get_logger()

security_scheme = HTTPBearer(auto_error=False)


async def get_auth_service(db: AsyncIOMotorDatabase = Depends(get_database)) -> AuthService:
    return AuthService(db)


async def get_current_user_dep(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(security_scheme)],
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await get_current_user(credentials.credentials, auth_service.db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User inactive",
        )
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user_dep)) -> User:
    return current_user


def require_permission(permission: Permission):
    async def permission_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if not PermissionService.user_has_permission(current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value}",
            )
        return current_user
    return permission_checker


def require_any_permission(permissions: list[Permission]):
    async def permission_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if not PermissionService.user_has_any_permission(current_user, permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: requires one of {[p.value for p in permissions]}",
            )
        return current_user
    return permission_checker


def require_all_permissions(permissions: list[Permission]):
    async def permission_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if not PermissionService.user_has_all_permissions(current_user, permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: requires all of {[p.value for p in permissions]}",
            )
        return current_user
    return permission_checker


def require_role(role: UserRole):
    async def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        role_hierarchy = {
            UserRole.VIEWER: 0,
            UserRole.ANALYST: 1,
            UserRole.ADMIN: 2,
            UserRole.SERVICE: 3,
        }
        if role_hierarchy.get(current_user.role, 0) < role_hierarchy.get(role, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {role.value}",
            )
        return current_user
    return role_checker


# Common permission dependencies
RequireEvidenceRead = require_permission(Permission.EVIDENCE_READ)
RequireEvidenceWrite = require_permission(Permission.EVIDENCE_WRITE)
RequireFindingsRead = require_permission(Permission.FINDINGS_READ)
RequireFindingsWrite = require_permission(Permission.FINDINGS_WRITE)
RequireFindingsManage = require_permission(Permission.FINDINGS_MANAGE)
RequireAnalysisRead = require_permission(Permission.ANALYSIS_READ)
RequireAnalysisWrite = require_permission(Permission.ANALYSIS_WRITE)
RequireAttackGraphRead = require_permission(Permission.ATTACK_GRAPH_READ)
RequireAttackGraphWrite = require_permission(Permission.ATTACK_GRAPH_WRITE)
RequireRemediationRead = require_permission(Permission.REMEDIATION_READ)
RequireRemediationWrite = require_permission(Permission.REMEDIATION_WRITE)
RequireRegressionRead = require_permission(Permission.REGRESSION_READ)
RequireRegressionWrite = require_permission(Permission.REGRESSION_WRITE)
RequirePoliciesRead = require_permission(Permission.POLICIES_READ)
RequirePoliciesWrite = require_permission(Permission.POLICIES_WRITE)
RequireBaselinesRead = require_permission(Permission.BASELINES_READ)
RequireBaselinesWrite = require_permission(Permission.BASELINES_WRITE)
RequireSeverityRead = require_permission(Permission.SEVERITY_READ)
RequireSeverityWrite = require_permission(Permission.SEVERITY_WRITE)
RequireAdminUsers = require_permission(Permission.ADMIN_USERS)
RequireAdminSystem = require_permission(Permission.ADMIN_SYSTEM)
RequireAdmin = require_role(UserRole.ADMIN)
RequireAnalyst = require_role(UserRole.ANALYST)