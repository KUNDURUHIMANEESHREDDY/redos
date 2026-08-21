from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict, EmailStr


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    SERVICE = "service"


class Permission(str, Enum):
    EVIDENCE_READ = "evidence:read"
    EVIDENCE_WRITE = "evidence:write"
    FINDINGS_READ = "findings:read"
    FINDINGS_WRITE = "findings:write"
    FINDINGS_MANAGE = "findings:manage"
    ANALYSIS_READ = "analysis:read"
    ANALYSIS_WRITE = "analysis:write"
    ATTACK_GRAPH_READ = "attack_graph:read"
    ATTACK_GRAPH_WRITE = "attack_graph:write"
    REMEDIATION_READ = "remediation:read"
    REMEDIATION_WRITE = "remediation:write"
    REGRESSION_READ = "regression:read"
    REGRESSION_WRITE = "regression:write"
    POLICIES_READ = "policies:read"
    POLICIES_WRITE = "policies:write"
    BASELINES_READ = "baselines:read"
    BASELINES_WRITE = "baselines:write"
    SEVERITY_READ = "severity:read"
    SEVERITY_WRITE = "severity:write"
    ADMIN_USERS = "admin:users"
    ADMIN_SYSTEM = "admin:system"


ROLE_PERMISSIONS: dict[UserRole, list[Permission]] = {
    UserRole.ADMIN: list(Permission),
    UserRole.ANALYST: [
        Permission.EVIDENCE_READ,
        Permission.EVIDENCE_WRITE,
        Permission.FINDINGS_READ,
        Permission.FINDINGS_WRITE,
        Permission.FINDINGS_MANAGE,
        Permission.ANALYSIS_READ,
        Permission.ANALYSIS_WRITE,
        Permission.ATTACK_GRAPH_READ,
        Permission.ATTACK_GRAPH_WRITE,
        Permission.REMEDIATION_READ,
        Permission.REMEDIATION_WRITE,
        Permission.REGRESSION_READ,
        Permission.REGRESSION_WRITE,
        Permission.POLICIES_READ,
        Permission.POLICIES_WRITE,
        Permission.BASELINES_READ,
        Permission.BASELINES_WRITE,
        Permission.SEVERITY_READ,
        Permission.SEVERITY_WRITE,
    ],
    UserRole.VIEWER: [
        Permission.EVIDENCE_READ,
        Permission.FINDINGS_READ,
        Permission.ANALYSIS_READ,
        Permission.ATTACK_GRAPH_READ,
        Permission.REMEDIATION_READ,
        Permission.REGRESSION_READ,
        Permission.POLICIES_READ,
        Permission.BASELINES_READ,
        Permission.SEVERITY_READ,
    ],
    UserRole.SERVICE: [
        Permission.EVIDENCE_WRITE,
        Permission.FINDINGS_WRITE,
        Permission.ANALYSIS_WRITE,
        Permission.ATTACK_GRAPH_WRITE,
        Permission.REMEDIATION_WRITE,
        Permission.REGRESSION_WRITE,
        Permission.SEVERITY_WRITE,
    ],
}


class User(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: UUID = Field(default_factory=uuid4)
    email: EmailStr
    username: str
    hashed_password: str
    role: UserRole = UserRole.VIEWER
    is_active: bool = True
    is_superuser: bool = False
    permissions: list[Permission] = Field(default_factory=list)
    last_login: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    role: UserRole = UserRole.VIEWER


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    username: str | None = None
    password: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class UserResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: UUID
    email: EmailStr
    username: str
    role: UserRole
    is_active: bool
    is_superuser: bool
    permissions: list[Permission]
    last_login: datetime | None
    created_at: datetime

    @classmethod
    def from_user(cls, user: User) -> "UserResponse":
        return cls(
            id=user.id,
            email=user.email,
            username=user.username,
            role=user.role,
            is_active=user.is_active,
            is_superuser=user.is_superuser,
            permissions=user.permissions,
            last_login=user.last_login,
            created_at=user.created_at,
        )


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenPayload(BaseModel):
    sub: str
    exp: int
    iat: int
    role: UserRole
    permissions: list[Permission]


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str