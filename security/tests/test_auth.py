import pytest
from uuid import uuid4
from datetime import datetime
from security.auth.models import (
    UserRole,
    Permission,
    User,
    UserCreate,
    UserUpdate,
    UserResponse,
    Token,
    TokenPayload,
    LoginRequest,
    ROLE_PERMISSIONS,
)


def test_user_role_enum():
    assert UserRole.ADMIN.value == "admin"
    assert UserRole.ANALYST.value == "analyst"
    assert UserRole.VIEWER.value == "viewer"
    assert UserRole.SERVICE.value == "service"


def test_permission_enum():
    assert Permission.EVIDENCE_READ.value == "evidence:read"
    assert Permission.FINDINGS_WRITE.value == "findings:write"
    assert Permission.ADMIN_USERS.value == "admin:users"


def test_role_permissions():
    admin_perms = ROLE_PERMISSIONS[UserRole.ADMIN]
    assert len(admin_perms) == len(Permission)
    
    analyst_perms = ROLE_PERMISSIONS[UserRole.ANALYST]
    assert Permission.EVIDENCE_READ in analyst_perms
    assert Permission.FINDINGS_WRITE in analyst_perms
    assert Permission.ADMIN_USERS not in analyst_perms
    
    viewer_perms = ROLE_PERMISSIONS[UserRole.VIEWER]
    assert Permission.EVIDENCE_READ in viewer_perms
    assert Permission.FINDINGS_WRITE not in viewer_perms
    assert Permission.ADMIN_USERS not in viewer_perms


def test_user_model():
    user = User(
        email="test@example.com",
        username="testuser",
        hashed_password="hashed_password",
        role=UserRole.ANALYST,
        permissions=[Permission.EVIDENCE_READ, Permission.FINDINGS_READ],
    )
    assert user.email == "test@example.com"
    assert user.username == "testuser"
    assert user.role == UserRole.ANALYST
    assert user.is_active is True
    assert user.is_superuser is False


def test_user_create_model():
    user_create = UserCreate(
        email="new@example.com",
        username="newuser",
        password="secure_password123",
        role=UserRole.VIEWER,
    )
    assert user_create.email == "new@example.com"
    assert user_create.password == "secure_password123"


def test_user_update_model():
    user_update = UserUpdate(
        email="updated@example.com",
        role=UserRole.ADMIN,
        is_active=False,
    )
    assert user_update.email == "updated@example.com"
    assert user_update.role == UserRole.ADMIN
    assert user_update.is_active is False


def test_user_response_model():
    user = User(
        id=uuid4(),
        email="test@example.com",
        username="testuser",
        hashed_password="hashed",
        role=UserRole.ANALYST,
        permissions=[Permission.EVIDENCE_READ],
    )
    response = UserResponse.from_user(user)
    assert response.email == "test@example.com"
    assert response.username == "testuser"
    assert response.role == UserRole.ANALYST
    assert Permission.EVIDENCE_READ in response.permissions


def test_token_model():
    token = Token(
        access_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        expires_in=1800,
    )
    assert token.token_type == "bearer"
    assert token.expires_in == 1800


def test_token_payload_model():
    payload = TokenPayload(
        sub=str(uuid4()),
        exp=1234567890,
        iat=1234567890,
        role=UserRole.ANALYST,
        permissions=[Permission.EVIDENCE_READ, Permission.FINDINGS_READ],
    )
    assert payload.role == UserRole.ANALYST


def test_login_request_model():
    login = LoginRequest(username="testuser", password="password123")
    assert login.username == "testuser"
    assert login.password == "password123"