from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from security.database import get_database
from security.auth.service import AuthService
from security.auth.dependencies import get_auth_service, get_current_active_user, RequireAdminUsers
from security.auth.models import User, UserCreate, UserUpdate, UserResponse, LoginRequest, Token, TokenPayload
from security.config import settings
import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
async def login(
    request: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    user = await auth_service.authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await auth_service.update_last_login(user.id)

    access_token = auth_service.create_access_token(
        user, expires_delta=timedelta(minutes=settings.access_token_expire_minutes)
    )
    return Token(
        access_token=access_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_create: UserCreate,
    auth_service: AuthService = Depends(get_auth_service),
):
    try:
        user = await auth_service.create_user(user_create)
        return UserResponse.from_user(user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user),
):
    return UserResponse.from_user(current_user)


@router.patch("/me", response_model=UserResponse)
async def update_current_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    updated = await auth_service.update_user(current_user.id, user_update)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse.from_user(updated)


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(RequireAdminUsers),
    auth_service: AuthService = Depends(get_auth_service),
):
    users = await auth_service.list_users(skip=skip, limit=limit)
    return [UserResponse.from_user(u) for u in users]


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: User = Depends(RequireAdminUsers),
    auth_service: AuthService = Depends(get_auth_service),
):
    from uuid import UUID
    user = await auth_service.get_user(UUID(user_id))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse.from_user(user)


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    current_user: User = Depends(RequireAdminUsers),
    auth_service: AuthService = Depends(get_auth_service),
):
    from uuid import UUID
    updated = await auth_service.update_user(UUID(user_id), user_update)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse.from_user(updated)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user: User = Depends(RequireAdminUsers),
    auth_service: AuthService = Depends(get_auth_service),
):
    from uuid import UUID
    deleted = await auth_service.delete_user(UUID(user_id))
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")


@router.post("/refresh", response_model=Token)
async def refresh_token(
    current_user: User = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    access_token = auth_service.create_access_token(
        current_user, expires_delta=timedelta(minutes=settings.access_token_expire_minutes)
    )
    return Token(
        access_token=access_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )