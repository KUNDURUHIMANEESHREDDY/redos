from datetime import datetime, timedelta
from typing import Any
from uuid import UUID
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field, ConfigDict
from passlib.context import CryptContext
from jose import jwt, JWTError
from security.database import get_database
from security.config import settings
from security.auth.models import User, UserCreate, UserUpdate, UserResponse, Token, TokenPayload, Permission, UserRole
import structlog

logger = structlog.get_logger()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    def __init__(self, db: AsyncIOMotorDatabase | None = None):
        self.db = db or get_database()
        self.users_collection = self.db.users

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str) -> str:
        return pwd_context.hash(password)

    def create_access_token(self, user: User, expires_delta: timedelta | None = None) -> str:
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)

        to_encode = {
            "sub": str(user.id),
            "username": user.username,
            "role": user.role.value,
            "permissions": [p.value for p in user.permissions],
            "exp": expire,
            "iat": datetime.utcnow(),
        }
        encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
        return encoded_jwt

    def decode_token(self, token: str) -> TokenPayload | None:
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
            return TokenPayload(**payload)
        except JWTError as e:
            logger.warning("Invalid token", error=str(e))
            return None

    async def authenticate_user(self, username: str, password: str) -> User | None:
        user = await self.get_user_by_username(username)
        if not user:
            return None
        if not self.verify_password(password, user.hashed_password):
            return None
        if not user.is_active:
            return None
        return user

    async def get_user_by_username(self, username: str) -> User | None:
        doc = await self.users_collection.find_one({"username": username})
        return User(**doc) if doc else None

    async def get_user_by_email(self, email: str) -> User | None:
        doc = await self.users_collection.find_one({"email": email})
        return User(**doc) if doc else None

    async def get_user(self, user_id: UUID) -> User | None:
        doc = await self.users_collection.find_one({"id": str(user_id)})
        return User(**doc) if doc else None

    async def create_user(self, user_create: UserCreate) -> User:
        existing = await self.get_user_by_username(user_create.username)
        if existing:
            raise ValueError("Username already exists")
        existing = await self.get_user_by_email(user_create.email)
        if existing:
            raise ValueError("Email already exists")

        hashed_password = self.get_password_hash(user_create.password)
        user = User(
            email=user_create.email,
            username=user_create.username,
            hashed_password=hashed_password,
            role=user_create.role,
            permissions=ROLE_PERMISSIONS.get(user_create.role, []),
        )
        await self.users_collection.insert_one(user.model_dump())
        logger.info("User created", user_id=str(user.id), username=user.username)
        return user

    async def update_user(self, user_id: UUID, user_update: UserUpdate) -> User | None:
        update_data = user_update.model_dump(exclude_unset=True)
        if "password" in update_data:
            update_data["hashed_password"] = self.get_password_hash(update_data.pop("password"))
        update_data["updated_at"] = datetime.utcnow()

        doc = await self.users_collection.find_one_and_update(
            {"id": str(user_id)},
            {"$set": update_data},
            return_document=True,
        )
        return User(**doc) if doc else None

    async def delete_user(self, user_id: UUID) -> bool:
        result = await self.users_collection.delete_one({"id": str(user_id)})
        return result.deleted_count > 0

    async def list_users(self, skip: int = 0, limit: int = 100) -> list[User]:
        cursor = self.users_collection.find().skip(skip).limit(limit)
        return [User(**doc) async for doc in cursor]

    async def update_last_login(self, user_id: UUID) -> None:
        await self.users_collection.update_one(
            {"id": str(user_id)},
            {"$set": {"last_login": datetime.utcnow()}},
        )


class PermissionService:
    @staticmethod
    def get_permissions_for_role(role: UserRole) -> list[Permission]:
        return ROLE_PERMISSIONS.get(role, [])

    @staticmethod
    def user_has_permission(user: User, permission: Permission) -> bool:
        if user.is_superuser:
            return True
        return permission in user.permissions

    @staticmethod
    def user_has_any_permission(user: User, permissions: list[Permission]) -> bool:
        if user.is_superuser:
            return True
        return any(p in user.permissions for p in permissions)

    @staticmethod
    def user_has_all_permissions(user: User, permissions: list[Permission]) -> bool:
        if user.is_superuser:
            return True
        return all(p in user.permissions for p in permissions)


async def get_current_user(token: str, db: AsyncIOMotorDatabase) -> User | None:
    auth_service = AuthService(db)
    payload = auth_service.decode_token(token)
    if not payload:
        return None
    user = await auth_service.get_user(UUID(payload.sub))
    return user