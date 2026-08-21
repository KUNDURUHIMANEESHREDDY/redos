from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from security.config import settings
import structlog

logger = structlog.get_logger()

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


async def get_database() -> AsyncIOMotorDatabase:
    global _db
    if _db is None:
        await connect_to_mongo()
    return _db


async def connect_to_mongo() -> None:
    global _client, _db
    logger.info("Connecting to MongoDB", uri=settings.mongodb_uri)
    _client = AsyncIOMotorClient(settings.mongodb_uri)
    _db = _client[settings.mongodb_db]
    await _db.command("ping")
    logger.info("Connected to MongoDB", database=settings.mongodb_db)


async def close_mongo_connection() -> None:
    global _client
    if _client:
        _client.close()
        logger.info("Closed MongoDB connection")


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("Database not initialized. Call connect_to_mongo() first.")
    return _db