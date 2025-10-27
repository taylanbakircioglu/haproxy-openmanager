import asyncpg
import redis
import logging
from config import DATABASE_URL, REDIS_URL

logger = logging.getLogger(__name__)

# Redis client instance
redis_client = redis.Redis.from_url(REDIS_URL)

async def get_database_connection():
    """Get a database connection"""
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        raise

async def close_database_connection(conn):
    """Close a database connection"""
    try:
        if conn:
            await conn.close()
    except Exception as e:
        logger.error(f"Failed to close database connection: {e}")

def get_redis_client():
    """Get the Redis client instance"""
    return redis_client 