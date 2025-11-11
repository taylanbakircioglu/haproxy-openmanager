import asyncpg
import redis
import logging
from config import DATABASE_URL, REDIS_URL

logger = logging.getLogger(__name__)

# Redis client instance
redis_client = redis.Redis.from_url(REDIS_URL)

# Database connection pool instance
_connection_pool = None

async def init_database_pool():
    """
    Initialize database connection pool
    
    This replaces the previous per-request connection approach with a connection pool
    to improve performance and prevent connection exhaustion under high load.
    
    Pool configuration:
    - min_size=10: Maintain at least 10 connections ready
    - max_size=50: Allow up to 50 concurrent connections
    - command_timeout=60: Queries timeout after 60 seconds
    - max_inactive_connection_lifetime=300: Recycle idle connections after 5 minutes
    """
    global _connection_pool
    if _connection_pool is None:
        try:
            _connection_pool = await asyncpg.create_pool(
                DATABASE_URL,
                min_size=10,
                max_size=50,
                command_timeout=60,
                max_inactive_connection_lifetime=300
            )
            logger.info("✅ Database connection pool initialized (min=10, max=50)")
        except Exception as e:
            logger.error(f"❌ Failed to initialize database connection pool: {e}")
            raise
    return _connection_pool

async def get_database_connection():
    """
    Get a database connection from the connection pool
    
    This function now uses connection pooling instead of creating new connections.
    Connections are automatically returned to the pool when closed.
    """
    global _connection_pool
    try:
        if _connection_pool is None:
            await init_database_pool()
        return await _connection_pool.acquire()
    except Exception as e:
        logger.error(f"Failed to acquire database connection from pool: {e}")
        raise

async def close_database_connection(conn):
    """
    Release a database connection back to the pool
    
    The connection is returned to the pool for reuse, not actually closed.
    """
    global _connection_pool
    try:
        if _connection_pool and conn:
            await _connection_pool.release(conn)
    except Exception as e:
        logger.error(f"Failed to release database connection to pool: {e}")

async def close_database_pool():
    """
    Close the database connection pool gracefully
    
    Should be called during application shutdown.
    """
    global _connection_pool
    if _connection_pool:
        await _connection_pool.close()
        logger.info("Database connection pool closed")
        _connection_pool = None

def get_redis_client():
    """Get the Redis client instance"""
    return redis_client 