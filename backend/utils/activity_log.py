import asyncio
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from database.connection import get_database_connection, close_database_connection

logger = logging.getLogger(__name__)

async def log_user_activity(
    user_id: int,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
):
    """Log user activity to the database"""
    try:
        conn = await get_database_connection()
        
        # Serialize details to JSON if it's a dict
        details_json = json.dumps(details) if details and isinstance(details, dict) else details
        
        # Try with created_at column first, then fallback
        try:
            await conn.execute("""
                INSERT INTO user_activity_logs 
                (user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """, user_id, action, resource_type, resource_id, 
                details_json, ip_address, user_agent, datetime.utcnow())
        except Exception as column_error:
            logger.warning(f"created_at column not found, trying fallback: {column_error}")
            # Fallback without created_at column
            await conn.execute("""
                INSERT INTO user_activity_logs 
                (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            """, user_id, action, resource_type, resource_id, 
                details_json, ip_address, user_agent)
        
        await close_database_connection(conn)
        
    except Exception as e:
        logger.error(f"Failed to log user activity: {e}")
        # Don't raise exception - activity logging should not break the main flow

async def get_user_activity_logs(
    user_id: Optional[int] = None,
    limit: int = 100,
    offset: int = 0
) -> list:
    """Get user activity logs"""
    try:
        conn = await get_database_connection()
        
        # Schema-safe activity log queries
        try:
            if user_id:
                logs = await conn.fetch("""
                    SELECT ual.*, u.username
                    FROM user_activity_logs ual
                    LEFT JOIN users u ON ual.user_id = u.id
                    WHERE ual.user_id = $1
                    ORDER BY ual.created_at DESC
                    LIMIT $2 OFFSET $3
                """, user_id, limit, offset)
            else:
                logs = await conn.fetch("""
                    SELECT ual.*, u.username
                    FROM user_activity_logs ual
                    LEFT JOIN users u ON ual.user_id = u.id
                    ORDER BY ual.created_at DESC
                    LIMIT $1 OFFSET $2
                """, limit, offset)
        except Exception as schema_error:
            logger.warning(f"Schema error in activity logs, using fallback: {schema_error}")
            # Fallback without ORDER BY created_at
            if user_id:
                logs = await conn.fetch("""
                    SELECT ual.*, u.username
                    FROM user_activity_logs ual
                    LEFT JOIN users u ON ual.user_id = u.id
                    WHERE ual.user_id = $1
                    LIMIT $2 OFFSET $3
                """, user_id, limit, offset)
            else:
                logs = await conn.fetch("""
                    SELECT ual.*, u.username
                    FROM user_activity_logs ual
                    LEFT JOIN users u ON ual.user_id = u.id
                    LIMIT $1 OFFSET $2
                """, limit, offset)
        
        await close_database_connection(conn)
        return logs
        
    except Exception as e:
        logger.error(f"Failed to get user activity logs: {e}")
        return [] 