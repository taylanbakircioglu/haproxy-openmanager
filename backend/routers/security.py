from fastapi import APIRouter, HTTPException, Header, Request
from typing import Optional, List
import logging
import secrets
import string
from datetime import datetime, timedelta
from pydantic import BaseModel

from database.connection import get_database_connection, close_database_connection
from auth_middleware import get_current_user_from_token
from utils.activity_log import log_user_activity

router = APIRouter(prefix="/api/security", tags=["security"])
logger = logging.getLogger(__name__)

class AgentTokenCreate(BaseModel):
    name: str
    description: Optional[str] = None
    expires_in_days: Optional[int] = None  # None = no expiration

class AgentTokenResponse(BaseModel):
    id: int
    agent_id: int
    agent_name: str
    name: str
    description: Optional[str]
    token: Optional[str] = None  # Only returned when creating
    created_at: datetime
    expires_at: Optional[datetime]
    last_used: Optional[datetime]
    created_by_username: str
    is_expired: bool

def generate_secure_api_key() -> str:
    """Generate a cryptographically secure API key"""
    # Generate 32 bytes of random data and encode as base64
    random_bytes = secrets.token_bytes(32)
    # Use URL-safe base64 encoding and remove padding
    api_key = secrets.token_urlsafe(32)
    return f"hap_{api_key}"

@router.get("/agent-tokens")
async def get_agent_tokens(authorization: str = Header(None)):
    """Get all agent API tokens (without revealing the actual tokens)"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get tokens with agent counts and details
        tokens = await conn.fetch("""
            SELECT 
                a.api_key,
                a.api_key_name as name,
                a.api_key_created_at as created_at,
                a.api_key_expires_at as expires_at,
                a.api_key_last_used as last_used,
                u.username as created_by_username,
                CASE 
                    WHEN a.api_key_expires_at IS NOT NULL AND a.api_key_expires_at < CURRENT_TIMESTAMP 
                    THEN true 
                    ELSE false 
                END as is_expired,
                COUNT(CASE WHEN a.name NOT LIKE 'token_%' THEN 1 END) as agent_count,
                ARRAY_AGG(
                    CASE WHEN a.name NOT LIKE 'token_%' 
                    THEN a.name 
                    END
                ) FILTER (WHERE a.name NOT LIKE 'token_%') as agent_names,
                MIN(a.id) as primary_agent_id
            FROM agents a
            LEFT JOIN users u ON a.api_key_created_by = u.id
            WHERE a.api_key IS NOT NULL AND a.enabled = TRUE
            GROUP BY a.api_key, a.api_key_name, a.api_key_created_at, 
                     a.api_key_expires_at, a.api_key_last_used, u.username
            ORDER BY a.api_key_created_at DESC
        """)
        
        await close_database_connection(conn)
        
        return {
            "tokens": [dict(token) for token in tokens],
            "total": len(tokens)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch agent tokens: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch agent tokens")

@router.post("/agent-tokens")
async def create_agent_token(token_data: AgentTokenCreate, request: Request, authorization: str = Header(None)):
    """Create a new API token for an agent"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Generate secure API key
        api_key = generate_secure_api_key()
        
        # Calculate expiration date
        expires_at = None
        if token_data.expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=token_data.expires_in_days)
        
        # Create a placeholder agent entry for standalone token
        # Agent will update this when it registers with this token
        placeholder_name = f"token_{api_key[-8:]}"  # Last 8 chars of token as placeholder name
        agent_id = await conn.fetchval("""
            INSERT INTO agents (
                name, api_key, api_key_name, api_key_created_at, 
                api_key_expires_at, api_key_created_by, status, 
                enabled, created_at, updated_at
            ) VALUES ($1, $2, $3, CURRENT_TIMESTAMP, $4, $5, 'pending', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING id
        """, placeholder_name, api_key, token_data.name, expires_at, current_user['id'])
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='create_api_token',
            resource_type='agent',
            resource_id=str(agent_id),
            details={
                'agent_name': placeholder_name,
                'token_name': token_data.name,
                'expires_in_days': token_data.expires_in_days,
                'token_type': 'standalone'
            },
            ip_address=str(request.client.host) if request.client else None,
            user_agent=request.headers.get('user-agent')
        )
        
        logger.info(f"Created standalone API token '{token_data.name}' (placeholder: {placeholder_name})")
        
        return {
            "message": "API token created successfully",
            "agent_name": placeholder_name,
            "token_name": token_data.name,
            "api_key": api_key,  # Return the token only once
            "expires_at": expires_at.isoformat() if expires_at else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create agent token: {e}")
        raise HTTPException(status_code=500, detail="Failed to create agent token")

@router.delete("/agent-tokens/{agent_id}")
async def revoke_agent_token(agent_id: int, request: Request, authorization: str = Header(None)):
    """Revoke an agent's API token"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get agent info and API key before revoking
        agent_info = await conn.fetchrow("""
            SELECT api_key, api_key_name, 
                   COUNT(*) OVER (PARTITION BY api_key) as agent_count,
                   ARRAY_AGG(name) OVER (PARTITION BY api_key) as agent_names
            FROM agents 
            WHERE id = $1 AND enabled = TRUE AND api_key IS NOT NULL
        """, agent_id)
        
        if not agent_info:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Agent or API token not found")
        
        api_key = agent_info['api_key']
        token_name = agent_info['api_key_name']
        
        # Revoke the API key from ALL agents using this token
        revoked_count = await conn.fetchval("""
            UPDATE agents SET 
                api_key = NULL,
                api_key_name = NULL,
                api_key_created_at = NULL,
                api_key_expires_at = NULL,
                api_key_last_used = NULL,
                api_key_created_by = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE api_key = $1
            RETURNING (SELECT COUNT(*) FROM agents WHERE api_key = $1)
        """, api_key)
        
        # Delete placeholder agents (token_*) after revoking
        await conn.execute("""
            DELETE FROM agents 
            WHERE name LIKE 'token_%' AND api_key IS NULL
        """)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='revoke_api_token',
            resource_type='token',
            resource_id=str(agent_id),
            details={
                'token_name': token_name,
                'affected_agents': agent_info['agent_names'],
                'revoked_count': agent_info['agent_count']
            },
            ip_address=str(request.client.host) if request.client else None,
            user_agent=request.headers.get('user-agent')
        )
        
        logger.info(f"🔒 Revoked API token '{token_name}' affecting {agent_info['agent_count']} agent(s): {agent_info['agent_names']}")
        
        return {
            "message": f"API token revoked successfully. Affected {agent_info['agent_count']} agent(s).",
            "token_name": token_name,
            "affected_agents": agent_info['agent_names']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke agent token: {e}")
        raise HTTPException(status_code=500, detail="Failed to revoke agent token")

@router.delete("/agent-tokens/by-name/{token_name}")
async def revoke_agent_token_by_name(token_name: str, request: Request, authorization: str = Header(None)):
    """Revoke an agent token by token name"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get token info and all agents using this token
        token_info = await conn.fetchrow("""
            SELECT api_key, api_key_name, 
                   COUNT(*) as agent_count,
                   ARRAY_AGG(name) as agent_names
            FROM agents 
            WHERE api_key_name = $1 AND enabled = TRUE AND api_key IS NOT NULL
            GROUP BY api_key, api_key_name
        """, token_name)
        
        if not token_info:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Token not found")
        
        api_key = token_info['api_key']
        
        # Revoke the API key from ALL agents using this token
        await conn.execute("""
            UPDATE agents SET 
                api_key = NULL,
                api_key_name = NULL,
                api_key_created_at = NULL,
                api_key_expires_at = NULL,
                api_key_last_used = NULL,
                api_key_created_by = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE api_key = $1
        """, api_key)
        
        # Delete placeholder agents (token_*) after revoking
        await conn.execute("""
            DELETE FROM agents 
            WHERE name LIKE 'token_%' AND api_key IS NULL
        """)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='revoke_api_token',
            resource_type='token',
            resource_id=token_name,
            details={
                'token_name': token_name,
                'affected_agents': token_info['agent_names'],
                'revoked_count': token_info['agent_count']
            },
            ip_address=str(request.client.host) if request.client else None,
            user_agent=request.headers.get('user-agent')
        )
        
        logger.info(f"🔒 Revoked API token '{token_name}' affecting {token_info['agent_count']} agent(s): {token_info['agent_names']}")
        
        return {
            "message": f"API token '{token_name}' revoked successfully. Affected {token_info['agent_count']} agent(s).",
            "token_name": token_name,
            "affected_agents": token_info['agent_names']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke agent token by name: {e}")
        raise HTTPException(status_code=500, detail="Failed to revoke agent token")

@router.get("/agents-without-tokens")
async def get_agents_without_tokens(authorization: str = Header(None)):
    """Get agents that don't have API tokens yet"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # First, let's see all agents
        all_agents = await conn.fetch("""
            SELECT id, name, hostname, status, last_seen, api_key, enabled
            FROM agents 
            ORDER BY name
        """)
        
        logger.info(f"SECURITY DEBUG: All agents in database: {len(all_agents)}")
        for agent in all_agents:
            logger.info(f"SECURITY DEBUG: Agent {agent['name']}: api_key={agent['api_key'] is not None}, enabled={agent['enabled']}")
        
        agents = await conn.fetch("""
            SELECT id, name, hostname, status, last_seen
            FROM agents 
            WHERE api_key IS NULL AND enabled = TRUE
            ORDER BY name
        """)
        
        logger.info(f"SECURITY DEBUG: Agents without tokens: {len(agents)}")
        
        await close_database_connection(conn)
        
        return {
            "agents": [dict(agent) for agent in agents],
            "total": len(agents)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch agents without tokens: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch agents")
