from fastapi import APIRouter, HTTPException, Header, Query
from typing import Optional
from pydantic import BaseModel
import logging
from datetime import datetime, timedelta

from database.connection import get_database_connection, close_database_connection
from auth_middleware import get_current_user_from_token, validate_agent_api_key
from utils.activity_log import log_user_activity

router = APIRouter(prefix="/api/configuration", tags=["configuration"])
logger = logging.getLogger(__name__)

# ====== REQUEST/RESPONSE MODELS ======

class ConfigResponse(BaseModel):
    request_id: int
    config_content: str
    config_path: str

# ====== USER ENDPOINTS (Frontend -> Backend) ======

@router.post("/request")
async def create_config_request(
    agent_name: str = Query(..., description="Agent name"),
    cluster_id: int = Query(..., description="Cluster ID"),
    request_type: str = Query(..., description="Request type: 'view' or 'download'"),
    authorization: str = Header(None)
):
    """
    Create a configuration request for an agent.
    User initiates this from the Configuration Management page.
    """
    try:
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get agent info and verify it belongs to the cluster
        agent_info = await conn.fetchrow("""
            SELECT a.id, a.name, a.status, a.pool_id
            FROM agents a
            WHERE a.name = $1
        """, agent_name)
        
        if not agent_info:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")
        
        # Verify cluster belongs to agent's pool
        cluster_info = await conn.fetchrow("""
            SELECT id, name, pool_id
            FROM haproxy_clusters
            WHERE id = $1
        """, cluster_id)
        
        if not cluster_info:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail=f"Cluster ID {cluster_id} not found")
        
        if cluster_info['pool_id'] != agent_info['pool_id']:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=400, 
                detail=f"Agent '{agent_name}' does not belong to cluster '{cluster_info['name']}'"
            )
        
        if agent_info['status'] != 'online':
            await close_database_connection(conn)
            raise HTTPException(
                status_code=400, 
                detail=f"Agent '{agent_name}' is not online (status: {agent_info['status']})"
            )
        
        # Check for existing pending requests
        existing_request = await conn.fetchrow("""
            SELECT id FROM agent_config_requests 
            WHERE agent_name = $1 AND status IN ('pending', 'processing')
            AND expires_at > CURRENT_TIMESTAMP
            LIMIT 1
        """, agent_name)
        
        if existing_request:
            await close_database_connection(conn)
            return {
                "request_id": existing_request['id'],
                "status": "existing",
                "message": "A config request is already pending for this agent"
            }
        
        # Create new request
        request_id = await conn.fetchval("""
            INSERT INTO agent_config_requests (
                agent_id, agent_name, cluster_id, request_type, status, requested_by
            ) VALUES ($1, $2, $3, $4, 'pending', $5)
            RETURNING id
        """, agent_info['id'], agent_name, cluster_id, request_type, current_user['id'])
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user['id'],
            action='config_request',
            resource_type='agent',
            resource_id=str(agent_info['id']),
            details={
                'agent_name': agent_name,
                'cluster_id': cluster_id,
                'cluster_name': cluster_info['name'],
                'request_type': request_type,
                'request_id': request_id
            }
        )
        
        logger.info(f"📄 CONFIG REQUEST: Created request #{request_id} for agent '{agent_name}' in cluster '{cluster_info['name']}' (type: {request_type})")
        
        return {
            "request_id": request_id,
            "agent_name": agent_name,
            "request_type": request_type,
            "status": "pending",
            "message": "Configuration request created successfully. Agent will process it on next heartbeat."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create config request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/response/{request_id}")
async def get_config_response(request_id: int, authorization: str = Header(None)):
    """
    Get configuration response for a request.
    Frontend polls this endpoint to check if agent has responded.
    """
    try:
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get request info
        request_info = await conn.fetchrow("""
            SELECT acr.id, acr.agent_name, acr.request_type, acr.status,
                   acr.requested_at, acr.expires_at,
                   acresp.config_content, acresp.config_path, acresp.file_size,
                   acresp.response_at
            FROM agent_config_requests acr
            LEFT JOIN agent_config_responses acresp ON acr.id = acresp.request_id
            WHERE acr.id = $1
        """, request_id)
        
        await close_database_connection(conn)
        
        if not request_info:
            raise HTTPException(status_code=404, detail="Config request not found")
        
        # Check if request expired
        if request_info['expires_at'] < datetime.now():
            return {
                "request_id": request_id,
                "status": "expired",
                "message": "Request expired. Agent did not respond in time."
            }
        
        # Check if response is available
        if request_info['config_content']:
            return {
                "request_id": request_id,
                "agent_name": request_info['agent_name'],
                "request_type": request_info['request_type'],
                "status": "completed",
                "config_content": request_info['config_content'],
                "config_path": request_info['config_path'],
                "file_size": request_info['file_size'],
                "response_at": request_info['response_at'].isoformat() if request_info['response_at'] else None
            }
        else:
            # Still pending
            return {
                "request_id": request_id,
                "status": request_info['status'],
                "message": "Waiting for agent response..."
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get config response: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== AGENT ENDPOINTS (Agent -> Backend) ======

@router.get("/agents/{agent_name}/pending-requests")
async def get_pending_config_requests(agent_name: str, x_api_key: Optional[str] = Header(None)):
    """
    Agent calls this endpoint to check for pending config requests.
    Called during heartbeat.
    """
    try:
        # Validate agent API key
        agent_auth = await validate_agent_api_key(x_api_key)
        
        if x_api_key and not agent_auth:
            logger.warning(f"Invalid API key provided by agent '{agent_name}' for pending requests")
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        conn = await get_database_connection()
        
        # Get pending requests
        requests = await conn.fetch("""
            SELECT id, request_type, requested_at
            FROM agent_config_requests
            WHERE agent_name = $1 
            AND status = 'pending'
            AND expires_at > CURRENT_TIMESTAMP
            ORDER BY requested_at ASC
            LIMIT 5
        """, agent_name)
        
        # Mark found requests as processing
        if requests:
            request_ids = [r['id'] for r in requests]
            await conn.execute("""
                UPDATE agent_config_requests
                SET status = 'processing', updated_at = CURRENT_TIMESTAMP
                WHERE id = ANY($1)
            """, request_ids)
            
            logger.info(f"📄 CONFIG REQUEST: Agent '{agent_name}' picked up {len(requests)} pending request(s)")
        
        await close_database_connection(conn)
        
        return {
            "agent_name": agent_name,
            "pending_requests": [
                {
                    "request_id": r['id'],
                    "request_type": r['request_type'],
                    "requested_at": r['requested_at'].isoformat()
                }
                for r in requests
            ]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get pending config requests for agent '{agent_name}': {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agents/{agent_name}/config-response")
async def submit_config_response(
    agent_name: str,
    response: ConfigResponse,
    x_api_key: Optional[str] = Header(None)
):
    """
    Agent submits the haproxy.cfg content in response to a request.
    """
    try:
        # Validate agent API key
        agent_auth = await validate_agent_api_key(x_api_key)
        
        if x_api_key and not agent_auth:
            logger.warning(f"Invalid API key provided by agent '{agent_name}' for config response")
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        conn = await get_database_connection()
        
        # Verify request exists and belongs to this agent
        request_info = await conn.fetchrow("""
            SELECT id, agent_name, status FROM agent_config_requests
            WHERE id = $1 AND agent_name = $2
        """, response.request_id, agent_name)
        
        if not request_info:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=404, 
                detail="Config request not found or does not belong to this agent"
            )
        
        # Insert response
        file_size = len(response.config_content.encode('utf-8'))
        
        await conn.execute("""
            INSERT INTO agent_config_responses (
                request_id, agent_name, config_content, config_path, file_size
            ) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING
        """, response.request_id, agent_name, response.config_content, response.config_path, file_size)
        
        # Update request status
        await conn.execute("""
            UPDATE agent_config_requests
            SET status = 'completed', updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
        """, response.request_id)
        
        await close_database_connection(conn)
        
        logger.info(f"CONFIG RESPONSE: Agent '{agent_name}' submitted config for request #{response.request_id} (size: {file_size} bytes)")
        
        return {
            "status": "ok",
            "message": "Configuration response received successfully",
            "request_id": response.request_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to submit config response from agent '{agent_name}': {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ====== CLEANUP ENDPOINT ======

@router.delete("/cleanup-expired")
async def cleanup_expired_requests():
    """
    Cleanup expired config requests and responses.
    Called by scheduled job or manually.
    """
    try:
        conn = await get_database_connection()
        
        # Delete expired responses
        deleted_responses = await conn.fetchval("""
            DELETE FROM agent_config_responses
            WHERE expires_at < CURRENT_TIMESTAMP
            RETURNING count(*)
        """)
        
        # Delete expired requests
        deleted_requests = await conn.fetchval("""
            DELETE FROM agent_config_requests
            WHERE expires_at < CURRENT_TIMESTAMP
            RETURNING count(*)
        """)
        
        await close_database_connection(conn)
        
        logger.info(f"🧹 CLEANUP: Deleted {deleted_responses or 0} expired responses and {deleted_requests or 0} expired requests")
        
        return {
            "status": "ok",
            "deleted_responses": deleted_responses or 0,
            "deleted_requests": deleted_requests or 0
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup expired data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

