from fastapi import APIRouter, HTTPException, Request, Header
from typing import Optional
import logging
import time
import hashlib
import json

from models.backend import BackendConfig, BackendConfigUpdate, ServerConfig
from database.connection import get_database_connection, close_database_connection
from utils.activity_log import log_user_activity
from services.haproxy_config import generate_haproxy_config_for_cluster

router = APIRouter(prefix="/api/backends", tags=["backends", "servers"])
logger = logging.getLogger(__name__)

async def validate_user_cluster_access(user_id: int, cluster_id: int, conn):
    """Validate that user has access to the specified cluster"""
    # Check if cluster exists
    cluster_exists = await conn.fetchval("""
        SELECT id FROM haproxy_clusters WHERE id = $1
    """, cluster_id)
    
    if not cluster_exists:
        raise HTTPException(
            status_code=404, 
            detail="Cluster not found"
        )
    
    # Check if user is admin - admins can access everything
    is_admin = await conn.fetchval("""
        SELECT is_admin FROM users WHERE id = $1
    """, user_id)
    
    if is_admin:
        logger.info(f"Admin user {user_id} granted access to cluster {cluster_id}")
        return True
    
    # Check if user_pool_access table exists (for backward compatibility)
    table_exists = await conn.fetchval("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_name = 'user_pool_access'
        )
    """)
    
    if not table_exists:
        # Fallback to basic validation if table doesn't exist yet
        logger.warning("user_pool_access table not found, using basic cluster validation")
        return True
    
    # Check if expires_at column exists (for backward compatibility)
    expires_at_exists = await conn.fetchval("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_name = 'user_pool_access' AND column_name = 'expires_at'
        )
    """)
    
    # Regular users need explicit pool access
    if expires_at_exists:
        user_access = await conn.fetchrow("""
            SELECT upa.access_level, hc.id, hc.name
            FROM haproxy_clusters hc
            JOIN haproxy_cluster_pools hcp ON hc.pool_id = hcp.id
            JOIN user_pool_access upa ON hcp.id = upa.pool_id
            WHERE upa.user_id = $1 AND hc.id = $2 AND upa.is_active = TRUE
            AND (upa.expires_at IS NULL OR upa.expires_at > CURRENT_TIMESTAMP)
        """, user_id, cluster_id)
    else:
        # Fallback query without expires_at column
        user_access = await conn.fetchrow("""
            SELECT upa.access_level, hc.id, hc.name
            FROM haproxy_clusters hc
            JOIN haproxy_cluster_pools hcp ON hc.pool_id = hcp.id
            JOIN user_pool_access upa ON hcp.id = upa.pool_id
            WHERE upa.user_id = $1 AND hc.id = $2 AND upa.is_active = TRUE
        """, user_id, cluster_id)
    
    if not user_access:
        raise HTTPException(
            status_code=403, 
            detail="You don't have access to this cluster. Please contact your administrator."
        )
    
    logger.info(f"User {user_id} granted {user_access['access_level']} access to cluster {cluster_id}")
    return True

# Health check functions (simplified versions)
async def check_server_health_via_haproxy(backend_name: str, server_name: str, cluster_id: int) -> str:
    """Check server health via HAProxy stats socket through agent"""
    # Simplified implementation - would normally connect to agent
    return "UNKNOWN"

async def check_server_health(host: str, port: int, timeout: int = 5) -> str:
    """Legacy TCP connection health check"""
    import asyncio
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return "UP"
    except:
        return "DOWN"

@router.get("", summary="Get All Backends", response_description="List of backends with servers")
async def get_backends(cluster_id: Optional[int] = None, include_inactive: bool = False):
    """
    # Get All Backends
    
    Retrieve all backend configurations with their associated servers. Optionally filter by cluster.
    
    ## Query Parameters
    - **cluster_id** (optional): Filter backends by cluster ID
    
    ## Example Request - All Backends
    ```bash
    curl -X GET "{BASE_URL}/api/backends" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Request - By Cluster
    ```bash
    curl -X GET "{BASE_URL}/api/backends?cluster_id=1" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Response
    ```json
    [
      {
        "id": 1,
        "name": "web-backend",
        "balance_method": "roundrobin",
        "mode": "http",
        "cluster_id": 1,
        "health_check_uri": "/health",
        "health_check_interval": "5s",
        "cookie_name": "SERVERID",
        "servers": [
          {
            "id": 1,
            "name": "web-01",
            "address": "10.0.1.10",
            "port": 8080,
            "weight": 100,
            "check_enabled": true,
            "backup": false,
            "status": "UP"
          },
          {
            "id": 2,
            "name": "web-02",
            "address": "10.0.1.11",
            "port": 8080,
            "weight": 100,
            "check_enabled": true,
            "backup": false,
            "status": "UP"
          }
        ]
      }
    ]
    ```
    
    ## Load Balancing Methods
    - **roundrobin**: Each server used in turn
    - **leastconn**: Server with least connections
    - **source**: Based on source IP hash
    - **uri**: Based on URI hash
    """
    try:
        conn = await get_database_connection()
        
        # Get backends with optional cluster filter
        # include_inactive parameter controls whether to show soft-deleted (is_active=FALSE) backends
        # Default FALSE: Normal views (BackendServers, FrontendManagement, Dashboard) only show active
        # Set TRUE: Apply Management shows all including deleted for pending change visibility
        if cluster_id:
            if include_inactive:
                backends = await conn.fetch("""
                    SELECT id, name, balance_method, mode, health_check_uri, 
                           health_check_interval, health_check_expected_status, fullconn,
                           cookie_name, cookie_options, default_server_inter, default_server_fall, default_server_rise,
                           request_headers, response_headers,
                           is_active, created_at, updated_at, cluster_id, last_config_status,
                           timeout_connect, timeout_server, timeout_queue
                    FROM backends WHERE cluster_id = $1 ORDER BY name
                """, cluster_id)
            else:
                backends = await conn.fetch("""
                    SELECT id, name, balance_method, mode, health_check_uri, 
                           health_check_interval, health_check_expected_status, fullconn,
                           cookie_name, cookie_options, default_server_inter, default_server_fall, default_server_rise,
                           request_headers, response_headers,
                           is_active, created_at, updated_at, cluster_id, last_config_status,
                           timeout_connect, timeout_server, timeout_queue
                    FROM backends WHERE cluster_id = $1 AND is_active = TRUE ORDER BY name
                """, cluster_id)
        else:
            if include_inactive:
                backends = await conn.fetch("""
                    SELECT id, name, balance_method, mode, health_check_uri, 
                           health_check_interval, health_check_expected_status, fullconn,
                           cookie_name, cookie_options, default_server_inter, default_server_fall, default_server_rise,
                           request_headers, response_headers,
                           is_active, created_at, updated_at, cluster_id, last_config_status,
                           timeout_connect, timeout_server, timeout_queue
                    FROM backends ORDER BY name
                """)
            else:
                backends = await conn.fetch("""
                    SELECT id, name, balance_method, mode, health_check_uri, 
                           health_check_interval, health_check_expected_status, fullconn,
                           cookie_name, cookie_options, default_server_inter, default_server_fall, default_server_rise,
                           request_headers, response_headers,
                           is_active, created_at, updated_at, cluster_id, last_config_status,
                           timeout_connect, timeout_server, timeout_queue
                    FROM backends WHERE is_active = TRUE ORDER BY name
                """)
        
        result = []
        for backend in backends:
            # Get servers for this backend with cluster_id (ONLY show active servers)
            # CRITICAL FIX: Add is_active = TRUE filter to prevent soft-deleted servers from appearing
            if cluster_id:
                servers = await conn.fetch("""
                    SELECT id, server_name, server_address, server_port, weight, maxconn,
                           check_enabled, check_port, backup_server, ssl_enabled, ssl_verify, ssl_certificate_id,
                           cookie_value, inter, fall, rise,
                           is_active, cluster_id,
                           haproxy_status, haproxy_status_updated_at, backend_name
                    FROM backend_servers 
                    WHERE backend_name = $1 AND cluster_id = $2 AND is_active = TRUE ORDER BY server_name
                """, backend["name"], cluster_id)
            else:
                servers = await conn.fetch("""
                    SELECT id, server_name, server_address, server_port, weight, maxconn,
                           check_enabled, check_port, backup_server, ssl_enabled, ssl_verify, ssl_certificate_id,
                           cookie_value, inter, fall, rise,
                           is_active, cluster_id,
                           haproxy_status, haproxy_status_updated_at, backend_name
                    FROM backend_servers 
                    WHERE backend_name = $1 AND is_active = TRUE ORDER BY server_name
                """, backend["name"]) 
            
            # Prepare server list with real-time HAProxy status from agents
            server_list = []
            for s in servers:
                # Use real-time HAProxy status if available from agent, otherwise fallback
                server_status = "UNKNOWN"
                status_age_minutes = None
                
                if s.get("haproxy_status") and s.get("haproxy_status_updated_at"):
                    server_status = s["haproxy_status"]
                    # Calculate how old the status is
                    import datetime
                    now = datetime.datetime.now(datetime.timezone.utc)
                    updated_at = s["haproxy_status_updated_at"]
                    if hasattr(updated_at, 'replace'):  # Handle timezone-naive datetime
                        updated_at = updated_at.replace(tzinfo=datetime.timezone.utc)
                    age_seconds = (now - updated_at).total_seconds()
                    status_age_minutes = int(age_seconds / 60)
                    
                    # If status is too old (>5 minutes), mark as stale
                    if age_seconds > 300:  # 5 minutes
                        server_status = f"{server_status} (stale)"
                elif s["cluster_id"]:
                    # Fallback to HAProxy-based check (but this should be deprecated)
                    server_status = await check_server_health_via_haproxy(
                        backend_name=backend["name"],
                        server_name=s["server_name"], 
                        cluster_id=s["cluster_id"]
                    )
                else:
                    # Final fallback to TCP check for servers without cluster assignment
                    server_status = await check_server_health(s["server_address"], s["server_port"])
                
                server_list.append({
                    "id": s["id"],
                    "name": s["server_name"],
                    "server_name": s["server_name"],  # CRITICAL FIX: Include server_name field in API response
                    "address": f"{s['server_address']}:{s['server_port']}",
                    "weight": s["weight"],
                    "check_enabled": s["check_enabled"],
                    "check_port": s.get("check_port"),
                    "backup_server": s["backup_server"],
                    "ssl_enabled": s.get("ssl_enabled", False),
                    "ssl_verify": s.get("ssl_verify"),
                    "ssl_certificate_id": s.get("ssl_certificate_id"),
                    "cookie_value": s.get("cookie_value"),
                    "inter": s.get("inter"),
                    "fall": s.get("fall"),
                    "rise": s.get("rise"),
                    "is_active": s["is_active"],
                    "status": server_status,
                    "status_age_minutes": status_age_minutes,
                    "last_status_update": s.get("haproxy_status_updated_at").isoformat().replace('+00:00', 'Z') if s.get("haproxy_status_updated_at") else None,
                    "backend_name": s["backend_name"],
                    "cluster_id": s["cluster_id"]  # CRITICAL FIX: Include cluster_id field in API response
                })
            
            result.append({
                "id": backend["id"],
                "name": backend["name"],
                "balance_method": backend["balance_method"],
                "mode": backend["mode"],
                "health_check_uri": backend.get("health_check_uri"),
                "timeout_connect": backend.get("timeout_connect"),
                "timeout_server": backend.get("timeout_server"),
                "timeout_queue": backend.get("timeout_queue"),
                "config_status": backend.get("last_config_status") or "APPLIED",
                "last_config_status": backend.get("last_config_status") if backend.get("last_config_status") is not None else "APPLIED",
                "is_active": backend.get("is_active", True),
                "cluster_id": backend["cluster_id"],
                "created_at": backend["created_at"].isoformat().replace('+00:00', 'Z') if backend["created_at"] else None,
                "updated_at": backend["updated_at"].isoformat().replace('+00:00', 'Z') if backend["updated_at"] else None,
                "servers": server_list
            })
        
        # Check for pending configurations by cluster
        pending_backend_ids = set()
        if result:
            cluster_ids = [b["cluster_id"] for b in result if b["cluster_id"]]
            if cluster_ids:
                try:
                    # Check for backend-specific and server-specific pending changes
                    # More robust approach: Check cluster-level pending changes and map to backends
                    
                    # Get all PENDING versions in these clusters
                    pending_versions = await conn.fetch("""
                        SELECT version_name, cluster_id FROM config_versions 
                        WHERE cluster_id = ANY($1) AND status = 'PENDING'
                    """, cluster_ids)
                    
                    # Extract backend IDs from version names
                    # CRITICAL: Validate that backend actually belongs to version's cluster (prevent orphan versions)
                    for version in pending_versions:
                        version_name = version['version_name']
                        version_cluster_id = version['cluster_id']
                        
                        # Backend changes: backend-{id}-{action}-{timestamp}
                        if version_name.startswith('backend-'):
                            parts = version_name.split('-')
                            if len(parts) >= 2 and parts[1].isdigit():
                                backend_id = int(parts[1])
                                
                                # CRITICAL: Verify backend actually belongs to this cluster (prevent ID reuse false positives)
                                backend_cluster_check = await conn.fetchval("""
                                    SELECT cluster_id FROM backends WHERE id = $1
                                """, backend_id)
                                
                                # Only add to pending_backend_ids if backend exists in the version's cluster
                                # Handle NULL cluster_id (legacy data): NULL == NULL should match
                                if backend_cluster_check == version_cluster_id:
                                    pending_backend_ids.add(backend_id)
                                elif backend_cluster_check is None and version_cluster_id is None:
                                    # Both NULL - legacy backend with legacy version
                                    pending_backend_ids.add(backend_id)
                                else:
                                    logger.warning(f"ORPHAN VERSION: {version_name} in cluster {version_cluster_id} references backend {backend_id} from cluster {backend_cluster_check}")
                        
                        # Server changes: server-{server_id}-{action}-{timestamp}
                        elif version_name.startswith('server-'):
                            parts = version_name.split('-')
                            if len(parts) >= 2 and parts[1].isdigit():
                                server_id = int(parts[1])
                                # Find which backend this server belongs to
                                # CRITICAL: Also validate server belongs to version's cluster
                                backend_row = await conn.fetchrow("""
                                    SELECT b.id as backend_id, bs.cluster_id as server_cluster_id
                                    FROM backend_servers bs 
                                    JOIN backends b ON bs.backend_name = b.name AND b.cluster_id = bs.cluster_id
                                    WHERE bs.id = $1
                                """, server_id)
                                if backend_row and backend_row['server_cluster_id'] == version_cluster_id:
                                    pending_backend_ids.add(backend_row['backend_id'])
                                elif backend_row:
                                    logger.warning(f"ORPHAN VERSION: {version_name} in cluster {version_cluster_id} references server {server_id} from cluster {backend_row['server_cluster_id']}")
                    
                    logger.info(f"BACKEND API: Found {len(pending_backend_ids)} backends with pending changes: {pending_backend_ids}")
                except Exception as e:
                    logger.warning(f"BACKEND API: Failed to check pending configs: {e}")
                    pending_backend_ids = set()
        
        # Add has_pending_config field to each backend (entity-specific)
        for backend in result:
            # Check if backend has pending changes via:
            # 1. Config versions (pending_backend_ids) - version name parsing
            # 2. Entity's own last_config_status (for bulk import and other operations)
            # 3. Backend is inactive (soft delete) - BUT NOT if REJECTED
            has_config_version = backend["id"] in pending_backend_ids
            has_pending_status = backend.get("last_config_status") == "PENDING"
            is_inactive = not backend.get("is_active", True)
            is_rejected = backend.get("last_config_status") == "REJECTED"
            
            # CRITICAL: Exclude REJECTED entities from pending (already rejected, no action needed)
            backend["has_pending_config"] = (has_config_version or has_pending_status or is_inactive) and not is_rejected
            
            # Enhanced debug logging
            if backend['name'] == 'backend7' or has_config_version or has_pending_status:
                logger.info(f"BACKEND DEBUG {backend['id']} ({backend['name']}): has_config_version={has_config_version}, has_pending_status={has_pending_status}, is_inactive={is_inactive}, config_status={backend.get('config_status')}, final_has_pending={backend['has_pending_config']}")
            else:
                logger.debug(f"BACKEND {backend['id']} ({backend['name']}): has_config_version={has_config_version}, has_pending_status={has_pending_status}, is_inactive={is_inactive}, final={backend['has_pending_config']}")
        
        await close_database_connection(conn)
        return {"backends": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("")
async def create_backend(backend: BackendConfig, authorization: str = Header(None)):
    """Create new backend configuration"""
    try:
        # Get current user for activity logging and cluster validation
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for backend create
        has_permission = await check_user_permission(current_user["id"], "backends", "create")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: backends.create required"
            )
        
        conn = await get_database_connection()
        
        # Validate cluster access for multi-cluster security
        if backend.cluster_id:
            await validate_user_cluster_access(current_user['id'], backend.cluster_id, conn)
        
        # Check if backend name already exists in the same cluster (only active backends)
        existing = await conn.fetchrow("""
            SELECT id FROM backends 
            WHERE name = $1 AND (cluster_id = $2 OR cluster_id IS NULL) AND is_active = TRUE
        """, backend.name, backend.cluster_id)
        if existing:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail=f"Backend '{backend.name}' already exists")
        
        # Insert new backend
        backend_id = await conn.fetchval("""
            INSERT INTO backends (name, balance_method, mode, health_check_uri, health_check_interval, 
                                health_check_expected_status, fullconn, cookie_name, cookie_options,
                                default_server_inter, default_server_fall, default_server_rise,
                                request_headers, response_headers,
                                timeout_connect, timeout_server, timeout_queue, cluster_id) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING id
        """, backend.name, backend.balance_method, backend.mode, 
            backend.health_check_uri, backend.health_check_interval,
            backend.health_check_expected_status, backend.fullconn, backend.cookie_name, backend.cookie_options,
            backend.default_server_inter, backend.default_server_fall, backend.default_server_rise,
            backend.request_headers, backend.response_headers,
            backend.timeout_connect, backend.timeout_server, backend.timeout_queue, backend.cluster_id)
        
        # If cluster_id provided, create new config version for agents
        sync_results = []
        if backend.cluster_id:
            try:
                # Generate new HAProxy config
                config_content = await generate_haproxy_config_for_cluster(backend.cluster_id)
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"backend-{backend_id}-create-{int(time.time())}"
                
                # Get system admin user ID for created_by (fresh DB has admin with ID 1)
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Try with status field first, fallback to old behavior if field doesn't exist
                try:
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                        VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                        RETURNING id
                    """, backend.cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {backend.cluster_id}")
                    # Mark entity as PENDING for UI
                    await conn.execute("UPDATE backends SET last_config_status = 'PENDING' WHERE id = $1", backend_id)
                    
                    # Don't notify agents yet - wait for manual Apply
                    sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'Changes created. Click Apply to activate.'}]
                    
                except Exception as status_error:
                    logger.warning(f"FALLBACK: Status field not available, using old immediate-apply behavior: {status_error}")
                    # Fallback to old behavior without status field
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active)
                        VALUES ($1, $2, $3, $4, $5, TRUE)
                        RETURNING id
                    """, backend.cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    # Deactivate previous versions for this cluster
                    await conn.execute("""
                        UPDATE config_versions 
                        SET is_active = FALSE 
                        WHERE cluster_id = $1 AND id != $2
                    """, backend.cluster_id, config_version_id)
                    
                    logger.info(f"FALLBACK: Using immediate-apply, agents notified")
                
            except Exception as e:
                logger.error(f"Cluster config update failed for backend {backend.name}: {e}")
                # Still return success for database save, but with sync warning
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        await close_database_connection(conn)
        
        return {
            "message": f"Backend '{backend.name}' created successfully",
            "id": backend_id,
            "backend": backend.dict(),
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{backend_id}/servers")
async def add_server_to_backend(backend_id: int, server: ServerConfig):
    """Add server to backend"""
    try:
        conn = await get_database_connection()
        
        # Get backend name and cluster_id
        backend = await conn.fetchrow("SELECT name, cluster_id FROM backends WHERE id = $1", backend_id)
        if not backend:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Backend not found")
        
        # Check if server name already exists in this backend within the same cluster (only active servers)
        existing = await conn.fetchrow("""
            SELECT id FROM backend_servers 
            WHERE backend_name = $1 AND server_name = $2 AND cluster_id = $3 AND is_active = TRUE
        """, backend["name"], server.server_name, backend["cluster_id"])
        if existing:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail=f"Server '{server.server_name}' already exists in backend '{backend['name']}' within this cluster")
        
        # Add server with cluster_id from backend
        server_id = await conn.fetchval("""
            INSERT INTO backend_servers 
            (backend_id, backend_name, server_name, server_address, server_port, weight, 
             maxconn, check_enabled, check_port, backup_server, ssl_enabled, ssl_verify, ssl_certificate_id,
             cookie_value, inter, fall, rise, cluster_id) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING id
        """, backend_id, backend["name"], server.server_name, server.server_address, server.server_port, server.weight,
            server.max_connections, server.check_enabled, server.check_port, server.backup_server, 
            server.ssl_enabled, server.ssl_verify, server.ssl_certificate_id, server.cookie_value, server.inter, server.fall, server.rise,
            backend["cluster_id"])
        
        # If backend has cluster_id, create new config version for agents
        sync_results = []
        if backend["cluster_id"]:
            try:
                # Generate new HAProxy config
                config_content = await generate_haproxy_config_for_cluster(backend["cluster_id"])
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"server-{server_id}-add-{int(time.time())}"
                
                # Get system admin user ID for created_by (fresh DB has admin with ID 1)
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Try with status field first, fallback to old behavior if field doesn't exist
                try:
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                        VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                        RETURNING id
                    """, backend["cluster_id"], version_name, config_content, config_hash, admin_user_id)
                    
                    logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {backend['cluster_id']}")
                    
                    # Mark parent backend as PENDING for Apply Management
                    await conn.execute("UPDATE backends SET last_config_status = 'PENDING' WHERE id = $1", backend_id)
                    logger.info(f"BACKEND SYNC: Marked backend {backend_id} as PENDING due to server addition")
                    
                    # Don't notify agents yet - wait for manual Apply
                    sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'Server changes created. Click Apply to activate.'}]
                    
                except Exception as status_error:
                    logger.warning(f"FALLBACK: Status field not available, using old immediate-apply behavior: {status_error}")
                    # Fallback to old behavior without status field
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active)
                        VALUES ($1, $2, $3, $4, $5, TRUE)
                        RETURNING id
                    """, backend["cluster_id"], version_name, config_content, config_hash, admin_user_id)
                    
                    # Deactivate previous versions for this cluster
                    await conn.execute("""
                        UPDATE config_versions 
                        SET is_active = FALSE 
                        WHERE cluster_id = $1 AND id != $2
                    """, backend["cluster_id"], config_version_id)
                    
                    logger.info(f"Created new config version {version_name} for cluster {backend['cluster_id']}")
                
            except Exception as e:
                logger.error(f"Cluster config update failed for server {server.server_name}: {e}")
                # Still return success for database save, but with sync warning
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        await close_database_connection(conn)
        
        return {
            "message": f"Server '{server.server_name}' added to backend '{backend['name']}' successfully",
            "id": server_id,
            "server": server.dict(),
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{backend_id}/config-versions")
async def get_backend_config_versions(backend_id: int, authorization: str = Header(None)):
    """Get config version history for a specific backend"""
    try:
        # Verify user authentication
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get backend info first
        backend_info = await conn.fetchrow("""
            SELECT b.id, b.name, c.name as cluster_name, b.cluster_id
            FROM backends b
            LEFT JOIN haproxy_clusters c ON b.cluster_id = c.id
            WHERE b.id = $1
        """, backend_id)
        
        if not backend_info:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Backend not found")
        
        # Get all APPLIED config versions that are related to this backend (including server changes)
        # For server changes, we need to check if the server belongs to this backend
        versions = await conn.fetch("""
            SELECT cv.id, cv.version_name, cv.description, cv.status, cv.is_active,
                   cv.created_at, cv.file_size, cv.checksum,
                   u.username as created_by_username
            FROM config_versions cv
            LEFT JOIN users u ON cv.created_by = u.id
            WHERE cv.cluster_id = $1 AND cv.status = 'APPLIED'
            AND (cv.version_name ~ $2 OR 
                 (cv.version_name ~ '^server-[0-9]+-' AND 
                  EXISTS (SELECT 1 FROM backend_servers bs 
                          JOIN backends b ON bs.backend_name = b.name 
                          WHERE b.id = $3 AND bs.id = SUBSTRING(cv.version_name FROM 'server-([0-9]+)-')::int)))
            ORDER BY cv.created_at DESC
        """, backend_info['cluster_id'], f'^backend-{backend_id}-', backend_id)
        
        await close_database_connection(conn)
        
        # Format the response
        formatted_versions = []
        for version in versions:
            version_type = "Backend"
            if "server-" in version["version_name"]:
                version_type = "Backend Server"
                
            formatted_versions.append({
                "id": version["id"],
                "version_name": version["version_name"],
                "description": version["description"] or f"{version_type} configuration update",
                "type": version_type,
                "status": version["status"],
                "is_active": version["is_active"],
                "created_at": version["created_at"].isoformat().replace('+00:00', 'Z') if version["created_at"] else None,
                "created_by": version["created_by_username"] or "System",
                "file_size": version["file_size"],
                "checksum": version["checksum"][:8] + "..." if version["checksum"] else "No checksum"
            })
        
        return {
            "versions": formatted_versions,
            "entity_info": {
                "entityName": backend_info["name"],
                "clusterName": backend_info["cluster_name"] or "No Cluster",
                "clusterId": backend_info["cluster_id"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error fetching backend config versions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{backend_id}")
async def update_backend(backend_id: int, backend_update: BackendConfigUpdate, request: Request, authorization: str = Header(None)):
    """Update an existing HAProxy backend and its servers"""
    try:
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for backend update
        has_permission = await check_user_permission(current_user["id"], "backends", "update")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: backends.update required"
            )
        
        conn = await get_database_connection()
        
        # Check if backend exists
        existing_backend = await conn.fetchrow("SELECT * FROM backends WHERE id = $1", backend_id)
        if not existing_backend:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Backend not found")
            
        cluster_id = existing_backend['cluster_id']
        
        # Validate cluster access for multi-cluster security
        if cluster_id:
            await validate_user_cluster_access(current_user['id'], cluster_id, conn)

        # Merge existing data with update request
        update_data = backend_update.dict(exclude_unset=True)
        updated_backend_data = {**existing_backend, **update_data}

        # Build the update query dynamically
        update_fields = []
        update_values = []
        param_idx = 1

        # Check if backend name is being changed
        old_backend_name = existing_backend['name']
        new_backend_name = update_data.get('name', old_backend_name)
        backend_name_changed = old_backend_name != new_backend_name

        for field, value in update_data.items():
            if field in ['name', 'balance_method', 'mode', 'health_check_uri', 'health_check_interval', 
                         'health_check_expected_status', 'fullconn', 'cookie_name', 'cookie_options',
                         'default_server_inter', 'default_server_fall', 'default_server_rise',
                         'request_headers', 'response_headers', 'timeout_connect', 'timeout_server', 'timeout_queue']:
                update_fields.append(f"{field} = ${param_idx}")
                update_values.append(value)
                param_idx += 1

        if not update_fields:
            # Nothing to update besides servers, which are handled separately
            # Still, we should regenerate config if server list is being updated
            pass
        else:
            update_fields.append("updated_at = CURRENT_TIMESTAMP")
            query = f"UPDATE backends SET {', '.join(update_fields)} WHERE id = ${param_idx}"
            update_values.append(backend_id)
            
            await conn.execute(query, *update_values)
            
            # CRITICAL FIX: Update server backend_name references if backend name changed
            if backend_name_changed:
                logger.info(f"BACKEND UPDATE: Backend name changed from '{old_backend_name}' to '{new_backend_name}', updating server references")
                await conn.execute("""
                    UPDATE backend_servers 
                    SET backend_name = $1, updated_at = CURRENT_TIMESTAMP
                    WHERE backend_name = $2
                """, new_backend_name, old_backend_name)
                
                updated_servers_count = await conn.fetchval("""
                    SELECT COUNT(*) FROM backend_servers WHERE backend_name = $1
                """, new_backend_name)
                logger.info(f"BACKEND UPDATE: Updated {updated_servers_count} server references to new backend name")
                
                # CRITICAL FIX: Update frontend default_backend references if backend name changed
                logger.info(f"FRONTEND UPDATE: Updating frontend default_backend references from '{old_backend_name}' to '{new_backend_name}'")
                await conn.execute("""
                    UPDATE frontends 
                    SET default_backend = $1, updated_at = CURRENT_TIMESTAMP
                    WHERE default_backend = $2 AND cluster_id = $3
                """, new_backend_name, old_backend_name, cluster_id)
                
                updated_frontends_count = await conn.fetchval("""
                    SELECT COUNT(*) FROM frontends WHERE default_backend = $1 AND cluster_id = $2
                """, new_backend_name, cluster_id)
                logger.info(f"FRONTEND UPDATE: Updated {updated_frontends_count} frontend default_backend references to new backend name")

        async with conn.transaction():
            # Update main backend properties
            # await conn.execute("""
            #     UPDATE backends SET 
            #         name = $1, 
            #         balance_method = $2, 
            #         mode = $3, 
            #         health_check_uri = $4,
            #         health_check_interval = $5,
            #         timeout_connect = $6,
            #         timeout_server = $7,
            #         timeout_queue = $8,
            #         updated_at = CURRENT_TIMESTAMP
            #     WHERE id = $9
            # """, updated_backend_data.get('name'), updated_backend_data.get('balance_method'),
            #     updated_backend_data.get('mode'), updated_backend_data.get('health_check_uri'),
            #     updated_backend_data.get('health_check_interval'),
            #     updated_backend_data.get('timeout_connect'), updated_backend_data.get('timeout_server'),
            #     updated_backend_data.get('timeout_queue'),
            #     backend_id)

            # Mark PENDING for UI before generating config
            await conn.execute("UPDATE backends SET last_config_status = 'PENDING' WHERE id = $1", backend_id)

            # Create a PENDING config version
            config_content = await generate_haproxy_config_for_cluster(cluster_id, conn=conn)
            config_hash = hashlib.sha256(config_content.encode()).hexdigest()
            version_name = f"backend-{backend_id}-update-{int(time.time())}"
            
            await conn.execute("""
                INSERT INTO config_versions (cluster_id, version_name, config_content, checksum, created_by, status)
                VALUES ($1, $2, $3, $4, $5, 'PENDING')
            """, cluster_id, version_name, config_content, config_hash, current_user['id'])

        await close_database_connection(conn)
        
        # Log activity with comprehensive details
        await log_user_activity(
            user_id=current_user["id"],
            action='update',
            resource_type='backend',
            resource_id=str(backend_id),
            details={
                'backend_name': updated_backend_data.get('name'),
                'balance_method': updated_backend_data.get('balance_method'),
                'cluster_id': updated_backend_data.get('cluster_id'),
                'mode': updated_backend_data.get('mode'),
                'health_check_uri': updated_backend_data.get('health_check_uri')
            },
            ip_address=str(request.client.host) if request.client else None,
            user_agent=request.headers.get('user-agent')
        )
        
        return {"message": f"Backend '{updated_backend_data.get('name')}' updated successfully. Please apply changes."}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update backend: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update backend: {str(e)}")


@router.delete("/{backend_id}", summary="Delete Backend", response_description="Backend deleted successfully")
async def delete_backend(backend_id: int, authorization: str = Header(None)):
    """
    # Delete Backend
    
    Delete a backend configuration and all its servers.
    
    ## Path Parameters
    - **backend_id**: Backend ID to delete
    
    ## Important Notes
    - All associated servers will be deleted
    - Frontends using this backend will need to be updated
    - Change will be applied to agents on next sync
    
    ## Example Request
    ```bash
    curl -X DELETE "{BASE_URL}/api/backends/1" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Response
    ```json
    {
      "message": "Backend 'api-backend' and its servers deleted successfully"
    }
    ```
    
    ## Error Responses
    - **403**: Insufficient permissions or backend is in use by frontends
    - **404**: Backend not found
    - **500**: Server error
    """
    try:
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for backend delete
        has_permission = await check_user_permission(current_user["id"], "backends", "delete")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: backends.delete required"
            )
        
        conn = await get_database_connection()
        
        # Check if backend exists
        backend = await conn.fetchrow("SELECT name, cluster_id FROM backends WHERE id = $1", backend_id)
        if not backend:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Backend not found")
        
        # Validate cluster access for multi-cluster security
        if backend['cluster_id']:
            await validate_user_cluster_access(current_user['id'], backend['cluster_id'], conn)
        
        # Before deleting backend, handle dependencies properly
        backend_name = backend["name"]
        cluster_id = backend["cluster_id"]
        
        # 1. Soft delete all servers belonging to this backend (mark inactive)
        # CRITICAL: Include cluster_id to prevent affecting other clusters with same backend name
        # Handle NULL cluster_id (legacy data) - must use IS NULL check
        if cluster_id is not None:
            await conn.execute("""
                UPDATE backend_servers 
                SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                WHERE backend_name = $1 AND cluster_id = $2
            """, backend_name, cluster_id)
        else:
            await conn.execute("""
                UPDATE backend_servers 
                SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                WHERE backend_name = $1 AND cluster_id IS NULL
            """, backend_name)
        
        # 2. Update frontends that use this backend (set default_backend to NULL)
        # CRITICAL: Include cluster_id to prevent affecting other clusters
        # Handle NULL cluster_id (legacy data)
        if cluster_id is not None:
            await conn.execute("""
                UPDATE frontends 
                SET default_backend = NULL, last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP
                WHERE default_backend = $1 AND cluster_id = $2
            """, backend_name, cluster_id)
        else:
            await conn.execute("""
                UPDATE frontends 
                SET default_backend = NULL, last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP
                WHERE default_backend = $1 AND cluster_id IS NULL
            """, backend_name)
        
        # 2b. CRITICAL FIX: Remove use_backend rules referencing deleted backend from frontends
        # Frontend may have ACL rules like "use_backend Apmserver if Apmserver"
        # These must be removed to prevent HAProxy validation errors
        # Handle NULL cluster_id (legacy data)
        if cluster_id is not None:
            frontends_with_acl_refs = await conn.fetch("""
                SELECT id, name, use_backend_rules, acl_rules 
                FROM frontends 
                WHERE cluster_id = $1 AND is_active = TRUE
            """, cluster_id)
        else:
            frontends_with_acl_refs = await conn.fetch("""
                SELECT id, name, use_backend_rules, acl_rules 
                FROM frontends 
                WHERE cluster_id IS NULL AND is_active = TRUE
            """)
        
        for frontend in frontends_with_acl_refs:
            # Parse use_backend_rules (JSONB array)
            use_backend_rules = frontend['use_backend_rules'] if frontend['use_backend_rules'] else []
            acl_rules = frontend['acl_rules'] if frontend['acl_rules'] else []
            
            # Filter out rules referencing deleted backend
            filtered_use_backend = [rule for rule in use_backend_rules if backend_name not in rule]
            filtered_acl = [rule for rule in acl_rules if backend_name not in rule]
            
            # Update frontend if rules were removed
            if len(filtered_use_backend) != len(use_backend_rules) or len(filtered_acl) != len(acl_rules):
                import json
                await conn.execute("""
                    UPDATE frontends 
                    SET use_backend_rules = $1, acl_rules = $2, 
                        last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP
                    WHERE id = $3
                """, json.dumps(filtered_use_backend), json.dumps(filtered_acl), frontend['id'])
                
                logger.info(f"BACKEND DELETE: Cleaned ACL/use_backend rules for frontend '{frontend['name']}' (removed {backend_name} references)")
        
        # 3. Soft delete the backend (mark as inactive and set PENDING)
        await conn.execute("""
            UPDATE backends 
            SET is_active = FALSE, last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP 
            WHERE id = $1
        """, backend_id)
        
        # Prepare user-friendly success message
        success_message = f"Backend '{backend_name}' and its associated servers have been deleted. Any frontends using this backend have been updated."
        
        await close_database_connection(conn)
        
        # Create new config version for Apply Changes workflow
        sync_results = []
        if cluster_id:
            try:
                from services.haproxy_config import create_pending_config_version
                version_result = await create_pending_config_version(
                    cluster_id=cluster_id,
                    change_description=f"Delete backend: {backend_name}",
                    user_id=current_user["id"],
                    entity_type="backend",
                    entity_id=backend_id
                )
                logger.info(f"BACKEND DELETE: Created pending config version {version_result['version']} for cluster {cluster_id}")
            except Exception as e:
                logger.error(f"BACKEND DELETE: Failed to create config version for cluster {cluster_id}: {e}")
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='delete',
            resource_type='backend',
            resource_id=str(backend_id),
            details={'backend_name': backend['name']}
        )
        
        return {"message": success_message}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete backend: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete backend: {str(e)}")

@router.delete("/servers/{server_id}")
async def delete_server(server_id: int, request: Request, authorization: str = Header(None)):
    """Delete a server from backend"""
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get server info before deletion
        server = await conn.fetchrow("""
            SELECT id, server_name, backend_name, ip_address, port, cluster_id, is_active
            FROM backend_servers WHERE id = $1
        """, server_id)
        
        if not server:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Server not found")
        
        cluster_id = server['cluster_id']
        backend_name = server['backend_name']
        server_name = server['server_name']
        
        # Get request body for cluster_id validation
        request_body = await request.json() if hasattr(request, 'json') else {}
        expected_cluster_id = request_body.get('cluster_id')
        
        # Validate cluster ownership for multi-cluster security
        if expected_cluster_id and cluster_id != expected_cluster_id:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=403, 
                detail=f"Server belongs to cluster {cluster_id}, not cluster {expected_cluster_id}"
            )
        
        # Use the validate_user_cluster_access helper function
        await validate_user_cluster_access(current_user['id'], cluster_id, conn)
        
        logger.info(f"Server delete: server_id={server_id}, name={server_name}, backend={backend_name}, cluster_id={cluster_id}")
        
        # 1. Soft delete the server first (mark as inactive and for deletion)
        await conn.execute("""
            UPDATE backend_servers 
            SET is_active = FALSE, last_config_status = 'DELETION', updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
        """, server_id)
        
        # 2. Also mark the parent backend as PENDING since its server list changed
        await conn.execute("""
            UPDATE backends 
            SET last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP
            WHERE name = $1 AND cluster_id = $2
        """, backend_name, cluster_id)
        
        # Create config version for server deletion (like frontend/SSL delete)
        sync_results = []
        if cluster_id:
            try:
                # Generate new HAProxy config without this server (now inactive)
                from services.haproxy_config import generate_haproxy_config_for_cluster
                config_content = await generate_haproxy_config_for_cluster(cluster_id)
                
                logger.info(f"SERVER DELETE DEBUG: Generated config content length: {len(config_content) if config_content else 0}")
                if config_content:
                    logger.info(f"SERVER DELETE DEBUG: Config contains 'DISABLED': {'DISABLED' in config_content}")
                else:
                    logger.error(f"SERVER DELETE DEBUG: Config content is empty or None!")
                
                # Create new config version
                config_hash = __import__('hashlib').sha256(config_content.encode()).hexdigest()
                version_name = f"server-{server_id}-delete-{int(__import__('time').time())}"
                
                # Get system admin user ID for created_by
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Create PENDING config version (server will be deleted on Apply)
                config_version_id = await conn.fetchval("""
                    INSERT INTO config_versions 
                    (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                    VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                    RETURNING id
                """, cluster_id, version_name, config_content, config_hash, admin_user_id)
                
                logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {cluster_id}")
                
                # Don't notify agents yet - wait for manual Apply
                sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'Server deletion created. Click Apply to activate.'}]
                
            except Exception as sync_error:
                logger.error(f"Server deletion sync failed: {sync_error}")
                sync_results = [{"cluster_id": cluster_id, "success": False, "error": str(sync_error)}]
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='delete',
                resource_type='server',
                resource_id=str(server_id),
                details={
                    'server_name': server_name,
                    'backend_name': backend_name,
                    'cluster_id': cluster_id,
                    'ip_address': server.get('ip_address'),
                    'port': server.get('port')
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        return {
            "message": f"Server '{server_name}' deleted successfully from backend '{backend_name}'",
            "sync_results": sync_results,
            "requires_apply": len(sync_results) > 0 and any(r.get('success') for r in sync_results)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Server deletion failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete server: {str(e)}")

@router.put("/servers/{server_id}")
async def update_server(server_id: int, server_data: dict, request: Request, authorization: str = Header(None)):
    """Update server details"""
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Check if server exists
        existing_server = await conn.fetchrow("""
            SELECT id, server_name, backend_name, cluster_id 
            FROM backend_servers WHERE id = $1
        """, server_id)
        
        if not existing_server:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Server not found")
        
        cluster_id = existing_server['cluster_id']
        
        # Build dynamic update query
        update_fields = []
        update_values = []
        param_idx = 1
        
        # Allow updating these fields
        allowed_fields = ['server_name', 'server_address', 'server_port', 'weight', 'max_connections', 
                         'check_enabled', 'check_port', 'backup_server', 'ssl_enabled', 'ssl_verify', 'ssl_certificate_id',
                         'cookie_value', 'inter', 'fall', 'rise', 'is_active']
        
        for field in allowed_fields:
            if field in server_data:
                update_fields.append(f"{field} = ${param_idx}")
                update_values.append(server_data[field])
                param_idx += 1
        
        if not update_fields:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="No valid fields to update")
        
        # Add timestamp and server_id
        update_fields.append("updated_at = CURRENT_TIMESTAMP")
        query = f"UPDATE backend_servers SET {', '.join(update_fields)} WHERE id = ${param_idx}"
        update_values.append(server_id)
        
        await conn.execute(query, *update_values)
        
        # CRITICAL FIX: Also mark the parent Backend as PENDING for Agent Sync (same as server toggle/delete)
        try:
            await conn.execute("""
                UPDATE backends SET last_config_status = 'PENDING' 
                WHERE name = $1 AND cluster_id = $2
            """, existing_server['backend_name'], cluster_id)
            logger.info(f"BACKEND SYNC: Marked backend '{existing_server['backend_name']}' as PENDING due to server update")
        except Exception as e:
            logger.error(f"Failed to mark parent backend as PENDING: {e}")
        
        await close_database_connection(conn)
        
        # Generate new config after database update (like frontend/backend)
        sync_results = []
        if cluster_id:
            try:
                from services.haproxy_config import generate_haproxy_config_for_cluster
                import hashlib
                import time
                
                # Generate new HAProxy config (after database commit)
                config_content = await generate_haproxy_config_for_cluster(cluster_id)
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"server-{server_id}-update-{int(time.time())}"
                
                # Get system admin user ID for created_by
                conn2 = await get_database_connection()
                admin_user_id = await conn2.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Create PENDING config version
                config_version_id = await conn2.fetchval("""
                    INSERT INTO config_versions 
                    (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                    VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                    RETURNING id
                """, cluster_id, version_name, config_content, config_hash, admin_user_id)
                
                logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {cluster_id}")
                
                # Mark entity config status as PENDING for UI (if column exists)
                try:
                    await conn2.execute("UPDATE backend_servers SET last_config_status = 'PENDING' WHERE id = $1", server_id)
                except Exception:
                    # Column doesn't exist, skip this step
                    logger.info("backend_servers.last_config_status column not found, skipping status update")
                
                # CRITICAL FIX: Also mark the parent Backend as PENDING for Agent Sync
                try:
                    await conn2.execute("""
                        UPDATE backends SET last_config_status = 'PENDING' 
                        WHERE name = $1 AND cluster_id = $2
                    """, existing_server['backend_name'], cluster_id)
                    logger.info(f"BACKEND SYNC: Marked backend '{existing_server['backend_name']}' as PENDING due to server update")
                except Exception as e:
                    logger.warning(f"Failed to update backend last_config_status: {e}")
                
                await close_database_connection(conn2)
                
                # Don't notify agents yet - wait for manual Apply
                sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'Server updated. Click Apply to activate.'}]
                
            except Exception as e:
                logger.error(f"Config generation failed for server update: {e}")
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='update',
            resource_type='server',
            resource_id=str(server_id),
            details={'server_name': server_data.get('server_name', existing_server['server_name'])}
        )
        
        return {
            "message": "Server updated successfully",
            "sync_results": sync_results,
            "requires_apply": len(sync_results) > 0 and any(r.get('success') for r in sync_results)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Server update failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update server: {str(e)}")

@router.put("/servers/{server_id}/toggle")
async def toggle_server(server_id: int, request: Request, authorization: str = Header(None)):
    """Toggle server enabled/disabled status"""
    logger.error(f"SERVER TOGGLE DEBUG: Starting toggle for server_id={server_id}")
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        logger.error(f"SERVER TOGGLE DEBUG: User authenticated: {current_user.get('username')}")
        
        conn = await get_database_connection()
        
        # Get server info
        server = await conn.fetchrow("""
            SELECT id, server_name, backend_name, is_active, cluster_id
            FROM backend_servers WHERE id = $1
        """, server_id)
        
        if not server:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Server not found")
        
        # Toggle server status
        new_status = not server['is_active']
        logger.error(f"SERVER TOGGLE DEBUG: Toggling server {server['server_name']} from {server['is_active']} to {new_status}")
        await conn.execute("""
            UPDATE backend_servers 
            SET is_active = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $2
        """, new_status, server_id)
        logger.error(f"SERVER TOGGLE DEBUG: Server status updated successfully")
        
        cluster_id = server['cluster_id']
        
        # Mark entity config status as PENDING for UI (if column exists) - same as server edit
        try:
            await conn.execute("UPDATE backend_servers SET last_config_status = 'PENDING' WHERE id = $1", server_id)
            logger.error(f"SERVER TOGGLE DEBUG: Server {server_id} marked as PENDING")
        except Exception as e:
            # Column doesn't exist, skip this step
            logger.error(f"SERVER TOGGLE DEBUG: backend_servers.last_config_status column not found: {e}")
        
        # CRITICAL FIX: Also mark the parent Backend as PENDING for Agent Sync - same as server edit
        if cluster_id:
            try:
                await conn.execute("""
                    UPDATE backends SET last_config_status = 'PENDING' 
                    WHERE name = $1 AND cluster_id = $2
                """, server['backend_name'], cluster_id)
                logger.error(f"SERVER TOGGLE DEBUG: Backend '{server['backend_name']}' marked as PENDING due to server toggle")
            except Exception as e:
                logger.error(f"SERVER TOGGLE DEBUG: Failed to mark backend as PENDING: {e}")
        
        # Log activity
        from utils.activity_log import log_user_activity
        await log_user_activity(
            current_user['id'],
            f"Server {'enabled' if new_status else 'disabled'}",
            f"server",
            f"Toggled server '{server['server_name']}' in backend '{server['backend_name']}' to {'enabled' if new_status else 'disabled'}",
            cluster_id
        )
        
        await close_database_connection(conn)
        
        # Generate new config version after database update (same as server edit)
        if cluster_id:
            try:
                from services.haproxy_config import generate_haproxy_config_for_cluster
                import hashlib
                import time
                
                # Generate new HAProxy config (after database commit)
                config_content = await generate_haproxy_config_for_cluster(cluster_id)
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"server-{server_id}-toggle-{int(time.time())}"
                
                # Get system admin user ID for created_by
                conn2 = await get_database_connection()
                admin_user_id = await conn2.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Create PENDING config version
                config_version_id = await conn2.fetchval("""
                    INSERT INTO config_versions 
                    (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                    VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                    RETURNING id
                """, cluster_id, version_name, config_content, config_hash, admin_user_id)
                
                logger.error(f"SERVER TOGGLE DEBUG: Created PENDING config version {version_name} for cluster {cluster_id}")
                
                await close_database_connection(conn2)
                
            except Exception as config_error:
                logger.error(f"SERVER TOGGLE DEBUG: Failed to create config version: {config_error}")
        
        logger.error(f"SERVER TOGGLE DEBUG: Toggle completed successfully for server {server['server_name']}")
        return {
            "success": True,
            "message": f"Server '{server['server_name']}' {'enabled' if new_status else 'disabled'} successfully",
            "server_id": server_id,
            "enabled": new_status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling server {server_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to toggle server status") 