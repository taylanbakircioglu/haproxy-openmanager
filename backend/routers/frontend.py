from fastapi import APIRouter, HTTPException, Request, Header
from typing import Optional
import logging
import time
import hashlib
import json

from models import FrontendConfig
from database.connection import get_database_connection, close_database_connection
from utils.activity_log import log_user_activity
from services.haproxy_config import generate_haproxy_config_for_cluster

router = APIRouter(prefix="/api/frontends", tags=["frontends"])
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

@router.get("", summary="Get All Frontends", response_description="List of frontend configurations")
async def get_frontends(cluster_id: Optional[int] = None):
    """
    # Get All Frontends
    
    Retrieve all frontend configurations (HAProxy listeners). Frontends define how HAProxy receives incoming traffic.
    
    ## Query Parameters
    - **cluster_id** (optional): Filter frontends by cluster ID
    
    ## Example Request
    ```bash
    curl -X GET "{BASE_URL}/api/frontends?cluster_id=1" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Response
    ```json
    [
      {
        "id": 1,
        "name": "web-frontend",
        "bind_address": "*",
        "bind_port": 443,
        "mode": "http",
        "cluster_id": 1,
        "default_backend": "web-backend",
        "ssl_enabled": true,
        "ssl_certificate_id": 1,
        "https_redirect": true,
        "created_at": "2024-01-15T10:30:00Z"
      }
    ]
    ```
    
    ## Frontend Purpose
    - Define listen addresses and ports
    - SSL/TLS termination
    - Request routing to backends
    - HTTP to HTTPS redirection
    """
    try:
        conn = await get_database_connection()
        
        if cluster_id:
            # Filter by cluster_id when provided (only active frontends)
            # Debug: Check if ssl_certificate_id column exists
            ssl_cert_id_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'frontends' AND column_name = 'ssl_certificate_id'
                )
            """)
            logger.info(f"FRONTEND DEBUG: ssl_certificate_id column exists: {ssl_cert_id_exists}")
            
            if ssl_cert_id_exists:
                frontends = await conn.fetch("""
                    SELECT id, name, bind_address, bind_port, default_backend, mode, 
                           ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port, ssl_cert_path, ssl_cert, ssl_verify,
                           acl_rules, redirect_rules, use_backend_rules,
                           request_headers, response_headers, tcp_request_rules,
                           timeout_client, timeout_http_request,
                           rate_limit, compression, log_separate, monitor_uri,
                           maxconn, is_active, created_at, updated_at, cluster_id, last_config_status
                    FROM frontends 
                    WHERE (cluster_id = $1 OR cluster_id IS NULL)
                    ORDER BY name
                """, cluster_id)
            else:
                # Fallback query without ssl_certificate_id
                logger.warning("FRONTEND DEBUG: ssl_certificate_id column missing, using fallback query")
                frontends = await conn.fetch("""
                    SELECT id, name, bind_address, bind_port, default_backend, mode, 
                           ssl_enabled, ssl_cert_path, ssl_cert, ssl_verify,
                           acl_rules, redirect_rules, use_backend_rules,
                           request_headers, response_headers, tcp_request_rules,
                           timeout_client, timeout_http_request,
                           rate_limit, compression, log_separate, monitor_uri,
                           maxconn, is_active, created_at, updated_at, cluster_id, last_config_status
                    FROM frontends 
                    WHERE (cluster_id = $1 OR cluster_id IS NULL)
                    ORDER BY name
                """, cluster_id)
        else:
            # Debug: Check if ssl_certificate_id column exists for global query
            ssl_cert_id_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'frontends' AND column_name = 'ssl_certificate_id'
                )
            """)
            logger.info(f"FRONTEND DEBUG (Global): ssl_certificate_id column exists: {ssl_cert_id_exists}")
            
            if ssl_cert_id_exists:
                frontends = await conn.fetch("""
                    SELECT id, name, bind_address, bind_port, default_backend, mode,
                           ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port, ssl_cert_path, ssl_cert, ssl_verify,
                           acl_rules, redirect_rules, use_backend_rules,
                           request_headers, response_headers, tcp_request_rules,
                           timeout_client, timeout_http_request,
                           rate_limit, compression, log_separate, monitor_uri,
                           maxconn, is_active, created_at, updated_at, cluster_id, last_config_status
                    FROM frontends ORDER BY name
                """)
            else:
                # Fallback query without ssl_certificate_id
                logger.warning("FRONTEND DEBUG (Global): ssl_certificate_id column missing, using fallback query")
                frontends = await conn.fetch("""
                    SELECT id, name, bind_address, bind_port, default_backend, mode,
                           ssl_enabled, ssl_cert_path, ssl_cert, ssl_verify,
                           acl_rules, redirect_rules, use_backend_rules,
                           request_headers, response_headers, tcp_request_rules,
                           timeout_client, timeout_http_request,
                           rate_limit, compression, log_separate, monitor_uri,
                           maxconn, is_active, created_at, updated_at, cluster_id, last_config_status
                    FROM frontends ORDER BY name
                """)
        
        # Check for pending configurations by cluster
        pending_frontend_ids = set()
        if frontends:
            cluster_ids = [f["cluster_id"] for f in frontends if f["cluster_id"]]
            if cluster_ids:
                try:
                    # Check for frontend-specific pending changes using entity ID in version name
                    # Exclude WAF changes as they don't require Frontend page Apply
                    pending_configs = await conn.fetch("""
                        SELECT DISTINCT 
                            CASE 
                                WHEN version_name ~ 'frontend-[0-9]+-' THEN 
                                    SUBSTRING(version_name FROM 'frontend-([0-9]+)-')::int
                                ELSE NULL
                            END as frontend_id
                        FROM config_versions 
                        WHERE cluster_id = ANY($1) AND status = 'PENDING'
                        AND version_name ~ 'frontend-[0-9]+-'
                        AND version_name NOT LIKE 'waf-%'
                    """, cluster_ids)
                    pending_frontend_ids = {pc["frontend_id"] for pc in pending_configs if pc["frontend_id"]}
                except Exception as e:
                    logger.warning(f"FRONTEND API: Failed to check pending configs: {e}")
                    pending_frontend_ids = set()
        
        await close_database_connection(conn)
        
        # Debug: Log SSL-enabled frontends before returning
        ssl_frontends = [f for f in frontends if f.get("ssl_enabled")]
        if ssl_frontends:
            logger.info(f"FRONTEND API DEBUG: Returning {len(ssl_frontends)} SSL-enabled frontends:")
            for f in ssl_frontends:
                logger.info(f"SSL FRONTEND: {f['name']} - ssl_enabled: {f.get('ssl_enabled')}, ssl_certificate_id: {f.get('ssl_certificate_id')}, ssl_certificate_ids: {f.get('ssl_certificate_ids')}, ssl_port: {f.get('ssl_port')}")
        
        # CRITICAL: Parse JSONB fields that may come as strings
        def parse_jsonb_field(value, default=[]):
            """Parse JSONB field that may be string or already parsed"""
            if value is None:
                return default
            if isinstance(value, list):
                return value
            if isinstance(value, str):
                try:
                    import json as json_lib
                    return json_lib.loads(value)
                except:
                    return default
            return default
        
        return {
            "frontends": [
                {
                    "id": f["id"],
                    "name": f["name"],
                    "bind_address": f["bind_address"],
                    "bind_port": f["bind_port"],
                    "default_backend": f["default_backend"],
                    "mode": f["mode"],
                    "ssl_enabled": f.get("ssl_enabled", False),
                    "ssl_certificate_id": f.get("ssl_certificate_id"),
                    "ssl_certificate_ids": parse_jsonb_field(f.get("ssl_certificate_ids"), []),
                    "ssl_port": f.get("ssl_port"),
                    "ssl_cert_path": f.get("ssl_cert_path"),
                    "ssl_cert": f.get("ssl_cert"),
                    "ssl_verify": f.get("ssl_verify", "optional"),
                    "acl_rules": parse_jsonb_field(f.get("acl_rules"), []),
                    "redirect_rules": parse_jsonb_field(f.get("redirect_rules"), []),
                    "use_backend_rules": f.get("use_backend_rules"),
                    "request_headers": f.get("request_headers"),
                    "response_headers": f.get("response_headers"),
                    "timeout_client": f.get("timeout_client"),
                    "timeout_http_request": f.get("timeout_http_request"),
                    "rate_limit": f.get("rate_limit"),
                    "compression": f.get("compression", False),
                    "log_separate": f.get("log_separate", False),
                    "monitor_uri": f.get("monitor_uri"),
                    "maxconn": f.get("maxconn"),
                    "is_active": f["is_active"],
                    "last_config_status": f.get("last_config_status") or "APPLIED",
                    "created_at": f["created_at"].isoformat().replace('+00:00', 'Z') if f["created_at"] else None,
                    "updated_at": f["updated_at"].isoformat().replace('+00:00', 'Z') if f["updated_at"] else None,
                    "cluster_id": f.get("cluster_id"),
                    "has_pending_config": f["id"] in pending_frontend_ids or not f.get("is_active", True)
                } for f in frontends
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("")
async def create_frontend(frontend: FrontendConfig, request: Request, authorization: str = Header(None)):
    """Create new frontend configuration with cluster synchronization"""
    try:
        # Get current user for activity logging
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for frontend create
        has_permission = await check_user_permission(current_user["id"], "frontends", "create")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: frontends.create required"
            )
        
        conn = await get_database_connection()
        
        # Validate cluster access for multi-cluster security
        if frontend.cluster_id:
            await validate_user_cluster_access(current_user['id'], frontend.cluster_id, conn)
        
        # Check if frontend name already exists in the same cluster (only active frontends)
        existing = await conn.fetchrow("""
            SELECT id FROM frontends 
            WHERE name = $1 AND (cluster_id = $2 OR cluster_id IS NULL) AND is_active = TRUE
        """, frontend.name, frontend.cluster_id)
        if existing:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail=f"Frontend '{frontend.name}' already exists")
        
        # ENTERPRISE DUAL-MODE: Save ssl_certificate_ids (NEW) and ssl_certificate_id (OLD - backward compat)
        # Convert ssl_certificate_ids to JSONB for database
        ssl_cert_ids_json = json.dumps(frontend.ssl_certificate_ids) if frontend.ssl_certificate_ids else '[]'
        
        # Insert new frontend with all form fields
        frontend_id = await conn.fetchval("""
            INSERT INTO frontends (
                name, bind_address, bind_port, default_backend, mode, 
                ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port, ssl_cert_path, ssl_cert, ssl_verify,
                acl_rules, redirect_rules, use_backend_rules,
                request_headers, response_headers, tcp_request_rules, timeout_client, timeout_http_request,
                rate_limit, compression, log_separate, monitor_uri,
                cluster_id, maxconn, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, CURRENT_TIMESTAMP) 
            RETURNING id
        """, frontend.name, frontend.bind_address, frontend.bind_port, 
            frontend.default_backend, frontend.mode, frontend.ssl_enabled,
            frontend.ssl_certificate_id, ssl_cert_ids_json, frontend.ssl_port, frontend.ssl_cert_path, frontend.ssl_cert, frontend.ssl_verify,
            json.dumps(frontend.acl_rules or []), json.dumps(frontend.redirect_rules or []), json.dumps(frontend.use_backend_rules or []),
            frontend.request_headers, frontend.response_headers, frontend.tcp_request_rules, frontend.timeout_client, frontend.timeout_http_request,
            frontend.rate_limit, frontend.compression, frontend.log_separate, frontend.monitor_uri,
            frontend.cluster_id, frontend.maxconn)
        
        # If cluster_id provided, create new config version for agents
        sync_results = []
        if frontend.cluster_id:
            try:
                # Generate new HAProxy config
                config_content = await generate_haproxy_config_for_cluster(frontend.cluster_id)
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"frontend-{frontend_id}-create-{int(time.time())}"
                
                # Get system admin user ID for created_by (fresh DB has admin with ID 1)
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Try with status field first, fallback to old behavior if field doesn't exist
                try:
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                        VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                        RETURNING id
                    """, frontend.cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {frontend.cluster_id}")
                    # Mark entity config status as PENDING for UI
                    await conn.execute("UPDATE frontends SET last_config_status = 'PENDING' WHERE id = $1", frontend_id)
                    
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
                    """, frontend.cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    # Deactivate previous versions for this cluster
                    await conn.execute("""
                        UPDATE config_versions 
                        SET is_active = FALSE 
                        WHERE cluster_id = $1 AND id != $2
                    """, frontend.cluster_id, config_version_id)
                    
                    # Use old notification behavior - notify agents immediately
                    from agent_notifications import notify_agents_config_change
                    sync_results = await notify_agents_config_change(frontend.cluster_id, version_name)
                    logger.info(f"FALLBACK: Using immediate-apply, agents notified")
                
            except Exception as e:
                logger.error(f"Cluster config update failed for frontend {frontend.name}: {e}")
                # Still return success for database save, but with sync warning
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='create',
                resource_type='frontend',
                resource_id=str(frontend_id),
                details={
                    'frontend_name': frontend.name,
                    'bind_address': frontend.bind_address,
                    'bind_port': frontend.bind_port,
                    'cluster_id': frontend.cluster_id,
                    'sync_results': len(sync_results)
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        return {
            "message": f"Frontend '{frontend.name}' created successfully",
            "id": frontend_id,
            "frontend": frontend.dict(),
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{frontend_id}/config-versions")
async def get_frontend_config_versions(frontend_id: int, authorization: str = Header(None)):
    """Get config version history for a specific frontend"""
    try:
        # Verify user authentication
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get frontend info first
        frontend_info = await conn.fetchrow("""
            SELECT f.id, f.name, c.name as cluster_name, f.cluster_id
            FROM frontends f
            LEFT JOIN haproxy_clusters c ON f.cluster_id = c.id
            WHERE f.id = $1
        """, frontend_id)
        
        if not frontend_info:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Frontend not found")
        
        # Get all APPLIED config versions that are related to this frontend
        versions = await conn.fetch("""
            SELECT cv.id, cv.version_name, cv.description, cv.status, cv.is_active,
                   cv.created_at, cv.file_size, cv.checksum,
                   u.username as created_by_username
            FROM config_versions cv
            LEFT JOIN users u ON cv.created_by = u.id
            WHERE cv.cluster_id = $1 AND cv.status = 'APPLIED'
            AND cv.version_name ~ $2
            ORDER BY cv.created_at DESC
        """, frontend_info['cluster_id'], f'^frontend-{frontend_id}-')
        
        await close_database_connection(conn)
        
        # Format the response
        formatted_versions = []
        for version in versions:
            formatted_versions.append({
                "id": version["id"],
                "version_name": version["version_name"],
                "description": version["description"] or "Frontend configuration update",
                "type": "Frontend",
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
                "entityName": frontend_info["name"],
                "clusterName": frontend_info["cluster_name"] or "No Cluster",
                "clusterId": frontend_info["cluster_id"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error fetching frontend config versions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{frontend_id}")
async def update_frontend(frontend_id: int, frontend: FrontendConfig, request: Request, authorization: str = Header(None)):
    """Update existing frontend configuration with cluster synchronization"""
    try:
        # Get current user for activity logging
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for frontend update
        has_permission = await check_user_permission(current_user["id"], "frontends", "update")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: frontends.update required"
            )
        
        conn = await get_database_connection()
        
        # Check if frontend exists and get current SSL configuration
        existing = await conn.fetchrow("""
            SELECT id, name, cluster_id, ssl_enabled, ssl_certificate_id, ssl_port, ssl_cert_path, ssl_cert, ssl_verify 
            FROM frontends WHERE id = $1
        """, frontend_id)
        if not existing:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Frontend not found")
        
        # Validate cluster access for multi-cluster security
        cluster_id = existing['cluster_id'] or frontend.cluster_id
        if cluster_id:
            await validate_user_cluster_access(current_user['id'], cluster_id, conn)
        
        # Check if name is being changed and if new name already exists
        if frontend.name != existing["name"]:
            name_exists = await conn.fetchrow("SELECT id FROM frontends WHERE name = $1 AND id != $2", frontend.name, frontend_id)
            if name_exists:
                await close_database_connection(conn)
                raise HTTPException(status_code=400, detail=f"Frontend name '{frontend.name}' already exists")
        
        # CRITICAL FIX: Preserve SSL configuration if not explicitly changed
        # If SSL is currently enabled but incoming data has ssl_enabled=False or ssl_certificate_id=None,
        # check if this is an intentional change or just missing data from the form
        # Preserve existing SSL config if incoming SSL fields are None/False but existing config has SSL enabled
        preserve_ssl_config = False
        if existing['ssl_enabled'] and existing['ssl_certificate_id']:
            # If existing has SSL enabled, but incoming data doesn't have ssl_enabled or has it as False with None certificate_id
            if not frontend.ssl_enabled and not frontend.ssl_certificate_id:
                # This appears to be unintentional loss of SSL config - preserve it
                preserve_ssl_config = True
                logger.warning(f"FRONTEND UPDATE FIX: Preserving SSL config for frontend {frontend.name} (ssl_certificate_id={existing['ssl_certificate_id']})")
        
        # Use preserved values if needed
        if preserve_ssl_config:
            ssl_enabled = existing['ssl_enabled']
            ssl_certificate_id = existing['ssl_certificate_id']
            ssl_port = existing['ssl_port'] if existing['ssl_port'] else frontend.ssl_port
            ssl_cert_path = existing['ssl_cert_path']
            ssl_cert = existing['ssl_cert']
            ssl_verify = existing['ssl_verify'] if existing['ssl_verify'] else frontend.ssl_verify
            logger.info(f"PRESERVED SSL CONFIG: ssl_enabled={ssl_enabled}, ssl_certificate_id={ssl_certificate_id}, ssl_port={ssl_port}")
        else:
            ssl_enabled = frontend.ssl_enabled
            ssl_certificate_id = frontend.ssl_certificate_id
            ssl_port = frontend.ssl_port
            ssl_cert_path = frontend.ssl_cert_path
            ssl_cert = frontend.ssl_cert
            ssl_verify = frontend.ssl_verify
        
        # Debug SSL certificate assignment
        logger.info(f"FRONTEND UPDATE DEBUG: Incoming - ssl_enabled={frontend.ssl_enabled}, ssl_certificate_id={frontend.ssl_certificate_id}, ssl_certificate_ids={frontend.ssl_certificate_ids}, ssl_port={frontend.ssl_port}")
        logger.info(f"FRONTEND UPDATE DEBUG: Final - ssl_enabled={ssl_enabled}, ssl_certificate_id={ssl_certificate_id}, ssl_port={ssl_port}")
        
        # ENTERPRISE DUAL-MODE: Save ssl_certificate_ids (NEW) and ssl_certificate_id (OLD - backward compat)
        ssl_cert_ids_json = json.dumps(frontend.ssl_certificate_ids) if frontend.ssl_certificate_ids else '[]'
        
        # Update frontend with all form fields (using preserved SSL values if needed)
        await conn.execute("""
            UPDATE frontends SET 
                name = $1, bind_address = $2, bind_port = $3, 
                default_backend = $4, mode = $5, ssl_enabled = $6,
                ssl_certificate_id = $7, ssl_certificate_ids = $8, ssl_port = $9, ssl_cert_path = $10, ssl_cert = $11, ssl_verify = $12,
                acl_rules = $13, redirect_rules = $14, use_backend_rules = $15,
                request_headers = $16, response_headers = $17, tcp_request_rules = $18, timeout_client = $19, timeout_http_request = $20,
                rate_limit = $21, compression = $22, log_separate = $23, monitor_uri = $24,
                cluster_id = $25, maxconn = $26, updated_at = CURRENT_TIMESTAMP
            WHERE id = $27
        """, frontend.name, frontend.bind_address, frontend.bind_port, 
            frontend.default_backend, frontend.mode, ssl_enabled,
            ssl_certificate_id, ssl_cert_ids_json, ssl_port, ssl_cert_path, ssl_cert, ssl_verify,
            json.dumps(frontend.acl_rules or []), json.dumps(frontend.redirect_rules or []), json.dumps(frontend.use_backend_rules or []),
            frontend.request_headers, frontend.response_headers, frontend.tcp_request_rules, frontend.timeout_client, frontend.timeout_http_request,
            frontend.rate_limit, frontend.compression, frontend.log_separate, frontend.monitor_uri,
            frontend.cluster_id, frontend.maxconn, frontend_id)
            
        # Debug: Check what was actually saved
        updated_frontend = await conn.fetchrow("""
            SELECT ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port 
            FROM frontends WHERE id = $1
        """, frontend_id)
        logger.info(f"FRONTEND UPDATE RESULT: {dict(updated_frontend)}")
        
        # Additional debug: Check the full record to see what changed
        full_record = await conn.fetchrow("""
            SELECT id, name, ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port, last_config_status, updated_at
            FROM frontends WHERE id = $1
        """, frontend_id)
        logger.info(f"FRONTEND FULL RECORD AFTER UPDATE: {dict(full_record)}")
        
        # If cluster_id provided, create new config version for agents
        sync_results = []
        if frontend.cluster_id:
            try:
                # Generate new HAProxy config
                config_content = await generate_haproxy_config_for_cluster(frontend.cluster_id)
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"frontend-{frontend_id}-update-{int(time.time())}"
                
                # Get system admin user ID for created_by
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Try with status field first, fallback to old behavior if field doesn't exist
                try:
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                        VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                        RETURNING id
                    """, frontend.cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {frontend.cluster_id}")
                    # Mark entity config status as PENDING for UI
                    await conn.execute("UPDATE frontends SET last_config_status = 'PENDING' WHERE id = $1", frontend_id)
                    
                    # Don't notify agents yet - wait for manual Apply
                    sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'Changes updated. Click Apply to activate.'}]
                    
                except Exception as status_error:
                    logger.warning(f"FALLBACK: Status field not available, using old immediate-apply behavior: {status_error}")
                    # Fallback to old behavior without status field
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active)
                        VALUES ($1, $2, $3, $4, $5, TRUE)
                        RETURNING id
                    """, frontend.cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    # Deactivate previous versions for this cluster
                    await conn.execute("""
                        UPDATE config_versions 
                        SET is_active = FALSE 
                        WHERE cluster_id = $1 AND id != $2
                    """, frontend.cluster_id, config_version_id)
                    
                    # Use old notification behavior - notify agents immediately
                    from agent_notifications import notify_agents_config_change
                    sync_results = await notify_agents_config_change(frontend.cluster_id, version_name)
                    logger.info(f"FALLBACK: Using immediate-apply, agents notified")
                
            except Exception as e:
                logger.error(f"Cluster config update failed for frontend {frontend.name}: {e}")
                # Still return success for database save, but with sync warning
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='update',
                resource_type='frontend',
                resource_id=str(frontend_id),
                details={
                    'frontend_name': frontend.name,
                    'bind_address': frontend.bind_address,
                    'bind_port': frontend.bind_port,
                    'cluster_id': frontend.cluster_id,
                    'sync_results': len(sync_results)
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        return {
            "message": f"Frontend '{frontend.name}' updated successfully",
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{frontend_id}")
async def delete_frontend(frontend_id: int, request: Request, authorization: str = Header(None)):
    """Delete frontend configuration with cluster synchronization"""
    try:
        # Get current user for activity logging
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for frontend delete
        has_permission = await check_user_permission(current_user["id"], "frontends", "delete")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: frontends.delete required"
            )
        
        conn = await get_database_connection()
        
        # Check if frontend exists and get cluster_id and default_backend
        frontend = await conn.fetchrow("SELECT name, cluster_id, is_active, default_backend FROM frontends WHERE id = $1", frontend_id)
        if not frontend:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Frontend not found")
        
        # Validate cluster access for multi-cluster security
        if frontend['cluster_id']:
            await validate_user_cluster_access(current_user['id'], frontend['cluster_id'], conn)
        
        if not frontend['is_active']:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Frontend already deleted")
        
        cluster_id = frontend['cluster_id']
        logger.info(f"Frontend delete: frontend_id={frontend_id}, name={frontend['name']}, cluster_id={cluster_id}")
        
        # Handle dependencies properly before deletion
        frontend_name = frontend["name"]
        
        # Check if frontend has a default backend configured
        backend_dependency = None
        if frontend.get('default_backend'):
            # Check if the backend still exists
            backend_exists = await conn.fetchval("""
                SELECT name FROM backends 
                WHERE name = $1 AND is_active = TRUE
            """, frontend['default_backend'])
            if backend_exists:
                backend_dependency = frontend['default_backend']
        
        # If frontend uses a backend, suggest deleting the backend first
        if backend_dependency:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot delete frontend '{frontend_name}': it uses backend '{backend_dependency}'. Please delete the backend first, then the frontend will be automatically updated."
            )
        
        # Remove WAF rule associations (cascade delete)
        waf_rules_removed_rows = await conn.fetch("""
            DELETE FROM frontend_waf_rules 
            WHERE frontend_id = $1 
            RETURNING *
        """, frontend_id)
        waf_rules_removed = len(waf_rules_removed_rows)
        
        # Soft delete frontend - mark as inactive and set PENDING
        await conn.execute(
            "UPDATE frontends SET is_active = FALSE, last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP WHERE id = $1", 
            frontend_id
        )
        
        # If cluster_id provided, create new config version for agents
        sync_results = []
        if cluster_id:
            try:
                # Generate new HAProxy config without this frontend
                config_content = await generate_haproxy_config_for_cluster(cluster_id)
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"frontend-{frontend_id}-delete-{int(time.time())}"
                
                # Get system admin user ID for created_by
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Try with status field first, fallback to old behavior if field doesn't exist
                try:
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                        VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                        RETURNING id
                    """, cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {cluster_id}")
                    
                    # Don't notify agents yet - wait for manual Apply
                    sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'Frontend deletion created. Click Apply to activate.'}]
                    
                except Exception as status_error:
                    logger.warning(f"FALLBACK: Status field not available, using old immediate-apply behavior: {status_error}")
                    # Fallback to old behavior without status field
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active)
                        VALUES ($1, $2, $3, $4, $5, TRUE)
                        RETURNING id
                    """, cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    # Deactivate previous versions for this cluster
                    await conn.execute("""
                        UPDATE config_versions 
                        SET is_active = FALSE 
                        WHERE cluster_id = $1 AND id != $2
                    """, cluster_id, config_version_id)
                    
                    # Use old notification behavior - notify agents immediately
                    from agent_notifications import notify_agents_config_change
                    sync_results = await notify_agents_config_change(cluster_id, version_name)
                    logger.info(f"FALLBACK: Using immediate-apply, agents notified")
                
            except Exception as e:
                logger.error(f"Cluster config update failed after deleting frontend {frontend['name']}: {e}")
                # Still return success for database save, but with sync warning
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='delete',
                resource_type='frontend',
                resource_id=str(frontend_id),
                details={
                    'frontend_name': frontend['name'],
                    'cluster_id': cluster_id,
                    'sync_results': len(sync_results)
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        # Prepare user-friendly success message
        success_parts = [f"Frontend '{frontend_name}' deleted successfully"]
        if waf_rules_removed > 0:
            success_parts.append(f"{waf_rules_removed} WAF rule association(s) also removed")
        
        success_message = ". ".join(success_parts) + "."
        
        return {
            "message": success_message,
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 