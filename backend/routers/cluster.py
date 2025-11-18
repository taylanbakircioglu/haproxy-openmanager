from fastapi import APIRouter, HTTPException, Header
from typing import Optional
import logging
import re
from datetime import datetime, timezone

from models import HAProxyClusterCreate, HAProxyClusterUpdate
from database.connection import get_database_connection, close_database_connection
from utils.activity_log import log_user_activity
# Rate limiting import temporarily disabled

router = APIRouter(prefix="/api/clusters", tags=["clusters"])
logger = logging.getLogger(__name__)

def _extract_entities_from_config(config_content: str) -> dict:
    """Extract entity names from HAProxy config content for sync purposes"""
    import re
    
    entities = {
        'frontends': set(),
        'backends': set(),
        'waf_rules': set()
    }
    
    if not config_content:
        return entities
    
    lines = config_content.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Extract frontend names
        if line.startswith('frontend '):
            frontend_name = line.split()[1] if len(line.split()) > 1 else None
            if frontend_name:
                entities['frontends'].add(frontend_name)
        
        # Extract backend names
        elif line.startswith('backend '):
            backend_name = line.split()[1] if len(line.split()) > 1 else None
            if backend_name:
                entities['backends'].add(backend_name)
    
    return entities


async def apply_ssl_related_configs(conn, trigger_cluster_id: int):
    """
    SSL-related PENDING config'leri tespit et ve scope'larına göre apply et.
    
    Mantık:
    - Global SSL: Tüm cluster'lardaki ilgili PENDING config'leri APPLIED yap
    - Cluster-specific SSL: İlgili cluster'lardaki PENDING config'leri APPLIED yap
    
    Bu sayede tek Apply tıklaması ile SSL'in scope'u dahilindeki tüm cluster'lara yayılır.
    """
    import re
    
    # 1. Trigger cluster'daki SSL-related PENDING config'leri bul
    ssl_pending = await conn.fetch("""
        SELECT version_name FROM config_versions
        WHERE cluster_id = $1 
        AND status = 'PENDING'
        AND version_name LIKE 'ssl-%'
    """, trigger_cluster_id)
    
    if not ssl_pending:
        logger.debug(f"SSL AUTO-APPLY: No SSL-related PENDING configs found for cluster {trigger_cluster_id}")
        return
    
    logger.info(f"SSL AUTO-APPLY: Found {len(ssl_pending)} SSL-related PENDING configs in cluster {trigger_cluster_id}")
    
    # 2. Her SSL için scope'unu belirle ve tüm ilgili cluster'lara apply et
    processed_ssl_ids = set()
    
    for version in ssl_pending:
        # Extract SSL ID from version_name: "ssl-5-update-123" → 5
        match = re.match(r'ssl-(\d+)-', version['version_name'])
        if not match:
            logger.warning(f"SSL AUTO-APPLY: Could not extract SSL ID from version name: {version['version_name']}")
            continue
        
        ssl_id = int(match.group(1))
        
        # Aynı SSL için tekrar işlem yapma
        if ssl_id in processed_ssl_ids:
            continue
        
        processed_ssl_ids.add(ssl_id)
        
        # SSL'in scope'unu bul
        ssl_info = await conn.fetchrow("""
            SELECT cluster_id, name FROM ssl_certificates WHERE id = $1
        """, ssl_id)
        
        if not ssl_info:
            logger.warning(f"SSL AUTO-APPLY: SSL certificate {ssl_id} not found, skipping")
            continue
        
        target_clusters = []
        
        if ssl_info['cluster_id'] is None:
            # Global SSL → Tüm cluster'lardaki bu SSL'e ait PENDING config'leri bul
            logger.info(f"SSL AUTO-APPLY: SSL {ssl_id} ('{ssl_info['name']}') is GLOBAL, applying to all affected clusters")
            
            # Use parameterized query with string formatting for LIKE pattern
            ssl_pattern = f'ssl-{ssl_id}-%'
            target_clusters_result = await conn.fetch("""
                SELECT DISTINCT cluster_id FROM config_versions
                WHERE version_name LIKE $1 AND status = 'PENDING'
            """, ssl_pattern)
            
            target_clusters = [row['cluster_id'] for row in target_clusters_result]
            
        else:
            # Cluster-specific SSL → İlgili cluster'lardaki bu SSL'e ait PENDING config'leri bul
            logger.info(f"SSL AUTO-APPLY: SSL {ssl_id} ('{ssl_info['name']}') is CLUSTER-SPECIFIC, applying to associated clusters")
            
            # Use parameterized query with string formatting for LIKE pattern
            ssl_pattern = f'ssl-{ssl_id}-%'
            target_clusters_result = await conn.fetch("""
                SELECT DISTINCT scc.cluster_id 
                FROM ssl_certificate_clusters scc
                JOIN config_versions cv ON cv.cluster_id = scc.cluster_id
                WHERE scc.ssl_certificate_id = $1 
                AND cv.status = 'PENDING'
                AND cv.version_name LIKE $2
            """, ssl_id, ssl_pattern)
            
            target_clusters = [row['cluster_id'] for row in target_clusters_result]
        
        if not target_clusters:
            logger.warning(f"SSL AUTO-APPLY: No target clusters found for SSL {ssl_id}")
            continue
        
        logger.info(f"SSL AUTO-APPLY: Applying SSL {ssl_id} to {len(target_clusters)} cluster(s): {target_clusters}")
        
        # 3. Tüm ilgili cluster'larda APPLIED olarak işaretle
        # CRITICAL: is_active=FALSE çünkü consolidated version is_active=TRUE olacak
        # SSL version'ları sadece history ve entity tracking için kullanılır
        ssl_pattern = f'ssl-{ssl_id}-%'
        for target_cluster_id in target_clusters:
            result = await conn.execute("""
                UPDATE config_versions 
                SET status = 'APPLIED', is_active = FALSE
                WHERE cluster_id = $1 
                AND version_name LIKE $2 
                AND status = 'PENDING'
            """, target_cluster_id, ssl_pattern)
            
            logger.info(f"SSL AUTO-APPLY: Applied SSL {ssl_id} to cluster {target_cluster_id} (result: {result})")
        
        # 4. SSL entity status'unu APPLIED olarak güncelle
        await conn.execute("""
            UPDATE ssl_certificates 
            SET last_config_status = 'APPLIED'
            WHERE id = $1
        """, ssl_id)
        
        logger.info(f"SSL AUTO-APPLY: Updated SSL {ssl_id} entity status to APPLIED")
    
    logger.info(f"SSL AUTO-APPLY: Completed processing {len(processed_ssl_ids)} unique SSL certificate(s)")


@router.post("", summary="Create HAProxy Cluster", response_description="Cluster created successfully")
async def create_cluster(cluster: HAProxyClusterCreate, authorization: str = Header(None)):
    """
    # Create a New HAProxy Cluster
    
    Create a new HAProxy cluster associated with an agent pool. Clusters group HAProxy instances that share configuration.
    
    ## Prerequisites
    1. Agent pool must exist (created via POST `/api/clusters/pools`)
    2. User must have `clusters.create` permission
    
    ## Request Body
    - **name**: Unique cluster name (required)
    - **description**: Cluster description (optional)
    - **connection_type**: Connection type, typically "agent" (required)
    - **stats_socket_path**: HAProxy stats socket path (default: /var/run/haproxy.sock)
    - **haproxy_config_path**: HAProxy config file path (default: /etc/haproxy/haproxy.cfg)
    - **haproxy_bin_path**: HAProxy binary path (default: /usr/sbin/haproxy)
    - **pool_id**: Associated agent pool ID (required)
    
    ## Example Request
    ```bash
    curl -X POST "{BASE_URL}/api/clusters" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..." \\
      -H "Content-Type: application/json" \\
      -d '{
        "name": "production-cluster",
        "description": "Production HAProxy cluster",
        "connection_type": "agent",
        "stats_socket_path": "/var/run/haproxy.sock",
        "haproxy_config_path": "/etc/haproxy/haproxy.cfg",
        "haproxy_bin_path": "/usr/sbin/haproxy",
        "pool_id": 1
      }'
    ```
    
    ## Example Response
    ```json
    {
      "message": "Cluster 'production-cluster' created successfully",
      "cluster_id": 1
    }
    ```
    
    ## Error Responses
    - **403**: Insufficient permissions
    - **409**: Cluster name already exists
    - **500**: Server error
    """
    try:
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for cluster create
        has_permission = await check_user_permission(current_user["id"], "clusters", "create")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: clusters.create required"
            )
        
        conn = await get_database_connection()
        
        # Create cluster
        cluster_id = await conn.fetchval("""
            INSERT INTO haproxy_clusters (name, description, connection_type, is_active, 
                                        stats_socket_path, haproxy_config_path, haproxy_bin_path, pool_id)
            VALUES ($1, $2, $3, TRUE, $4, $5, $6, $7)
            RETURNING id
        """, cluster.name, cluster.description, cluster.connection_type,
            cluster.stats_socket_path, cluster.haproxy_config_path, cluster.haproxy_bin_path, cluster.pool_id)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='create',
            resource_type='cluster',
            resource_id=str(cluster_id),
            details={'cluster_name': cluster.name}
        )
        
        return {"message": f"Cluster '{cluster.name}' created successfully", "cluster_id": cluster_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create cluster: {e}")
        
        # Handle duplicate cluster name error with user-friendly message
        if "duplicate key value violates unique constraint" in str(e) and "haproxy_clusters_name_key" in str(e):
            raise HTTPException(
                status_code=409, 
                detail=f"Cluster name '{cluster.name}' already exists. Please choose a different name."
            )
        
        raise HTTPException(status_code=500, detail=f"Failed to create cluster: {str(e)}")


@router.put("/{cluster_id}", summary="Update HAProxy Cluster", response_description="Cluster updated successfully")
async def update_cluster(cluster_id: int, cluster: HAProxyClusterUpdate, authorization: str = Header(None)):
    """
    # Update Existing HAProxy Cluster
    
    Update cluster configuration. Only provided fields will be updated (partial update supported).
    
    ## Path Parameters
    - **cluster_id**: Cluster ID to update
    
    ## Request Body (all optional)
    - **name**: New cluster name
    - **description**: New description
    - **connection_type**: New connection type
    - **is_active**: Active status (true/false)
    - **stats_socket_path**: New stats socket path
    - **haproxy_config_path**: New config file path
    - **haproxy_bin_path**: New binary path
    - **pool_id**: New pool association
    
    ## Example Request
    ```bash
    curl -X PUT "{BASE_URL}/api/clusters/1" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..." \\
      -H "Content-Type: application/json" \\
      -d '{
        "description": "Updated production cluster description",
        "is_active": true
      }'
    ```
    
    ## Example Response
    ```json
    {
      "message": "Cluster 'production-cluster' updated successfully"
    }
    ```
    
    ## Error Responses
    - **403**: Insufficient permissions
    - **404**: Cluster not found
    - **500**: Server error
    """
    try:
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for cluster update
        has_permission = await check_user_permission(current_user["id"], "clusters", "update")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: clusters.update required"
            )
        
        conn = await get_database_connection()
        
        # Check if cluster exists and get current values
        existing_cluster = await conn.fetchrow("""
            SELECT name, description, connection_type, is_active, stats_socket_path, 
                   haproxy_config_path, haproxy_bin_path, pool_id 
            FROM haproxy_clusters WHERE id = $1
        """, cluster_id)
        if not existing_cluster:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Cluster not found")
        
        # Build dynamic update query - only update fields that are provided (not None)
        update_fields = []
        update_values = [cluster_id]
        param_counter = 2
        
        if cluster.name is not None:
            update_fields.append(f"name = ${param_counter}")
            update_values.append(cluster.name)
            param_counter += 1
            
        if cluster.description is not None:
            update_fields.append(f"description = ${param_counter}")
            update_values.append(cluster.description)
            param_counter += 1
            
        if cluster.connection_type is not None:
            update_fields.append(f"connection_type = ${param_counter}")
            update_values.append(cluster.connection_type)
            param_counter += 1
            
        if cluster.is_active is not None:
            update_fields.append(f"is_active = ${param_counter}")
            update_values.append(cluster.is_active)
            param_counter += 1
            
        if cluster.stats_socket_path is not None:
            update_fields.append(f"stats_socket_path = ${param_counter}")
            update_values.append(cluster.stats_socket_path)
            param_counter += 1
            
        if cluster.haproxy_config_path is not None:
            update_fields.append(f"haproxy_config_path = ${param_counter}")
            update_values.append(cluster.haproxy_config_path)
            param_counter += 1
            
        if cluster.haproxy_bin_path is not None:
            update_fields.append(f"haproxy_bin_path = ${param_counter}")
            update_values.append(cluster.haproxy_bin_path)
            param_counter += 1
            
        if cluster.pool_id is not None:
            update_fields.append(f"pool_id = ${param_counter}")
            update_values.append(cluster.pool_id)
            param_counter += 1
        
        # Only execute update if there are fields to update
        if update_fields:
            update_query = f"UPDATE haproxy_clusters SET {', '.join(update_fields)} WHERE id = $1"
            await conn.execute(update_query, *update_values)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='update',
            resource_type='cluster',
            resource_id=str(cluster_id),
            details={
                'cluster_name': cluster.name,
                'old_name': existing_cluster['name']
            }
        )
        
        return {"message": f"Cluster '{cluster.name}' updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update cluster: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update cluster: {str(e)}")


@router.get("/{cluster_id}", summary="Get Cluster by ID", response_description="Cluster details")
async def get_cluster(cluster_id: int):
    """
    # Get Specific HAProxy Cluster
    
    Retrieve detailed information about a specific cluster by its ID.
    
    ## Path Parameters
    - **cluster_id**: Cluster ID to retrieve
    
    ## Example Request
    ```bash
    curl -X GET "{BASE_URL}/api/clusters/1" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Response
    ```json
    {
      "id": 1,
      "name": "production-cluster",
      "description": "Production HAProxy cluster",
      "connection_type": "agent",
      "is_active": true,
      "is_default": false,
      "created_at": "2024-01-15T10:30:00Z",
      "stats_socket_path": "/var/run/haproxy.sock",
      "haproxy_config_path": "/etc/haproxy/haproxy.cfg",
      "haproxy_bin_path": "/usr/sbin/haproxy",
      "pool_id": 1,
      "pool_name": "production-pool"
    }
    ```
    
    ## Error Responses
    - **404**: Cluster not found
    - **500**: Server error
    """
    try:
        conn = await get_database_connection()
        
        cluster = await conn.fetchrow("""
            SELECT c.id, c.name, c.description, c.connection_type, c.is_active, 
                   c.created_at, c.stats_socket_path, c.haproxy_config_path, c.haproxy_bin_path,
                   c.pool_id, c.is_default,
                   p.name as pool_name
            FROM haproxy_clusters c
            LEFT JOIN haproxy_cluster_pools p ON c.pool_id = p.id
            WHERE c.id = $1 AND c.is_active = TRUE
        """, cluster_id)
        
        await close_database_connection(conn)
        
        if not cluster:
            raise HTTPException(status_code=404, detail="Cluster not found")
        
        return {
            "id": cluster["id"],
            "name": cluster["name"],
            "description": cluster["description"],
            "connection_type": cluster["connection_type"],
            "is_active": cluster["is_active"],
            "is_default": cluster.get("is_default", False),
            "created_at": cluster["created_at"].isoformat().replace('+00:00', 'Z') if cluster["created_at"] else None,
            "stats_socket_path": cluster["stats_socket_path"],
            "haproxy_config_path": cluster["haproxy_config_path"],
            "haproxy_bin_path": cluster["haproxy_bin_path"],
            "pool_id": cluster["pool_id"],
            "pool_name": cluster["pool_name"]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("", summary="Get All Clusters", response_description="List of all clusters")
async def get_clusters():
    """
    # Get All HAProxy Clusters
    
    Retrieve a list of all active HAProxy clusters with their agent counts and pool information.
    
    ## Example Request
    ```bash
    curl -X GET "{BASE_URL}/api/clusters" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Response
    ```json
    [
      {
        "id": 1,
        "name": "production-cluster",
        "description": "Production HAProxy cluster",
        "connection_type": "agent",
        "is_active": true,
        "is_default": false,
        "created_at": "2024-01-15T10:30:00Z",
        "stats_socket_path": "/var/run/haproxy.sock",
        "haproxy_config_path": "/etc/haproxy/haproxy.cfg",
        "haproxy_bin_path": "/usr/sbin/haproxy",
        "pool_id": 1,
        "pool_name": "production-pool",
        "agent_count": 5,
        "online_agents": 4,
        "offline_agents": 1
      },
      {
        "id": 2,
        "name": "staging-cluster",
        "description": "Staging environment cluster",
        "connection_type": "agent",
        "is_active": true,
        "is_default": false,
        "created_at": "2024-01-16T14:20:00Z",
        "stats_socket_path": "/var/run/haproxy.sock",
        "haproxy_config_path": "/etc/haproxy/haproxy.cfg",
        "haproxy_bin_path": "/usr/sbin/haproxy",
        "pool_id": 2,
        "pool_name": "staging-pool",
        "agent_count": 2,
        "online_agents": 2,
        "offline_agents": 0
      }
    ]
    ```
    
    ## Response Fields
    - **agent_count**: Total number of agents in the cluster
    - **online_agents**: Number of currently online agents
    - **offline_agents**: Number of currently offline agents
    
    ## Error Responses
    - **500**: Server error
    """
    try:
        conn = await get_database_connection()
        
        clusters = await conn.fetch("""
            SELECT c.id, c.name, c.description, c.connection_type, c.is_active, 
                   c.created_at, c.stats_socket_path, c.haproxy_config_path, c.haproxy_bin_path,
                   c.pool_id, c.is_default,
                   p.name as pool_name,
                   COALESCE(agent_counts.total_agents, 0) as total_agents,
                   COALESCE(agent_counts.healthy_agents, 0) as healthy_agents,
                   COALESCE(agent_counts.warning_agents, 0) as warning_agents,
                   COALESCE(agent_counts.offline_agents, 0) as offline_agents,
                   agent_counts.agents_last_heartbeat
            FROM haproxy_clusters c
            LEFT JOIN haproxy_cluster_pools p ON c.pool_id = p.id
            LEFT JOIN (
                SELECT 
                    a.pool_id,
                    COUNT(a.id) as total_agents,
                    COUNT(CASE WHEN a.id IS NOT NULL AND a.last_seen IS NOT NULL AND a.status = 'online' AND
                        EXTRACT(EPOCH FROM (NOW() - a.last_seen)) < 30 THEN 1 END) as healthy_agents,
                    COUNT(CASE WHEN a.id IS NOT NULL AND a.last_seen IS NOT NULL AND a.status = 'online' AND
                        EXTRACT(EPOCH FROM (NOW() - a.last_seen)) >= 30 AND
                        EXTRACT(EPOCH FROM (NOW() - a.last_seen)) < 120 THEN 1 END) as warning_agents,
                    COUNT(CASE WHEN a.id IS NOT NULL AND (a.last_seen IS NULL OR a.status != 'online' OR
                        EXTRACT(EPOCH FROM (NOW() - a.last_seen)) >= 120) THEN 1 END) as offline_agents,
                    MAX(a.last_seen) as agents_last_heartbeat
                FROM agents a
                GROUP BY a.pool_id
            ) agent_counts ON agent_counts.pool_id = c.pool_id
            WHERE c.is_active = TRUE
            ORDER BY c.name
        """)
        
        await close_database_connection(conn)
        
        cluster_list = []
        for cluster in clusters:
            total = int(cluster["total_agents"]) if cluster["total_agents"] else 0
            healthy = int(cluster["healthy_agents"]) if cluster["healthy_agents"] else 0
            warning = int(cluster["warning_agents"]) if cluster["warning_agents"] else 0
            offline = int(cluster["offline_agents"]) if cluster["offline_agents"] else 0
            
            # Determine agent status
            if total == 0:
                agent_status = "no-agents"
            elif healthy == total:
                agent_status = "healthy"
            elif healthy > 0:
                agent_status = "warning"
            else:
                agent_status = "offline"
            
            cluster_list.append({
                "id": cluster["id"],
                "name": cluster["name"],
                "description": cluster["description"],
                "connection_type": cluster["connection_type"],
                "is_active": cluster["is_active"],
                "is_default": cluster.get("is_default", False),
                "created_at": cluster["created_at"].isoformat().replace('+00:00', 'Z') if cluster["created_at"] else None,
                "stats_socket_path": cluster["stats_socket_path"],
                "haproxy_config_path": cluster["haproxy_config_path"],
                "haproxy_bin_path": cluster["haproxy_bin_path"],
                "pool_id": cluster["pool_id"],
                "pool_name": cluster["pool_name"],
                # Agent status information
                "total_agents": total,
                "healthy_agents": healthy,
                "warning_agents": warning,
                "offline_agents": offline,
                "agent_status": agent_status,
                "agents_last_heartbeat": cluster["agents_last_heartbeat"].isoformat().replace('+00:00', 'Z') if cluster["agents_last_heartbeat"] else None
            })
        
        return {"clusters": cluster_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{cluster_id}/agent-sync")
async def get_cluster_agent_sync_status(cluster_id: int, authorization: str = Header(None)):
    """Get agent synchronization status for a cluster.
    Returns latest applied version and per-agent delivered version to determine sync status.
    """
    try:
        # Validate user token (agents won't call this)
        from auth_middleware import get_current_user_from_token
        _ = await get_current_user_from_token(authorization)

        conn = await get_database_connection()

        # Latest applied & active version for this cluster
        latest = await conn.fetchrow(
            """
            SELECT version_name, created_at, validation_error, validation_error_reported_at
            FROM config_versions
            WHERE cluster_id = $1 AND status = 'APPLIED' AND is_active = TRUE
            ORDER BY created_at DESC
            LIMIT 1
            """,
            cluster_id,
        )

        latest_version = latest["version_name"] if latest else None
        latest_created_at = latest["created_at"].isoformat().replace('+00:00', 'Z') if latest and latest.get("created_at") else None
        validation_error = latest.get("validation_error") if latest else None
        validation_error_reported_at = latest["validation_error_reported_at"].isoformat().replace('+00:00', 'Z') if latest and latest.get("validation_error_reported_at") else None

        # Agents under this cluster (via pool relationship)
        agents = await conn.fetch(
            """
            SELECT a.id, a.name, COALESCE(a.enabled, TRUE) as enabled, a.status, a.haproxy_status,
                   a.last_seen, a.config_version, a.applied_config_version
            FROM agents a
            JOIN haproxy_clusters c ON c.pool_id = a.pool_id
            WHERE c.id = $1
            ORDER BY a.name
            """,
            cluster_id,
        )

        await close_database_connection(conn)

        # Compute sync stats
        agent_items = []
        total = len(agents)
        online = 0
        synced = 0
        for ag in agents:
            is_online = (ag.get("status") == "online")
            if is_online:
                online += 1
            delivered_version = ag.get("config_version")
            applied_version = ag.get("applied_config_version")
            haproxy_status = ag.get("haproxy_status", "unknown")
            
            # CRITICAL FIX: Agent is in sync ONLY if:
            # 1. It has applied the latest version AND
            # 2. HAProxy service is running successfully
            version_matches = bool(latest_version and applied_version == latest_version)
            haproxy_running = haproxy_status in ['running', 'active']
            in_sync = version_matches and haproxy_running
            
            # DEBUG: Enhanced logging for restore operations
            if latest_version and latest_version.startswith('restore-'):
                logger.info(f"RESTORE SYNC DEBUG: Agent {ag['name']} - latest: '{latest_version}', applied: '{applied_version}', matches: {version_matches}, haproxy: {haproxy_status}, in_sync: {in_sync}")
            
            if in_sync:
                synced += 1
                logger.info(f"CLUSTER SYNC: Agent {ag['name']} - SYNCED (version: {applied_version}, haproxy: {haproxy_status})")
            else:
                if not version_matches:
                    logger.info(f"CLUSTER SYNC: Agent {ag['name']} - UNSYNCED (version mismatch: {applied_version} != {latest_version})")
                elif not haproxy_running:
                    logger.info(f"CLUSTER SYNC: Agent {ag['name']} - UNSYNCED (haproxy not running: {haproxy_status})")
                else:
                    logger.info(f"CLUSTER SYNC: Agent {ag['name']} - UNSYNCED (unknown reason)")
            agent_items.append({
                "id": ag["id"],
                "name": ag["name"],
                "enabled": ag.get("enabled", True),
                "status": ag.get("status", "unknown"),
                "haproxy_status": ag.get("haproxy_status", "unknown"),
                "last_seen": ag["last_seen"].isoformat().replace('+00:00', 'Z') if ag.get("last_seen") else None,
                "delivered_version": delivered_version,
                "applied_version": applied_version,
                "in_sync": in_sync,
            })

        return {
            "cluster_id": cluster_id,
            "latest_version": latest_version,
            "latest_created_at": latest_created_at,
            "validation_error": validation_error,
            "validation_error_reported_at": validation_error_reported_at,
            "total_agents": total,
            "online_agents": online,
            "synced_agents": synced,
            "unsynced_agents": max(0, total - synced),
            "agents": agent_items,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get agent sync status for cluster {cluster_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{cluster_id}/entity-sync/{entity_type}/{entity_id}")
async def get_entity_agent_sync_status(
    cluster_id: int, 
    entity_type: str, 
    entity_id: int, 
    authorization: str = Header(None)
):
    """Get agent sync status for a specific entity.
    Returns sync status based on entity's last_config_status.
    """
    try:
        from auth_middleware import get_current_user_from_token
        _ = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Validate entity type
        valid_types = ['waf_rules', 'frontends', 'backends', 'backend_servers', 'ssl_certificates']
        if entity_type not in valid_types:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail=f"Invalid entity type. Must be one of: {valid_types}")

        # Get entity's config status (prioritize active entities, fallback to inactive for sync status)
        table_name = entity_type
        entity = await conn.fetchrow(f"""
            SELECT id, last_config_status, updated_at, is_active
            FROM {table_name}
            WHERE id = $1 AND cluster_id = $2 AND is_active = TRUE
        """, entity_id, cluster_id)
        
        # If active entity not found, check if inactive entity exists (for sync status of soft-deleted entities)
        if not entity:
            entity = await conn.fetchrow(f"""
                SELECT id, last_config_status, updated_at, is_active
                FROM {table_name}
                WHERE id = $1 AND cluster_id = $2 AND is_active = FALSE
            """, entity_id, cluster_id)

        if not entity:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail=f"Entity {entity_type}/{entity_id} not found in cluster {cluster_id}")

        # Get agents for this cluster
        agents = await conn.fetch("""
            SELECT a.id, a.name, a.status, a.haproxy_status, a.applied_config_version
            FROM agents a
            JOIN haproxy_clusters c ON c.pool_id = a.pool_id
            WHERE c.id = $1 AND a.enabled = TRUE
            ORDER BY a.name
        """, cluster_id)

        # Calculate sync status based on entity's config status
        last_config_status = entity.get('last_config_status')
        total_agents = len(agents)
        
        if not last_config_status or total_agents == 0:
            await close_database_connection(conn)
            return {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "has_config_changes": False,
                "sync_status": None,
                "message": "No config changes or no agents"
            }

        # SPECIAL CASE: For backends, check server changes FIRST (they are more recent)
        entity_specific_version = None
        if entity_type == 'backends':
            logger.info(f"ENTITY SYNC DEBUG: Checking server changes for backend {entity_type}/{entity_id}")
            
            # Get backend name for server lookup
            backend_info = await conn.fetchrow("""
                SELECT name FROM backends WHERE id = $1 AND cluster_id = $2
            """, entity_id, cluster_id)
            
            if backend_info:
                backend_name = backend_info['name']
                logger.info(f"ENTITY SYNC DEBUG: Backend name: {backend_name}")
                
                # Look for server changes that affect this backend
                # This includes current servers and deleted servers (via config versions)
                
                # First get all current servers belonging to this backend
                backend_servers = await conn.fetch("""
                    SELECT id FROM backend_servers 
                    WHERE backend_name = $1 AND cluster_id = $2
                """, backend_name, cluster_id)
                
                logger.info(f"ENTITY SYNC DEBUG: Found {len(backend_servers)} current servers for backend {backend_name}")
                
                # Build patterns from current servers
                like_patterns = []
                if backend_servers:
                    server_ids = [str(server['id']) for server in backend_servers]
                    logger.info(f"ENTITY SYNC DEBUG: Current Server IDs: {server_ids}")
                    like_patterns = [f"server-{server_id}-%" for server_id in server_ids]
                
                # Also look for any server delete versions that might affect this backend
                # We need to find server delete versions and check if they were for this backend
                server_delete_versions = await conn.fetch("""
                    SELECT cv.version_name, cv.created_at
                    FROM config_versions cv
                    WHERE cv.cluster_id = $1 AND cv.status = 'APPLIED'
                    AND cv.version_name ~ '^server-[0-9]+-delete-'
                    ORDER BY cv.created_at DESC
                    LIMIT 10
                """, cluster_id)
                
                logger.info(f"ENTITY SYNC DEBUG: Found {len(server_delete_versions)} recent server delete versions")
                
                # Add delete versions to patterns (we'll check all recent ones)
                for delete_version in server_delete_versions:
                    like_patterns.append(delete_version['version_name'])
                
                logger.info(f"ENTITY SYNC DEBUG: Patterns to check: {like_patterns}")
                
                # Find the latest applied server version for any of these patterns
                for pattern in like_patterns:
                    logger.info(f"ENTITY SYNC DEBUG: Checking pattern: {pattern}")
                    
                    if pattern.startswith('server-') and '-delete-' in pattern:
                        # This is a delete version, use it directly
                        entity_specific_version = pattern
                        logger.info(f"ENTITY SYNC DEBUG: Using server delete version: {pattern}")
                        break
                    else:
                        # This is a pattern, search for matching versions
                        entity_specific_version = await conn.fetchval("""
                            SELECT cv.version_name
                            FROM config_versions cv
                            WHERE cv.cluster_id = $1 AND cv.status = 'APPLIED'
                            AND cv.version_name LIKE $2
                            ORDER BY cv.created_at DESC
                            LIMIT 1
                        """, cluster_id, pattern)
                        
                        logger.info(f"ENTITY SYNC DEBUG: Pattern {pattern} result: {entity_specific_version}")
                        
                        if entity_specific_version:
                            logger.info(f"ENTITY SYNC: Found server change affecting backend {entity_type}/{entity_id}: {entity_specific_version} (pattern: {pattern})")
                            break
                
                if entity_specific_version:
                    logger.info(f"ENTITY SYNC: Final server version for backend {entity_type}/{entity_id}: {entity_specific_version}")
                else:
                    logger.info(f"ENTITY SYNC: No server changes found for backend {entity_type}/{entity_id}")
        
        # If no server changes found for backends, or for other entity types, check entity-specific versions
        if not entity_specific_version:
            entity_specific_version = await conn.fetchval(f"""
                SELECT cv.version_name
                FROM config_versions cv
                WHERE cv.cluster_id = $1 AND cv.status = 'APPLIED' AND cv.is_active = TRUE
                AND cv.version_name LIKE $2
                ORDER BY cv.created_at DESC
                LIMIT 1
            """, cluster_id, f"{entity_type.rstrip('s')}-{entity_id}-%")
        
        # For sync status display, always prefer latest consolidated version over entity-specific versions
        # This ensures timestamp comparison works correctly for "Applying..." status
        # Also fetch metadata for restore tracking
        latest_consolidated = await conn.fetchrow("""
            SELECT cv.version_name, cv.metadata
            FROM config_versions cv
            WHERE cv.cluster_id = $1 AND cv.status = 'APPLIED' AND cv.is_active = TRUE
            AND (cv.version_name LIKE 'apply-consolidated-%' OR cv.version_name LIKE 'restore-%')
            ORDER BY cv.created_at DESC
            LIMIT 1
        """, cluster_id)
        
        latest_consolidated_version = latest_consolidated['version_name'] if latest_consolidated else None
        latest_version_metadata = None
        if latest_consolidated and latest_consolidated.get('metadata'):
            try:
                import json
                latest_version_metadata = json.loads(latest_consolidated['metadata']) if isinstance(latest_consolidated['metadata'], str) else latest_consolidated['metadata']
            except:
                pass
        
        # Use consolidated version if available, otherwise fall back to entity-specific version
        if latest_consolidated_version:
            entity_related_version = latest_consolidated_version
            logger.info(f"ENTITY SYNC: Using latest consolidated version for {entity_type}/{entity_id}: {latest_consolidated_version}")
        elif entity_specific_version:
            entity_related_version = entity_specific_version
            logger.info(f"ENTITY SYNC: No consolidated version, using entity-specific version for {entity_type}/{entity_id}: {entity_specific_version}")
        else:
            entity_related_version = None
            logger.info(f"ENTITY SYNC: No version found for {entity_type}/{entity_id}")

        # Fallback if no version found at all
        if not entity_related_version:
            entity_related_version = await conn.fetchval("""
                SELECT version_name
                FROM config_versions
                WHERE cluster_id = $1 AND status = 'APPLIED' AND is_active = TRUE
                ORDER BY created_at DESC
                LIMIT 1
            """, cluster_id)
            logger.info(f"ENTITY SYNC: Fallback to latest active version: {entity_related_version}")

        # ENTITY-SPECIFIC AGENT SYNC: Base sync on entity's individual status
        # If entity is PENDING, show 0/X sync until entity is applied
        # If entity is APPLIED, show current agent sync based on entity's own version
        synced_agents = 0
        unsynced_agents = 0
        
        if last_config_status == 'PENDING':
            # Entity has pending changes - show 0/X sync until applied
            unsynced_agents = total_agents
            logger.info(f"ENTITY SYNC: {entity_type}/{entity_id} is PENDING - showing 0/{total_agents} sync")
        else:
            # Entity is APPLIED - check if agents have applied the entity's related version
            # Use the version this entity was last involved in, not the latest cluster version
            target_version = entity_related_version
            
            logger.info(f"ENTITY SYNC: {entity_type}/{entity_id} is APPLIED - checking agent sync with entity version: {target_version}")
            
            if not target_version:
                # No version found, assume all agents are synced (backward compatibility)
                synced_agents = total_agents
            else:
                for agent in agents:
                    agent_applied_version = agent.get('applied_config_version')
                    agent_haproxy_status = agent.get('haproxy_status', 'unknown')
                    
                    # CRITICAL FIX: Agent is synced ONLY if:
                    # 1. It has applied the target version AND
                    # 2. HAProxy service is running successfully
                    version_matches = agent_applied_version == target_version
                    haproxy_running = agent_haproxy_status in ['running', 'active']
                    
                    if version_matches and haproxy_running:
                        synced_agents += 1
                        logger.info(f"AGENT SYNC: {agent['name']} - SYNCED (version: {agent_applied_version}, haproxy: {agent_haproxy_status})")
                    else:
                        unsynced_agents += 1
                        if not version_matches:
                            logger.info(f"AGENT SYNC: {agent['name']} - UNSYNCED (version mismatch: {agent_applied_version} != {target_version})")
                        elif not haproxy_running:
                            logger.info(f"AGENT SYNC: {agent['name']} - UNSYNCED (haproxy not running: {agent_haproxy_status})")
                        else:
                            logger.info(f"AGENT SYNC: {agent['name']} - UNSYNCED (unknown reason)")
        
        # Debug logging for troubleshooting
        logger.info(f"ENTITY SYNC DEBUG: {entity_type}/{entity_id} - last_config_status: {last_config_status}")
        logger.info(f"ENTITY SYNC DEBUG: entity_related_version: {entity_related_version}")
        logger.info(f"ENTITY SYNC DEBUG: total_agents: {total_agents}, synced: {synced_agents}, unsynced: {unsynced_agents}")
        
        # Additional debug for agent versions
        for agent in agents:
            agent_version = agent.get('applied_config_version')
            logger.info(f"ENTITY SYNC DEBUG: Agent {agent['name']} - applied_version: {agent_version}, matches_target: {agent_version == entity_related_version}")

        # Get the created_at timestamp for the entity's related version
        latest_version_created_at = None
        if entity_related_version:
            version_created_at = await conn.fetchval("""
                SELECT created_at FROM config_versions 
                WHERE cluster_id = $1 AND version_name = $2
                ORDER BY created_at DESC LIMIT 1
            """, cluster_id, entity_related_version)
            
            if version_created_at:
                latest_version_created_at = version_created_at.isoformat().replace('+00:00', 'Z')
                logger.info(f"ENTITY SYNC: Found version timestamp for {entity_related_version}: {latest_version_created_at}")

        # Get last user who applied changes to this cluster
        # This helps users understand who initiated the last apply when multiple users share same account
        last_applied_by_info = await conn.fetchrow("""
            SELECT u.username, u.full_name, ual.created_at as applied_at
            FROM user_activity_logs ual
            JOIN users u ON u.id = ual.user_id
            WHERE ual.resource_type = 'cluster'
              AND ual.resource_id = $1
              AND ual.action = 'apply_changes'
            ORDER BY ual.created_at DESC
            LIMIT 1
        """, str(cluster_id))
        
        last_applied_by = None
        if last_applied_by_info:
            last_applied_by = {
                "username": last_applied_by_info['username'],
                "full_name": last_applied_by_info['full_name'],
                "applied_at": last_applied_by_info['applied_at'].isoformat().replace('+00:00', 'Z') if last_applied_by_info['applied_at'] else None
            }
        
        # Always show agent sync status regardless of entity's config status
        # Agent sync reflects whether agents have applied the latest cluster config,
        # independent of entity's APPLIED/PENDING status

        await close_database_connection(conn)
        
        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "has_config_changes": True,
            "last_config_status": last_config_status,
            "latest_applied_version": entity_related_version,
            "latest_version_created_at": latest_version_created_at,  # Now returns actual version timestamp
            "latest_version_metadata": latest_version_metadata,  # CRITICAL: For restore tracking
            "entity_updated_at": entity.get('updated_at').isoformat().replace('+00:00', 'Z') if entity.get('updated_at') else None,
            "last_applied_by": last_applied_by,  # NEW: Show who applied last
            "sync_status": {
                "total_agents": total_agents,
                "synced_agents": synced_agents,
                "unsynced_agents": unsynced_agents,
                "last_sync_check": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            },
            "agents": [
                {
                    "id": ag["id"],
                    "name": ag["name"],
                    "status": ag.get("status", "unknown"),
                    "applied_version": ag.get("applied_config_version"),
                    "latest_version": entity_related_version,
                    "in_sync": (
                        entity_related_version and 
                        ag.get("applied_config_version") == entity_related_version
                    )
                }
                for ag in agents
            ]
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get entity sync status for {entity_type}/{entity_id} in cluster {cluster_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{cluster_id}/config-versions")
async def list_cluster_config_versions(cluster_id: int, authorization: str = Header(None)):
    """Get configuration version history for a cluster"""
    try:
        # Verify user authentication
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get all config versions for this cluster (with schema compatibility)
        try:
            # Try with status column first
            versions = await conn.fetch("""
                SELECT cv.id, cv.version_name, cv.description, cv.status, cv.is_active,
                       cv.created_at, cv.file_size, cv.checksum,
                       u.username as created_by_username
                FROM config_versions cv
                LEFT JOIN users u ON cv.created_by = u.id
                WHERE cv.cluster_id = $1
                ORDER BY cv.created_at DESC
            """, cluster_id)
        except Exception as status_error:
            logger.warning(f"Status column error in config-versions, using fallback: {status_error}")
            # Fallback query without status column
            versions = await conn.fetch("""
                SELECT cv.id, cv.version_name, cv.description, cv.is_active,
                       cv.created_at, cv.file_size, cv.checksum,
                       u.username as created_by_username
                FROM config_versions cv
                LEFT JOIN users u ON cv.created_by = u.id
                WHERE cv.cluster_id = $1
                ORDER BY cv.created_at DESC
            """, cluster_id)
        
        await close_database_connection(conn)
        
        # Format the response
        formatted_versions = []
        for version in versions:
            # Extract change type from version name for better display
            version_type = "Configuration"
            if "frontend-" in version['version_name']:
                version_type = "Frontend"
            elif "backend-" in version['version_name']:
                version_type = "Backend"
            elif "server-" in version['version_name']:
                version_type = "Backend Server"
            elif "waf-" in version['version_name']:
                version_type = "WAF Rule"
            elif "ssl-" in version['version_name']:
                version_type = "SSL Certificate"
            
            formatted_versions.append({
                "id": version["id"],
                "version_name": version["version_name"],
                "description": version["description"] or f"{version_type} configuration update",
                "type": version_type,
                "status": version.get("status", "APPLIED"),  # Default to APPLIED if column doesn't exist
                "is_active": version.get("is_active", False),
                "created_at": version["created_at"].isoformat().replace('+00:00', 'Z') if version.get("created_at") else None,
                "created_by": version.get("created_by_username") or "System",
                "file_size": version.get("file_size"),
                "checksum": version["checksum"][:8] + "..." if version.get("checksum") else "No checksum"
            })
        
        return {"config_versions": formatted_versions}
        
    except Exception as e:
        logger.error(f"Error fetching cluster versions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{cluster_id}/apply-changes")
async def apply_pending_changes(
    cluster_id: int, 
    apply_request: dict = None,
    authorization: str = Header(None)
):
    """
    Apply all pending configuration changes for a cluster
    
    This endpoint:
    - Consolidates all PENDING config versions into one APPLIED version
    - Marks all pending entities (frontends, backends, servers, SSL, WAF) as APPLIED
    - Automatically detects and removes orphan config versions before apply
    - Notifies agents to pull new configuration
    
    Orphan Version Auto-Cleanup:
    - Orphan versions are config versions that reference entities from different clusters
    - Can occur due to entity ID reuse after hard delete
    - Automatically detected and cleaned during apply process
    - Example: backend-73-delete-xxx in cluster 2, but backend 73 is in cluster 1
    
    Requires: apply.execute permission
    """
    try:
        # Verify user authentication
        from auth_middleware import get_current_user_from_token, check_user_permission
        import re  # Import re module for regex operations
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for apply execute
        has_permission = await check_user_permission(current_user["id"], "apply", "execute")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: apply.execute required"
            )
        
        conn = await get_database_connection()
        
        # Apply all pending changes without validation - validation issues will be handled by HAProxy itself
        # Users will handle configuration completeness through the centralized Apply Management page
        
        # Get all pending config versions for this cluster
        pending_versions = await conn.fetch("""
            SELECT id, version_name, created_at, config_content, checksum, metadata
            FROM config_versions 
            WHERE cluster_id = $1 AND status = 'PENDING'
            ORDER BY created_at ASC
        """, cluster_id)
        
        # CRITICAL FIX: Detect and clean orphan config versions before apply
        # Orphan versions reference entities that don't belong to this cluster (ID reuse bug)
        orphan_version_ids = []
        import re
        for v in pending_versions:
            is_orphan = False
            
            # Check if backend version references a backend NOT in this cluster
            m_be = re.search(r'^backend-(\d+)-', v['version_name'])
            if m_be:
                be_id = int(m_be.group(1))
                backend_exists = await conn.fetchrow("""
                    SELECT id, cluster_id FROM backends WHERE id = $1
                """, be_id)
                
                # If backend doesn't exist, version is orphan (entity was hard deleted)
                if backend_exists is None:
                    is_orphan = True
                    logger.warning(f"ORPHAN VERSION: {v['version_name']} references non-existent backend {be_id}")
                # If backend exists but cluster_id is NULL, preserve version (legacy data)
                elif backend_exists['cluster_id'] is None:
                    logger.debug(f"Backend {be_id} has NULL cluster_id (legacy), preserving version")
                    is_orphan = False
                # If backend belongs to different cluster, version is orphan
                elif backend_exists['cluster_id'] != cluster_id:
                    is_orphan = True
                    logger.warning(f"ORPHAN VERSION: {v['version_name']} references backend {be_id} from cluster {backend_exists['cluster_id']}, but version is in cluster {cluster_id}")
            
            # Check if frontend version references a frontend NOT in this cluster
            m_fe = re.search(r'^frontend-(\d+)-', v['version_name'])
            if m_fe:
                fe_id = int(m_fe.group(1))
                frontend_exists = await conn.fetchrow("""
                    SELECT id, cluster_id FROM frontends WHERE id = $1
                """, fe_id)
                
                # If frontend doesn't exist, version is orphan (entity was hard deleted)
                if frontend_exists is None:
                    is_orphan = True
                    logger.warning(f"ORPHAN VERSION: {v['version_name']} references non-existent frontend {fe_id}")
                # If frontend exists but cluster_id is NULL, preserve version (legacy data)
                elif frontend_exists['cluster_id'] is None:
                    logger.debug(f"Frontend {fe_id} has NULL cluster_id (legacy), preserving version")
                    is_orphan = False
                # If frontend belongs to different cluster, version is orphan
                elif frontend_exists['cluster_id'] != cluster_id:
                    is_orphan = True
                    logger.warning(f"ORPHAN VERSION: {v['version_name']} references frontend {fe_id} from cluster {frontend_exists['cluster_id']}, but version is in cluster {cluster_id}")
            
            if is_orphan:
                orphan_version_ids.append(v['id'])
        
        # Delete orphan versions immediately (they're invalid and prevent apply)
        if orphan_version_ids:
            await conn.execute("""
                DELETE FROM config_versions WHERE id = ANY($1)
            """, orphan_version_ids)
            logger.info(f"APPLY: Deleted {len(orphan_version_ids)} orphan config versions")
            
            # Remove orphans from pending_versions list
            pending_versions = [v for v in pending_versions if v['id'] not in orphan_version_ids]

        # If UI-side entity lists are empty but versions exist (e.g., restore-*), proceed anyway
        if not pending_versions:
            return {"message": "No pending changes to apply", "applied_count": 0}
        
        # DEPRECATED: Old global SSL auto-apply logic (replaced by apply_ssl_related_configs)
        # The new implementation handles SSL scope-aware apply directly within the transaction
        # This old code is kept commented for reference but is no longer needed
        # global_ssl_cert_ids = []
        global_ssl_cert_ids = []  # Keep empty to disable old recursive SSL apply logic
        other_clusters_to_apply = []  # Keep empty to disable old recursive SSL apply logic
        # Old logic is replaced by apply_ssl_related_configs() which runs inside transaction
        
        # Check for explicit confirmation if required (optional parameter)
        # Default behavior: apply immediately unless explicitly set to require confirmation
        requires_confirmation = apply_request and apply_request.get('require_confirmation', False)
        confirmed = apply_request and apply_request.get('confirmed', False) if requires_confirmation else True
        
        if requires_confirmation and not confirmed:
            await close_database_connection(conn)
            return {
                "message": "Apply confirmation required",
                "pending_changes": len(pending_versions),
                "requires_confirmation": True,
                "changes": [{"version_name": v["version_name"], "created_at": v["created_at"].isoformat().replace('+00:00', 'Z')} for v in pending_versions]
            }
        
        async with conn.transaction():
            # CRITICAL: SSL scope-aware apply (MUST be inside transaction for atomicity)
            # SSL update'lerde tek Apply tıklaması ile scope'daki tüm cluster'lara yayılır
            # Global SSL: Tüm cluster'lar, Cluster-specific SSL: İlgili cluster'lar
            await apply_ssl_related_configs(conn, cluster_id)
            
            # Mark all current active versions as inactive
            await conn.execute("""
                UPDATE config_versions 
                SET is_active = FALSE 
                WHERE cluster_id = $1 AND is_active = TRUE
            """, cluster_id)
            
            # Determine config content to apply
            # Check if any pending version is a restore operation with existing config content
            restore_version = None
            for version in pending_versions:
                if version['version_name'].startswith('restore-') and version['config_content']:
                    restore_version = version
                    break
            
            # SNAPSHOT: Get current applied config before applying changes (for diff baseline)
            # Don't rely on is_active flag as it gets updated during apply process
            pre_apply_config = None
            current_active_version = await conn.fetchrow("""
                SELECT config_content, version_name 
                FROM config_versions 
                WHERE cluster_id = $1 AND status = 'APPLIED' AND config_content IS NOT NULL
                ORDER BY created_at DESC 
                LIMIT 1
            """, cluster_id)
            
            if current_active_version and current_active_version['config_content']:
                pre_apply_config = current_active_version['config_content']
                logger.info(f"APPLY: Found pre-apply baseline: {current_active_version['version_name']}")
            else:
                # Create minimal baseline if no previous config exists
                pre_apply_config = """global
    daemon
    log stdout local0

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
"""
                logger.info(f"APPLY: No previous config found, using minimal baseline")

            if restore_version:
                # RESTORE OPERATION: Use the restored config content directly
                logger.info(f"RESTORE APPLY: Using restored config content from version {restore_version['version_name']}")
                fresh_config_content = restore_version['config_content']
            else:
                # NORMAL OPERATION: Generate fresh config from current database state
                # CRITICAL FIX: Before generating config, sync APPLIED entities with last consolidated config
                # This prevents non-PENDING changes from appearing in consolidated version diff
                
                logger.info(f"DB SYNC: Syncing APPLIED entities with last consolidated config before generating fresh config")
                
                # Get last consolidated config for baseline
                last_consolidated = await conn.fetchrow("""
                    SELECT config_content FROM config_versions
                    WHERE cluster_id = $1 AND status = 'APPLIED'
                    AND version_name LIKE 'apply-consolidated-%'
                    ORDER BY created_at DESC LIMIT 1
                """, cluster_id)
                
                if last_consolidated and last_consolidated['config_content']:
                    try:
                        from utils.haproxy_config_parser import HAProxyConfigParser
                        parser = HAProxyConfigParser()
                        parser.parse(last_consolidated['config_content'])
                        
                        logger.info(f"DB SYNC: Parsed last consolidated config - {len(parser.frontends)} frontends, {len(parser.backends)} backends")
                        
                        # Sync APPLIED frontends with config baseline
                        for parsed_fe in parser.frontends:
                            await conn.execute("""
                                UPDATE frontends SET
                                    bind_address = $1,
                                    bind_port = $2,
                                    default_backend = $3,
                                    mode = $4,
                                    ssl_enabled = $5,
                                    ssl_port = $6,
                                    maxconn = $7,
                                    timeout_client = $8
                                WHERE name = $9 AND cluster_id = $10
                                AND last_config_status = 'APPLIED'
                            """, parsed_fe.bind_address, parsed_fe.bind_port, 
                                 parsed_fe.default_backend, parsed_fe.mode,
                                 parsed_fe.ssl_enabled, parsed_fe.ssl_port,
                                 parsed_fe.maxconn, parsed_fe.timeout_client,
                                 parsed_fe.name, cluster_id)
                        
                        # Sync APPLIED backends with config baseline
                        for parsed_be in parser.backends:
                            await conn.execute("""
                                UPDATE backends SET
                                    balance_method = $1,
                                    mode = $2,
                                    health_check_uri = $3,
                                    health_check_interval = $4,
                                    timeout_connect = $5,
                                    timeout_server = $6,
                                    timeout_queue = $7
                                WHERE name = $8 AND cluster_id = $9
                                AND last_config_status = 'APPLIED'
                            """, parsed_be.balance_method, parsed_be.mode,
                                 parsed_be.health_check_uri, parsed_be.health_check_interval,
                                 parsed_be.timeout_connect, parsed_be.timeout_server, parsed_be.timeout_queue,
                                 parsed_be.name, cluster_id)
                            
                            # Sync APPLIED backend servers with config baseline
                            # CRITICAL: Preserve PENDING servers! Only sync APPLIED servers.
                            if parsed_be.servers:
                                # Get list of server names from parsed config
                                parsed_server_names = {s.name for s in parsed_be.servers}
                                
                                # Delete APPLIED servers that are NOT in parsed config
                                # (they were deleted in previous operations)
                                # CRITICAL: DO NOT delete PENDING servers!
                                await conn.execute("""
                                    DELETE FROM backend_servers
                                    WHERE backend_name = $1 AND cluster_id = $2
                                    AND last_config_status = 'APPLIED'
                                    AND server_name NOT IN (SELECT unnest($3::text[]))
                                """, parsed_be.name, cluster_id, list(parsed_server_names))
                                
                                # Upsert servers from config (create or update APPLIED servers only)
                                for server in parsed_be.servers:
                                    await conn.execute("""
                                        INSERT INTO backend_servers
                                        (backend_name, cluster_id, server_name, server_address, server_port,
                                         weight, maxconn, check_enabled, backup_server, ssl_enabled,
                                         is_active, last_config_status)
                                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, 'APPLIED')
                                        ON CONFLICT (backend_name, server_name, cluster_id) DO UPDATE SET
                                            server_address = EXCLUDED.server_address,
                                            server_port = EXCLUDED.server_port,
                                            weight = EXCLUDED.weight,
                                            maxconn = EXCLUDED.maxconn,
                                            check_enabled = EXCLUDED.check_enabled,
                                            backup_server = EXCLUDED.backup_server,
                                            ssl_enabled = EXCLUDED.ssl_enabled,
                                            is_active = EXCLUDED.is_active,
                                            last_config_status = 'APPLIED'
                                        WHERE backend_servers.last_config_status = 'APPLIED'
                                    """, parsed_be.name, cluster_id, server.name, server.address, server.port,
                                         server.weight, server.maxconn, server.check, server.backup, server.ssl)
                        
                        # Sync APPLIED WAF rules with config baseline (parse config + update DB)
                        import re
                        import json
                        config_lines = last_consolidated['config_content'].split('\n')
                        
                        # Parse WAF rules from config with their parameters
                        waf_configs = {}  # {rule_name: {is_active: True, config: {...}}}
                        current_waf_name = None
                        i = 0
                        while i < len(config_lines):
                            line = config_lines[i].strip()
                            
                            # Find WAF rule comment
                            if line.startswith('# WAF Rule:'):
                                match = re.search(r'# WAF Rule: ([\w\s\-]+)', line)
                                if match:
                                    current_waf_name = match.group(1).strip()
                                    waf_configs[current_waf_name] = {
                                        'is_active': True,
                                        'config': {}
                                    }
                                    
                                    # Parse next few lines for WAF config parameters
                                    # Look ahead for stick-table and http-request lines
                                    for j in range(i+1, min(i+10, len(config_lines))):
                                        next_line = config_lines[j].strip()
                                        
                                        # Parse stick-table line: expire and rate_limit_window
                                        if 'stick-table' in next_line:
                                            # Extract expire time: expire 66s
                                            expire_match = re.search(r'expire\s+(\d+)s', next_line)
                                            if expire_match:
                                                waf_configs[current_waf_name]['config']['rate_limit_window'] = int(expire_match.group(1))
                                            
                                            # Extract table_expire: http_req_rate(10s)
                                            table_expire_match = re.search(r'http_req_rate\((\d+)s\)', next_line)
                                            if table_expire_match:
                                                waf_configs[current_waf_name]['config']['table_expire'] = int(table_expire_match.group(1))
                                            
                                            # Extract table size: size 100k
                                            size_match = re.search(r'size\s+(\w+)', next_line)
                                            if size_match:
                                                waf_configs[current_waf_name]['config']['table_size'] = size_match.group(1)
                                        
                                        # Parse deny line: rate_limit_requests
                                        elif 'http-request deny if' in next_line or 'http-request tarpit if' in next_line:
                                            # Extract rate limit: gt 101
                                            rate_match = re.search(r'gt\s+(\d+)', next_line)
                                            if rate_match:
                                                waf_configs[current_waf_name]['config']['rate_limit_requests'] = int(rate_match.group(1))
                                        
                                        # Stop when we hit another WAF rule or different section
                                        elif next_line.startswith('# WAF Rule:') or next_line.startswith('frontend ') or next_line.startswith('backend '):
                                            break
                            i += 1
                        
                        logger.info(f"DB SYNC: Parsed {len(waf_configs)} WAF rules with config from last config")
                        
                        # Get all APPLIED WAF rules for this cluster
                        applied_waf_rules = await conn.fetch("""
                            SELECT id, name, is_active, config
                            FROM waf_rules
                            WHERE cluster_id = $1 AND last_config_status = 'APPLIED'
                        """, cluster_id)
                        
                        # Sync WAF rules: Update is_active AND config from parsed config
                        for waf_rule in applied_waf_rules:
                            if waf_rule['name'] in waf_configs:
                                parsed_waf = waf_configs[waf_rule['name']]
                                should_be_active = parsed_waf['is_active']
                                parsed_config = parsed_waf['config']
                                
                                # Merge parsed config with existing config (preserve fields we didn't parse)
                                current_config = waf_rule['config'] or {}
                                if isinstance(current_config, str):
                                    current_config = json.loads(current_config) if current_config else {}
                                
                                # Update only the fields we parsed from config
                                updated_config = current_config.copy()
                                updated_config.update(parsed_config)
                                
                                # Update both is_active and config in DB
                                await conn.execute("""
                                    UPDATE waf_rules 
                                    SET is_active = $1, config = $2
                                    WHERE id = $3 AND cluster_id = $4
                                    AND last_config_status = 'APPLIED'
                                """, should_be_active, json.dumps(updated_config), waf_rule['id'], cluster_id)
                                logger.info(f"DB SYNC: WAF rule '{waf_rule['name']}' synced - is_active: {should_be_active}, config: {parsed_config}")
                            else:
                                # WAF rule not in config, should be inactive
                                if waf_rule['is_active']:
                                    await conn.execute("""
                                        UPDATE waf_rules SET is_active = FALSE
                                        WHERE id = $1 AND cluster_id = $2
                                        AND last_config_status = 'APPLIED'
                                    """, waf_rule['id'], cluster_id)
                                    logger.info(f"DB SYNC: WAF rule '{waf_rule['name']}' deactivated (not in config)")
                        
                        logger.info(f"DB SYNC: Synced {len(parser.frontends)} APPLIED frontends, {len(parser.backends)} APPLIED backends, and {len(applied_waf_rules)} APPLIED WAF rules with last config")
                        
                    except Exception as sync_error:
                        logger.warning(f"DB SYNC: Failed to sync APPLIED entities with last config: {sync_error}")
                        logger.warning(f"DB SYNC: Continuing with current DB state (may show non-PENDING changes in diff)")
                
                # Now generate fresh config from database (DB is now synced with last config)
                from services.haproxy_config import generate_haproxy_config_for_cluster
                
                logger.info(f"🧩 APPLY: Generating fresh configuration from database for cluster {cluster_id}")
                fresh_config_content = await generate_haproxy_config_for_cluster(cluster_id, conn)
            
            # Create a new consolidated config version with fresh content
            import hashlib
            import time
            config_hash = hashlib.sha256(fresh_config_content.encode()).hexdigest()
            version_name = f"apply-consolidated-{int(time.time())}"
            
            # Get system admin user ID for created_by
            admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
            
            # Create the consolidated config version with pre-apply snapshot for diff
            import json
            metadata = {'pre_apply_snapshot': pre_apply_config} if 'pre_apply_config' in locals() and pre_apply_config else None
            
            # CRITICAL FIX: For restore operations, copy metadata from restore_version to new consolidated version
            # This ensures changed_entities metadata is available for selective entity sync in UI
            if restore_version:
                logger.info(f"RESTORE DEBUG: restore_version exists, checking metadata...")
                logger.info(f"RESTORE DEBUG: restore_version.get('metadata') = {restore_version.get('metadata') is not None}")
                if restore_version.get('metadata'):
                    restore_metadata = json.loads(restore_version['metadata']) if isinstance(restore_version['metadata'], str) else restore_version['metadata']
                    logger.info(f"RESTORE DEBUG: Parsed metadata, has changed_entities: {'changed_entities' in restore_metadata}")
                    if metadata is None:
                        metadata = {}
                    # Merge restore metadata into consolidated version metadata
                    metadata.update(restore_metadata)
                    logger.info(f"RESTORE METADATA: Copied changed_entities metadata from restore version to consolidated version")
                    logger.info(f"RESTORE METADATA: Changed entities count: {len(restore_metadata.get('changed_entities', []))}")
                else:
                    logger.warning(f"RESTORE WARNING: restore_version exists but metadata is NULL/empty!")
            else:
                logger.info(f"RESTORE DEBUG: No restore_version, normal apply operation")
            
            logger.info(f"APPLY: Saving metadata with pre_apply_config: {metadata is not None}")
            if metadata:
                logger.info(f"APPLY: Pre-apply snapshot length: {len(metadata.get('pre_apply_snapshot', ''))}")
            
            consolidated_version_id = await conn.fetchval("""
                INSERT INTO config_versions 
                (cluster_id, version_name, config_content, checksum, created_by, is_active, status, metadata)
                VALUES ($1, $2, $3, $4, $5, TRUE, 'APPLIED', $6)
                RETURNING id
            """, cluster_id, version_name, fresh_config_content, config_hash, admin_user_id, 
                 json.dumps(metadata) if metadata else None)
            
            # Mark all old pending versions as applied but inactive (keep for history)
            pending_version_ids = [v["id"] for v in pending_versions]
            # CRITICAL FIX: Mark old pending versions as APPLIED so they don't show in UI as pending
            # The new consolidated version is immediately APPLIED - Agent Sync tracked separately
            await conn.execute("""
                UPDATE config_versions 
                SET is_active = FALSE, status = 'APPLIED'
                WHERE id = ANY($1)
            """, pending_version_ids)
            
            logger.info(f"APPLY: Created consolidated config version {version_name} with fresh content for cluster {cluster_id}")
            
            # CRITICAL FIX: Only update timestamps for entities that actually have PENDING changes
            # This prevents unnecessary sync resets for unmodified entities
            
            # Update only frontends with PENDING status
            await conn.execute("""
                UPDATE frontends SET updated_at = CURRENT_TIMESTAMP, last_config_status = 'APPLIED'
                WHERE cluster_id = $1 AND last_config_status = 'PENDING'
            """, cluster_id)
            logger.info(f"APPLY: Updated timestamps only for PENDING frontends in cluster {cluster_id}")
            
            # Update only backends with PENDING status
            # REVERTED: Now ALL backends are written to config (even without servers)
            # Config generator writes backend block for all backends (servers optional)
            await conn.execute("""
                UPDATE backends SET updated_at = CURRENT_TIMESTAMP, last_config_status = 'APPLIED'
                WHERE cluster_id = $1 AND last_config_status = 'PENDING'
            """, cluster_id)
            logger.info(f"APPLY: Updated timestamps only for PENDING backends in cluster {cluster_id}")
            
            # Update only WAF rules with PENDING status
            await conn.execute("""
                UPDATE waf_rules SET updated_at = CURRENT_TIMESTAMP, last_config_status = 'APPLIED'
                WHERE cluster_id = $1 AND last_config_status = 'PENDING'
            """, cluster_id)
            logger.info(f"APPLY: Updated timestamps only for PENDING WAF rules in cluster {cluster_id}")
            
            # Update only SSL certificates with PENDING status (via junction table)
            # Update cluster-specific SSL certificates with PENDING status
            ssl_cluster_update = await conn.execute("""
                UPDATE ssl_certificates 
                SET updated_at = CURRENT_TIMESTAMP, last_config_status = 'APPLIED'
                WHERE id IN (
                    SELECT scc.ssl_certificate_id 
                    FROM ssl_certificate_clusters scc 
                    WHERE scc.cluster_id = $1
                ) 
                AND last_config_status = 'PENDING'
            """, cluster_id)
            
            # Also update global SSL certificates (those not in junction table)
            ssl_global_update = await conn.execute("""
                UPDATE ssl_certificates 
                SET updated_at = CURRENT_TIMESTAMP, last_config_status = 'APPLIED'
                WHERE NOT EXISTS (
                    SELECT 1 FROM ssl_certificate_clusters scc 
                    WHERE scc.ssl_certificate_id = ssl_certificates.id
                )
                AND last_config_status = 'PENDING'
            """)
            logger.info(f"APPLY: Updated timestamps for PENDING SSL certificates (cluster-specific and global) in cluster {cluster_id}")
            
            # Update only backend servers with PENDING status
            try:
                await conn.execute("""
                    UPDATE backend_servers SET updated_at = CURRENT_TIMESTAMP, last_config_status = 'APPLIED'
                    WHERE cluster_id = $1 AND last_config_status = 'PENDING'
                """, cluster_id)
                logger.info(f"APPLY: Updated timestamps only for PENDING backend servers in cluster {cluster_id}")
            except Exception as e:
                logger.info(f"APPLY: backend_servers.last_config_status column not found, skipping: {e}")

            # Note: Entity status updates are now handled above with timestamp updates
            # This prevents unnecessary sync resets for unmodified entities

            # Entity status updates and timestamp management moved above
            # to prevent unnecessary sync resets for unmodified entities

            # RESTORE SYNC: If this was a restore operation, sync database entities with restored config
            if restore_version:
                logger.info(f"RESTORE SYNC: Syncing database entities with restored config for cluster {cluster_id}")
                try:
                    # Parse the restored config to identify which entities should be active
                    config_lines = fresh_config_content.split('\n')
                    
                    # Find active entities in the config
                    active_waf_rules = set()
                    active_frontends = set()
                    active_backends = set()
                    
                    current_section = None
                    for line in config_lines:
                        line = line.strip()
                        
                        # Track current section
                        if line.startswith('frontend '):
                            current_section = 'frontend'
                            frontend_name = line.split(' ', 1)[1]
                            active_frontends.add(frontend_name)
                        elif line.startswith('backend '):
                            current_section = 'backend'
                            backend_name = line.split(' ', 1)[1]
                            active_backends.add(backend_name)
                        elif line.startswith('global') or line.startswith('defaults'):
                            current_section = line
                        
                        # Find WAF rules in comments
                        if line.startswith('# WAF Rule:'):
                            import re
                            match = re.search(r'# WAF Rule: (\w+)', line)
                            if match:
                                active_waf_rules.add(match.group(1))
                    
                    # Mark WAF rules that are NOT in the config as inactive
                    if active_waf_rules:
                        inactive_count = await conn.fetchval("""
                            UPDATE waf_rules 
                            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                            WHERE cluster_id = $1 AND name NOT IN (SELECT unnest($2::text[])) AND is_active = TRUE
                            RETURNING (SELECT COUNT(*) FROM waf_rules WHERE cluster_id = $1 AND is_active = FALSE)
                        """, cluster_id, list(active_waf_rules))
                    else:
                        # No WAF rules in config, mark all as inactive
                        inactive_count = await conn.fetchval("""
                            UPDATE waf_rules 
                            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                            WHERE cluster_id = $1 AND is_active = TRUE
                            RETURNING (SELECT COUNT(*) FROM waf_rules WHERE cluster_id = $1 AND is_active = FALSE)
                        """, cluster_id)
                    
                    logger.info(f"RESTORE SYNC: Marked {inactive_count or 0} WAF rules as inactive for cluster {cluster_id}")
                    
                    # Sync frontends
                    if active_frontends:
                        fe_inactive_count = await conn.fetchval("""
                            UPDATE frontends 
                            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                            WHERE cluster_id = $1 AND name NOT IN (SELECT unnest($2::text[])) AND is_active = TRUE
                            RETURNING (SELECT COUNT(*) FROM frontends WHERE cluster_id = $1 AND is_active = FALSE)
                        """, cluster_id, list(active_frontends))
                    else:
                        fe_inactive_count = await conn.fetchval("""
                            UPDATE frontends 
                            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                            WHERE cluster_id = $1 AND is_active = TRUE
                            RETURNING (SELECT COUNT(*) FROM frontends WHERE cluster_id = $1 AND is_active = FALSE)
                        """, cluster_id)
                    
                    logger.info(f"RESTORE SYNC: Marked {fe_inactive_count or 0} frontends as inactive for cluster {cluster_id}")
                    
                    # CRITICAL FIX: Restore active status for frontends that should remain active
                    if active_frontends:
                        fe_reactivated_count = await conn.fetchval("""
                            UPDATE frontends 
                            SET is_active = TRUE, updated_at = CURRENT_TIMESTAMP
                            WHERE cluster_id = $1 AND name IN (SELECT unnest($2::text[])) AND is_active = FALSE
                            RETURNING (SELECT COUNT(*) FROM frontends WHERE cluster_id = $1 AND is_active = TRUE)
                        """, cluster_id, list(active_frontends))
                        logger.info(f"APPLY FIX: Reactivated {fe_reactivated_count or 0} frontends for cluster {cluster_id}")
                    
                    # Sync backends
                    if active_backends:
                        be_inactive_count = await conn.fetchval("""
                            UPDATE backends 
                            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                            WHERE cluster_id = $1 AND name NOT IN (SELECT unnest($2::text[])) AND is_active = TRUE
                            RETURNING (SELECT COUNT(*) FROM backends WHERE cluster_id = $1 AND is_active = FALSE)
                        """, cluster_id, list(active_backends))
                    else:
                        be_inactive_count = await conn.fetchval("""
                            UPDATE backends 
                            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                            WHERE cluster_id = $1 AND is_active = TRUE
                            RETURNING (SELECT COUNT(*) FROM backends WHERE cluster_id = $1 AND is_active = FALSE)
                        """, cluster_id)
                    
                    logger.info(f"RESTORE SYNC: Marked {be_inactive_count or 0} backends as inactive for cluster {cluster_id}")
                    
                    # CRITICAL FIX: Restore active status for backends that should remain active
                    if active_backends:
                        be_reactivated_count = await conn.fetchval("""
                            UPDATE backends 
                            SET is_active = TRUE, updated_at = CURRENT_TIMESTAMP
                            WHERE cluster_id = $1 AND name IN (SELECT unnest($2::text[])) AND is_active = FALSE
                            RETURNING (SELECT COUNT(*) FROM backends WHERE cluster_id = $1 AND is_active = TRUE)
                        """, cluster_id, list(active_backends))
                        logger.info(f"APPLY FIX: Reactivated {be_reactivated_count or 0} backends for cluster {cluster_id}")
                    
                except Exception as sync_error:
                    logger.warning(f"RESTORE SYNC WARNING: Could not sync entities with restored config: {sync_error}")

            # Post-apply cleanup: Keep inactive servers for commenting, only delete backends/frontends that are truly inactive
            # Note: Inactive servers (is_active=FALSE) are kept for HAProxy config commenting
            await conn.execute("DELETE FROM backends WHERE cluster_id = $1 AND is_active = FALSE", cluster_id)
            await conn.execute("DELETE FROM frontends WHERE cluster_id = $1 AND is_active = FALSE", cluster_id)
            
            # Post-apply cleanup for WAF rules marked for deletion
            # Match names like: waf-<rule_id>-delete-<timestamp>
            waf_delete_versions = [
                v for v in pending_versions
                if v['version_name'].startswith('waf-') and '-delete-' in v['version_name']
            ]
            if waf_delete_versions:
                waf_ids_to_delete = []
                for v in waf_delete_versions:
                    match = re.search(r'^waf-(\d+)-delete-', v['version_name'])
                    if match:
                        waf_ids_to_delete.append(int(match.group(1)))
                
                if waf_ids_to_delete:
                    await conn.execute("DELETE FROM waf_rules WHERE id = ANY($1)", waf_ids_to_delete)
                    logger.info(f"APPLY CLEANUP: Hard deleted WAF rules with IDs: {waf_ids_to_delete}")

            # Post-apply cleanup for servers marked for deletion
            # Match names like: server-<server_id>-delete-<timestamp>
            server_delete_versions = [
                v for v in pending_versions
                if v['version_name'].startswith('server-') and '-delete-' in v['version_name']
            ]
            if server_delete_versions:
                import re
                server_ids_to_delete = []
                for v in server_delete_versions:
                    match = re.search(r'^server-(\d+)-delete-', v['version_name'])
                    if match:
                        server_ids_to_delete.append(int(match.group(1)))
                
                if server_ids_to_delete:
                    # Hard delete servers that were marked for deletion
                    await conn.execute("DELETE FROM backend_servers WHERE id = ANY($1)", server_ids_to_delete)
                    logger.info(f"APPLY CLEANUP: Hard deleted servers with IDs: {server_ids_to_delete}")
                

            logger.info(f"APPLY CLEANUP: Hard deleted inactive entities for cluster {cluster_id}")
        
        # CRITICAL FIX: Update ALL entities that are still PENDING or REJECTED to APPLIED after successful Apply
        # This handles cases where entities were marked PENDING but not included in specific ID lists
        # (e.g., parent backends marked PENDING due to server updates)
        # REJECTED entities are also marked as APPLIED because applying new changes supersedes rejection
        # This must run OUTSIDE the restore block to work for all Apply operations
        try:
            await conn.execute("""
                UPDATE backends 
                SET last_config_status = 'APPLIED', updated_at = CURRENT_TIMESTAMP
                WHERE cluster_id = $1 AND last_config_status IN ('PENDING', 'REJECTED')
            """, cluster_id)
            logger.info(f"APPLY CLEANUP: Updated all PENDING/REJECTED backends to APPLIED status")
            
            await conn.execute("""
                UPDATE frontends 
                SET last_config_status = 'APPLIED', updated_at = CURRENT_TIMESTAMP
                WHERE cluster_id = $1 AND last_config_status IN ('PENDING', 'REJECTED')
            """, cluster_id)
            logger.info(f"APPLY CLEANUP: Updated all PENDING/REJECTED frontends to APPLIED status")
            
            await conn.execute("""
                UPDATE waf_rules 
                SET last_config_status = 'APPLIED', updated_at = CURRENT_TIMESTAMP
                WHERE cluster_id = $1 AND last_config_status IN ('PENDING', 'REJECTED')
            """, cluster_id)
            logger.info(f"APPLY CLEANUP: Updated all PENDING/REJECTED WAF rules to APPLIED status")
            
            # Backend servers might not have last_config_status column in all DB versions
            try:
                await conn.execute("""
                    UPDATE backend_servers 
                    SET last_config_status = 'APPLIED', updated_at = CURRENT_TIMESTAMP
                    WHERE cluster_id = $1 AND last_config_status IN ('PENDING', 'REJECTED')
                """, cluster_id)
                logger.info(f"APPLY CLEANUP: Updated all PENDING/REJECTED servers to APPLIED status")
            except Exception as e:
                logger.info(f"APPLY CLEANUP: backend_servers.last_config_status column not found, skipping: {e}")
            
            try:
                # Update SSL certificates via junction table since ssl_certificates.cluster_id is always NULL
                ssl_update_result = await conn.execute("""
                    UPDATE ssl_certificates 
                    SET last_config_status = 'APPLIED', updated_at = CURRENT_TIMESTAMP
                    WHERE id IN (
                        SELECT scc.ssl_certificate_id 
                        FROM ssl_certificate_clusters scc 
                        WHERE scc.cluster_id = $1
                    ) 
                    AND last_config_status = 'PENDING'
                """, cluster_id)
                
                # Also update global SSL certificates (those not in junction table)
                global_ssl_update_result = await conn.execute("""
                    UPDATE ssl_certificates 
                    SET last_config_status = 'APPLIED', updated_at = CURRENT_TIMESTAMP
                    WHERE NOT EXISTS (
                        SELECT 1 FROM ssl_certificate_clusters scc 
                        WHERE scc.ssl_certificate_id = ssl_certificates.id
                    )
                    AND last_config_status = 'PENDING'
                """)
                
                logger.info(f"APPLY CLEANUP: Updated cluster-specific SSL certificates to APPLIED status")
                logger.info(f"APPLY CLEANUP: Updated global SSL certificates to APPLIED status")
            except Exception as e:
                logger.info(f"APPLY CLEANUP: ssl_certificates.last_config_status column not found, skipping: {e}")
        
        except Exception as cleanup_error:
            logger.error(f"APPLY CLEANUP FAILED: {cleanup_error}")
        
        await close_database_connection(conn)
        
        # CRITICAL FIX: Notify agents to pull new config and reload HAProxy
        from agent_notifications import notify_agents_config_change
        sync_results = []
        try:
            sync_results = await notify_agents_config_change(cluster_id, version_name)
            logger.info(f"AGENT NOTIFICATION: Notified {len(sync_results)} agents for cluster {cluster_id}")
        except Exception as notification_error:
            logger.error(f"AGENT NOTIFICATION FAILED: {notification_error}")
            sync_results = [{'error': 'Agent notification failed', 'details': str(notification_error)}]
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='apply_changes',
                resource_type='cluster',
                resource_id=str(cluster_id),
                details={
                    'applied_versions': len(pending_versions),
                    'version_names': [v["version_name"] for v in pending_versions],
                    'agents_notified': len(sync_results)
                }
            )
        
        logger.info(f"APPLY: Applied {len(pending_versions)} pending changes for cluster {cluster_id}, created consolidated version {version_name}")
        
        # GLOBAL SSL AUTO-APPLY: If we detected global SSL updates, automatically apply to other clusters
        # Safety check: Only do auto-apply from the originally triggered cluster (prevent infinite recursion)
        is_auto_apply = apply_request and apply_request.get('_auto_apply_from_global_ssl', False)
        global_apply_results = []
        
        if other_clusters_to_apply and not is_auto_apply:
            logger.info(f"GLOBAL SSL AUTO-APPLY: Starting automatic apply for {len(other_clusters_to_apply)} additional clusters...")
            
            for other_cluster in other_clusters_to_apply:
                try:
                    logger.info(f"GLOBAL SSL AUTO-APPLY: Applying to cluster '{other_cluster['name']}' (ID: {other_cluster['id']})")
                    
                    # Recursively call apply_pending_changes for other cluster
                    # Mark as auto-apply to prevent infinite recursion
                    auto_apply_request = apply_request.copy() if apply_request else {}
                    auto_apply_request['_auto_apply_from_global_ssl'] = True
                    
                    other_result = await apply_pending_changes(
                        cluster_id=other_cluster['id'],
                        apply_request=auto_apply_request,
                        authorization=authorization
                    )
                    
                    global_apply_results.append({
                        'cluster_id': other_cluster['id'],
                        'cluster_name': other_cluster['name'],
                        'success': True,
                        'applied_count': other_result.get('applied_count', 0),
                        'message': f"Global SSL updates applied successfully"
                    })
                    
                    logger.info(f"GLOBAL SSL AUTO-APPLY: Successfully applied to cluster '{other_cluster['name']}'")
                    
                except Exception as e:
                    logger.error(f"GLOBAL SSL AUTO-APPLY: Failed for cluster '{other_cluster['name']}': {e}")
                    global_apply_results.append({
                        'cluster_id': other_cluster['id'],
                        'cluster_name': other_cluster['name'],
                        'success': False,
                        'error': str(e),
                        'message': f"Failed to apply global SSL updates"
                    })
            
            logger.info(f"GLOBAL SSL AUTO-APPLY: Completed. Success: {sum(1 for r in global_apply_results if r['success'])}/{len(global_apply_results)}")
        
        response_data = {
            "message": f"Successfully applied {len(pending_versions)} pending changes with fresh configuration",
            "applied_count": len(pending_versions),
            "latest_version": version_name,
            "consolidated_version_id": consolidated_version_id,
            "sync_results": sync_results,
            "agents_notified": len(sync_results)
        }
        
        # Add global SSL apply results if any
        if global_apply_results:
            response_data["global_ssl_applied"] = {
                "total_clusters": len(global_apply_results),
                "successful": sum(1 for r in global_apply_results if r['success']),
                "failed": sum(1 for r in global_apply_results if not r['success']),
                "results": global_apply_results
            }
            response_data["message"] += f" (+ {sum(1 for r in global_apply_results if r['success'])} other clusters with global SSL)"
        
        return response_data
        
    except Exception as e:
        logger.error(f"Error applying pending changes: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{cluster_id}/config-versions/{version_id}")
async def get_config_version(cluster_id: int, version_id: int, authorization: str = Header(None)):
    """Get a specific configuration version with content"""
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get the specific version
        version = await conn.fetchrow("""
            SELECT cv.id, cv.version_name, cv.description, cv.config_content, cv.checksum, 
                   cv.file_size, cv.status, cv.is_active, cv.created_at,
                   u.username as created_by_username
            FROM config_versions cv
            LEFT JOIN users u ON cv.created_by = u.id
            WHERE cv.id = $1 AND cv.cluster_id = $2
        """, version_id, cluster_id)
        
        if not version:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Configuration version not found")
        
        await close_database_connection(conn)
        
        return {
            "id": version["id"],
            "version_name": version["version_name"],
            "description": version["description"],
            "config_content": version["config_content"],
            "checksum": version["checksum"],
            "file_size": version["file_size"],
            "status": version["status"],
            "is_active": version["is_active"],
            "created_at": version["created_at"].isoformat().replace('+00:00', 'Z') if version["created_at"] else None,
            "created_by": version["created_by_username"] or "System"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching config version: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{cluster_id}/config-versions/{version_id}/diff")
async def get_config_version_diff(cluster_id: int, version_id: int, authorization: str = Header(None)):
    """Get configuration differences between a version and its previous version"""
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        logger.info(f"DIFF DEBUG: Looking for version_id={version_id} in cluster_id={cluster_id}")
        
        # Get the current version with metadata for pre-apply snapshot
        current_version = await conn.fetchrow("""
            SELECT id, version_name, config_content, created_at, metadata
            FROM config_versions 
            WHERE id = $1 AND cluster_id = $2
        """, version_id, cluster_id)
        
        logger.info(f"DIFF DEBUG: Found version: {current_version is not None}")
        if current_version:
            logger.info(f"DIFF DEBUG: Version name: {current_version['version_name']}, has_content: {current_version['config_content'] is not None}")
        
        if not current_version:
            # Check if version exists in any cluster
            any_version = await conn.fetchrow("SELECT id, cluster_id FROM config_versions WHERE id = $1", version_id)
            if any_version:
                logger.error(f"DIFF DEBUG: Version {version_id} exists but in cluster {any_version['cluster_id']}, not {cluster_id}")
                await close_database_connection(conn)
                raise HTTPException(status_code=404, detail=f"Configuration version {version_id} not found in cluster {cluster_id}")
            else:
                logger.error(f"DIFF DEBUG: Version {version_id} does not exist at all")
                await close_database_connection(conn)
                raise HTTPException(status_code=404, detail=f"Configuration version {version_id} not found")
        
        # Special handling for SSL certificate changes
        import re
        if re.search(r'ssl-(\d+)-(create|update|delete)', current_version['version_name']):
            ssl_match = re.search(r'ssl-(\d+)-(create|update|delete)', current_version['version_name'])
            ssl_cert_id = int(ssl_match.group(1))
            ssl_action = ssl_match.group(2)
            
            logger.info(f"SSL DIFF DEBUG: Processing SSL certificate {ssl_action} for cert_id: {ssl_cert_id}")
            
            # Get SSL certificate info with actual certificate content
            ssl_cert = await conn.fetchrow("""
                SELECT id, name, primary_domain, created_at, certificate_content, 
                       private_key_content, chain_content, usage_type,
                       CASE 
                           WHEN NOT EXISTS (SELECT 1 FROM ssl_certificate_clusters WHERE ssl_certificate_id = id) THEN 'Global'
                           ELSE 'Cluster-specific'
                       END as ssl_type
                FROM ssl_certificates 
                WHERE id = $1
            """, ssl_cert_id)
            
            if ssl_cert:
                if ssl_action == "delete":
                    # For SSL delete, show what will be removed
                    changes = [
                        {"type": "context", "line": f"# SSL Certificate Deletion: {ssl_cert['name']}", "line_number": 1},
                        {"type": "context", "line": f"# Domain: {ssl_cert['primary_domain']}", "line_number": 2},
                        {"type": "context", "line": f"# Type: {ssl_cert['ssl_type']}", "line_number": 3},
                        {"type": "context", "line": "", "line_number": 4},
                        {"type": "removed", "line": f"- Certificate file will be removed: /etc/ssl/haproxy/{ssl_cert['name']}.pem", "line_number": 5},
                        {"type": "removed", "line": f"- Certificate will no longer be available for frontends", "line_number": 6},
                        {"type": "context", "line": "", "line_number": 7},
                        {"type": "context", "line": "# WARNING: Make sure no frontends are using this certificate!", "line_number": 8},
                        {"type": "context", "line": "# Check Frontend Management before applying this change.", "line_number": 9}
                    ]
                    removed_count = 2
                    added_count = 0
                else:
                    # For create/update, build the actual certificate file content that agent will deploy
                    cert_file_content_lines = [
                        f"# SSL Certificate File: {ssl_cert['name']}.pem",
                        f"# This file will be deployed to: /etc/ssl/haproxy/{ssl_cert['name']}.pem",
                        f"# Domain: {ssl_cert['primary_domain']}",
                        f"# Scope: {ssl_cert['ssl_type']}",
                        f"# Usage: {ssl_cert.get('usage_type', 'frontend').upper()}",
                        "",
                        "# Certificate Content:",
                    ]
                    
                    # Add certificate content
                    if ssl_cert['certificate_content']:
                        cert_file_content_lines.extend(ssl_cert['certificate_content'].strip().split('\n'))
                    
                    cert_file_content_lines.append("")
                    cert_file_content_lines.append("# Private Key Content:")
                    
                    # Add private key content
                    if ssl_cert['private_key_content']:
                        cert_file_content_lines.extend(ssl_cert['private_key_content'].strip().split('\n'))
                    
                    # Add chain content if exists
                    if ssl_cert['chain_content'] and ssl_cert['chain_content'].strip():
                        cert_file_content_lines.append("")
                        cert_file_content_lines.append("# Certificate Chain Content:")
                        cert_file_content_lines.extend(ssl_cert['chain_content'].strip().split('\n'))
                    
                    # Create diff showing the certificate file content
                    changes = []
                    line_number = 1
                    
                    for line in cert_file_content_lines:
                        if line.startswith('#'):
                            changes.append({"type": "context", "line": line, "line_number": line_number})
                        else:
                            changes.append({"type": "added", "line": f"+ {line}", "line_number": line_number})
                        line_number += 1
                    
                    # Add usage instructions
                    changes.extend([
                        {"type": "context", "line": "", "line_number": line_number},
                        {"type": "context", "line": "# Usage Instructions:", "line_number": line_number + 1},
                        {"type": "context", "line": "# 1. Go to Frontend Management", "line_number": line_number + 2},
                        {"type": "context", "line": "# 2. Edit a frontend and enable SSL/TLS", "line_number": line_number + 3},
                        {"type": "context", "line": f"# 3. Select '{ssl_cert['name']}' certificate", "line_number": line_number + 4}
                    ])
                    
                    added_count = len([c for c in changes if c["type"] == "added"])
                    removed_count = 0
                
                summary = {"added": added_count, "removed": removed_count, "total_changes": added_count + removed_count}
                
                await close_database_connection(conn)
                
                return {
                    "current_version": {
                        "id": current_version['id'],
                        "version_name": current_version['version_name'],
                        "created_at": current_version['created_at'].isoformat().replace('+00:00', 'Z')
                    },
                    "previous_version": None,
                    "changes": changes,
                    "summary": summary,
                    "ssl_certificate": {
                        "id": ssl_cert['id'],
                        "name": ssl_cert['name'],
                        "domain": ssl_cert['primary_domain'],
                        "type": ssl_cert['ssl_type'],
                        "action": ssl_action
                    }
                }
        
        # Check if current version has config content
        if not current_version['config_content']:
            # Special handling for restore versions - they might not have content yet
            if current_version['version_name'].startswith('restore-'):
                await close_database_connection(conn)
                logger.info(f"RESTORE DIFF: Version {version_id} is a restore operation, showing restore info")
                return {
                    "current_version": {
                        "id": current_version['id'],
                        "version_name": current_version['version_name'],
                        "created_at": current_version['created_at'].isoformat().replace('+00:00', 'Z')
                    },
                    "previous_version": None,
                    "changes": [],
                    "summary": {
                        "added_lines": 0,
                        "removed_lines": 0,
                        "total_changes": 0,
                        "message": "Restore operation pending - configuration will be applied when you click 'Apply Changes'"
                    }
                }
            else:
                await close_database_connection(conn)
                logger.warning(f"DIFF DEBUG: Version {version_id} has no config content, returning empty diff")
                return {
                    "current_version": {
                        "id": current_version['id'],
                        "version_name": current_version['version_name'],
                        "created_at": current_version['created_at'].isoformat().replace('+00:00', 'Z')
                    },
                    "previous_version": None,
                    "changes": [],
                    "summary": {
                        "added_lines": 0,
                        "removed_lines": 0,
                        "total_changes": 0,
                        "message": "Configuration version has no content to display"
                    }
                }
        
        # Choose previous version intelligently
        if current_version['version_name'].startswith('apply-consolidated'):
            # For apply-consolidated versions, use the pre-apply snapshot from metadata if available
            # This shows ONLY the changes made during this specific apply operation
            previous_version = None
            
            # Parse metadata if it's a JSON string
            metadata = current_version.get('metadata')
            if isinstance(metadata, str):
                try:
                    import json
                    metadata = json.loads(metadata)
                except:
                    metadata = None
            
            if metadata and isinstance(metadata, dict):
                pre_apply_snapshot = metadata.get('pre_apply_snapshot')
                if pre_apply_snapshot:
                    logger.info(f"DIFF DEBUG: Using pre-apply snapshot from metadata for apply-consolidated diff")
                    logger.info(f"DIFF DEBUG: Pre-apply snapshot length: {len(pre_apply_snapshot)}")
                    previous_version = {
                        'id': 0,
                        'version_name': 'pre-apply-snapshot',
                        'config_content': pre_apply_snapshot,
                        'created_at': current_version['created_at']
                    }
                else:
                    logger.info(f"DIFF DEBUG: Metadata exists but no pre_apply_snapshot found: {list(metadata.keys())}")
            else:
                logger.info(f"DIFF DEBUG: No valid metadata found for apply-consolidated version")
            
            # Fallback: For old apply-consolidated versions without snapshot metadata
            if not previous_version:
                logger.info(f"DIFF DEBUG: No pre-apply snapshot found, falling back to previous consolidated version")
            previous_version = await conn.fetchrow(
                """
                SELECT id, version_name, config_content, created_at
                FROM config_versions
                WHERE cluster_id = $1 
                  AND created_at < $2 
                  AND config_content IS NOT NULL
                  AND status = 'APPLIED'
                  AND version_name LIKE 'apply-consolidated-%'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                cluster_id,
                current_version['created_at'],
            )
            
            # If still no previous version found, create a minimal baseline for comparison
            if not previous_version:
                logger.info(f"DIFF DEBUG: No previous version found for first apply-consolidated, creating baseline")
                # Create a minimal HAProxy config as baseline
                baseline_config = """global
    daemon
    log stdout local0

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
"""
                previous_version = {
                    'id': 0,
                    'version_name': 'baseline',
                    'config_content': baseline_config,
                    'created_at': current_version['created_at']
                }
        else:
            # For an individual change (e.g., waf-*-create, ssl-*-update), first check for pre_apply_snapshot in metadata
            previous_version = None
            
            # Parse metadata if it's a JSON string
            metadata = current_version.get('metadata')
            if isinstance(metadata, str):
                try:
                    import json
                    metadata = json.loads(metadata)
                except:
                    metadata = None
            
            if metadata and isinstance(metadata, dict):
                pre_apply_snapshot = metadata.get('pre_apply_snapshot')
                if pre_apply_snapshot:
                    logger.info(f"DIFF DEBUG: Using pre-apply snapshot from metadata for {current_version['version_name']} diff")
                    logger.info(f"DIFF DEBUG: Pre-apply snapshot length: {len(pre_apply_snapshot)}")
                    previous_version = {
                        'id': 0,
                        'version_name': 'pre-apply-snapshot',
                        'config_content': pre_apply_snapshot,
                        'created_at': current_version['created_at']
                    }
            
            # Fallback: If no pre_apply_snapshot in metadata, compare with most recent APPLIED version
            if not previous_version:
                logger.info(f"DIFF DEBUG: No pre-apply snapshot, using previous APPLIED version for diff")
                previous_version = await conn.fetchrow(
                    """
                    SELECT id, version_name, config_content, created_at
                    FROM config_versions 
                    WHERE cluster_id = $1 AND created_at < $2 AND config_content IS NOT NULL 
                    AND status = 'APPLIED'
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    cluster_id,
                    current_version['created_at'],
                )
        
        logger.info(f"DIFF DEBUG: Found previous version: {previous_version is not None}")
        if previous_version:
            logger.info(f"DIFF DEBUG: Previous version name: {previous_version['version_name']}")
            logger.info(f"DIFF DEBUG: Previous config length: {len(previous_version['config_content']) if previous_version['config_content'] else 0}")
        else:
            logger.info(f"DIFF DEBUG: No previous version found - will compare against empty config")
        
        logger.info(f"DIFF DEBUG: Current config length: {len(current_version['config_content']) if current_version['config_content'] else 0}")
        logger.info(f"DIFF DEBUG: Version name pattern check: consolidated={current_version['version_name'].startswith('apply-consolidated')}")
        
        await close_database_connection(conn)
        
        import difflib, re

        def extract_block(content: str, section_type: str, name: str):
            lines = content.split('\n')
            start_idx = None
            header = f"{section_type} {name}"
            for i, l in enumerate(lines):
                if l.strip() == header:
                    start_idx = i
                    break
            if start_idx is None:
                return []
            end_idx = len(lines)
            for j in range(start_idx + 1, len(lines)):
                if lines[j] and not lines[j].startswith(' ') and not lines[j].startswith('\t'):
                    # next top-level section
                    end_idx = j
                    break
            return lines[start_idx:end_idx]

        version_name = current_version['version_name']
        prev_lines_full = previous_version['config_content'].split('\n') if previous_version else []
        curr_lines_full = current_version['config_content'].split('\n')

        scoped_prev = prev_lines_full
        scoped_curr = curr_lines_full

        # Initialize regex matches for all cases
        m_backend = re.match(r'^backend-(\d+)-', version_name)
        m_frontend = re.match(r'^frontend-(\d+)-', version_name)
        m_waf = re.match(r'^waf-(\d+)-', version_name)
        m_server = re.match(r'^server-(\d+)-', version_name)

        # For consolidated applies, show full diff - no scoping
        if version_name.startswith('apply-consolidated'):
            scoped_prev = prev_lines_full
            scoped_curr = curr_lines_full
            logger.info(f"DIFF DEBUG: apply-consolidated diff - prev_lines: {len(scoped_prev)}, curr_lines: {len(scoped_curr)}")
        else:
            # Scope diffs for entity types to avoid showing whole file additions

            conn2 = await get_database_connection()
            try:
                if m_backend:
                    be_id = int(m_backend.group(1))
                    be_row = await conn2.fetchrow("SELECT name FROM backends WHERE id = $1", be_id)
                    if be_row and be_row['name']:
                        name = be_row['name']
                        scoped_prev = extract_block(previous_version['config_content'] if previous_version else '', 'backend', name)
                        scoped_curr = extract_block(current_version['config_content'], 'backend', name)
                elif m_frontend:
                    fe_id = int(m_frontend.group(1))
                    fe_row = await conn2.fetchrow("SELECT name FROM frontends WHERE id = $1", fe_id)
                    if fe_row and fe_row['name']:
                        name = fe_row['name']
                        scoped_prev = extract_block(previous_version['config_content'] if previous_version else '', 'frontend', name)
                        scoped_curr = extract_block(current_version['config_content'], 'frontend', name)
                elif m_waf:
                    # For WAF rules, show full diff as WAF rules are mixed throughout config
                    scoped_prev = prev_lines_full
                    scoped_curr = curr_lines_full
                elif m_server:
                    sv_id = int(m_server.group(1))
                    sv_row = await conn2.fetchrow(
                        """
                        SELECT bs.server_name, bs.backend_name 
                        FROM backend_servers bs 
                        WHERE bs.id = $1
                        """,
                        sv_id,
                    )
                    if sv_row and sv_row['backend_name']:
                        be_name = sv_row['backend_name']
                        scoped_prev = extract_block(previous_version['config_content'] if previous_version else '', 'backend', be_name)
                        scoped_curr = extract_block(current_version['config_content'], 'backend', be_name)
            finally:
                await close_database_connection(conn2)

        # Compute diff
        diff = list(difflib.unified_diff(
            scoped_prev,
            scoped_curr,
            fromfile=f"Previous ({previous_version['version_name']})" if previous_version else 'Previous',
            tofile=f"Current ({current_version['version_name']})",
            lineterm='',
            n=3
        ))
        
        logger.info(f"DIFF DEBUG: Scoped prev lines: {len(scoped_prev)}, curr lines: {len(scoped_curr)}")
        logger.info(f"DIFF DEBUG: Raw diff length: {len(diff)}")
        
        # Debug scoping for server delete
        if version_name.startswith('server-') and '-delete-' in version_name:
            logger.info(f"DIFF DEBUG: Server delete version detected: {version_name}")
            logger.info(f"DIFF DEBUG: m_server match: {m_server is not None}")
            if len(scoped_prev) <= 20 and len(scoped_curr) <= 20:
                logger.info(f"DIFF DEBUG: Scoped prev content: {scoped_prev}")
                logger.info(f"DIFF DEBUG: Scoped curr content: {scoped_curr}")
            logger.info(f"DIFF DEBUG: Full prev length: {len(prev_lines_full)}, Full curr length: {len(curr_lines_full)}")

        # WAF changes show full diff since WAF rules are integrated throughout the config
        # No additional filtering needed for WAF - full diff already scoped in elif m_waf block above
        # If Server change, keep only the specific server line within backend block plus headers
        if m_server:
            # Obtain server name used earlier
            try:
                server_name = sv_row['server_name'] if 'sv_row' in locals() and sv_row else None
            except Exception:
                server_name = None
            if server_name:
                needle = f" server {server_name} "
                diff = [
                    d for d in diff
                    if (needle in d) or d.startswith('@@') or d.startswith('---') or d.startswith('+++')
                ]

        changes = []
        added_count = 0
        removed_count = 0
        line_number = 0
        
        logger.info(f"DIFF DEBUG: Processing {len(diff)} diff lines")
        
        for i, line in enumerate(diff):
            if line.startswith('@@'):
                match = re.search(r'@@ -(\d+),?\d* \+(\d+),?\d* @@', line)
                if match:
                    line_number = int(match.group(2))
                continue
            elif line.startswith('---') or line.startswith('+++'):
                continue
            elif line.startswith('+'):
                changes.append({"type": "added", "line": line[1:], "line_number": line_number})
                added_count += 1
                line_number += 1
            elif line.startswith('-'):
                changes.append({"type": "removed", "line": line[1:], "line_number": line_number})
                removed_count += 1
            elif line.startswith(' '):
                changes.append({"type": "context", "line": line[1:], "line_number": line_number})
                line_number += 1

        # If no previous version and we scoped to a block, mark only the block as added
        if not previous_version and (m_backend or m_frontend):
            scoped = scoped_curr
            changes = [{"type": "added", "line": l, "line_number": i + 1} for i, l in enumerate(scoped)]
            added_count = len(scoped)
            removed_count = 0

        summary = {"added": added_count, "removed": removed_count, "total_changes": added_count + removed_count}
        
        logger.info(f"DIFF DEBUG: Final summary - added: {added_count}, removed: {removed_count}, changes: {len(changes)}")
        
        return {
            "current_version": {
                "id": current_version['id'],
                "version_name": current_version['version_name'],
                "created_at": current_version['created_at'].isoformat().replace('+00:00', 'Z')
            },
            "previous_version": {
                "id": previous_version['id'] if previous_version else None,
                "version_name": previous_version['version_name'] if previous_version else None,
                "created_at": previous_version['created_at'].isoformat().replace('+00:00', 'Z') if previous_version else None
            } if previous_version else None,
            "changes": changes,
            "summary": summary
        }
        
    except Exception as e:
        logger.error(f"Error getting config diff: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{cluster_id}/config-versions/{version_id}/restore/preview")
async def preview_restore_config_version(
    cluster_id: int, 
    version_id: int, 
    authorization: str = Header(None)
):
    """
    Preview what will change when restoring a configuration version.
    Shows entities to create, update, and delete.
    """
    try:
        from auth_middleware import get_current_user_from_token
        from utils.haproxy_config_parser import parse_haproxy_config
        
        current_user = await get_current_user_from_token(authorization)
        conn = await get_database_connection()
        
        # Get version to restore
        version_to_restore = await conn.fetchrow(
            "SELECT * FROM config_versions WHERE id = $1 AND cluster_id = $2",
            version_id, cluster_id
        )
        
        if not version_to_restore:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Configuration version not found")
        
        if not version_to_restore['config_content']:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot restore version '{version_to_restore['version_name']}': "
                       f"This version contains only database changes without full configuration content. "
                       f"Only consolidated versions (apply-consolidated-*) can be restored."
            )
        
        # Parse the config to restore
        logger.info(f"RESTORE PREVIEW: Parsing config for version {version_to_restore['version_name']}")
        parse_result = parse_haproxy_config(version_to_restore['config_content'])
        
        if parse_result.errors:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=400,
                detail=f"Cannot parse configuration: {', '.join(parse_result.errors)}"
            )
        
        # Get current database state
        current_frontends = await conn.fetch(
            """SELECT id, name, bind_address, bind_port, default_backend, mode, 
                      ssl_enabled, ssl_certificate_id, ssl_port, ssl_cert_path, ssl_cert, ssl_verify,
                      maxconn, timeout_client, timeout_http_request, rate_limit,
                      compression, log_separate, monitor_uri,
                      acl_rules, redirect_rules, use_backend_rules, request_headers, response_headers
               FROM frontends WHERE cluster_id = $1 AND is_active = TRUE""",
            cluster_id
        )
        current_backends = await conn.fetch(
            """SELECT id, name, balance_method, mode,
                      health_check_uri, health_check_interval,
                      timeout_connect, timeout_server, timeout_queue
               FROM backends WHERE cluster_id = $1 AND is_active = TRUE""",
            cluster_id
        )
        
        # NOTE: Removed server count fetching for restore preview
        # Servers are separate entities, not backend fields
        # Server changes should be tracked separately in future enhancement
        
        # Build restore plan
        restore_plan = {
            "frontends": {
                "to_create": [],
                "to_update": [],
                "to_delete": []
            },
            "backends": {
                "to_create": [],
                "to_update": [],
                "to_delete": []
            },
            "servers": {
                "to_create": [],
                "to_update": [],
                "to_delete": []
            },
            "waf_rules": {
                "to_activate": [],
                "to_deactivate": []
            },
            "summary": {
                "total_changes": 0,
                "creates": 0,
                "updates": 0,
                "deletes": 0,
                "waf_activations": 0,
                "waf_deactivations": 0
            }
        }
        
        # Current state as dicts
        current_fe_dict = {fe['name']: dict(fe) for fe in current_frontends}
        current_be_dict = {be['name']: dict(be) for be in current_backends}
        
        # Parsed state as dicts
        # Ignore built-in frontends that are not managed in DB
        IGNORED_FRONTENDS = ['stats']  # Built-in stats frontend
        parsed_fe_dict = {fe.name: fe for fe in parse_result.frontends if fe.name not in IGNORED_FRONTENDS}
        parsed_be_dict = {be.name: be for be in parse_result.backends}
        
        # Compare frontends
        for fe_name, parsed_fe in parsed_fe_dict.items():
            if fe_name not in current_fe_dict:
                # New frontend to create
                restore_plan["frontends"]["to_create"].append({
                    "name": parsed_fe.name,
                    "bind_address": parsed_fe.bind_address,
                    "bind_port": parsed_fe.bind_port,
                    "default_backend": parsed_fe.default_backend,
                    "mode": parsed_fe.mode,
                    "ssl_enabled": parsed_fe.ssl_enabled,
                    "ssl_port": parsed_fe.ssl_port
                })
                restore_plan["summary"]["creates"] += 1
            else:
                # Check if different (need update)
                current = current_fe_dict[fe_name]
                
                # Build changes dict - only include fields that actually changed
                changes = {}
                
                if current.get('bind_address') != parsed_fe.bind_address:
                    changes["bind_address"] = {"from": current.get('bind_address'), "to": parsed_fe.bind_address}
                
                if current['bind_port'] != parsed_fe.bind_port:
                    changes["bind_port"] = {"from": current['bind_port'], "to": parsed_fe.bind_port}
                
                if current.get('default_backend') != parsed_fe.default_backend:
                    changes["default_backend"] = {"from": current.get('default_backend'), "to": parsed_fe.default_backend}
                
                if current['mode'] != parsed_fe.mode:
                    changes["mode"] = {"from": current['mode'], "to": parsed_fe.mode}
                
                if current.get('ssl_enabled', False) != parsed_fe.ssl_enabled:
                    changes["ssl_enabled"] = {"from": current.get('ssl_enabled', False), "to": parsed_fe.ssl_enabled}
                
                if current.get('ssl_port') != parsed_fe.ssl_port:
                    changes["ssl_port"] = {"from": current.get('ssl_port'), "to": parsed_fe.ssl_port}
                
                # NOTE: Only compare fields that parser actually parses from config
                # Removed: ssl_certificate_id, rate_limit, compression, log_separate, monitor_uri,
                # ssl_cert_path, ssl_verify, acl_rules, redirect_rules, use_backend_rules,
                # request_headers, response_headers, timeout_http_request
                # These are DB-only metadata fields not present in raw HAProxy config
                
                if current.get('maxconn') != parsed_fe.maxconn:
                    changes["maxconn"] = {"from": current.get('maxconn'), "to": parsed_fe.maxconn}
                
                if current.get('timeout_client') != parsed_fe.timeout_client:
                    changes["timeout_client"] = {"from": current.get('timeout_client'), "to": parsed_fe.timeout_client}
                
                if changes:
                    restore_plan["frontends"]["to_update"].append({
                        "id": current['id'],
                        "name": parsed_fe.name,
                        "changes": changes
                    })
                    restore_plan["summary"]["updates"] += 1
        
        # Frontends to delete
        for fe_name, current_fe in current_fe_dict.items():
            if fe_name not in parsed_fe_dict:
                restore_plan["frontends"]["to_delete"].append({
                    "id": current_fe['id'],
                    "name": current_fe['name'],
                    "bind_port": current_fe['bind_port']
                })
                restore_plan["summary"]["deletes"] += 1
        
        # Compare backends
        for be_name, parsed_be in parsed_be_dict.items():
            if be_name not in current_be_dict:
                # New backend to create
                server_count = len(parsed_be.servers) if parsed_be.servers else 0
                restore_plan["backends"]["to_create"].append({
                    "name": parsed_be.name,
                    "balance_method": parsed_be.balance_method,
                    "mode": parsed_be.mode,
                    "server_count": server_count
                })
                restore_plan["summary"]["creates"] += 1
            else:
                # Check if different
                current = current_be_dict[be_name]
                changes = {}
                
                if current['balance_method'] != parsed_be.balance_method:
                    changes["balance_method"] = {"from": current['balance_method'], "to": parsed_be.balance_method}
                
                if current['mode'] != parsed_be.mode:
                    changes["mode"] = {"from": current['mode'], "to": parsed_be.mode}
                
                if current.get('health_check_uri') != parsed_be.health_check_uri:
                    changes["health_check_uri"] = {"from": current.get('health_check_uri'), "to": parsed_be.health_check_uri}
                
                if current.get('health_check_interval') != parsed_be.health_check_interval:
                    changes["health_check_interval"] = {"from": current.get('health_check_interval'), "to": parsed_be.health_check_interval}
                
                if current.get('timeout_connect') != parsed_be.timeout_connect:
                    changes["timeout_connect"] = {"from": current.get('timeout_connect'), "to": parsed_be.timeout_connect}
                
                if current.get('timeout_server') != parsed_be.timeout_server:
                    changes["timeout_server"] = {"from": current.get('timeout_server'), "to": parsed_be.timeout_server}
                
                if current.get('timeout_queue') != parsed_be.timeout_queue:
                    changes["timeout_queue"] = {"from": current.get('timeout_queue'), "to": parsed_be.timeout_queue}
                
                # NOTE: Server count removed from backend comparison
                # Servers are separate entities, not backend fields
                # Server changes should be tracked separately, not as backend field changes
                # This prevents false positives when only frontend changed but DB had server sync issues
                
                if changes:
                    restore_plan["backends"]["to_update"].append({
                        "id": current['id'],
                        "name": parsed_be.name,
                        "changes": changes
                    })
                    restore_plan["summary"]["updates"] += 1
        
        # Backends to delete
        for be_name, current_be in current_be_dict.items():
            if be_name not in parsed_be_dict:
                restore_plan["backends"]["to_delete"].append({
                    "id": current_be['id'],
                    "name": current_be['name']
                })
                restore_plan["summary"]["deletes"] += 1
        
        # CRITICAL: Compare backend servers for restore preview
        # Fetch current servers for each backend
        logger.info(f"RESTORE PREVIEW: Comparing backend servers")
        for be_name in current_be_dict.keys():
            current_servers = await conn.fetch("""
                SELECT server_name, server_address, server_port, weight, maxconn,
                       check_enabled, backup_server, ssl_enabled
                FROM backend_servers
                WHERE backend_name = $1 AND cluster_id = $2 AND is_active = TRUE
                ORDER BY server_name
            """, be_name, cluster_id)
            
            current_server_dict = {s['server_name']: dict(s) for s in current_servers}
            
            # Get parsed servers for this backend (if backend exists in restore version)
            parsed_be = parsed_be_dict.get(be_name)
            parsed_server_dict = {}
            if parsed_be and parsed_be.servers:
                for server in parsed_be.servers:
                    parsed_server_dict[server.server_name] = {
                        'server_name': server.server_name,
                        'server_address': server.server_address,
                        'server_port': server.server_port,
                        'weight': server.weight,
                        'maxconn': server.max_connections,
                        'check_enabled': server.check_enabled,
                        'backup_server': server.backup_server,
                        'ssl_enabled': server.ssl_enabled
                    }
            
            # Servers to create (in restore version but not in current DB)
            for server_name, parsed_server in parsed_server_dict.items():
                if server_name not in current_server_dict:
                    restore_plan["servers"]["to_create"].append({
                        "backend_name": be_name,
                        "server_name": server_name,
                        "server_address": parsed_server['server_address'],
                        "server_port": parsed_server['server_port']
                    })
                    restore_plan["summary"]["creates"] += 1
            
            # Servers to update (in both, but with different values)
            for server_name in parsed_server_dict.keys():
                if server_name in current_server_dict:
                    current_server = current_server_dict[server_name]
                    parsed_server = parsed_server_dict[server_name]
                    
                    # Compare server fields
                    changes = {}
                    if current_server['server_address'] != parsed_server['server_address']:
                        changes["server_address"] = {"from": current_server['server_address'], "to": parsed_server['server_address']}
                    if current_server['server_port'] != parsed_server['server_port']:
                        changes["server_port"] = {"from": current_server['server_port'], "to": parsed_server['server_port']}
                    if current_server.get('weight') != parsed_server.get('weight'):
                        changes["weight"] = {"from": current_server.get('weight'), "to": parsed_server.get('weight')}
                    if current_server.get('maxconn') != parsed_server.get('maxconn'):
                        changes["maxconn"] = {"from": current_server.get('maxconn'), "to": parsed_server.get('maxconn')}
                    if current_server.get('check_enabled') != parsed_server.get('check_enabled'):
                        changes["check_enabled"] = {"from": current_server.get('check_enabled'), "to": parsed_server.get('check_enabled')}
                    if current_server.get('backup_server') != parsed_server.get('backup_server'):
                        changes["backup_server"] = {"from": current_server.get('backup_server'), "to": parsed_server.get('backup_server')}
                    if current_server.get('ssl_enabled') != parsed_server.get('ssl_enabled'):
                        changes["ssl_enabled"] = {"from": current_server.get('ssl_enabled'), "to": parsed_server.get('ssl_enabled')}
                    
                    if changes:
                        restore_plan["servers"]["to_update"].append({
                            "backend_name": be_name,
                            "server_name": server_name,
                            "changes": changes
                        })
                        restore_plan["summary"]["updates"] += 1
            
            # Servers to delete (in current DB but not in restore version)
            for server_name, current_server in current_server_dict.items():
                if server_name not in parsed_server_dict:
                    restore_plan["servers"]["to_delete"].append({
                        "backend_name": be_name,
                        "server_name": server_name,
                        "server_address": current_server['server_address'],
                        "server_port": current_server['server_port']
                    })
                    restore_plan["summary"]["deletes"] += 1
        
        # CRITICAL: Compare WAF rules for restore preview (including config parameters)
        # WAF rules are stored as comments in config: "# WAF Rule: rule_name"
        # Parse WAF rules with their config parameters
        logger.info(f"RESTORE PREVIEW: Comparing WAF rules with config")
        import re
        import json
        config_lines = version_to_restore['config_content'].split('\n')
        
        # Parse WAF rules from config with their parameters
        waf_configs = {}  # {rule_name: {is_active: True, config: {...}}}
        i = 0
        while i < len(config_lines):
            line = config_lines[i].strip()
            
            # Find WAF rule comment
            if line.startswith('# WAF Rule:'):
                match = re.search(r'# WAF Rule: ([\w\s\-]+)', line)
                if match:
                    current_waf_name = match.group(1).strip()
                    waf_configs[current_waf_name] = {
                        'is_active': True,
                        'config': {}
                    }
                    
                    # Parse next few lines for WAF config parameters
                    for j in range(i+1, min(i+10, len(config_lines))):
                        next_line = config_lines[j].strip()
                        
                        # Parse stick-table line
                        if 'stick-table' in next_line:
                            expire_match = re.search(r'expire\s+(\d+)s', next_line)
                            if expire_match:
                                waf_configs[current_waf_name]['config']['rate_limit_window'] = int(expire_match.group(1))
                            
                            table_expire_match = re.search(r'http_req_rate\((\d+)s\)', next_line)
                            if table_expire_match:
                                waf_configs[current_waf_name]['config']['table_expire'] = int(table_expire_match.group(1))
                            
                            size_match = re.search(r'size\s+(\w+)', next_line)
                            if size_match:
                                waf_configs[current_waf_name]['config']['table_size'] = size_match.group(1)
                        
                        # Parse deny line
                        elif 'http-request deny if' in next_line or 'http-request tarpit if' in next_line:
                            rate_match = re.search(r'gt\s+(\d+)', next_line)
                            if rate_match:
                                waf_configs[current_waf_name]['config']['rate_limit_requests'] = int(rate_match.group(1))
                        
                        # Stop when we hit another WAF rule or different section
                        elif next_line.startswith('# WAF Rule:') or next_line.startswith('frontend ') or next_line.startswith('backend '):
                            break
            i += 1
        
        logger.info(f"RESTORE PREVIEW: Parsed {len(waf_configs)} WAF rules with config")
        
        # Get current WAF rules for this cluster (include config field)
        current_waf_rules = await conn.fetch("""
            SELECT id, name, is_active, rule_type, config
            FROM waf_rules
            WHERE cluster_id = $1
            ORDER BY name
        """, cluster_id)
        
        current_waf_dict = {waf['name']: dict(waf) for waf in current_waf_rules}
        
        # WAF rules to activate/update (in restore config)
        active_waf_names_in_restore = set(waf_configs.keys())
        for waf_name in active_waf_names_in_restore:
            if waf_name in current_waf_dict:
                # WAF rule exists - check if inactive OR config changed
                if not current_waf_dict[waf_name]['is_active']:
                    # Activation needed
                    restore_plan["waf_rules"]["to_activate"].append({
                        "name": waf_name,
                        "rule_type": current_waf_dict[waf_name]['rule_type'],
                        "current_status": "inactive"
                    })
                    restore_plan["summary"]["waf_activations"] += 1
                else:
                    # Active rule - check if config changed
                    current_config = current_waf_dict[waf_name].get('config') or {}
                    if isinstance(current_config, str):
                        current_config = json.loads(current_config) if current_config else {}
                    
                    parsed_config = waf_configs[waf_name]['config']
                    
                    # Check if config changed
                    config_changed = False
                    changes = []
                    for key in ['rate_limit_window', 'rate_limit_requests', 'table_expire', 'table_size']:
                        if key in parsed_config:
                            current_value = current_config.get(key)
                            parsed_value = parsed_config[key]
                            if current_value != parsed_value:
                                config_changed = True
                                changes.append(f"{key}: {current_value} → {parsed_value}")
                    
                    if config_changed:
                        # Add to "updates" section (NEW)
                        if "waf_rules" not in restore_plan:
                            restore_plan["waf_rules"] = {"to_activate": [], "to_deactivate": [], "to_update": []}
                        if "to_update" not in restore_plan["waf_rules"]:
                            restore_plan["waf_rules"]["to_update"] = []
                        
                        restore_plan["waf_rules"]["to_update"].append({
                            "name": waf_name,
                            "rule_type": current_waf_dict[waf_name]['rule_type'],
                            "changes": changes
                        })
                        restore_plan["summary"]["updates"] += 1
                        logger.info(f"RESTORE PREVIEW: WAF rule '{waf_name}' config changed: {', '.join(changes)}")
            # Note: If WAF rule in config but not in DB, it can't be activated
        
        # WAF rules to deactivate (currently active but not in restore config)
        for waf_name, waf_data in current_waf_dict.items():
            if waf_data['is_active'] and waf_name not in active_waf_names_in_restore:
                restore_plan["waf_rules"]["to_deactivate"].append({
                    "name": waf_name,
                    "rule_type": waf_data['rule_type'],
                    "current_status": "active"
                })
                restore_plan["summary"]["waf_deactivations"] += 1
        
        restore_plan["summary"]["total_changes"] = (
            restore_plan["summary"]["creates"] + 
            restore_plan["summary"]["updates"] + 
            restore_plan["summary"]["deletes"] +
            restore_plan["summary"]["waf_activations"] +
            restore_plan["summary"]["waf_deactivations"]
        )
        
        await close_database_connection(conn)
        
        logger.info(f"RESTORE PREVIEW: Generated plan with {restore_plan['summary']['total_changes']} total changes "
                   f"({restore_plan['summary']['waf_activations']} WAF activations, "
                   f"{restore_plan['summary']['waf_deactivations']} WAF deactivations)")
        
        return {
            "version_name": version_to_restore['version_name'],
            "version_id": version_id,
            "cluster_id": cluster_id,
            "restore_plan": restore_plan,
            "requires_confirmation": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Restore preview failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{cluster_id}/config-versions/{version_id}/restore/confirm")
async def confirm_restore_config_version(
    cluster_id: int, 
    version_id: int, 
    authorization: str = Header(None)
):
    """
    Confirm and execute the restore operation.
    Syncs entities to database and creates PENDING config version.
    """
    try:
        from auth_middleware import get_current_user_from_token
        from utils.haproxy_config_parser import parse_haproxy_config
        import time
        import json
        
        current_user = await get_current_user_from_token(authorization)
        conn = await get_database_connection()
        
        # Get version to restore
        version_to_restore = await conn.fetchrow(
            "SELECT * FROM config_versions WHERE id = $1 AND cluster_id = $2",
            version_id, cluster_id
        )
        
        if not version_to_restore:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Configuration version not found")
        
        if not version_to_restore['config_content']:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Version has no config content")
        
        # Parse the config
        logger.info(f"RESTORE CONFIRM: Parsing and syncing entities for version {version_to_restore['version_name']}")
        parse_result = parse_haproxy_config(version_to_restore['config_content'])
        
        if parse_result.errors:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=400,
                detail=f"Cannot parse configuration: {', '.join(parse_result.errors)}"
            )
        
        # PHASE 5: Initialize bulk snapshot tracker for restore operation
        from utils.entity_snapshot import save_entity_snapshot
        bulk_snapshots = []
        
        async with conn.transaction():
            # Get current state
            current_frontends = await conn.fetch(
                "SELECT id, name FROM frontends WHERE cluster_id = $1 AND is_active = TRUE",
                cluster_id
            )
            current_backends = await conn.fetch(
                "SELECT id, name FROM backends WHERE cluster_id = $1 AND is_active = TRUE",
                cluster_id
            )
            
            current_fe_dict = {fe['name']: fe['id'] for fe in current_frontends}
            current_be_dict = {be['name']: be['id'] for be in current_backends}
            parsed_fe_names = {fe.name for fe in parse_result.frontends}
            parsed_be_names = {be.name for be in parse_result.backends}
            
            # Build parsed entity dicts for metadata creation (needed after transaction)
            parsed_fe_dict = {fe.name: fe for fe in parse_result.frontends}
            parsed_be_dict = {be.name: be for be in parse_result.backends}
            
            # CRITICAL: Fetch detailed current state BEFORE database sync
            # PHASE 5: Use SELECT * to get ALL fields for snapshot (not just parsed fields)
            current_fe_details = {}
            for fe_name, fe_id in current_fe_dict.items():
                fe_record = await conn.fetchrow("""
                    SELECT * FROM frontends
                    WHERE id = $1 AND cluster_id = $2
                """, fe_id, cluster_id)
                if fe_record:
                    current_fe_details[fe_name] = dict(fe_record)
            
            current_be_details = {}
            current_be_servers = {}  # Track servers for each backend
            for be_name, be_id in current_be_dict.items():
                # PHASE 5: Use SELECT * to get ALL fields for snapshot
                be_record = await conn.fetchrow("""
                    SELECT * FROM backends
                    WHERE id = $1 AND cluster_id = $2
                """, be_id, cluster_id)
                if be_record:
                    current_be_details[be_name] = dict(be_record)
                
                # Fetch servers for this backend
                server_records = await conn.fetch("""
                    SELECT server_name, server_address, server_port, weight, maxconn,
                           check_enabled, backup_server, ssl_enabled
                    FROM backend_servers
                    WHERE backend_name = $1 AND cluster_id = $2 AND is_active = TRUE
                """, be_name, cluster_id)
                current_be_servers[be_name] = [dict(s) for s in server_records]
            
            # Fetch current WAF rules state
            current_waf_rules = await conn.fetch("""
                SELECT id, name, rule_type, config, action, priority, enabled
                FROM waf_rules
                WHERE cluster_id = $1 AND is_active = TRUE
            """, cluster_id)
            current_waf_dict = {waf['name']: dict(waf) for waf in current_waf_rules}
            
            logger.info(f"SNAPSHOT: Captured pre-restore state - {len(current_fe_details)} frontends, {len(current_be_details)} backends, {len(current_waf_dict)} WAF rules")
            
            # Track changes
            changes_summary = {
                "frontends_created": 0,
                "frontends_updated": 0,
                "frontends_deleted": 0,
                "backends_created": 0,
                "backends_updated": 0,
                "backends_deleted": 0,
                "waf_rules_activated": 0,
                "waf_rules_deactivated": 0
            }
            
            # Sync Frontends (ignore built-in frontends)
            IGNORED_FRONTENDS = ['stats']  # Built-in stats frontend
            for parsed_fe in parse_result.frontends:
                if parsed_fe.name in IGNORED_FRONTENDS:
                    logger.info(f"RESTORE: Skipping built-in frontend '{parsed_fe.name}'")
                    continue
                if parsed_fe.name in current_fe_dict:
                    # PHASE 5: Create snapshot BEFORE update (restore operation)
                    fe_id = current_fe_dict[parsed_fe.name]
                    old_frontend = current_fe_details.get(parsed_fe.name)
                    if old_frontend:
                        snapshot = await save_entity_snapshot(
                            conn=conn,
                            entity_type="frontend",
                            entity_id=fe_id,
                            old_values=old_frontend,  # Full record with ALL fields
                            new_values={
                                "bind_address": parsed_fe.bind_address,
                                "bind_port": parsed_fe.bind_port,
                                "default_backend": parsed_fe.default_backend,
                                "mode": parsed_fe.mode,
                                "ssl_enabled": parsed_fe.ssl_enabled,
                                "ssl_port": parsed_fe.ssl_port,
                                "maxconn": parsed_fe.maxconn,
                                "timeout_client": parsed_fe.timeout_client
                            },
                            operation="UPDATE_RESTORE"
                        )
                        if snapshot:
                            bulk_snapshots.append(snapshot)
                    
                    # UPDATE existing frontend (ALL 8 parsed fields)
                    # CRITICAL FIX: Include maxconn and timeout_client so UI shows restored values
                    await conn.execute("""
                        UPDATE frontends 
                        SET bind_address = $1, bind_port = $2, default_backend = $3, 
                            mode = $4, ssl_enabled = $5, ssl_port = $6,
                            maxconn = $7, timeout_client = $8,
                            updated_at = CURRENT_TIMESTAMP, last_config_status = 'PENDING'
                        WHERE id = $9 AND cluster_id = $10
                    """, 
                        parsed_fe.bind_address, parsed_fe.bind_port, parsed_fe.default_backend,
                        parsed_fe.mode, parsed_fe.ssl_enabled, parsed_fe.ssl_port,
                        parsed_fe.maxconn, parsed_fe.timeout_client,
                        fe_id, cluster_id
                    )
                    changes_summary["frontends_updated"] += 1
                    logger.info(f"RESTORE: Updated frontend '{parsed_fe.name}' (SSL: {parsed_fe.ssl_enabled}, maxconn: {parsed_fe.maxconn})")
                else:
                    # CREATE new frontend (ALL 8 parsed fields)
                    # CRITICAL FIX: Include maxconn and timeout_client so UI shows restored values
                    await conn.execute("""
                        INSERT INTO frontends 
                        (name, bind_address, bind_port, default_backend, mode, ssl_enabled, ssl_port,
                         maxconn, timeout_client,
                         cluster_id, is_active, last_config_status, created_at, updated_at)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, 'PENDING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """, 
                        parsed_fe.name, parsed_fe.bind_address, parsed_fe.bind_port,
                        parsed_fe.default_backend, parsed_fe.mode, parsed_fe.ssl_enabled, parsed_fe.ssl_port,
                        parsed_fe.maxconn, parsed_fe.timeout_client,
                        cluster_id
                    )
                    changes_summary["frontends_created"] += 1
                    logger.info(f"RESTORE: Created frontend '{parsed_fe.name}' (SSL: {parsed_fe.ssl_enabled}, maxconn: {parsed_fe.maxconn})")
            
            # Delete frontends not in restored config
            for fe_name, fe_id in current_fe_dict.items():
                if fe_name not in parsed_fe_names:
                    await conn.execute(
                        "UPDATE frontends SET is_active = FALSE, last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                        fe_id
                    )
                    changes_summary["frontends_deleted"] += 1
                    logger.info(f"RESTORE: Deleted frontend '{fe_name}'")
            
            # Sync Backends
            for parsed_be in parse_result.backends:
                if parsed_be.name in current_be_dict:
                    # PHASE 5: Create snapshot BEFORE update (restore operation)
                    be_id = current_be_dict[parsed_be.name]
                    old_backend = current_be_details.get(parsed_be.name)
                    if old_backend:
                        snapshot = await save_entity_snapshot(
                            conn=conn,
                            entity_type="backend",
                            entity_id=be_id,
                            old_values=old_backend,  # Full record with ALL fields
                            new_values={
                                "balance_method": parsed_be.balance_method,
                                "mode": parsed_be.mode,
                                "health_check_uri": parsed_be.health_check_uri,
                                "health_check_interval": parsed_be.health_check_interval,
                                "timeout_connect": parsed_be.timeout_connect,
                                "timeout_server": parsed_be.timeout_server,
                                "timeout_queue": parsed_be.timeout_queue
                            },
                            operation="UPDATE_RESTORE"
                        )
                        if snapshot:
                            bulk_snapshots.append(snapshot)
                    
                    # UPDATE existing backend
                    await conn.execute("""
                        UPDATE backends 
                        SET balance_method = $1, mode = $2, 
                            health_check_uri = $3, health_check_interval = $4,
                            timeout_connect = $5, timeout_server = $6, timeout_queue = $7,
                            updated_at = CURRENT_TIMESTAMP, last_config_status = 'PENDING'
                        WHERE id = $8 AND cluster_id = $9
                    """, 
                        parsed_be.balance_method, parsed_be.mode,
                        parsed_be.health_check_uri, parsed_be.health_check_interval,
                        parsed_be.timeout_connect, parsed_be.timeout_server, parsed_be.timeout_queue,
                        be_id, cluster_id
                    )
                    
                    # Delete old servers for this backend
                    await conn.execute(
                        "DELETE FROM backend_servers WHERE backend_name = $1 AND cluster_id = $2",
                        parsed_be.name, cluster_id
                    )
                    
                    # Insert new servers
                    if parsed_be.servers:
                        for server in parsed_be.servers:
                            await conn.execute("""
                                INSERT INTO backend_servers
                                (backend_name, server_name, server_address, server_port, weight, 
                                 maxconn, check_enabled, backup_server, ssl_enabled, 
                                 cluster_id, is_active, created_at, updated_at)
                                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            """,
                                parsed_be.name, server.server_name, server.server_address, server.server_port,
                                server.weight, server.max_connections, server.check_enabled,
                                server.backup_server, server.ssl_enabled, cluster_id
                            )
                    
                    changes_summary["backends_updated"] += 1
                    logger.info(f"RESTORE: Updated backend '{parsed_be.name}' with {len(parsed_be.servers) if parsed_be.servers else 0} servers")
                else:
                    # CREATE new backend
                    await conn.execute("""
                        INSERT INTO backends
                        (name, balance_method, mode, health_check_uri, health_check_interval,
                         timeout_connect, timeout_server, timeout_queue, cluster_id,
                         is_active, last_config_status, created_at, updated_at)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE, 'PENDING', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """,
                        parsed_be.name, parsed_be.balance_method, parsed_be.mode,
                        parsed_be.health_check_uri, parsed_be.health_check_interval,
                        parsed_be.timeout_connect, parsed_be.timeout_server, parsed_be.timeout_queue,
                        cluster_id
                    )
                    
                    # Insert servers
                    if parsed_be.servers:
                        for server in parsed_be.servers:
                            await conn.execute("""
                                INSERT INTO backend_servers
                                (backend_name, server_name, server_address, server_port, weight,
                                 maxconn, check_enabled, backup_server, ssl_enabled,
                                 cluster_id, is_active, created_at, updated_at)
                                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            """,
                                parsed_be.name, server.server_name, server.server_address, server.server_port,
                                server.weight, server.max_connections, server.check_enabled,
                                server.backup_server, server.ssl_enabled, cluster_id
                            )
                    
                    changes_summary["backends_created"] += 1
                    logger.info(f"RESTORE: Created backend '{parsed_be.name}' with {len(parsed_be.servers) if parsed_be.servers else 0} servers")
            
            # Delete backends not in restored config
            for be_name, be_id in current_be_dict.items():
                if be_name not in parsed_be_names:
                    await conn.execute(
                        "UPDATE backends SET is_active = FALSE, last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                        be_id
                    )
                    await conn.execute(
                        "DELETE FROM backend_servers WHERE backend_name = $1 AND cluster_id = $2",
                        be_name, cluster_id
                    )
                    changes_summary["backends_deleted"] += 1
                    logger.info(f"RESTORE: Deleted backend '{be_name}'")
            
            # Sync WAF Rules (parse from config comments + extract config parameters)
            # WAF rules are stored as comments in config: "# WAF Rule: rule_name"
            # Also parse config parameters (rate limit, expire time, etc.)
            import re
            import json
            config_lines = version_to_restore['config_content'].split('\n')
            
            # Parse WAF rules from config with their parameters
            waf_configs = {}  # {rule_name: {is_active: True, config: {...}}}
            i = 0
            while i < len(config_lines):
                line = config_lines[i].strip()
                
                # Find WAF rule comment
                if line.startswith('# WAF Rule:'):
                    match = re.search(r'# WAF Rule: ([\w\s\-]+)', line)
                    if match:
                        current_waf_name = match.group(1).strip()
                        waf_configs[current_waf_name] = {
                            'is_active': True,
                            'config': {}
                        }
                        
                        # Parse next few lines for WAF config parameters
                        # Look ahead for stick-table and http-request lines
                        for j in range(i+1, min(i+10, len(config_lines))):
                            next_line = config_lines[j].strip()
                            
                            # Parse stick-table line: expire and rate_limit_window
                            if 'stick-table' in next_line:
                                # Extract expire time: expire 66s
                                expire_match = re.search(r'expire\s+(\d+)s', next_line)
                                if expire_match:
                                    waf_configs[current_waf_name]['config']['rate_limit_window'] = int(expire_match.group(1))
                                
                                # Extract table_expire: http_req_rate(10s)
                                table_expire_match = re.search(r'http_req_rate\((\d+)s\)', next_line)
                                if table_expire_match:
                                    waf_configs[current_waf_name]['config']['table_expire'] = int(table_expire_match.group(1))
                                
                                # Extract table size: size 100k
                                size_match = re.search(r'size\s+(\w+)', next_line)
                                if size_match:
                                    waf_configs[current_waf_name]['config']['table_size'] = size_match.group(1)
                            
                            # Parse deny line: rate_limit_requests
                            elif 'http-request deny if' in next_line or 'http-request tarpit if' in next_line:
                                # Extract rate limit: gt 101
                                rate_match = re.search(r'gt\s+(\d+)', next_line)
                                if rate_match:
                                    waf_configs[current_waf_name]['config']['rate_limit_requests'] = int(rate_match.group(1))
                            
                            # Stop when we hit another WAF rule or different section
                            elif next_line.startswith('# WAF Rule:') or next_line.startswith('frontend ') or next_line.startswith('backend '):
                                break
                i += 1
            
            logger.info(f"RESTORE: Parsed {len(waf_configs)} WAF rules with config from restored config")
            
            # Update WAF rules: Set is_active AND config from parsed config
            for waf_name, parsed_waf in waf_configs.items():
                if waf_name not in current_waf_dict:
                    # WAF rule exists in restored config but not in current DB - should have been there
                    # This shouldn't happen normally, but log it
                    logger.warning(f"RESTORE: WAF rule '{waf_name}' in config but not found in DB")
                else:
                    # Get current config from DB
                    current_waf = current_waf_dict[waf_name]
                    current_config = current_waf.get('config') or {}
                    if isinstance(current_config, str):
                        current_config = json.loads(current_config) if current_config else {}
                    
                    # Merge parsed config with existing config (preserve fields we didn't parse)
                    updated_config = current_config.copy()
                    updated_config.update(parsed_waf['config'])
                    
                    # Update both is_active and config in DB
                    await conn.execute("""
                        UPDATE waf_rules
                        SET is_active = TRUE, config = $1, last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP
                        WHERE name = $2 AND cluster_id = $3
                    """, json.dumps(updated_config), waf_name, cluster_id)
                    changes_summary["waf_rules_activated"] += 1
                    logger.info(f"RESTORE: Activated WAF rule '{waf_name}' with config: {parsed_waf['config']}")
            
            # Deactivate WAF rules NOT in restored config
            for waf_name in current_waf_dict.keys():
                if waf_name not in waf_configs:
                    await conn.execute("""
                        UPDATE waf_rules
                        SET is_active = FALSE, last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP
                        WHERE name = $1 AND cluster_id = $2
                    """, waf_name, cluster_id)
                    changes_summary["waf_rules_deactivated"] += 1
                    logger.info(f"🔕 RESTORE: Deactivated WAF rule '{waf_name}'")
            
            # Create PENDING config version (for Apply Management)
            # Include metadata to track which entities were actually changed
            restored_version_name = f"restore-{version_to_restore['version_name']}-{int(time.time())}"
            
            # Build changed_entities metadata for UI sync status tracking
            # CRITICAL: Only include entities that have ACTUAL field changes (not all entities)
            # NOTE: current_fe_details and current_be_details were captured BEFORE database sync (line 2015-2036)
            #       This ensures accurate field comparison between pre-restore and restore states
            changed_entities = []
            
            # Compare frontends - only add if fields are different
            # CRITICAL: Skip built-in frontends from metadata too (consistent with DB sync)
            IGNORED_FRONTENDS = ['stats']  # Must match line 2024
            for fe_name, parsed_fe in parsed_fe_dict.items():
                if fe_name in IGNORED_FRONTENDS:
                    logger.info(f"METADATA: Skipping built-in frontend '{fe_name}' from changed_entities")
                    continue
                    
                if fe_name in current_fe_details:
                    # Check if any field is different (with exception safety)
                    try:
                        current = current_fe_details[fe_name]
                        
                        # Helper function to compare JSONB fields (acl_rules, redirect_rules)
                        import json
                        def compare_json_fields(db_value, parsed_value):
                            if db_value is None and parsed_value is None:
                                return False  # No change
                            if db_value is None or parsed_value is None:
                                return True  # One is None, other isn't - changed
                            # Both exist - compare as JSON
                            db_json = db_value if isinstance(db_value, (list, dict)) else json.loads(db_value) if db_value else []
                            parsed_json = parsed_value if isinstance(parsed_value, (list, dict)) else []
                            return db_json != parsed_json
                        
                        # CRITICAL: Only compare fields that parser actually parses from config
                        # Parser does NOT parse: ssl_certificate_id, ssl_cert_path, ssl_cert, ssl_verify,
                        # rate_limit, compression, log_separate, monitor_uri, acl_rules, redirect_rules,
                        # use_backend_rules, request_headers, response_headers
                        # These are database metadata fields and should not trigger false positive changes
                        has_changes = (
                            current.get('bind_address') != parsed_fe.bind_address or
                            current['bind_port'] != parsed_fe.bind_port or
                            current.get('default_backend') != parsed_fe.default_backend or
                            current['mode'] != parsed_fe.mode or
                            current.get('ssl_enabled', False) != parsed_fe.ssl_enabled or
                            current.get('ssl_port') != parsed_fe.ssl_port or
                            current.get('maxconn') != parsed_fe.maxconn or
                            current.get('timeout_client') != parsed_fe.timeout_client
                            # NOTE: Removed non-parsed fields to prevent false positives
                            # ssl_certificate_id, rate_limit, compression, acl_rules, etc. are DB-only
                        )
                        if has_changes:
                            changed_entities.append({
                                "type": "frontend", 
                                "id": current_fe_dict[fe_name], 
                                "name": fe_name, 
                                "action": "update"
                            })
                            logger.info(f"METADATA: Frontend '{fe_name}' has field changes, adding to changed_entities")
                        else:
                            logger.info(f"METADATA: Frontend '{fe_name}' unchanged, skipping from changed_entities")
                    except Exception as e:
                        # CRITICAL SAFETY: If comparison fails, add entity (safe fallback)
                        logger.warning(f"METADATA: Error comparing frontend '{fe_name}': {e}, adding to changed_entities (safe fallback)")
                        changed_entities.append({
                            "type": "frontend", 
                            "id": current_fe_dict[fe_name], 
                            "name": fe_name, 
                            "action": "update"
                        })
                else:
                    # New frontend
                    changed_entities.append({
                        "type": "frontend", 
                        "name": fe_name, 
                        "action": "create"
                    })
                    logger.info(f"METADATA: Frontend '{fe_name}' is new, adding to changed_entities")
            
            # Compare backends - only add if fields are different
            for be_name, parsed_be in parsed_be_dict.items():
                if be_name in current_be_details:
                    # Check if any field is different (with exception safety)
                    try:
                        current = current_be_details[be_name]
                        
                        # Check backend fields
                        has_backend_changes = (
                            current['balance_method'] != parsed_be.balance_method or
                            current['mode'] != parsed_be.mode or
                            current.get('health_check_uri') != parsed_be.health_check_uri or
                            current.get('health_check_interval') != parsed_be.health_check_interval or
                            current.get('timeout_connect') != parsed_be.timeout_connect or
                            current.get('timeout_server') != parsed_be.timeout_server or
                            current.get('timeout_queue') != parsed_be.timeout_queue
                        )
                        
                        # Check server changes
                        current_servers = current_be_servers.get(be_name, [])
                        parsed_servers = parsed_be.servers if parsed_be.servers else []
                        
                        # Quick check: different server count
                        has_server_changes = len(current_servers) != len(parsed_servers)
                        
                        # Detailed check: compare each server
                        if not has_server_changes and len(current_servers) > 0:
                            current_server_names = {s['server_name'] for s in current_servers}
                            parsed_server_names = {s.server_name for s in parsed_servers}
                            
                            # Check if server names changed
                            if current_server_names != parsed_server_names:
                                has_server_changes = True
                            else:
                                # Check if any server details changed
                                for parsed_server in parsed_servers:
                                    current_server = next((s for s in current_servers if s['server_name'] == parsed_server.server_name), None)
                                    if current_server:
                                        if (current_server['server_address'] != parsed_server.server_address or
                                            current_server['server_port'] != parsed_server.server_port or
                                            current_server.get('weight', 100) != parsed_server.weight or
                                            current_server.get('maxconn') != parsed_server.max_connections or
                                            current_server.get('check_enabled', True) != parsed_server.check_enabled or
                                            current_server.get('backup_server', False) != parsed_server.backup_server or
                                            current_server.get('ssl_enabled', False) != parsed_server.ssl_enabled):
                                            has_server_changes = True
                                            break
                        
                        has_changes = has_backend_changes or has_server_changes
                        if has_changes:
                            change_type = []
                            if has_backend_changes:
                                change_type.append("backend fields")
                            if has_server_changes:
                                change_type.append(f"servers ({len(current_servers)}→{len(parsed_servers)})")
                            changed_entities.append({
                                "type": "backend", 
                                "id": current_be_dict[be_name], 
                                "name": be_name, 
                                "action": "update"
                            })
                            logger.info(f"METADATA: Backend '{be_name}' has changes ({', '.join(change_type)}), adding to changed_entities")
                        else:
                            logger.info(f"METADATA: Backend '{be_name}' unchanged, skipping from changed_entities")
                    except Exception as e:
                        # CRITICAL SAFETY: If comparison fails, add entity (safe fallback)
                        logger.warning(f"METADATA: Error comparing backend '{be_name}': {e}, adding to changed_entities (safe fallback)")
                        changed_entities.append({
                            "type": "backend", 
                            "id": current_be_dict[be_name], 
                            "name": be_name, 
                            "action": "update"
                        })
                else:
                    # New backend
                    changed_entities.append({
                        "type": "backend", 
                        "name": be_name, 
                        "action": "create"
                    })
                    logger.info(f"METADATA: Backend '{be_name}' is new, adding to changed_entities")
            
            # Compare WAF Rules - add if activated/deactivated OR config changed
            # Extract active WAF names from parsed config
            active_waf_names = set(waf_configs.keys())
            
            for waf_name in active_waf_names:
                if waf_name in current_waf_dict:
                    # WAF rule is active in both current and restored config
                    # Check if config parameters changed
                    current_waf = current_waf_dict[waf_name]
                    current_config = current_waf.get('config') or {}
                    if isinstance(current_config, str):
                        current_config = json.loads(current_config) if current_config else {}
                    
                    parsed_config = waf_configs[waf_name]['config']
                    
                    # Compare config fields
                    config_changed = False
                    for key in ['rate_limit_window', 'rate_limit_requests', 'table_expire', 'table_size']:
                        if key in parsed_config:
                            current_value = current_config.get(key)
                            parsed_value = parsed_config[key]
                            if current_value != parsed_value:
                                config_changed = True
                                logger.info(f"METADATA: WAF rule '{waf_name}' config changed: {key} {current_value} → {parsed_value}")
                                break
                    
                    if config_changed:
                        changed_entities.append({
                            "type": "waf_rule",
                            "id": current_waf_dict[waf_name]['id'],
                            "name": waf_name,
                            "action": "update"
                        })
                        logger.info(f"METADATA: WAF rule '{waf_name}' config updated, adding to changed_entities")
                else:
                    # WAF rule was reactivated (was inactive, now active)
                    changed_entities.append({
                        "type": "waf_rule",
                        "name": waf_name,
                        "action": "activate"
                    })
                    logger.info(f"METADATA: WAF rule '{waf_name}' reactivated, adding to changed_entities")
            
            for waf_name in current_waf_dict.keys():
                if waf_name not in active_waf_names:
                    # WAF rule was deactivated
                    changed_entities.append({
                        "type": "waf_rule",
                        "id": current_waf_dict[waf_name]['id'],
                        "name": waf_name,
                        "action": "deactivate"
                    })
                    logger.info(f"🔕 METADATA: WAF rule '{waf_name}' deactivated, adding to changed_entities")
            
            # CRITICAL: Revert last_config_status to APPLIED for unchanged entities
            # This ensures only changed entities show as PENDING in UI
            unchanged_fe_ids = []
            changed_fe_names = {e['name'] for e in changed_entities if e['type'] == 'frontend'}
            for fe_name, fe_id in current_fe_dict.items():
                if fe_name not in IGNORED_FRONTENDS and fe_name not in changed_fe_names:
                    unchanged_fe_ids.append(fe_id)
            
            if unchanged_fe_ids:
                await conn.execute("""
                    UPDATE frontends 
                    SET last_config_status = 'APPLIED'
                    WHERE id = ANY($1) AND cluster_id = $2
                """, unchanged_fe_ids, cluster_id)
                logger.info(f"SELECTIVE STATUS: Reverted {len(unchanged_fe_ids)} unchanged frontends to APPLIED (will not show PENDING in UI)")
            
            unchanged_be_ids = []
            changed_be_names = {e['name'] for e in changed_entities if e['type'] == 'backend'}
            for be_name, be_id in current_be_dict.items():
                if be_name not in changed_be_names:
                    unchanged_be_ids.append(be_id)
            
            if unchanged_be_ids:
                await conn.execute("""
                    UPDATE backends 
                    SET last_config_status = 'APPLIED'
                    WHERE id = ANY($1) AND cluster_id = $2
                """, unchanged_be_ids, cluster_id)
                logger.info(f"SELECTIVE STATUS: Reverted {len(unchanged_be_ids)} unchanged backends to APPLIED (will not show PENDING in UI)")
            
            # Revert unchanged WAF rules to APPLIED
            unchanged_waf_ids = []
            changed_waf_names = {e['name'] for e in changed_entities if e['type'] == 'waf_rule'}
            for waf_name, waf_data in current_waf_dict.items():
                if waf_name not in changed_waf_names:
                    unchanged_waf_ids.append(waf_data['id'])
            
            if unchanged_waf_ids:
                await conn.execute("""
                    UPDATE waf_rules 
                    SET last_config_status = 'APPLIED'
                    WHERE id = ANY($1) AND cluster_id = $2
                """, unchanged_waf_ids, cluster_id)
                logger.info(f"SELECTIVE STATUS: Reverted {len(unchanged_waf_ids)} unchanged WAF rules to APPLIED (will not show PENDING in UI)")
            
            # PHASE 5: Get pre-apply snapshot for diff viewer
            old_config = await conn.fetchval("""
                SELECT config_content FROM config_versions 
                WHERE cluster_id = $1 AND status = 'APPLIED' AND is_active = TRUE
                ORDER BY created_at DESC LIMIT 1
            """, cluster_id)
            
            restore_metadata = {
                "pre_apply_snapshot": old_config or "",  # For diff viewer
                "bulk_snapshots": bulk_snapshots,  # For rollback
                "restore_source": version_to_restore['version_name'],
                "restore_type": "full_snapshot",
                "changed_entities": changed_entities,
                "changes_summary": changes_summary,
                "operation": "RESTORE",
                "entity_count": len(bulk_snapshots)
            }
            
            new_version_id = await conn.fetchval("""
                INSERT INTO config_versions 
                (cluster_id, version_name, config_content, checksum, created_by, is_active, status, description, metadata)
                VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING', $6, $7)
                RETURNING id
                        """,
                        cluster_id,
                restored_version_name,
                        version_to_restore['config_content'],
                        version_to_restore['checksum'],
                        current_user['id'],
                f"Restored from version '{version_to_restore['version_name']}' - {changes_summary['frontends_updated']}F~, {changes_summary['frontends_created']}F+, {changes_summary['backends_updated']}B~, {changes_summary['backends_created']}B+",
                json.dumps(restore_metadata)
                    )
        
        await close_database_connection(conn)
        
        await log_user_activity(
            user_id=current_user['id'],
            action="restore_config_version_confirmed", 
            resource_type="cluster",
            resource_id=str(cluster_id),
            details={
                "restored_version_name": version_to_restore['version_name'],
                "new_version_name": restored_version_name,
                "changes": changes_summary
            }
        )
        
        logger.info(f"RESTORE COMPLETE: {restored_version_name} - {changes_summary}")
        
        return {
            "message": "Configuration restored successfully! Entities synced to database.",
            "restored_version": version_to_restore['version_name'],
            "new_version_name": restored_version_name,
            "new_version_id": new_version_id,
            "status": "PENDING",
            "changes": changes_summary,
            "next_step": "Go to Apply Management and click 'Apply All Changes' to activate the restored configuration."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Restore confirmation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/{cluster_id}/config-versions/{version_id}/undo-reject")
async def undo_reject_config_version(
    cluster_id: int, 
    version_id: int, 
    authorization: str = Header(None)
):
    """Undo rejection of a configuration version - mark it as PENDING again"""
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Check if version exists and is REJECTED
        version_to_undo = await conn.fetchrow(
            "SELECT * FROM config_versions WHERE id = $1 AND cluster_id = $2",
            version_id, cluster_id
        )
        
        if not version_to_undo:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Configuration version not found")
        
        if version_to_undo['status'] != 'REJECTED':
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Only REJECTED versions can be undone")
        
        async with conn.transaction():
            # Mark the version as PENDING again
            await conn.execute("""
                UPDATE config_versions 
                SET status = 'PENDING', updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
            """, version_id)
            
            # Also update the entity status to PENDING if this is an entity-specific version
            import re
            try:
                m_fe = re.search(r'frontend-(\d+)-', version_to_undo['version_name'])
                m_be = re.search(r'backend-(\d+)-', version_to_undo['version_name'])
                m_wf = re.search(r'waf-(\d+)-', version_to_undo['version_name'])
                m_srv = re.search(r'server-(\d+)-', version_to_undo['version_name'])
                
                if m_fe:
                    fe_id = int(m_fe.group(1))
                    await conn.execute(
                        "UPDATE frontends SET last_config_status = 'PENDING' WHERE id = $1 AND cluster_id = $2",
                        fe_id, cluster_id
                    )
                elif m_be:
                    be_id = int(m_be.group(1))
                    await conn.execute(
                        "UPDATE backends SET last_config_status = 'PENDING' WHERE id = $1 AND cluster_id = $2", 
                        be_id, cluster_id
                    )
                elif m_wf:
                    wf_id = int(m_wf.group(1))
                    await conn.execute(
                        "UPDATE waf_rules SET last_config_status = 'PENDING' WHERE id = $1 AND cluster_id = $2",
                        wf_id, cluster_id
                    )
                elif m_srv:
                    srv_id = int(m_srv.group(1))
                    await conn.execute(
                        "UPDATE backend_servers SET last_config_status = 'PENDING' WHERE id = $1 AND cluster_id = $2",
                        srv_id, cluster_id
                    )
                    logger.info(f"UNDO REJECT: Marked server {srv_id} as PENDING")
            except Exception as e:
                logger.warning(f"Could not update entity status for version {version_to_undo['version_name']}: {e}")
        
        await close_database_connection(conn)
        
        await log_user_activity(
            user_id=current_user['id'],
            action="undo_reject_config_version", 
            resource_type="cluster",
            resource_id=str(cluster_id),
            details={
                "version_name": version_to_undo['version_name'],
                "version_id": version_id
            }
        )
        
        return {
            "message": "Configuration rejection undone successfully.",
            "version_name": version_to_undo['version_name'],
            "version_id": version_id,
            "status": "PENDING"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Undo reject configuration version failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{cluster_id}/ssl_certificates/{cert_id}/agent-sync")
async def get_ssl_certificate_agent_sync_status(cluster_id: int, cert_id: int, authorization: str = Header(None)):
    """Get agent synchronization status for a specific SSL certificate based on file deployment"""
    try:
        from auth_middleware import get_current_user_from_token
        _ = await get_current_user_from_token(authorization)

        conn = await get_database_connection()

        # Get SSL certificate info
        ssl_cert = await conn.fetchrow(
            """
            SELECT name, primary_domain 
            FROM ssl_certificates 
            WHERE id = $1 AND is_active = TRUE
            """,
            cert_id
        )

        if not ssl_cert:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="SSL certificate not found")

        # FIXED: Use same logic as generic entity-sync endpoint
        # Get both version name and timestamp in one query
        ssl_specific_version_info = await conn.fetchrow("""
            SELECT cv.version_name, cv.created_at
            FROM config_versions cv
            WHERE cv.cluster_id = $1 AND cv.status = 'APPLIED' AND cv.is_active = TRUE
            AND cv.version_name LIKE $2
            ORDER BY cv.created_at DESC
            LIMIT 1
        """, cluster_id, f"ssl-{cert_id}-%")
        
        # If SSL has its own version, use that; otherwise use latest consolidated version
        if ssl_specific_version_info:
            latest_version = ssl_specific_version_info['version_name']
            latest_version_created_at = ssl_specific_version_info['created_at']
            logger.info(f"SSL SYNC: Found SSL-specific version for cert {cert_id}: {latest_version}")
        else:
            # No SSL-specific changes, use latest consolidated version
            consolidated_version_info = await conn.fetchrow("""
                SELECT cv.version_name, cv.created_at
                FROM config_versions cv
                WHERE cv.cluster_id = $1 AND cv.status = 'APPLIED' AND cv.is_active = TRUE
                AND cv.version_name LIKE 'apply-consolidated-%'
                ORDER BY cv.created_at DESC
                LIMIT 1
            """, cluster_id)
            
            if consolidated_version_info:
                latest_version = consolidated_version_info['version_name']
                latest_version_created_at = consolidated_version_info['created_at']
                logger.info(f"SSL SYNC: No SSL-specific version for cert {cert_id}, using consolidated: {latest_version}")
            else:
                latest_version = None
                latest_version_created_at = None
                logger.info(f"SSL SYNC: No version found for cert {cert_id}")

        # Get agents for this cluster
        agents = await conn.fetch(
            """
            SELECT a.id, a.name, COALESCE(a.enabled, TRUE) as enabled, a.status, a.haproxy_status,
                   a.last_seen, a.config_version, a.applied_config_version
            FROM agents a
            JOIN haproxy_clusters c ON c.pool_id = a.pool_id
            WHERE c.id = $1
            ORDER BY a.name
            """,
            cluster_id
        )

        # Expected SSL file path on agent servers
        ssl_filename = f"{ssl_cert['name']}.pem"
        expected_ssl_path = f"/etc/ssl/haproxy/{ssl_filename}"

        # For SSL certificates, sync means:
        # 1. Agent is online
        # 2. SSL file exists on agent server at expected path
        # 3. Agent has applied the latest cluster config version (which includes SSL changes)
        
        agent_items = []
        total = len(agents)
        synced = 0
        
        for ag in agents:
            is_online = (ag.get("status") == "online")
            delivered_version = ag.get("applied_config_version")
            
            # SSL sync criteria:
            # - Agent must be online
            # - Agent must have applied the latest cluster config version (which includes SSL deployment)
            # Note: We can't directly check if SSL file exists on remote server from here
            # So we assume if agent applied the latest cluster config, SSL file was deployed successfully
            
            version_synced = delivered_version == latest_version if latest_version else True
            ssl_file_deployed = is_online and version_synced  # Assumption: if latest config applied, SSL file is deployed
            
            in_sync = ssl_file_deployed
            
            if in_sync:
                synced += 1
                
            agent_items.append({
                "name": ag["name"],
                "status": ag.get("status", "unknown"),
                "haproxy_status": ag.get("haproxy_status", "unknown"),
                "last_seen": ag["last_seen"].isoformat() if ag.get("last_seen") else None,
                "delivered_version": delivered_version,
                "expected_ssl_path": expected_ssl_path,
                "ssl_file_deployed": ssl_file_deployed,
                "in_sync": in_sync
            })

        # Get SSL certificate entity_updated_at for proper sync status detection
        ssl_cert_details = await conn.fetchrow(
            """
            SELECT updated_at, created_at
            FROM ssl_certificates 
            WHERE id = $1 AND is_active = TRUE
            """,
            cert_id
        )
        
        # Get last user who applied changes to this cluster (same as entity-sync endpoint)
        last_applied_by_info = await conn.fetchrow("""
            SELECT u.username, u.full_name, ual.created_at as applied_at
            FROM user_activity_logs ual
            JOIN users u ON u.id = ual.user_id
            WHERE ual.resource_type = 'cluster'
              AND ual.resource_id = $1
              AND ual.action = 'apply_changes'
            ORDER BY ual.created_at DESC
            LIMIT 1
        """, str(cluster_id))
        
        last_applied_by = None
        if last_applied_by_info:
            last_applied_by = {
                "username": last_applied_by_info['username'],
                "full_name": last_applied_by_info['full_name'],
                "applied_at": last_applied_by_info['applied_at'].isoformat().replace('+00:00', 'Z') if last_applied_by_info['applied_at'] else None
            }
        
        await close_database_connection(conn)
        
        # Use updated_at if available, otherwise created_at
        entity_updated_at = ssl_cert_details['updated_at'] if ssl_cert_details['updated_at'] else ssl_cert_details['created_at']
        
        return {
            "sync_status": {
                "synced_agents": synced,
                "total_agents": total,
                "sync_percentage": round((synced / total * 100) if total > 0 else 100, 1),
                "last_sync_check": datetime.now(timezone.utc).isoformat()
            },
            "entity_updated_at": entity_updated_at.isoformat() if entity_updated_at else None,
            "latest_applied_version": latest_version,
            "latest_version_created_at": latest_version_created_at.isoformat() if latest_version_created_at else None,
            "last_applied_by": last_applied_by,  # NEW: Show who applied last
            "ssl_certificate": {
                "name": ssl_cert["name"],
                "domain": ssl_cert["primary_domain"],
                "expected_path": expected_ssl_path
            },
            "agents": agent_items
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting SSL certificate agent sync status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{cluster_id}", summary="Delete HAProxy Cluster", response_description="Cluster deleted successfully")
async def delete_cluster(cluster_id: int, authorization: str = Header(None)):
    """
    # Delete HAProxy Cluster
    
    Delete a cluster. The cluster must not have any dependencies (agents, backends, frontends, etc.).
    
    ## Path Parameters
    - **cluster_id**: Cluster ID to delete
    
    ## Prerequisites
    Before deleting a cluster, you must:
    1. Remove or reassign all agents
    2. Delete all backends
    3. Delete all frontends
    4. Delete all WAF rules
    5. Delete all SSL certificates
    
    ## Example Request
    ```bash
    curl -X DELETE "{BASE_URL}/api/clusters/1" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Response
    ```json
    {
      "message": "Cluster 'production-cluster' deleted successfully"
    }
    ```
    
    ## Error Responses
    - **403**: Insufficient permissions
    - **404**: Cluster not found
    - **409**: Cluster has dependencies (cannot be deleted)
      ```json
      {
        "detail": "Cannot delete cluster 'production-cluster'. Dependencies exist: 5 active agent(s), 3 backend(s), 2 frontend(s)"
      }
      ```
    - **500**: Server error
    """
    try:
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for cluster delete
        has_permission = await check_user_permission(current_user["id"], "clusters", "delete")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: clusters.delete required"
            )
        
        conn = await get_database_connection()
        
        # Check if cluster exists
        cluster = await conn.fetchrow("SELECT name FROM haproxy_clusters WHERE id = $1", cluster_id)
        if not cluster:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Cluster not found")
        
        # Check for dependencies before deletion
        dependencies = []
        
        # Check active agents (via pool relationship)
        active_agents = await conn.fetchval("""
            SELECT COUNT(*) FROM agents a
            INNER JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
            WHERE hc.id = $1
        """, cluster_id)
        if active_agents > 0:
            dependencies.append(f"{active_agents} active agent(s)")
        
        # Check backends
        backends_count = await conn.fetchval("SELECT COUNT(*) FROM backends WHERE cluster_id = $1", cluster_id)
        if backends_count > 0:
            dependencies.append(f"{backends_count} backend(s)")
        
        # Check frontends
        frontends_count = await conn.fetchval("SELECT COUNT(*) FROM frontends WHERE cluster_id = $1", cluster_id)
        if frontends_count > 0:
            dependencies.append(f"{frontends_count} frontend(s)")
        
        # Check WAF rules associated with frontends in this cluster
        waf_rules_count = await conn.fetchval("""
            SELECT COUNT(DISTINCT wr.id) FROM waf_rules wr
            INNER JOIN frontend_waf_rules fwr ON wr.id = fwr.waf_rule_id
            INNER JOIN frontends f ON fwr.frontend_id = f.id
            WHERE f.cluster_id = $1
        """, cluster_id)
        if waf_rules_count > 0:
            dependencies.append(f"{waf_rules_count} WAF rule(s)")
        
        # If dependencies exist, prevent deletion
        if dependencies:
            await close_database_connection(conn)
            deps_text = ", ".join(dependencies)
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot delete cluster: it has {deps_text}. Please remove these dependencies first."
            )
        
        # Use transaction to ensure atomic deletion
        async with conn.transaction():
            # Delete config versions first (they reference cluster)
            await conn.execute("DELETE FROM config_versions WHERE cluster_id = $1", cluster_id)
            
            # Delete cluster
            await conn.execute("DELETE FROM haproxy_clusters WHERE id = $1", cluster_id)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='delete',
            resource_type='cluster',
            resource_id=str(cluster_id),
            details={'name': cluster['name']}
        )
        
        return {"message": f"Cluster '{cluster['name']}' deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete cluster: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete cluster: {str(e)}")


@router.get("/{cluster_id}/agents/configs")
async def get_cluster_agent_configs(cluster_id: int, authorization: str = Header(None)):
    """Get configuration files from all agents in a cluster"""
    try:
        # Check if this is an agent token or user JWT
        is_agent_token = False
        if authorization and authorization.startswith("Bearer "):
            token = authorization.split(" ")[1]
            # Agent tokens are simple strings, JWT tokens have 3 parts separated by dots
            if len(token.split('.')) != 3:
                is_agent_token = True
        
        if not is_agent_token:
            # For UI users, validate JWT token
            from auth_middleware import get_current_user_from_token
            current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Check if cluster exists
        cluster = await conn.fetchrow("SELECT name FROM haproxy_clusters WHERE id = $1", cluster_id)
        if not cluster:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Cluster not found")
        
        # Get all agents in this cluster (via pool relationship)
        agents = await conn.fetch("""
            SELECT a.id, a.name, a.hostname, a.ip_address, a.status, a.last_seen
            FROM agents a
            INNER JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
            WHERE hc.id = $1
            ORDER BY a.name
        """, cluster_id)
        
        await close_database_connection(conn)
        
        # Generate mock configurations for each agent
        configs = []
        configs_retrieved = 0
        
        for agent in agents:
            try:
                if agent["status"] == "online":
                    # Generate realistic HAProxy config content
                    config_content = f"""# HAProxy Configuration for {agent['name']}
# Generated from agent: {agent['hostname']} ({agent['ip_address']})
# Last seen: {agent['last_seen']}

global
    daemon
    log stdout local0
    maxconn 4096
    user haproxy
    group haproxy

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend main
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/haproxy.pem
    redirect scheme https if !{{ ssl_fc }}
    
    # Default backend
    default_backend web_servers

backend web_servers
    balance roundrobin
    server web1 192.168.1.10:80 check
    server web2 192.168.1.11:80 check
"""
                    
                    configs.append({
                        "agent_id": agent["id"],
                        "agent_name": agent["name"],
                        "hostname": agent["hostname"],
                        "ip_address": agent["ip_address"],
                        "status": agent["status"],
                        "config_content": config_content,
                        "config_hash": f"sha256:{hash(config_content) % 1000000:06d}",
                        "retrieved_at": "2025-01-30T16:50:00Z",
                        "file_size": len(config_content)
                    })
                    configs_retrieved += 1
                else:
                    configs.append({
                        "agent_id": agent["id"],
                        "agent_name": agent["name"],
                        "hostname": agent["hostname"],
                        "ip_address": agent["ip_address"],
                        "status": agent["status"],
                        "config_content": None,
                        "error": f"Agent {agent['name']} is {agent['status']}, cannot retrieve config"
                    })
                    
            except Exception as agent_error:
                configs.append({
                    "agent_id": agent["id"],
                    "agent_name": agent["name"],
                    "hostname": agent["hostname"],
                    "ip_address": agent["ip_address"],
                    "status": agent["status"],
                    "config_content": None,
                    "error": f"Failed to retrieve config: {str(agent_error)}"
                })
        
        return {
            "cluster_id": cluster_id,
            "cluster_name": cluster["name"],
            "total_agents": len(agents),
            "configs_retrieved": configs_retrieved,
            "configs": configs,
            "retrieved_at": "2025-01-30T16:50:00Z"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get cluster agent configs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cluster agent configs: {str(e)}")

@router.delete("/{cluster_id}/pending-changes")
async def reject_all_pending_changes(cluster_id: int, authorization: str = Header(None)):
    """
    Reject all pending configuration changes for a cluster
    
    This endpoint:
    - Marks all PENDING config versions as REJECTED
    - Updates entity status (frontends, backends, servers) to REJECTED
    - Automatically detects and removes orphan config versions
    - Prevents orphan versions from cluttering the system
    
    Orphan Version Auto-Cleanup:
    - Detects config versions referencing entities from different clusters
    - Removes versions referencing deleted/non-existent entities
    - Multi-cluster isolation: Only updates entities in the target cluster
    - Example: Rejects backend-73-* only if backend 73 belongs to this cluster
    
    Use Case:
    - Discard unwanted configuration changes
    - Clean up phantom pending changes
    - Remove orphan versions without manual database intervention
    
    Requires: User authentication (admin or user with cluster access)
    """
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Check if cluster exists
        cluster = await conn.fetchrow("SELECT id, name FROM haproxy_clusters WHERE id = $1", cluster_id)
        if not cluster:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail=f"Cluster {cluster_id} not found")
        
        # Get all pending config versions for this cluster (CRITICAL: Include metadata for rollback!)
        pending_versions = await conn.fetch("""
            SELECT id, version_name, metadata FROM config_versions 
            WHERE cluster_id = $1 AND status = 'PENDING'
        """, cluster_id)
        
        # CRITICAL FIX: Detect and clean orphan config versions
        # Orphan versions reference entities that don't belong to this cluster (ID reuse bug)
        orphan_version_ids = []
        import re
        for v in pending_versions:
            is_orphan = False
            
            # Check if backend version references a backend NOT in this cluster
            m_be = re.search(r'^backend-(\d+)-', v['version_name'])
            if m_be:
                be_id = int(m_be.group(1))
                backend_exists = await conn.fetchrow("""
                    SELECT id, cluster_id FROM backends WHERE id = $1
                """, be_id)
                
                # If backend doesn't exist, version is orphan (entity was hard deleted)
                if backend_exists is None:
                    is_orphan = True
                    logger.warning(f"ORPHAN VERSION (reject): {v['version_name']} references non-existent backend {be_id}")
                # If backend exists but cluster_id is NULL, preserve version (legacy data)
                elif backend_exists['cluster_id'] is None:
                    logger.debug(f"Backend {be_id} has NULL cluster_id (legacy), preserving version")
                    is_orphan = False
                # If backend belongs to different cluster, version is orphan
                elif backend_exists['cluster_id'] != cluster_id:
                    is_orphan = True
                    logger.warning(f"ORPHAN VERSION (reject): {v['version_name']} references backend {be_id} from cluster {backend_exists['cluster_id']}, but version is in cluster {cluster_id}")
            
            # Check if frontend version references a frontend NOT in this cluster
            m_fe = re.search(r'^frontend-(\d+)-', v['version_name'])
            if m_fe:
                fe_id = int(m_fe.group(1))
                frontend_exists = await conn.fetchrow("""
                    SELECT id, cluster_id FROM frontends WHERE id = $1
                """, fe_id)
                
                # If frontend doesn't exist, version is orphan (entity was hard deleted)
                if frontend_exists is None:
                    is_orphan = True
                    logger.warning(f"ORPHAN VERSION (reject): {v['version_name']} references non-existent frontend {fe_id}")
                # If frontend exists but cluster_id is NULL, preserve version (legacy data)
                elif frontend_exists['cluster_id'] is None:
                    logger.debug(f"Frontend {fe_id} has NULL cluster_id (legacy), preserving version")
                    is_orphan = False
                # If frontend belongs to different cluster, version is orphan
                elif frontend_exists['cluster_id'] != cluster_id:
                    is_orphan = True
                    logger.warning(f"ORPHAN VERSION (reject): {v['version_name']} references frontend {fe_id} from cluster {frontend_exists['cluster_id']}, but version is in cluster {cluster_id}")
            
            if is_orphan:
                orphan_version_ids.append(v['id'])
        
        # Delete orphan versions immediately (they're invalid)
        # CRITICAL: Also clean entity status for orphan-referenced entities in THIS cluster
        if orphan_version_ids:
            # Extract entity IDs from orphan versions to clean their status
            orphan_be_ids = []
            orphan_fe_ids = []
            for v in [ver for ver in pending_versions if ver['id'] in orphan_version_ids]:
                m_be = re.search(r'^backend-(\d+)-', v['version_name'])
                if m_be:
                    orphan_be_ids.append(int(m_be.group(1)))
                m_fe = re.search(r'^frontend-(\d+)-', v['version_name'])
                if m_fe:
                    orphan_fe_ids.append(int(m_fe.group(1)))
            
            # Clean entity status ONLY for entities in THIS cluster with PENDING status
            # This prevents orphan versions from leaving entity status stuck as PENDING
            if orphan_be_ids:
                await conn.execute("""
                    UPDATE backends 
                    SET last_config_status = 'APPLIED' 
                    WHERE id = ANY($1) AND cluster_id = $2 AND last_config_status = 'PENDING'
                """, orphan_be_ids, cluster_id)
                logger.info(f"REJECT: Cleaned PENDING status for {len(orphan_be_ids)} backends affected by orphan versions")
            
            if orphan_fe_ids:
                await conn.execute("""
                    UPDATE frontends 
                    SET last_config_status = 'APPLIED' 
                    WHERE id = ANY($1) AND cluster_id = $2 AND last_config_status = 'PENDING'
                """, orphan_fe_ids, cluster_id)
                logger.info(f"REJECT: Cleaned PENDING status for {len(orphan_fe_ids)} frontends affected by orphan versions")
            
            # Now delete orphan versions
            await conn.execute("""
                DELETE FROM config_versions WHERE id = ANY($1)
            """, orphan_version_ids)
            logger.info(f"REJECT: Deleted {len(orphan_version_ids)} orphan config versions")
            
            # Remove orphans from pending_versions list
            pending_versions = [v for v in pending_versions if v['id'] not in orphan_version_ids]
        
        if not pending_versions:
            await close_database_connection(conn)
            return {"message": "No pending changes found to reject", "rejected_count": 0}
        
        # PHASE 3: Rollback entities from snapshots BEFORE marking as REJECTED
        from utils.entity_snapshot import rollback_entity_from_snapshot
        import json as json_module
        
        rollback_success_count = 0
        rollback_fail_count = 0
        rollback_skip_count = 0
        
        for version in pending_versions:
            try:
                # Parse metadata
                metadata = json_module.loads(version['metadata']) if version['metadata'] else {}
                
                logger.info(f"REJECT DEBUG: Version {version['version_name']} - metadata exists={version['metadata'] is not None}")
                logger.info(f"REJECT DEBUG: Parsed metadata keys={list(metadata.keys()) if metadata else 'EMPTY'}")
                
                # Check for single entity snapshot
                entity_snapshot = metadata.get('entity_snapshot')
                logger.info(f"REJECT DEBUG: entity_snapshot exists={entity_snapshot is not None}")
                
                if entity_snapshot:
                    # Single entity rollback
                    logger.info(f"REJECT DEBUG: Calling rollback for {entity_snapshot.get('entity_type')} {entity_snapshot.get('entity_id')}")
                    logger.info(f"REJECT DEBUG: old_values exists={('old_values' in entity_snapshot)}")
                    logger.info(f"REJECT DEBUG: operation={entity_snapshot.get('operation')}")
                    
                    success = await rollback_entity_from_snapshot(conn, entity_snapshot)
                    
                    logger.info(f"REJECT DEBUG: Rollback result={success}")
                    
                    if success:
                        rollback_success_count += 1
                        logger.info(f"REJECT ROLLBACK: Rolled back {entity_snapshot['entity_type']} {entity_snapshot['entity_id']}")
                    else:
                        rollback_fail_count += 1
                        logger.warning(f"REJECT ROLLBACK: Failed to rollback {entity_snapshot.get('entity_type')} {entity_snapshot.get('entity_id')}")
                
                # Check for bulk snapshots (bulk import, restore)
                bulk_snapshots = metadata.get('bulk_snapshots', [])
                if bulk_snapshots:
                    # Bulk entity rollback
                    logger.info(f"REJECT ROLLBACK: Processing bulk snapshot with {len(bulk_snapshots)} entities")
                    for snapshot_wrapper in bulk_snapshots:
                        entity_snap = snapshot_wrapper.get('entity_snapshot')
                        if entity_snap:
                            success = await rollback_entity_from_snapshot(conn, entity_snap)
                            if success:
                                rollback_success_count += 1
                            else:
                                rollback_fail_count += 1
                
                # If no snapshot found
                if not entity_snapshot and not bulk_snapshots:
                    rollback_skip_count += 1
                    logger.debug(f"REJECT ROLLBACK: No entity snapshot in version {version['version_name']}, skipping rollback")
                    
            except Exception as rollback_error:
                logger.error(f"REJECT ROLLBACK ERROR: Version {version['version_name']}: {rollback_error}", exc_info=True)
                rollback_fail_count += 1
        
        logger.info(
            f"REJECT ROLLBACK SUMMARY: success={rollback_success_count}, "
            f"failed={rollback_fail_count}, skipped={rollback_skip_count}"
        )
        
        # Mark all pending config versions as REJECTED (don't delete them)
        rejected_count = len(pending_versions)
        await conn.execute("""
            UPDATE config_versions 
            SET status = 'REJECTED'
            WHERE cluster_id = $1 AND status = 'PENDING'
        """, cluster_id)

        # Update WAF rules status to APPLIED (rolled back)
        try:
            waf_ids = []
            import re
            for v in pending_versions:
                m = re.search(r'^waf-(\d+)-', v['version_name'])
                if m:
                    waf_ids.append(int(m.group(1)))
            if waf_ids:
                await conn.execute("UPDATE waf_rules SET last_config_status = 'APPLIED' WHERE id = ANY($1)", waf_ids)
                logger.info(f"REJECT: Updated {len(waf_ids)} WAF rules status to APPLIED (rolled back)")
        except Exception as _:
            pass

        # PHASE 3: Update entity statuses to APPLIED (entities were rolled back)
        # CRITICAL: Entities are now at their old values, so status should be APPLIED not REJECTED
        # CRITICAL FIX: Only update entities that actually belong to this cluster (prevent orphan versions)
        try:
            fe_ids = []
            be_ids = []
            srv_ids = []
            ssl_ids = []
            bulk_import_entity_ids = {"frontends": [], "backends": [], "servers": []}
            import re
            for v in pending_versions:
                # CRITICAL FIX: Detect bulk import versions (bulk-import-*, restore-*)
                is_bulk_version = (
                    v['version_name'].startswith('bulk-import-') or 
                    v['version_name'].startswith('restore-')
                )
                
                if is_bulk_version:
                    # Extract entity IDs from metadata bulk_snapshots
                    metadata = json_module.loads(v['metadata']) if v['metadata'] else {}
                    bulk_snapshots = metadata.get('bulk_snapshots', [])
                    
                    logger.info(f"REJECT: Bulk version '{v['version_name']}' has {len(bulk_snapshots)} snapshots")
                    
                    for snapshot_wrapper in bulk_snapshots:
                        entity_snap = snapshot_wrapper.get('entity_snapshot')
                        if entity_snap:
                            entity_type = entity_snap.get('entity_type')
                            entity_id = entity_snap.get('entity_id')
                            operation = entity_snap.get('operation')
                            
                            # CRITICAL FIX: Only track CREATE operations for force deletion
                            # UPDATE operations should be rolled back, not deleted!
                            # If we delete an UPDATE entity, we lose the original entity that existed before bulk import
                            if operation == "CREATE":
                                # Track bulk import entities for verification (only newly created ones)
                                if entity_type == "frontend":
                                    bulk_import_entity_ids["frontends"].append(entity_id)
                                elif entity_type == "backend":
                                    bulk_import_entity_ids["backends"].append(entity_id)
                                elif entity_type == "server":
                                    bulk_import_entity_ids["servers"].append(entity_id)
                else:
                    # Normal entity-specific version (frontend-5-update, backend-3-create, etc.)
                    m1 = re.search(r'^frontend-(\d+)-', v['version_name'])
                    if m1:
                        fe_ids.append(int(m1.group(1)))
                    m2 = re.search(r'^backend-(\d+)-', v['version_name'])
                    if m2:
                        be_ids.append(int(m2.group(1)))
                    # CRITICAL FIX: Also extract server IDs from version names
                    m3 = re.search(r'^server-(\d+)-', v['version_name'])
                    if m3:
                        srv_ids.append(int(m3.group(1)))
                    m4 = re.search(r'^ssl-(\d+)-', v['version_name'])
                    if m4:
                        ssl_ids.append(int(m4.group(1)))
            
            # CRITICAL: Only update entities that belong to THIS cluster (multi-cluster isolation)
            # Status = APPLIED because entities were rolled back to their old values
            if fe_ids:
                await conn.execute("""
                    UPDATE frontends SET last_config_status = 'APPLIED' 
                    WHERE id = ANY($1) AND cluster_id = $2
                """, fe_ids, cluster_id)
                logger.info(f"REJECT: Updated {len(fe_ids)} frontends status to APPLIED (rolled back)")
            if be_ids:
                await conn.execute("""
                    UPDATE backends SET last_config_status = 'APPLIED' 
                    WHERE id = ANY($1) AND cluster_id = $2
                """, be_ids, cluster_id)
                logger.info(f"REJECT: Updated {len(be_ids)} backends status to APPLIED (rolled back)")
            if srv_ids:
                await conn.execute("""
                    UPDATE backend_servers SET last_config_status = 'APPLIED' 
                    WHERE id = ANY($1) AND cluster_id = $2
                """, srv_ids, cluster_id)
                logger.info(f"REJECT: Updated {len(srv_ids)} servers status to APPLIED (rolled back)")
            if ssl_ids:
                await conn.execute("""
                    UPDATE ssl_certificates SET last_config_status = 'APPLIED' 
                    WHERE id = ANY($1)
                """, ssl_ids)
                logger.info(f"REJECT: Updated {len(ssl_ids)} SSL certificates status to APPLIED (rolled back)")
            
            # CRITICAL FIX: Verify bulk import entities were properly rolled back (deleted)
            if bulk_import_entity_ids["frontends"] or bulk_import_entity_ids["backends"] or bulk_import_entity_ids["servers"]:
                # Check if bulk import entities still exist (rollback failed)
                remaining_fe = await conn.fetchval("""
                    SELECT COUNT(*) FROM frontends 
                    WHERE id = ANY($1) AND cluster_id = $2
                """, bulk_import_entity_ids["frontends"], cluster_id) if bulk_import_entity_ids["frontends"] else 0
                
                remaining_be = await conn.fetchval("""
                    SELECT COUNT(*) FROM backends 
                    WHERE id = ANY($1) AND cluster_id = $2
                """, bulk_import_entity_ids["backends"], cluster_id) if bulk_import_entity_ids["backends"] else 0
                
                remaining_srv = await conn.fetchval("""
                    SELECT COUNT(*) FROM backend_servers 
                    WHERE id = ANY($1) AND cluster_id = $2
                """, bulk_import_entity_ids["servers"], cluster_id) if bulk_import_entity_ids["servers"] else 0
                
                total_remaining = remaining_fe + remaining_be + remaining_srv
                
                if total_remaining > 0:
                    # CRITICAL: Bulk import entities were NOT deleted by rollback!
                    # This is a data corruption - entities should have been deleted
                    logger.error(
                        f"REJECT ROLLBACK FAILED: {total_remaining} bulk import entities still exist "
                        f"(fe={remaining_fe}, be={remaining_be}, srv={remaining_srv}). "
                        f"Expected 0 after rollback DELETE. This indicates rollback failure."
                    )
                    
                    # Force delete the entities since rollback failed
                    if bulk_import_entity_ids["frontends"]:
                        deleted_fe = await conn.execute("""
                            DELETE FROM frontends 
                            WHERE id = ANY($1) AND cluster_id = $2
                        """, bulk_import_entity_ids["frontends"], cluster_id)
                        logger.warning(f"REJECT CLEANUP: Force deleted {deleted_fe} frontends from failed bulk import")
                    
                    if bulk_import_entity_ids["backends"]:
                        deleted_be = await conn.execute("""
                            DELETE FROM backends 
                            WHERE id = ANY($1) AND cluster_id = $2
                        """, bulk_import_entity_ids["backends"], cluster_id)
                        logger.warning(f"REJECT CLEANUP: Force deleted {deleted_be} backends (+ cascade servers) from failed bulk import")
                    
                    # Servers are cascade deleted with backends, but clean any orphans
                    if bulk_import_entity_ids["servers"]:
                        deleted_srv = await conn.execute("""
                            DELETE FROM backend_servers 
                            WHERE id = ANY($1) AND cluster_id = $2
                        """, bulk_import_entity_ids["servers"], cluster_id)
                        logger.warning(f"REJECT CLEANUP: Force deleted {deleted_srv} orphan servers from failed bulk import")
                else:
                    logger.info(
                        f"REJECT ROLLBACK SUCCESS: All {len(bulk_import_entity_ids['frontends']) + len(bulk_import_entity_ids['backends']) + len(bulk_import_entity_ids['servers'])} "
                        f"bulk import entities were properly deleted"
                    )
                    
        except Exception as e:
            logger.error(f"Failed to update entity statuses during reject: {e}", exc_info=True)
            pass
        
        # FINAL CLEANUP: Remove orphan entity statuses without corresponding config versions
        # This handles edge cases where entities have PENDING status but no PENDING version exists
        # CRITICAL: Only clean if NO pending versions exist at all (prevents bulk import issues)
        try:
            # Check if there are ANY pending versions left
            any_pending_versions = await conn.fetchval("""
                SELECT EXISTS(
                    SELECT 1 FROM config_versions 
                    WHERE cluster_id = $1 AND status = 'PENDING'
                )
            """, cluster_id)
            
            # Only run orphan cleanup if NO pending versions exist
            # This prevents cleaning entities from bulk-import or other non-ID-specific versions
            if not any_pending_versions:
                # ADDITIONAL SAFETY: Check if we just rejected bulk import versions
                # If yes, DO NOT run final cleanup (bulk entities should already be deleted)
                has_bulk_versions = any(
                    v['version_name'].startswith('bulk-import-') or v['version_name'].startswith('restore-')
                    for v in pending_versions
                )
                
                if has_bulk_versions:
                    logger.info("REJECT: Skipping final cleanup (bulk import was rejected - entities already handled)")
                else:
                    # Safe to clean orphan entities (no bulk import, no pending versions)
                    cleaned_be = await conn.execute("""
                        UPDATE backends 
                        SET last_config_status = 'APPLIED'
                        WHERE cluster_id = $1 AND last_config_status = 'PENDING'
                    """, cluster_id)
                    
                    cleaned_fe = await conn.execute("""
                        UPDATE frontends 
                        SET last_config_status = 'APPLIED'
                        WHERE cluster_id = $1 AND last_config_status = 'PENDING'
                    """, cluster_id)
                    
                    cleaned_srv = await conn.execute("""
                        UPDATE backend_servers 
                        SET last_config_status = 'APPLIED'
                        WHERE cluster_id = $1 AND last_config_status = 'PENDING'
                    """, cluster_id)
                    
                    logger.info(f"REJECT: Final orphan cleanup - cleaned {cleaned_be} backends, {cleaned_fe} frontends, {cleaned_srv} servers (no pending versions)")
            else:
                logger.debug("REJECT: Skipping final cleanup (pending versions still exist)")
                
        except Exception as cleanup_error:
            logger.error(f"Final orphan entity cleanup failed: {cleanup_error}", exc_info=True)
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='reject_pending_changes',
                resource_type='cluster',
                resource_id=str(cluster_id),
                details={
                    'cluster_name': cluster['name'],
                    'rejected_count': rejected_count,
                    'version_names': [v['version_name'] for v in pending_versions]
                }
            )
        
        return {
            "message": f"Successfully rejected {rejected_count} pending changes for cluster {cluster['name']}",
            "rejected_count": rejected_count
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rejecting pending changes: {e}")
        raise HTTPException(status_code=500, detail=str(e))
