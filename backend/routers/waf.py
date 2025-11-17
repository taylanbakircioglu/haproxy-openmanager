from fastapi import APIRouter, HTTPException, Request, Header
from typing import Optional
import logging
import time
import hashlib
import json

from models import WAFRule, WAFRuleUpdate
from database.connection import get_database_connection, close_database_connection
from utils.activity_log import log_user_activity
from services.haproxy_config import generate_haproxy_config_for_cluster
from .waf_helpers import assign_frontends_and_get_clusters, create_pending_configs_for_clusters, log_activity


router = APIRouter(prefix="/api/waf", tags=["waf"])
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
    
    # Proper user-pool access validation
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

@router.get("/stats")
async def get_waf_stats(cluster_id: Optional[int] = None, authorization: str = Header(None)):
    """Get WAF statistics and overview, optionally filtered by cluster"""
    try:
        # Get current user for cluster validation
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Validate cluster access if cluster_id provided
        if cluster_id:
            await validate_user_cluster_access(current_user['id'], cluster_id, conn)
        
        # Build cluster filter condition
        cluster_filter = ""
        cluster_params = []
        if cluster_id:
            cluster_filter = " WHERE cluster_id = $1"
            cluster_params = [cluster_id]
        
        # Get total WAF rules count (cluster-filtered)
        total_rules = await conn.fetchval(f"SELECT COUNT(*) FROM waf_rules{cluster_filter}", *cluster_params)
        
        # Get rules by action type
        action_stats = await conn.fetch("""
            SELECT action, COUNT(*) as count
            FROM waf_rules
            GROUP BY action
            ORDER BY count DESC
        """)
        
        # Get rules by rule type
        type_stats = await conn.fetch("""
            SELECT rule_type, COUNT(*) as count
            FROM waf_rules
            GROUP BY rule_type
            ORDER BY count DESC
        """)
        
        # Get recently created rules (last 30 days)
        recent_rules = await conn.fetchval("""
            SELECT COUNT(*) FROM waf_rules 
            WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '30 days'
        """)
        
        # Get rules with frontend assignments (with schema safety)
        try:
            assigned_rules = await conn.fetchval("""
                SELECT COUNT(DISTINCT waf_rule_id) FROM frontend_waf_rules
            """)
            
            # Get top frontend assignments
            top_frontends = await conn.fetch("""
                SELECT f.name, f.id, COUNT(*) as rule_count
                FROM frontend_waf_rules fwr
                JOIN frontends f ON fwr.frontend_id = f.id
                GROUP BY f.id, f.name
                ORDER BY rule_count DESC
                LIMIT 5
            """)
        except Exception as relation_error:
            logger.warning(f"frontend_waf_rules table doesn't exist: {relation_error}")
            assigned_rules = 0
            top_frontends = []
        
        unassigned_rules = total_rules - (assigned_rules or 0)
        
        await close_database_connection(conn)
        
        return {
            "overview": {
                "total_rules": total_rules or 0,
                "assigned_rules": assigned_rules or 0,
                "unassigned_rules": unassigned_rules,
                "recent_rules": recent_rules or 0
            },
            "action_distribution": [
                {"action": row["action"], "count": row["count"]} 
                for row in action_stats
            ],
            "type_distribution": [
                {"type": row["rule_type"], "count": row["count"]} 
                for row in type_stats
            ],
            "top_frontends": [
                {"frontend_id": row["id"], "frontend_name": row["name"], "rule_count": row["rule_count"]} 
                for row in top_frontends
            ]
        }
        
    except Exception as e:
        logger.error(f"Error fetching WAF stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/rules", summary="Get WAF Rules", response_description="List of WAF rules")
async def get_waf_rules(cluster_id: Optional[int] = None):
    """
    # Get WAF Rules
    
    Retrieve all Web Application Firewall (WAF) rules for protecting web applications.
    
    ## Query Parameters
    - **cluster_id** (optional): Filter rules by cluster ID
    
    ## Example Request
    ```bash
    curl -X GET "{BASE_URL}/api/waf/rules?cluster_id=1" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Response
    ```json
    [
      {
        "id": 1,
        "name": "Block SQL Injection",
        "rule_type": "deny",
        "pattern": ".*(\\'|\\\")(union|select|insert|drop).*",
        "action": "deny",
        "priority": 100,
        "enabled": true,
        "cluster_ids": [1, 2],
        "frontend_names": ["web-frontend"]
      }
    ]
    ```
    """
    try:
        conn = await get_database_connection()
        
        # Detect if consolidated JSON config column exists (backward compatibility)
        config_column_exists = await conn.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'waf_rules' AND column_name = 'config'
            )
            """
        )
        # Detect if last_config_status column exists (schema-safety)
        status_column_exists = await conn.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'waf_rules' AND column_name = 'last_config_status'
            )
            """
        )
        
        # Build base query dynamically to avoid referencing non-existent column
        config_select = "w.config" if config_column_exists else "'{}'::jsonb AS config"
        status_select = "w.last_config_status" if status_column_exists else "'APPLIED'::text AS last_config_status"
        
        # Base query to fetch WAF rules with their configuration and frontend assignments
        base_query = f"""
            SELECT w.id, w.name, w.rule_type, {config_select}, w.action, 
                   w.priority, w.description, w.is_active, w.created_at, w.updated_at,
                   {status_select},
                   COALESCE(ARRAY_AGG(DISTINCT f.name) FILTER (WHERE f.name IS NOT NULL), ARRAY[]::VARCHAR[]) as frontend_names,
                   COALESCE(ARRAY_AGG(DISTINCT f.id) FILTER (WHERE f.id IS NOT NULL), ARRAY[]::INTEGER[]) as frontend_ids
            FROM waf_rules w
            LEFT JOIN frontend_waf_rules fwr ON w.id = fwr.waf_rule_id  
            LEFT JOIN frontends f ON fwr.frontend_id = f.id
        """
        
        if cluster_id:
            # Filter by cluster - include WAF rules that belong to this cluster directly or via frontend
            waf_rules = await conn.fetch(
                f"""{base_query}
                WHERE w.cluster_id = $1 OR f.cluster_id = $1 OR (w.cluster_id IS NULL AND w.id NOT IN (SELECT waf_rule_id FROM frontend_waf_rules))
                GROUP BY w.id
                ORDER BY w.priority, w.name
                """, 
                cluster_id
            )
        else:
            # Fetch all WAF rules if no cluster_id is specified
            waf_rules = await conn.fetch(
                f"""{base_query}
                GROUP BY w.id
                ORDER BY w.priority, w.name
                """
            )
        
        # Check for pending configurations for the given cluster
        pending_waf_ids = set()
        if waf_rules and cluster_id:
            try:
                pending_configs = await conn.fetch("""
                    SELECT DISTINCT 
                        (regexp_matches(version_name, '^waf-([0-9]+)-'))[1]::int as waf_id
                    FROM config_versions 
                    WHERE cluster_id = $1 AND status = 'PENDING'
                    AND version_name ~ '^waf-[0-9]+-'
                """, cluster_id)
                pending_waf_ids = {pc["waf_id"] for pc in pending_configs if pc["waf_id"]}
            except Exception as e:
                logger.warning(f"WAF API: Failed to check pending configs: {e}")
        
        await close_database_connection(conn)
        
        # Format the response with debug logging
        formatted_rules = []
        for rule in waf_rules:
            # Parse config if it's a string
            config = rule["config"] or {}
            if isinstance(config, str):
                try:
                    import json
                    config = json.loads(config)
                except:
                    config = {}
            
            # DEBUG: Log config data for troubleshooting edit form issues
            logger.info(f"WAF Rule {rule['id']} ({rule['name']}) - Config: {config}, Frontend IDs: {rule['frontend_ids']}")
            
            formatted_rule = {
                "id": rule["id"],
                "name": rule["name"],
                "rule_type": rule["rule_type"],
                "config": config,
                "action": rule["action"],
                "priority": rule["priority"],
                "description": rule["description"],
                "is_active": rule["is_active"],
                "last_config_status": rule.get("last_config_status", 'APPLIED'),
                "created_at": rule["created_at"].isoformat().replace('+00:00', 'Z') if rule["created_at"] else None,
                "updated_at": rule["updated_at"].isoformat().replace('+00:00', 'Z') if rule["updated_at"] else None,
                "frontend_names": rule["frontend_names"],
                "frontend_ids": rule["frontend_ids"],
                "frontend_count": len(rule["frontend_ids"]),
                "has_pending_config": rule["id"] in pending_waf_ids
            }
            formatted_rules.append(formatted_rule)
        
        return {"rules": formatted_rules}
    except Exception as e:
        logger.error(f"Error getting WAF rules: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/rules", summary="Create WAF Rule", response_description="WAF rule created successfully")
async def create_waf_rule(waf_rule_data: dict, cluster_id: Optional[int] = None, request: Request = None, authorization: str = Header(None)):
    """
    # Create WAF Rule
    
    Create a new Web Application Firewall rule to protect against attacks.
    
    ## Request Body
    - **name**: Rule name (required)
    - **rule_type**: Rule type (deny, allow, rate_limit)
    - **pattern**: Regex pattern to match (required)
    - **action**: Action to take (deny, allow)
    - **priority**: Rule priority (higher = applied first)
    - **enabled**: Enable rule (default: true)
    - **cluster_ids**: List of cluster IDs to apply rule
    
    ## Example Request
    ```bash
    curl -X POST "{BASE_URL}/api/waf/rules" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..." \\
      -H "Content-Type: application/json" \\
      -d '{
        "name": "Block SQL Injection",
        "rule_type": "deny",
        "pattern": ".*(union|select|insert|drop).*",
        "action": "deny",
        "priority": 100,
        "enabled": true,
        "cluster_ids": [1]
      }'
    ```
    """
    try:
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for WAF create
        has_permission = await check_user_permission(current_user["id"], "waf", "create")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: waf.create required"
            )
        
        conn = await get_database_connection()
        
        # Validate cluster access if cluster_id provided
        if cluster_id:
            await validate_user_cluster_access(current_user['id'], cluster_id, conn)
        
        # Prepare the config dictionary (support nested payload from UI)
        if isinstance(waf_rule_data.get('config'), dict):
            config = waf_rule_data['config']
        else:
            # Backward compatibility: flatten extra fields as config
            config = {
                k: v for k, v in waf_rule_data.items() if k not in [
                    'name', 'rule_type', 'action', 'priority', 'is_active', 
                    'description', 'frontend_ids'
                ]
            }
        
        # Create a WAFRule object for validation
        waf_rule = WAFRule(
            name=waf_rule_data.get('name'),
            rule_type=waf_rule_data.get('rule_type'),
            action=waf_rule_data.get('action'),
            priority=waf_rule_data.get('priority'),
            is_active=waf_rule_data.get('is_active', True),
            config=config,
            description=waf_rule_data.get('description'),
            frontend_ids=waf_rule_data.get('frontend_ids', [])
        )
        
        conn = await get_database_connection()
        
        # Check if rule name exists for this cluster
        if cluster_id:
            existing = await conn.fetchrow("SELECT id FROM waf_rules WHERE name = $1 AND cluster_id = $2", waf_rule.name, cluster_id)
        else:
            existing = await conn.fetchrow("SELECT id FROM waf_rules WHERE name = $1 AND cluster_id IS NULL", waf_rule.name)
        
        if existing:
            await close_database_connection(conn)
            cluster_info = f" in cluster {cluster_id}" if cluster_id else ""
            raise HTTPException(status_code=400, detail=f"WAF rule '{waf_rule.name}' already exists{cluster_info}")
        
        # CRITICAL VALIDATION: At least one frontend must be selected
        # Use case: Prevent unintentional application to ALL frontends
        # Risk: WAF rule without frontend = applies to ALL frontends in cluster (dangerous!)
        if not waf_rule.frontend_ids or len(waf_rule.frontend_ids) == 0:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=400,
                detail="At least one frontend must be selected for WAF rule. Please select target frontend(s) where this WAF rule should be applied."
            )
        
        async with conn.transaction():
            rule_id = await conn.fetchval("""
                INSERT INTO waf_rules (name, rule_type, config, action, priority, description, enabled, is_active, cluster_id) 
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id
            """, waf_rule.name, waf_rule.rule_type, json.dumps(waf_rule.config),
                waf_rule.action, waf_rule.priority, waf_rule.description, waf_rule.is_active, waf_rule.is_active, cluster_id)
            
            # CRITICAL FIX: Mark as PENDING *before* generating config
            await conn.execute("UPDATE waf_rules SET last_config_status = 'PENDING' WHERE id = $1", rule_id)
            
            frontend_assignments, cluster_ids = await assign_frontends_and_get_clusters(conn, rule_id, waf_rule.frontend_ids, cluster_id)
            
            sync_results = await create_pending_configs_for_clusters(conn, cluster_ids, "create", rule_id)

        await close_database_connection(conn)
        
        if current_user and current_user.get('id'):
            await log_activity(current_user, 'create', rule_id, waf_rule, frontend_assignments, cluster_ids, sync_results, request)
        
        return {
            "message": f"WAF rule '{waf_rule.name}' created successfully. Go to Apply Changes to activate.",
            "id": rule_id,
            "waf_rule": waf_rule.dict(),
            "frontend_assignments": frontend_assignments,
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating WAF rule: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/rules/{waf_rule_id}/config-versions")
async def get_waf_rule_config_versions(waf_rule_id: int, authorization: str = Header(None)):
    """Get config version history for a specific WAF rule"""
    try:
        # Verify user authentication
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get WAF rule info first
        waf_info = await conn.fetchrow("""
            SELECT w.id, w.name, 
                   ARRAY_AGG(DISTINCT c.name) as cluster_names,
                   ARRAY_AGG(DISTINCT c.id) as cluster_ids
            FROM waf_rules w
            LEFT JOIN frontend_waf_rules fwr ON w.id = fwr.waf_rule_id
            LEFT JOIN frontends f ON fwr.frontend_id = f.id  
            LEFT JOIN haproxy_clusters c ON f.cluster_id = c.id
            WHERE w.id = $1
            GROUP BY w.id, w.name
        """, waf_rule_id)
        
        if not waf_info:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="WAF rule not found")
        
        # Get all APPLIED config versions that are related to this WAF rule across all clusters
        cluster_ids = [cid for cid in waf_info['cluster_ids'] if cid] if waf_info['cluster_ids'] else []
        
        if cluster_ids:
            versions = await conn.fetch("""
                SELECT cv.id, cv.version_name, cv.description, cv.status, cv.is_active,
                       cv.created_at, cv.file_size, cv.checksum, cv.cluster_id,
                       u.username as created_by_username,
                       c.name as cluster_name
                FROM config_versions cv
                LEFT JOIN users u ON cv.created_by = u.id
                LEFT JOIN haproxy_clusters c ON cv.cluster_id = c.id
                WHERE cv.cluster_id = ANY($1) AND cv.status = 'APPLIED'
                AND cv.version_name ~ $2
                ORDER BY cv.created_at DESC
            """, cluster_ids, f'^waf-{waf_rule_id}-')
        else:
            versions = []
        
        await close_database_connection(conn)
        
        # Format the response
        formatted_versions = []
        for version in versions:
            formatted_versions.append({
                "id": version["id"],
                "version_name": version["version_name"],
                "description": version["description"] or "WAF rule configuration update",
                "type": "WAF Rule",
                "status": version["status"],
                "is_active": version["is_active"],
                "created_at": version["created_at"].isoformat().replace('+00:00', 'Z') if version["created_at"] else None,
                "created_by": version["created_by_username"] or "System",
                "cluster_name": version["cluster_name"],
                "cluster_id": version["cluster_id"],
                "file_size": version["file_size"],
                "checksum": version["checksum"][:8] + "..." if version["checksum"] else "No checksum"
            })
        
        return {
            "versions": formatted_versions,
            "entity_info": {
                "entityName": waf_info["name"],
                "clusterNames": [name for name in waf_info["cluster_names"] if name] if waf_info["cluster_names"] else ["No Cluster"],
                "clusterIds": cluster_ids
            }
        }
        
    except Exception as e:
        logger.error(f"Error fetching WAF rule config versions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/rules/{rule_id}")
async def update_waf_rule(rule_id: int, waf_rule_data: dict, request: Request, authorization: str = Header(None)):
    """Update existing WAF rule with multiple frontend assignments"""
    try:
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for WAF update
        has_permission = await check_user_permission(current_user["id"], "waf", "update")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: waf.update required"
            )
        
        conn = await get_database_connection()

        existing_rule = await conn.fetchrow("SELECT * FROM waf_rules WHERE id = $1", rule_id)
        if not existing_rule:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="WAF rule not found")

        # Prepare the config dictionary for the update
        import json
        config = existing_rule['config']
        if isinstance(config, str):
            config = json.loads(config) if config else {}
        elif config is None:
            config = {}
        
        # DEBUG: Log incoming data to trace config loss issue
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"WAF Update Debug - Rule ID: {rule_id}")
        logger.info(f"WAF Update Debug - Incoming data: {waf_rule_data}")
        logger.info(f"WAF Update Debug - Existing config: {existing_rule['config']}")
        logger.info(f"WAF Update Debug - Parsed config: {config}")
        
        # CRITICAL FIX: Merge form fields into config object
        # Frontend sends WAF-specific fields directly, not wrapped in 'config'
        config_fields = [
            # Header Filter fields
            'header_name', 'header_condition', 'header_value', 
            # IP Filter fields
            'ip_addresses', 'ip_action',
            # Rate Limit fields
            'rate_limit_requests', 'rate_limit_window',
            # Request Filter fields  
            'http_method', 'path_pattern',
            # Geo Block fields
            'countries', 'geo_action',
            # Size Limit fields
            'max_request_size', 'max_header_size',
            # Advanced/General fields (frontend field names)
            'log_message', 'custom_condition', 'redirect_url',
            # Legacy/alternative field names (backward compatibility)
            'custom_log_message', 'custom_haproxy_condition', 'rate_limit', 'time_window', 'method', 'request_size_limit', 'geo_countries'
        ]
        
        # Update config with any form fields that exist in the incoming data
        for field in config_fields:
            if field in waf_rule_data:
                config[field] = waf_rule_data[field]
                logger.info(f"WAF Update Debug - Updated config.{field} = {waf_rule_data[field]}")
        
        # Also handle explicit config updates if provided
        if 'config' in waf_rule_data:
            logger.info(f"WAF Update Debug - New config from request: {waf_rule_data['config']}")
            config.update(waf_rule_data['config'])
        else:
            logger.info("WAF Update Debug - No 'config' field in incoming data, using form fields")
            
        logger.info(f"WAF Update Debug - Final merged config: {config}")

        # Create a WAFRuleUpdate object for validation
        waf_rule = WAFRuleUpdate(
            name=waf_rule_data.get('name', existing_rule['name']),
            rule_type=waf_rule_data.get('rule_type', existing_rule['rule_type']),
            action=waf_rule_data.get('action', existing_rule['action']),
            priority=waf_rule_data.get('priority', existing_rule['priority']),
            is_active=waf_rule_data.get('is_active', existing_rule['is_active']),
            config=config,
            description=waf_rule_data.get('description', existing_rule['description']),
            frontend_ids=waf_rule_data.get('frontend_ids')
        )

        if waf_rule.name != existing_rule["name"]:
            # Check for name conflict within the same cluster
            cluster_id = existing_rule.get("cluster_id")
            if cluster_id:
                name_exists = await conn.fetchrow("SELECT id FROM waf_rules WHERE name = $1 AND cluster_id = $2 AND id != $3", waf_rule.name, cluster_id, rule_id)
            else:
                name_exists = await conn.fetchrow("SELECT id FROM waf_rules WHERE name = $1 AND cluster_id IS NULL AND id != $2", waf_rule.name, rule_id)
            
            if name_exists:
                await close_database_connection(conn)
                cluster_info = f" in cluster {cluster_id}" if cluster_id else ""
                raise HTTPException(status_code=400, detail=f"WAF rule name '{waf_rule.name}' already exists{cluster_info}")

        async with conn.transaction():
            await conn.execute("""
                UPDATE waf_rules SET 
                    name = $1, rule_type = $2, action = $3, priority = $4, 
                    description = $5, is_active = $6, updated_at = CURRENT_TIMESTAMP,
                    config = $7
                WHERE id = $8
            """, waf_rule.name, waf_rule.rule_type, waf_rule.action, 
                waf_rule.priority, waf_rule.description, waf_rule.is_active, 
                json.dumps(waf_rule.config), rule_id)
            
            # CRITICAL FIX: Mark as PENDING *before* generating config
            await conn.execute("UPDATE waf_rules SET last_config_status = 'PENDING' WHERE id = $1", rule_id)
            
            # PHASE 2: Create entity snapshot for rollback
            from utils.entity_snapshot import save_entity_snapshot
            
            new_values = {
                "name": waf_rule.name,
                "rule_type": waf_rule.rule_type,
                "action": waf_rule.action,
                "priority": waf_rule.priority,
                "description": waf_rule.description,
                "is_active": waf_rule.is_active,
                "config": json.dumps(waf_rule.config)
            }
            
            entity_snapshot_metadata = await save_entity_snapshot(
                conn=conn,
                entity_type="waf_rule",
                entity_id=rule_id,
                old_values=existing_rule,
                new_values=new_values,
                operation="UPDATE"
            )
            
            # Update frontend assignments if provided
            frontend_assignments = []
            cluster_ids = set()
            
            # CRITICAL FIX: Check if frontend_ids was explicitly sent in the request payload
            # We need to distinguish between:
            # - frontend_ids not sent at all (None) → keep existing associations
            # - frontend_ids sent as empty array ([]) → clear all associations  
            # - frontend_ids sent with values → update associations
            frontend_ids_in_payload = 'frontend_ids' in waf_rule_data
            
            if frontend_ids_in_payload:
                # CRITICAL VALIDATION: If frontend_ids explicitly provided, must have at least one
                # Use case: Prevent clearing all frontends (WAF rule would apply to nothing)
                if not waf_rule.frontend_ids or len(waf_rule.frontend_ids) == 0:
                    await close_database_connection(conn)
                    raise HTTPException(
                        status_code=400,
                        detail="At least one frontend must be selected for WAF rule. Cannot remove all frontend assignments. Please select target frontend(s)."
                    )
                
                # Frontend IDs were explicitly provided in the request (could be [] or [1,2,3])
                await conn.execute("DELETE FROM frontend_waf_rules WHERE waf_rule_id = $1", rule_id)
                frontend_assignments, cluster_ids = await assign_frontends_and_get_clusters(conn, rule_id, waf_rule.frontend_ids or [], existing_rule.get("cluster_id"))
                logger.info(f"WAF Update: Frontend associations updated for rule {rule_id}: {waf_rule.frontend_ids}")
            else:
                # Frontend IDs were not provided in the request → preserve existing associations
                assigned_frontends = await conn.fetch("SELECT frontend_id FROM frontend_waf_rules WHERE waf_rule_id = $1", rule_id)
                existing_frontend_ids = [af['frontend_id'] for af in assigned_frontends]
                _ , cluster_ids = await assign_frontends_and_get_clusters(conn, rule_id, existing_frontend_ids, existing_rule.get("cluster_id"))
                logger.info(f"WAF Update: Frontend associations preserved for rule {rule_id}: {existing_frontend_ids}")

            # Pass entity snapshot to config version creation
            sync_results = await create_pending_configs_for_clusters(conn, cluster_ids, "update", rule_id, entity_snapshot_metadata)

        await close_database_connection(conn)
        
        if current_user and current_user.get('id'):
             await log_activity(current_user, 'update', rule_id, waf_rule, frontend_assignments, cluster_ids, sync_results, request)

        return {
            "message": f"WAF rule '{waf_rule.name}' updated successfully. Go to Apply Changes to activate.",
            "waf_rule": waf_rule.dict(),
            "frontend_assignments": frontend_assignments,
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating WAF rule: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rules/{rule_id}/toggle")
async def toggle_waf_rule_status(
    rule_id: int,
    action: str = "toggle",
    cluster_id: Optional[int] = None,
    request: Request = None,
    authorization: str = Header(None)
):
    """Toggle, delete or enable/disable a WAF rule and create a pending config change"""
    try:
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for WAF toggle (uses update permission for toggle/enable/disable, delete permission for delete action)
        if action == "delete":
            has_permission = await check_user_permission(current_user["id"], "waf", "delete")
            if not has_permission:
                raise HTTPException(
                    status_code=403,
                    detail="Insufficient permissions: waf.delete required"
                )
        else:
            has_permission = await check_user_permission(current_user["id"], "waf", "toggle")
            if not has_permission:
                raise HTTPException(
                    status_code=403,
                    detail="Insufficient permissions: waf.toggle required"
                )
        
        conn = await get_database_connection()
        
        rule = await conn.fetchrow("SELECT * FROM waf_rules WHERE id = $1", rule_id)
        if not rule:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="WAF rule not found")
        
        # Determine new status based on action
        if action == "delete":
            new_status = False
            action_name = "delete"
        elif action == "enable":
            new_status = True
            action_name = "enable"
        elif action == "disable":
            new_status = False
            action_name = "disable"
        else:  # toggle
            new_status = not rule['is_active']
            action_name = "enable" if new_status else "disable"
        
        async with conn.transaction():
            await conn.execute(
                "UPDATE waf_rules SET is_active = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
                new_status, rule_id
            )
            
            # CRITICAL FIX: Mark PENDING *before* generating config
            await conn.execute("UPDATE waf_rules SET last_config_status = 'PENDING' WHERE id = $1", rule_id)
            
            # Get affected clusters to create pending changes
            assigned_frontends = await conn.fetch("SELECT frontend_id FROM frontend_waf_rules WHERE waf_rule_id = $1", rule_id)
            rule_cluster_id = await conn.fetchval("SELECT cluster_id FROM waf_rules WHERE id = $1", rule_id)
            _, cluster_ids = await assign_frontends_and_get_clusters(conn, rule_id, [af['frontend_id'] for af in assigned_frontends], rule_cluster_id)
            
            # If no clusters resolved via assignments or rule, but a cluster_id is provided by caller, use it
            if not cluster_ids and cluster_id:
                cluster_ids = {cluster_id}

            # If no clusters resolved via assignments or rule, but a cluster_id is provided by caller, use it
            if (not cluster_ids or len(cluster_ids) == 0) and cluster_id:
                cluster_ids = {cluster_id}
            
            sync_results = await create_pending_configs_for_clusters(conn, cluster_ids, action_name, rule_id)
        
        await close_database_connection(conn)
        
        # Log the activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action=action,
                resource_type='waf_rule',
                resource_id=str(rule_id),
                details={
                    'waf_rule_name': rule['name'],
                    'new_status': 'active' if new_status else 'inactive',
                    'affected_clusters': list(cluster_ids)
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        # Return appropriate message based on action
        if action == "delete":
            message = f"WAF rule '{rule['name']}' marked for deletion. Go to Apply Changes to remove it from agents."
        elif action_name == "enable":
            message = f"WAF rule '{rule['name']}' enabled. Go to Apply Changes to activate."
        else:
            message = f"WAF rule '{rule['name']}' disabled. Go to Apply Changes to deactivate."
        
        return {
            "message": message,
            "new_status": new_status,
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling WAF rule: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
 