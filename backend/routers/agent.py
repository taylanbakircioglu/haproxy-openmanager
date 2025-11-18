from fastapi import APIRouter, HTTPException, Header, Request, Depends
from typing import Optional
import logging
import time
import secrets
import base64
import string
import os
import json
# Pipeline trigger - force backend redeploy v2

from models import AgentCreate
from models.agent import AgentToggle, AgentHeartbeat, AgentScriptRequest, AgentUpgradeRequest
from database.connection import get_database_connection, close_database_connection
from utils.activity_log import log_user_activity
from auth_middleware import get_current_user_from_token, validate_agent_api_key, require_permission, check_user_permission
from utils.auth import authenticate_user
from config import MANAGEMENT_BASE_URL

router = APIRouter(prefix="/api/agents", tags=["agents"])
logger = logging.getLogger(__name__)

# ==== AGENT VERSION MANAGEMENT - HELPER FUNCTIONS ====
# Global version storage (acts as in-memory database)
AGENT_VERSIONS = {
    "macos": "2.1.0",  # Updated via endpoint
    "linux": "2.0.0"
}

def get_platform_key(agent_platform: str) -> str:
    """Convert agent platform to standardized platform key - fixed empty platform fallback"""
    platform = agent_platform.lower() if agent_platform else 'unknown'
    
    if platform in ['darwin', 'macos', 'osx', 'mac']:
        return 'macos'
    elif platform in ['linux', 'ubuntu', 'debian', 'centos', 'rhel', 'fedora', 'alpine']:
        return 'linux'
    else:
        # Default fallback for empty/unknown platforms - use linux as most common
        return 'linux'

async def get_version_for_platform(platform: str) -> str:
    """Get latest version for specified platform from database"""
    try:
        conn = await get_database_connection()
        platform_key = get_platform_key(platform)
        
        # CRITICAL FIX: Order by updated_at DESC instead of created_at DESC
        # This ensures "Reset to Default" updates are properly reflected
        # because ON CONFLICT updates updated_at but not created_at
        version_info = await conn.fetchrow("""
            SELECT version, created_at, updated_at
            FROM agent_versions 
            WHERE platform = $1 AND is_active = true
            ORDER BY updated_at DESC, created_at DESC
            LIMIT 1
        """, platform_key)
        
        await close_database_connection(conn)
        
        if version_info:
            logger.info(f"VERSION LOOKUP: platform={platform_key}, version={version_info['version']}, "
                       f"created_at={version_info['created_at']}, updated_at={version_info['updated_at']}")
            return version_info['version']
        else:
            # Fallback to global storage if no database entry
            logger.warning(f"VERSION LOOKUP: No active version in DB for platform={platform_key}, using fallback")
            return AGENT_VERSIONS.get(platform_key, 'unknown')
            
    except Exception as e:
        logger.error(f"Error getting version for platform {platform}: {e}")
        # Fallback to global storage
        platform_key = get_platform_key(platform)
        return AGENT_VERSIONS.get(platform_key, 'unknown')

# ==== FRONTEND SYNC HELPER ====
def _should_sync_frontend(frontend_name: str) -> bool:
    """
    Determine if a frontend should be synced from agent to management system.
    Returns False for system/manual frontends that should not be managed.
    """
    # List of frontend names/patterns that should NOT be synced
    skip_patterns = [
        'stats',           # HAProxy stats frontend
        'haproxy-stats',   # Alternative stats name
        'admin',           # Admin interfaces
        'monitoring',      # Monitoring frontends
        'health',          # Health check frontends
        'prometheus',      # Prometheus exporters
        'socket',          # Socket frontends
    ]
    
    frontend_lower = frontend_name.lower()
    
    # Check exact matches and patterns
    for pattern in skip_patterns:
        if pattern in frontend_lower:
            return False
    
    # Skip frontends that start with underscore (convention for system frontends)
    if frontend_name.startswith('_'):
        return False
        
    return True

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

def calculate_agent_health(status, last_seen):
    """Calculate agent health status based on status and last_seen timestamp"""
    if not last_seen:
        return "unknown"
    
    time_diff = time.time() - last_seen.timestamp()
    
    if status == "online" and time_diff < 30:
        return "healthy"
    elif status == "online" and time_diff < 120:
        return "warning"
    else:
        return "offline"

@router.get("", summary="Get All Agents", response_description="List of all agents")
async def get_agents(pool_id: Optional[int] = None, authorization: str = Header(None)):
    """
    # Get All Agents
    
    Retrieve list of all registered agents. Optionally filter by pool_id (cluster scope).
    
    ## Query Parameters
    - **pool_id** (optional): Filter agents by pool ID
    
    ## Example Request - All Agents
    ```bash
    curl -X GET "{BASE_URL}/api/agents" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Request - Filtered by Pool
    ```bash
    curl -X GET "{BASE_URL}/api/agents?pool_id=1" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Response
    ```json
    [
      {
        "id": 1,
        "name": "production-agent-01",
        "pool_id": 1,
        "pool_name": "production-pool",
        "pool_environment": "production",
        "platform": "linux",
        "architecture": "x86_64",
        "version": "2.0.0",
        "hostname": "haproxy-prod-01",
        "ip_address": "10.0.1.10",
        "operating_system": "Ubuntu 22.04",
        "status": "online",
        "enabled": true,
        "haproxy_status": "running",
        "haproxy_version": "2.8.3",
        "last_seen": "2024-01-15T10:30:00Z",
        "created_at": "2024-01-10T08:00:00Z"
      }
    ]
    ```
    
    ## Response Fields
    - **status**: Agent connection status (online/offline)
    - **enabled**: Whether agent is enabled to receive tasks
    - **haproxy_status**: Status of HAProxy service on agent's server
    - **last_seen**: Last heartbeat timestamp
    """
    try:
        conn = await get_database_connection()
        
        try:
            if pool_id:
                agents = await conn.fetch("""
                    SELECT a.id, a.name, a.pool_id, a.platform, a.architecture, a.version,
                           a.hostname, a.ip_address, a.operating_system, a.kernel_version,
                           a.uptime, a.cpu_count, a.memory_total, a.disk_space,
                           a.network_interfaces, a.capabilities, a.status, a.last_seen, a.last_action_time,
                           a.haproxy_status, a.haproxy_version, a.config_version, a.applied_config_version,
                           COALESCE(a.enabled, TRUE) as enabled,
                           a.created_at, a.updated_at,
                           p.name as pool_name, p.environment as pool_environment
                    FROM agents a
                    LEFT JOIN haproxy_cluster_pools p ON a.pool_id = p.id
                    WHERE a.pool_id = $1 AND a.name NOT LIKE 'token_%'
                    ORDER BY a.name
                """, pool_id)
            else:
                agents = await conn.fetch("""
                    SELECT a.id, a.name, a.pool_id, a.platform, a.architecture, a.version,
                           a.hostname, a.ip_address, a.operating_system, a.kernel_version,
                           a.uptime, a.cpu_count, a.memory_total, a.disk_space,
                           a.network_interfaces, a.capabilities, a.status, a.last_seen, a.last_action_time,
                           a.haproxy_status, a.haproxy_version, a.config_version, a.applied_config_version,
                           COALESCE(a.enabled, TRUE) as enabled,
                           a.created_at, a.updated_at,
                           p.name as pool_name, p.environment as pool_environment
                    FROM agents a
                    LEFT JOIN haproxy_cluster_pools p ON a.pool_id = p.id
                    WHERE a.name NOT LIKE 'token_%'
                    ORDER BY a.name
                """)
        except Exception as schema_error:
            logger.warning(f"Schema error in agents query, using fallback: {schema_error}")
            agents = await conn.fetch("""
                SELECT a.id, a.name, a.status, a.last_seen, 
                       COALESCE(a.enabled, TRUE) as enabled,
                       a.created_at, a.updated_at
                FROM agents a
                WHERE a.name NOT LIKE 'token_%'
                ORDER BY a.name
            """)
        
        await close_database_connection(conn)
        
        # Check if user has permission to view version info
        user_can_view_versions = False
        if authorization:
            try:
                current_user = await get_current_user_from_token(authorization)
                user_can_view_versions = await check_user_permission(current_user["id"], "agents", "version")
            except:
                pass  # User not authenticated or no permission, continue without version info
        
        # Build agents list with platform-aware versions
        agents_list = []
        for agent in agents:
            agent_dict = {
                "id": agent["id"],
                "name": agent["name"],
                "pool_id": agent.get("pool_id"),
                "pool_name": agent.get("pool_name"),
                "platform": agent.get("platform", "unknown"),
                "architecture": agent.get("architecture", "unknown"),
                "version": agent.get("version", "unknown"),
                "hostname": agent.get("hostname"),
                "ip_address": str(agent["ip_address"]) if agent.get("ip_address") else None,
                "operating_system": agent.get("operating_system"),
                "kernel_version": agent.get("kernel_version"),
                "uptime": agent.get("uptime"),
                "cpu_count": agent.get("cpu_count"),
                "memory_total": agent.get("memory_total"),
                "disk_space": agent.get("disk_space"),
                "network_interfaces": agent.get("network_interfaces", []),
                "capabilities": agent.get("capabilities", []),
                "status": agent.get("status", "unknown"),
                "haproxy_status": agent.get("haproxy_status", "unknown"),
                "haproxy_version": agent.get("haproxy_version", "unknown"),
                "config_version": agent.get("config_version"),
                "applied_config_version": agent.get("applied_config_version"),
                "pool_environment": agent.get("pool_environment"),
                "enabled": agent.get("enabled", True),
                "last_seen": agent["last_seen"].isoformat().replace('+00:00', 'Z') if agent.get("last_seen") else None,
                "last_action_time": agent["last_action_time"].isoformat().replace('+00:00', 'Z') if agent.get("last_action_time") else None,
                "health": calculate_agent_health(agent.get("status"), agent.get("last_seen")),
                "created_at": agent["created_at"].isoformat().replace('+00:00', 'Z') if agent.get("created_at") else None,
                "updated_at": agent["updated_at"].isoformat().replace('+00:00', 'Z') if agent.get("updated_at") else None,
            }
            
            # Add version info only if user has permission
            if user_can_view_versions:
                # Get platform-specific latest version
                latest_version = await get_version_for_platform(agent.get('platform', 'unknown'))
                
                # Upgrade available if versions differ (regardless of direction)
                current_ver = agent.get("version", "unknown")
                upgrade_available = (current_ver != latest_version and 
                                   current_ver != "unknown" and 
                                   latest_version != "unknown")
                
                agent_dict.update({
                    "current_version": current_ver,  # Agent's current script version
                    "available_version": latest_version,  # Platform-specific latest version
                    "upgrade_available": upgrade_available,
                })
            
            agents_list.append(agent_dict)
        
        return {
            "agents": agents_list
        }
    except Exception as e:
        logger.error(f"Error fetching agents: {e}")
        return {"agents": []}

@router.get("/platforms")
async def get_agent_platforms():
    """Get available agent platforms and architectures"""
    return {
        "platforms": {
            "linux": {
                "name": "Linux",
                "architectures": {
                    "amd64": {"display": "x86-64 (amd64)"},
                    "arm64": {"display": "ARM64 (aarch64)"}
                }
            },
            "darwin": {
                "name": "macOS",
                "architectures": {
                    "amd64": {"display": "Intel (amd64)"},
                    "arm64": {"display": "Apple Silicon (arm64)"}
                }
            }
        }
    }

@router.post("/generate-install-script", summary="Generate Agent Install Script", response_description="Installation script")
async def generate_install_script(req_data: AgentScriptRequest, request: Request, authorization: str = Header(None), x_api_key: Optional[str] = Header(None)):
    """
    # Generate Agent Installation Script
    
    Generate platform-specific installation script for deploying agent on HAProxy servers.
    This is the primary way to create and install agents.
    
    ## Request Body
    - **pool_id**: Agent pool ID (required) - Links agent to cluster
    - **platform**: Platform type: "macos" or "linux" (required)
    - **agent_name** (optional): Custom agent name (auto-generated if not provided)
    
    ## Example Request
    ```bash
    curl -X POST "{BASE_URL}/api/agents/generate-install-script" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..." \\
      -H "Content-Type: application/json" \\
      -d '{
        "pool_id": 1,
        "platform": "linux",
        "agent_name": "production-agent-01"
      }'
    ```
    
    ## Example Response
    ```json
    {
      "script": "#!/bin/bash\\n\\n# HAProxy Agent Installation Script\\n# Generated: 2024-01-15...\\n\\nAGENT_NAME=\\"production-agent-01\\"\\nAPI_KEY=\\"agt_abc123xyz789...\\n",
      "agent_name": "production-agent-01",
      "api_key": "agt_abc123xyz789...",
      "platform": "linux"
    }
    ```
    
    ## Installation Steps
    1. Save the returned script to a file (e.g., `install-agent.sh`)
    2. Make it executable: `chmod +x install-agent.sh`
    3. Run on target HAProxy server: `sudo ./install-agent.sh`
    4. Agent will start and appear online in UI
    
    ## Agent Features
    - Polls backend every 10-30 seconds for tasks
    - Applies configuration changes to local haproxy.cfg
    - Reloads HAProxy service automatically
    - Reports metrics and status
    - Self-updates when new versions available
    """
    try:
        # Support both user authentication and agent API key
        current_user = None
        if authorization:
            from auth_middleware import get_current_user_from_token, check_user_permission
            current_user = await get_current_user_from_token(authorization)
            
            # SECURITY: Check permission for agent script generation
            has_permission = await check_user_permission(current_user["id"], "agents", "create")
            if not has_permission:
                raise HTTPException(
                    status_code=403,
                    detail="Insufficient permissions: agents.create required"
                )
        elif x_api_key:
            # Agent API key authentication for upgrade process
            agent_auth = await validate_agent_api_key(x_api_key)
            if not agent_auth:
                raise HTTPException(status_code=401, detail="Invalid agent API key")
        else:
            raise HTTPException(status_code=401, detail="Authorization header or X-API-Key required")
        
        # Debug logging for agent upgrade requests
        logger.info(f"SCRIPT GENERATION: Request from agent - platform: {req_data.platform}, cluster_id: {req_data.cluster_id}, pool_id: {req_data.pool_id}")
        logger.info(f"SCRIPT GENERATION: agent_name: {req_data.agent_name}, hostname_prefix: {req_data.hostname_prefix}")
        logger.info(f"SCRIPT GENERATION: haproxy_bin_path: {req_data.haproxy_bin_path}, haproxy_config_path: {req_data.haproxy_config_path}")
        
        # Use the specific cluster_id sent from frontend instead of searching by pool_id
        cluster_id = req_data.cluster_id
        
        # Validate that the cluster exists and belongs to the specified pool
        conn = await get_database_connection()
        
        # CRITICAL: Check if this is an agent upgrade FIRST
        # Skip strict validation for upgrades - agent may have old/fallback config
        is_agent_upgrade = (x_api_key is not None and authorization is None)
        
        # For NEW agent creation, verify pool has at least one cluster
        if not is_agent_upgrade:
            pool_cluster_count = await conn.fetchval(
                "SELECT COUNT(*) FROM haproxy_clusters WHERE pool_id = $1",
                req_data.pool_id
            )
            
            if pool_cluster_count == 0:
                await close_database_connection(conn)
                raise HTTPException(
                    status_code=400,
                    detail=f"Pool {req_data.pool_id} has no clusters assigned. Please create a cluster for this pool or select a different pool."
                )
        
        cluster_result = await conn.fetchrow(
            "SELECT id, pool_id FROM haproxy_clusters WHERE id = $1", 
            req_data.cluster_id
        )
        
        if not cluster_result:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=404, 
                detail=f"Cluster {req_data.cluster_id} not found"
            )
        
        if not is_agent_upgrade:
            # NEW AGENT CREATION: Strict validation
            
            # Cluster must have a pool_id assigned
            if not cluster_result['pool_id']:
                await close_database_connection(conn)
                raise HTTPException(
                    status_code=400, 
                    detail=f"Cluster {req_data.cluster_id} does not have a pool assigned. Please edit the cluster and assign a pool before creating agents."
                )
            
            # Validate pool_id matches
            if cluster_result['pool_id'] != req_data.pool_id:
                await close_database_connection(conn)
                raise HTTPException(
                    status_code=400, 
                    detail=f"Cluster {req_data.cluster_id} belongs to pool {cluster_result['pool_id']}, not pool {req_data.pool_id}. Please select the correct cluster."
                )
        else:
            # AGENT UPGRADE: Allow upgrade even if pool_id mismatch (will be fixed by heartbeat)
            logger.info(f"AGENT UPGRADE: Skipping pool validation for agent upgrade request (cluster_id={req_data.cluster_id})")
            
            # If cluster has pool but agent sent different pool, log warning
            if cluster_result['pool_id'] and cluster_result['pool_id'] != req_data.pool_id:
                logger.warning(f"AGENT UPGRADE: Pool mismatch - cluster pool={cluster_result['pool_id']}, agent sent={req_data.pool_id}. Will be auto-corrected on next heartbeat.")
        
        await close_database_connection(conn)

        # Dynamic platform detection - more flexible approach
        platform = req_data.platform.lower()
        
        # macOS variants (Darwin-based systems)
        macos_variants = ['macos', 'darwin', 'osx', 'mac']
        # Linux variants  
        linux_variants = ['linux', 'ubuntu', 'debian', 'centos', 'rhel', 'fedora', 'alpine', 'amazon']
        
        if any(variant in platform for variant in macos_variants):
            template_filename = "macos_install.sh"
            logger.info(f"PLATFORM: Detected macOS variant: {platform} -> using macos_install.sh")
        elif any(variant in platform for variant in linux_variants):
            template_filename = "linux_install.sh"
            logger.info(f"PLATFORM: Detected Linux variant: {platform} -> using linux_install.sh")
        else:
            # Try to detect based on architecture or other hints
            if req_data.architecture and 'arm' in req_data.architecture.lower():
                # ARM architecture often indicates Apple Silicon (macOS)
                template_filename = "macos_install.sh"
                logger.info(f"PLATFORM: Unknown platform '{platform}' but ARM architecture detected -> using macos_install.sh")
            else:
                # Default to Linux for unknown platforms
                template_filename = "linux_install.sh"
                logger.info(f"PLATFORM: Unknown platform '{platform}' -> defaulting to linux_install.sh")

        # Try to get script template from database first
        conn = await get_database_connection()
        
        # Get platform key for database lookup
        platform_key = get_platform_key(req_data.platform)
        
        # Get latest version for this platform (function is defined later in this file)
        latest_version = await get_version_for_platform(req_data.platform)
        
        # CRITICAL FIX: Prefer database template (UI edits), fallback to file
        logger.info(f"TEMPLATE SEARCH: Looking for platform={platform_key}, version={latest_version}")
        
        template = await conn.fetchrow("""
            SELECT script_content, version, created_at, updated_at
            FROM agent_script_templates 
            WHERE platform = $1 AND version = $2 AND is_active = true
            LIMIT 1
        """, platform_key, latest_version)
        
        # Debug: Show what's actually in the database
        all_templates = await conn.fetch("""
            SELECT platform, version, is_active, created_at, updated_at
            FROM agent_script_templates 
            WHERE platform = $1 
            ORDER BY updated_at DESC, created_at DESC
        """, platform_key)
        logger.info(f"ALL TEMPLATES for {platform_key}: {[(t['version'], t['is_active'], str(t['updated_at'])[:19]) for t in all_templates]}")
        
        if template:
            script_template = template['script_content']
            script_length = len(script_template)
            logger.info(f"SCRIPT SOURCE: Using database template for {platform_key} version {latest_version} "
                       f"(size: {script_length} bytes, updated_at: {template['updated_at']})")
        else:
            # Fallback to file-based template (initial setup or database empty)
            script_template_path = os.path.join(os.path.dirname(__file__), '..', 'utils', 'agent_scripts', template_filename)
            
            if not os.path.exists(script_template_path):
                await close_database_connection(conn)
                raise HTTPException(status_code=500, detail=f"Script template not found: {template_filename}")

            with open(script_template_path, 'r') as f:
                script_template = f.read()
            
            logger.info(f"SCRIPT SOURCE: Using file template for {platform_key} (database empty, initial setup)")
            
            # Sync file template to database for future use
            try:
                await conn.execute("""
                    INSERT INTO agent_script_templates (platform, version, script_content, is_active)
                    VALUES ($1, $2, $3, true)
                    ON CONFLICT (platform, version) DO UPDATE SET
                        script_content = EXCLUDED.script_content,
                        updated_at = CURRENT_TIMESTAMP
                """, platform_key, latest_version, script_template)
                logger.info(f"SCRIPT SYNC: Synced file template to database for {platform_key} version {latest_version}")
            except Exception as sync_error:
                logger.warning(f"Could not sync template to database: {sync_error}")
        
        await close_database_connection(conn)
        
        # Debug each replacement value
        logger.info(f"REPLACEMENTS: cluster_id={cluster_id}, agent_name={req_data.agent_name}")
        logger.info(f"REPLACEMENTS: hostname_prefix={req_data.hostname_prefix}, haproxy_config_path={req_data.haproxy_config_path}")
        logger.info(f"REPLACEMENTS: haproxy_bin_path={req_data.haproxy_bin_path}, stats_socket_path={req_data.stats_socket_path}")
        logger.info(f"REPLACEMENTS: latest_version={latest_version}")
        
        replacements = {
            "{{MANAGEMENT_URL}}": MANAGEMENT_BASE_URL,
            "{{CLUSTER_ID}}": str(cluster_id),
            "{{AGENT_NAME}}": req_data.agent_name,
            "{{HOSTNAME_PREFIX}}": req_data.hostname_prefix,
            "{{HAPROXY_CONFIG_PATH}}": req_data.haproxy_config_path,
            "{{HAPROXY_BIN_PATH}}": req_data.haproxy_bin_path,
            "{{STATS_SOCKET_PATH}}": req_data.stats_socket_path,
            "{{AGENT_VERSION}}": latest_version,
        }

        script_content = script_template
        for key, value in replacements.items():
            script_content = script_content.replace(key, value)
        
        # Log activity (only if user authentication, not for agent API key)
        if current_user:
            await log_user_activity(
                user_id=current_user["id"],
                action='generate_script',
                resource_type='agent',
                resource_id=str(cluster_id),
                details={'platform': req_data.platform, 'agent_name': req_data.agent_name, 'hostname_prefix': req_data.hostname_prefix}
            )
        
        return {
            "script": script_content,
            "platform": req_data.platform,
            "cluster_id": cluster_id,
            "filename": f"install-agent-{req_data.platform}.sh"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate install script: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate install script: {str(e)}")

@router.delete("/{agent_id}", summary="Delete Agent", response_description="Agent deleted successfully")
async def delete_agent(agent_id: int, authorization: str = Header(None)):
    """
    # Delete Agent
    
    Delete an agent from the system. The agent service on the remote server will stop receiving tasks.
    
    ## Path Parameters
    - **agent_id**: Agent ID to delete
    
    ## Important Notes
    - Agent service on remote server should be uninstalled manually
    - Configuration will no longer be sent to this agent
    - Historical logs and activity will be preserved
    
    ## Example Request
    ```bash
    curl -X DELETE "{BASE_URL}/api/agents/1" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Response
    ```json
    {
      "message": "Agent deleted successfully"
    }
    ```
    
    ## Manual Uninstall on Remote Server
    Linux:
    ```bash
    sudo systemctl stop haproxy-agent
    sudo systemctl disable haproxy-agent
    sudo rm /etc/systemd/system/haproxy-agent.service
    sudo rm -rf /opt/haproxy-agent
    ```
    
    macOS:
    ```bash
    sudo launchctl unload /Library/LaunchDaemons/com.haproxy.agent.plist
    sudo rm /Library/LaunchDaemons/com.haproxy.agent.plist
    sudo rm -rf /opt/haproxy-agent
    ```
    
    ## Error Responses
    - **403**: Insufficient permissions
    - **404**: Agent not found
    - **500**: Server error
    """
    try:
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for agent delete
        has_permission = await check_user_permission(current_user["id"], "agents", "delete")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: agents.delete required"
            )
        
        conn = await get_database_connection()
        
        # Get agent info including cluster relationship
        agent = await conn.fetchrow("""
            SELECT a.name, a.pool_id, hc.id as cluster_id
            FROM agents a
            LEFT JOIN haproxy_clusters hc ON a.pool_id = hc.pool_id
            WHERE a.id = $1
        """, agent_id)
        if not agent:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Validate cluster access if agent belongs to a cluster
        if agent['cluster_id']:
            await validate_user_cluster_access(current_user['id'], agent['cluster_id'], conn)
        
        await conn.execute("DELETE FROM agents WHERE id = $1", agent_id)
        
        await close_database_connection(conn)
        
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='delete',
                resource_type='agent',
                resource_id=str(agent_id),
                details={'agent_name': agent['name']}
            )
        
        return {"message": f"Agent '{agent['name']}' deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete agent: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete agent: {str(e)}")

@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: int, heartbeat_data: AgentHeartbeat):
    """Receive agent heartbeat and update status."""
    try:
        conn = await get_database_connection()
        
        await conn.execute("""
            UPDATE agents 
            SET status = 'online', 
                last_seen = CURRENT_TIMESTAMP,
                hostname = COALESCE($2, hostname),
                haproxy_status = COALESCE($3, haproxy_status),
                haproxy_version = COALESCE($4, haproxy_version),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
        """, agent_id, heartbeat_data.hostname, heartbeat_data.haproxy_status, heartbeat_data.haproxy_version)
        
        await close_database_connection(conn)
        
        return {"status": "ok", "message": "Heartbeat received"}
        
    except Exception as e:
        logger.error(f"Heartbeat processing failed for agent ID {agent_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error during heartbeat processing for agent ID {agent_id}")

@router.post("/{agent_name}/config-applied")
async def agent_config_applied_notification(agent_name: str, notification_data: dict, x_api_key: Optional[str] = Header(None)):
    """Receive instant notification when agent applies configuration - for real-time UI sync"""
    try:
        # Validate agent API key for security
        from auth_middleware import validate_agent_api_key
        agent_auth = await validate_agent_api_key(x_api_key)
        
        if x_api_key and not agent_auth:
            logger.warning(f"Invalid API key provided by agent '{agent_name}' for config-applied")
            raise HTTPException(status_code=401, detail="Invalid API key")
        # GLOBAL TOKEN: Token can be used by multiple agents across different pools/clusters
        
        conn = await get_database_connection()
        
        # Update agent's applied config version for real-time sync
        if notification_data.get("status") == "applied" and notification_data.get("version"):
            version = notification_data["version"]
            
            # CRITICAL: Update agent's applied_config_version for Agent Sync calculation
            # Config versions are already APPLIED immediately after apply-changes
            # Agent Sync is tracked separately via applied_config_version vs latest_config_version
            logger.info(f"DEBUG: Updating applied_config_version for agent '{agent_name}' to '{version}'")
            
            try:
                # Use explicit transaction for asyncpg
                async with conn.transaction():
                    # First check if agent exists (moved inside transaction for atomic operation)
                    agent_exists = await conn.fetchrow("SELECT id, name FROM agents WHERE name = $1", agent_name)
                    logger.info(f"DEBUG: Agent exists check: {agent_exists}")
                    
                    if not agent_exists:
                        logger.error(f"DEBUG: Agent '{agent_name}' not found in database")
                        await close_database_connection(conn)
                        return {"status": "error", "message": f"Agent {agent_name} not found"}
                    
                    # SIMPLIFIED: Direct UPDATE without column check (column should exist from migration)
                    result = await conn.execute("""
                        UPDATE agents SET applied_config_version = $1, updated_at = CURRENT_TIMESTAMP 
                        WHERE name = $2
                    """, version, agent_name)
                    
                    logger.info(f"DEBUG: Database UPDATE result: {result}")
                    
                    # Verify the update was successful within the same transaction
                    updated_agent = await conn.fetchrow("SELECT applied_config_version FROM agents WHERE name = $1", agent_name)
                    logger.info(f"DEBUG: Agent '{agent_name}' applied_config_version after update: {updated_agent['applied_config_version'] if updated_agent else 'NOT_FOUND'}")
                
                logger.info(f"DEBUG: Transaction committed successfully for agent '{agent_name}'")
                logger.info(f"INSTANT SYNC: Agent '{agent_name}' applied config version '{version}' - UI sync updated")
                
            except Exception as transaction_error:
                logger.error(f"TRANSACTION ERROR: Failed to update applied_config_version for agent '{agent_name}': {transaction_error}", exc_info=True)
                await close_database_connection(conn)
                return {"status": "error", "message": f"Transaction failed: {str(transaction_error)}"}
            
            # Log activity
            await log_agent_activity(agent_name, "config_applied", {"version": version})
        else:
            logger.warning(f"CONFIG-APPLIED: Invalid notification format - status: {notification_data.get('status')}, version: {notification_data.get('version')}")
        
        await close_database_connection(conn)
        return {"status": "ok", "message": "Config applied notification received"}
        
    except Exception as e:
        logger.error(f"Failed to process config applied notification from agent '{agent_name}': {e}")
        return {"status": "error", "message": str(e)}

@router.post("/{agent_name}/config-validation-failed")
async def agent_config_validation_failed(agent_name: str, notification_data: dict, x_api_key: Optional[str] = Header(None)):
    """Receive notification when agent's HAProxy config validation fails - for UI error display"""
    try:
        # Validate agent API key for security
        from auth_middleware import validate_agent_api_key
        agent_auth = await validate_agent_api_key(x_api_key)
        
        if x_api_key and not agent_auth:
            logger.warning(f"Invalid API key provided by agent '{agent_name}' for validation-failed")
            raise HTTPException(status_code=401, detail="Invalid API key")
        # GLOBAL TOKEN: Token can be used by multiple agents across different pools/clusters
        
        conn = await get_database_connection()
        
        # Get agent and cluster info
        agent_info = await conn.fetchrow("""
            SELECT a.id, a.name, a.pool_id, hc.id as cluster_id
            FROM agents a
            LEFT JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
            WHERE a.name = $1
        """, agent_name)
        
        if not agent_info or not agent_info['cluster_id']:
            await close_database_connection(conn)
            logger.error(f"Agent '{agent_name}' or cluster not found for validation error notification")
            return {"status": "error", "message": "Agent or cluster not found"}
        
        cluster_id = agent_info['cluster_id']
        version = notification_data.get("version", "unknown")
        validation_error = notification_data.get("validation_error", "Unknown validation error")
        
        logger.error(f"VALIDATION FAILED: Agent '{agent_name}' (cluster {cluster_id}) - HAProxy config validation failed")
        logger.error(f"VALIDATION ERROR: {validation_error}")
        
        # Store validation error in config_versions table for UI display
        async with conn.transaction():
            # Update the config_version with validation error
            result = await conn.execute("""
                UPDATE config_versions 
                SET validation_error = $1, 
                    validation_error_reported_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE cluster_id = $2 AND version_name = $3
            """, validation_error, cluster_id, version)
            
            # Also update agent status to indicate validation failure
            await conn.execute("""
                UPDATE agents 
                SET last_validation_error = $1,
                    last_validation_error_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $2
            """, validation_error, agent_info['id'])
            
            logger.info(f"VALIDATION ERROR STORED: Agent '{agent_name}', version '{version}', cluster {cluster_id}")
        
        await close_database_connection(conn)
        
        return {"status": "ok", "message": "Validation error notification received"}
        
    except Exception as e:
        logger.error(f"Failed to process validation error notification from agent '{agent_name}': {e}")
        return {"status": "error", "message": str(e)}

@router.post("/{agent_name}/config-sync")
async def agent_config_sync(agent_name: str, sync_data: dict, x_api_key: Optional[str] = Header(None)):
    """Receive agent's current config content and sync database entities accordingly"""
    try:
        # Validate agent API key for security
        from auth_middleware import validate_agent_api_key
        agent_auth = await validate_agent_api_key(x_api_key)
        
        if x_api_key and not agent_auth:
            logger.warning(f"Invalid API key provided by agent '{agent_name}' for config-sync")
            raise HTTPException(status_code=401, detail="Invalid API key")
        # GLOBAL TOKEN: Token can be used by multiple agents across different pools/clusters
        
        conn = await get_database_connection()
        
        # Get agent and cluster info
        agent_info = await conn.fetchrow("""
            SELECT a.id, a.name, a.pool_id, hc.id as cluster_id
            FROM agents a
            LEFT JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
            WHERE a.name = $1
        """, agent_name)
        
        if not agent_info or not agent_info['cluster_id']:
            await close_database_connection(conn)
            return {"status": "error", "message": "Agent or cluster not found"}
        
        cluster_id = agent_info['cluster_id']
        config_content = sync_data.get('config_content', '')
        
        if not config_content:
            await close_database_connection(conn)
            return {"status": "error", "message": "No config content provided"}
        
        # Parse config content to extract all configuration entities
        active_servers = []
        active_backends = []
        active_frontends = []
        current_backend = None
        current_frontend = None
        
        for line in config_content.split('\n'):
            line = line.strip()
            
            # Parse backend definitions
            if line.startswith('backend '):
                backend_name = line.split(' ', 1)[1]
                current_backend = backend_name
                current_frontend = None
                active_backends.append({
                    'name': backend_name,
                    'is_commented': False
                })
                continue
            elif line.startswith('# DISABLED: backend '):
                backend_name = line[20:].strip()  # Remove "# DISABLED: backend "
                active_backends.append({
                    'name': backend_name,
                    'is_commented': True
                })
                continue
            
            # Parse frontend definitions - Filter out stats and manual frontends
            if line.startswith('frontend '):
                frontend_name = line.split(' ', 1)[1]
                current_frontend = frontend_name
                current_backend = None
                
                # Skip stats frontend and other system frontends
                if not _should_sync_frontend(frontend_name):
                    logger.info(f"🚫 AGENT SYNC: Skipping system/manual frontend '{frontend_name}' from sync")
                    continue
                    
                active_frontends.append({
                    'name': frontend_name,
                    'is_commented': False
                })
                continue
            elif line.startswith('# DISABLED: frontend '):
                frontend_name = line[21:].strip()  # Remove "# DISABLED: frontend "
                
                # Skip stats frontend and other system frontends even if disabled
                if not _should_sync_frontend(frontend_name):
                    continue
                    
                active_frontends.append({
                    'name': frontend_name,
                    'is_commented': True
                })
                continue
            
            # Parse server lines (existing logic)
            if current_backend and line.startswith('server '):
                parts = line.split()
                if len(parts) >= 3:
                    server_name = parts[1]
                    server_address = parts[2]
                    active_servers.append({
                        'backend_name': current_backend,
                        'server_name': server_name,
                        'server_address': server_address,
                        'is_commented': False
                    })
            elif current_backend and line.startswith('# DISABLED: server '):
                # Parse commented out servers
                parts = line[12:].split()  # Remove "# DISABLED: "
                if len(parts) >= 3:
                    server_name = parts[1]
                    server_address = parts[2]
                    active_servers.append({
                        'backend_name': current_backend,
                        'server_name': server_name,
                        'server_address': server_address,
                        'is_commented': True
                    })
        
        # Sync database with agent's actual config
        async with conn.transaction():
            # 1. SYNC BACKENDS
            # Mark all backends in this cluster as potentially inactive
            await conn.execute("""
                UPDATE backends 
                SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                WHERE cluster_id = $1
            """, cluster_id)
            
            # Update backends that exist in agent's config
            for backend_info in active_backends:
                is_active = not backend_info['is_commented']
                
                # Try to update existing backend
                result = await conn.execute("""
                    UPDATE backends 
                    SET is_active = $1, last_config_status = 'APPLIED', updated_at = CURRENT_TIMESTAMP
                    WHERE name = $2 AND cluster_id = $3
                """, is_active, backend_info['name'], cluster_id)
                
                # If backend doesn't exist, create it (this handles restore scenarios)
                if result == "UPDATE 0":
                    await conn.execute("""
                        INSERT INTO backends 
                        (name, balance_method, mode, cluster_id, is_active)
                        VALUES ($1, 'roundrobin', 'http', $2, $3)
                        ON CONFLICT (name, cluster_id) DO UPDATE SET
                        is_active = EXCLUDED.is_active,
                        updated_at = CURRENT_TIMESTAMP
                    """, backend_info['name'], cluster_id, is_active)
            
            # 2. SYNC FRONTENDS
            # Mark all frontends in this cluster as potentially inactive
            await conn.execute("""
                UPDATE frontends 
                SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                WHERE cluster_id = $1
            """, cluster_id)
            
            # Update frontends that exist in agent's config
            for frontend_info in active_frontends:
                is_active = not frontend_info['is_commented']
                
                # CRITICAL FIX: Only update status fields, preserve all other configuration
                # including SSL settings, ports, backends, etc. that are managed via UI
                result = await conn.execute("""
                    UPDATE frontends 
                    SET is_active = $1, last_config_status = 'APPLIED', updated_at = CURRENT_TIMESTAMP
                    WHERE name = $2 AND cluster_id = $3
                """, is_active, frontend_info['name'], cluster_id)
                
                # If frontend doesn't exist, create it (this handles restore scenarios)
                if result == "UPDATE 0":
                    await conn.execute("""
                        INSERT INTO frontends 
                        (name, bind_address, bind_port, mode, cluster_id, is_active)
                        VALUES ($1, '*', 80, 'http', $2, $3)
                        ON CONFLICT (name, cluster_id) DO UPDATE SET
                        is_active = EXCLUDED.is_active,
                        updated_at = CURRENT_TIMESTAMP
                    """, frontend_info['name'], cluster_id, is_active)
            
            # 3. SYNC SERVERS (existing logic)
            # Mark all servers in this cluster as potentially inactive
            await conn.execute("""
                UPDATE backend_servers 
                SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                WHERE cluster_id = $1
            """, cluster_id)
            
            # Update servers that exist in agent's config
            for server_info in active_servers:
                is_active = not server_info['is_commented']
                
                # Try to update existing server
                result = await conn.execute("""
                    UPDATE backend_servers 
                    SET is_active = $1, last_config_status = 'APPLIED', updated_at = CURRENT_TIMESTAMP
                    WHERE backend_name = $2 AND server_name = $3 AND cluster_id = $4
                """, is_active, server_info['backend_name'], server_info['server_name'], cluster_id)
                
                # If server doesn't exist, create it ONLY if it's not commented (deleted)
                # Commented servers that don't exist in DB were intentionally hard deleted
                if result == "UPDATE 0" and not server_info['is_commented']:
                    # Extract IP and port from server_address
                    address_parts = server_info['server_address'].split(':')
                    server_ip = address_parts[0]
                    server_port = int(address_parts[1]) if len(address_parts) > 1 else 80
                    
                    # Insert new server without ON CONFLICT since constraint doesn't exist
                    await conn.execute("""
                        INSERT INTO backend_servers 
                        (backend_name, server_name, server_address, server_port, weight, is_active, cluster_id)
                        VALUES ($1, $2, $3, $4, 100, $5, $6)
                    """, server_info['backend_name'], server_info['server_name'], 
                         server_ip, server_port, is_active, cluster_id)
                elif result == "UPDATE 0" and server_info['is_commented']:
                    logger.info(f"🗑️ AGENT SYNC: Skipping creation of commented (deleted) server {server_info['server_name']} in backend {server_info['backend_name']}")
        
        await close_database_connection(conn)
        
        logger.info(f"CONFIG SYNC: Agent '{agent_name}' synced {len(active_backends)} backends, {len(active_frontends)} frontends, {len(active_servers)} servers with database")
        return {"status": "ok", "message": f"Config synced - {len(active_backends)} backends, {len(active_frontends)} frontends, {len(active_servers)} servers processed"}
        
    except Exception as e:
        logger.error(f"Failed to process config sync from agent '{agent_name}': {e}")
        return {"status": "error", "message": str(e)}

@router.post("/heartbeat")
async def agent_heartbeat_by_name(
    request: Request,
    heartbeat_data: AgentHeartbeat, 
    x_api_key: Optional[str] = Header(None)
):
    """Receive agent heartbeat by agent name, with auto-registration and data validation.
    
    Enhanced with robust error handling and detailed logging for malformed JSON payloads.
    """
    try:
        # Validate agent API key for security
        from auth_middleware import validate_agent_api_key
        agent_auth = await validate_agent_api_key(x_api_key)
        
        conn = await get_database_connection()
        agent_name = heartbeat_data.name

        # If API key provided, validate it exists but allow placeholder agent updates
        if x_api_key and not agent_auth:
            await close_database_connection(conn)
            logger.warning(f"Invalid API key provided by agent '{agent_name}'")
            raise HTTPException(status_code=401, detail="Invalid API key")

        agent = await conn.fetchrow("SELECT id, pool_id FROM agents WHERE name = $1", agent_name)
        
        if not agent and x_api_key and agent_auth:
            # Check if there's a placeholder agent with this API key
            # Check if API key already used by another agent
            existing_agent = await conn.fetchrow("SELECT id, name, pool_id FROM agents WHERE api_key = $1 AND name = $2", x_api_key, agent_name)
            if existing_agent:
                # Agent already exists with this API key
                agent = {'id': existing_agent['id'], 'pool_id': existing_agent['pool_id']}
            else:
                # Check if there's a placeholder agent with this API key
                placeholder_agent = await conn.fetchrow("SELECT id, name, pool_id FROM agents WHERE api_key = $1 AND name LIKE 'token_%'", x_api_key)
                if placeholder_agent:
                    # Create new agent instead of updating placeholder (allows multiple agents per token)
                    logger.info(f"Creating new agent '{agent_name}' using token '{placeholder_agent['name']}'")
                    agent_id = await conn.fetchval("""
                        INSERT INTO agents (
                            name, api_key, api_key_name, api_key_created_at, 
                            api_key_expires_at, api_key_created_by, status, 
                            enabled, created_at, updated_at, pool_id
                        ) 
                        SELECT $1, api_key, api_key_name, api_key_created_at,
                               api_key_expires_at, api_key_created_by, 'online',
                               TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, pool_id
                        FROM agents WHERE id = $2
                        RETURNING id
                    """, agent_name, placeholder_agent['id'])
                    agent = {'id': agent_id, 'pool_id': placeholder_agent['pool_id']}
                else:
                    # Auto-register new agent
                    logger.info(f"Agent '{agent_name}' not found. Auto-registering...")
                    try:
                        agent_id = await conn.fetchval("""
                            INSERT INTO agents (name, status, last_seen, api_key) 
                            VALUES ($1, 'online', CURRENT_TIMESTAMP, $2) RETURNING id
                        """, agent_name, x_api_key)
                        logger.info(f"Auto-registered new agent '{agent_name}' with ID {agent_id}")
                        agent = {'id': agent_id, 'pool_id': None} 
                    except Exception as e:
                        await close_database_connection(conn)
                        logger.error(f"Failed to auto-register agent '{agent_name}': {e}", exc_info=True)
                        raise HTTPException(status_code=500, detail=f"Could not create agent: {agent_name}")
        elif not agent:
            # Auto-register new agent without API key
            logger.info(f"Agent '{agent_name}' not found. Auto-registering...")
            try:
                agent_id = await conn.fetchval("""
                    INSERT INTO agents (name, status, last_seen) 
                    VALUES ($1, 'online', CURRENT_TIMESTAMP) RETURNING id
                """, agent_name)
                logger.info(f"Auto-registered new agent '{agent_name}' with ID {agent_id}")
                agent = {'id': agent_id, 'pool_id': None} 
            except Exception as e:
                await close_database_connection(conn)
                logger.error(f"Failed to auto-register agent '{agent_name}': {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Could not create agent: {agent_name}")
        
        agent_id = agent['id']
        
        # Update API key last used timestamp for all agents using this token
        if x_api_key:
            await conn.execute("""
                UPDATE agents 
                SET api_key_last_used = CURRENT_TIMESTAMP
                WHERE api_key = $1
            """, x_api_key)

        # Check if agent was in upgrading status and version has changed
        current_agent_status = await conn.fetchval("SELECT status FROM agents WHERE id = $1", agent_id)
        current_agent_version = await conn.fetchval("SELECT version FROM agents WHERE id = $1", agent_id)
        current_upgrade_status = await conn.fetchval("SELECT upgrade_status FROM agents WHERE id = $1", agent_id)
        
        # Determine new status - preserve upgrading status unless version actually changed
        new_status = current_agent_status or 'online'
        if current_agent_status == 'upgrading':
            # CRITICAL FIX: If upgrade_status is NULL but status is 'upgrading', this is an error state
            # This happens after cleanup job or manual intervention - agent should be online
            if not current_upgrade_status:
                new_status = 'online'
                logger.info(f"AGENT STATUS FIX: Agent '{heartbeat_data.name}' status was 'upgrading' but upgrade_status is NULL - marking as 'online'")
            # Only mark as online if version actually changed (upgrade completed)
            elif heartbeat_data.version and heartbeat_data.version != current_agent_version:
                new_status = 'online'
                logger.info(f"AGENT UPGRADE: Agent '{heartbeat_data.name}' completed upgrade to version '{heartbeat_data.version}' (was: {current_agent_version})")
                logger.info(f"AGENT UPGRADE: Status changed from 'upgrading' to 'online' - upgrade cycle complete")
            else:
                # Keep upgrading status if version hasn't changed yet
                new_status = 'upgrading'
                logger.debug(f"AGENT UPGRADE: Agent '{heartbeat_data.name}' still upgrading (version unchanged: {heartbeat_data.version})")
        else:
            new_status = 'online'
        
        # Auto-detect platform if not provided or empty
        detected_platform = heartbeat_data.platform
        if not detected_platform or detected_platform.strip() == "":
            # Try to detect from hostname or operating system
            if heartbeat_data.hostname and 'mac' in heartbeat_data.hostname.lower():
                detected_platform = 'darwin'
                logger.info(f"PLATFORM AUTO-DETECT: Agent '{agent_name}' platform detected as 'darwin' from hostname")
            elif heartbeat_data.operating_system and any(os_hint in heartbeat_data.operating_system.lower() for os_hint in ['macos', 'darwin', 'mac']):
                detected_platform = 'darwin'
                logger.info(f"PLATFORM AUTO-DETECT: Agent '{agent_name}' platform detected as 'darwin' from OS")
            elif heartbeat_data.operating_system and any(os_hint in heartbeat_data.operating_system.lower() for os_hint in ['linux', 'ubuntu', 'centos', 'rhel', 'debian']):
                detected_platform = 'linux'
                logger.info(f"PLATFORM AUTO-DETECT: Agent '{agent_name}' platform detected as 'linux' from OS")
            else:
                # Default to linux for unknown platforms
                detected_platform = 'linux'
                logger.info(f"PLATFORM AUTO-DETECT: Agent '{agent_name}' platform defaulted to 'linux' (unknown)")

        # CRITICAL FIX: Only update applied_config_version if agent sends a VALID value
        # Agent sends "none" on startup before any config is applied - don't override DB value with this
        update_applied_version = heartbeat_data.applied_config_version and heartbeat_data.applied_config_version not in ["none", ""]
        
        await conn.execute("""
            UPDATE agents 
            SET status = $18, 
                last_seen = CURRENT_TIMESTAMP,
                hostname = COALESCE($2, hostname),
                platform = $3,
                architecture = COALESCE($4, architecture),
                version = COALESCE($5, version),
                operating_system = COALESCE($6, operating_system),
                kernel_version = COALESCE($7, kernel_version),
                uptime = COALESCE($8, uptime),
                cpu_count = COALESCE($9, cpu_count),
                memory_total = COALESCE($10, memory_total),
                disk_space = COALESCE($11, disk_space),
                network_interfaces = COALESCE($12, network_interfaces),
                capabilities = COALESCE($13, capabilities),
                ip_address = COALESCE($14, ip_address),
                haproxy_status = COALESCE($15, haproxy_status),
                haproxy_version = COALESCE($16, haproxy_version),
                applied_config_version = CASE WHEN $19 THEN $17 ELSE applied_config_version END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
        """, agent_id, heartbeat_data.hostname, detected_platform, 
            heartbeat_data.architecture, heartbeat_data.version,
            heartbeat_data.operating_system, heartbeat_data.kernel_version,
            heartbeat_data.uptime, heartbeat_data.cpu_count, heartbeat_data.memory_total,
            heartbeat_data.disk_space, 
            # Convert lists to JSON for JSONB columns
            heartbeat_data.network_interfaces if isinstance(heartbeat_data.network_interfaces, str) else json.dumps(heartbeat_data.network_interfaces or []),
            heartbeat_data.capabilities if isinstance(heartbeat_data.capabilities, str) else json.dumps(heartbeat_data.capabilities or []),
            heartbeat_data.ip_address, heartbeat_data.haproxy_status, heartbeat_data.haproxy_version,
            heartbeat_data.applied_config_version, new_status, update_applied_version)

        # API key validation is already done at the beginning - no need for final check
        # Multi-agent token system allows multiple agents to use the same token

        if heartbeat_data.server_statuses:
            logger.info(f"AGENT HEARTBEAT: Agent '{agent_name}' reported server statuses: {heartbeat_data.server_statuses}")
            
            # CRITICAL FIX: Find cluster_id even if agent pool_id is NULL
            # This handles the case where cluster was created before pool, then pool was assigned later
            cluster_id = None
            
            # Method 1: Try to find cluster via agent's pool_id (if set)
            if agent['pool_id']:
                cluster_result = await conn.fetchrow(
                    "SELECT id FROM haproxy_clusters WHERE pool_id = $1 LIMIT 1", 
                    agent['pool_id']
                )
                if cluster_result:
                    cluster_id = cluster_result['id']
                    logger.debug(f"CLUSTER LOOKUP: Found cluster {cluster_id} via agent pool_id {agent['pool_id']}")
            
            # Method 2: If cluster_id not found and agent sends cluster_id in heartbeat, use that
            # This provides fallback when agent pool_id is NULL (e.g. cluster created before pool)
            if not cluster_id and heartbeat_data.cluster_id:
                # Verify this cluster actually exists and get its pool
                cluster_pool = await conn.fetchval(
                    "SELECT pool_id FROM haproxy_clusters WHERE id = $1", 
                    heartbeat_data.cluster_id
                )
                
                if cluster_pool:
                    # Cluster exists, use it for stats processing
                    cluster_id = heartbeat_data.cluster_id
                    logger.info(f"CLUSTER LOOKUP: Using cluster_id {cluster_id} from agent heartbeat data")
                    
                    # IMPORTANT: Update agent's pool_id if missing (fixes the cluster-created-before-pool scenario)
                    if not agent['pool_id']:
                        await conn.execute(
                            "UPDATE agents SET pool_id = $1 WHERE id = $2", 
                            cluster_pool, agent_id
                        )
                        logger.info(f"AGENT FIX: Auto-assigned agent '{agent_name}' to pool {cluster_pool} via heartbeat cluster_id {cluster_id}")
                else:
                    logger.warning(f"CLUSTER LOOKUP: Cluster {heartbeat_data.cluster_id} not found or has no pool assigned")
            
            if cluster_id:
                # Process stats for dashboard cache
                try:
                    from services.dashboard_stats_service import dashboard_stats_service
                    import base64
                    
                    # Log what agent sent
                    logger.info(f"HEARTBEAT: Agent '{agent_name}' heartbeat received")
                    logger.info(f"HEARTBEAT: Has haproxy_stats_csv: {heartbeat_data.haproxy_stats_csv is not None}")
                    logger.info(f"HEARTBEAT: Has server_statuses: {heartbeat_data.server_statuses is not None}")
                    
                    # Decode CSV stats if provided (supports both base64 and plain text)
                    raw_csv = None
                    if heartbeat_data.haproxy_stats_csv:
                        try:
                            # Try base64 decode first (for new agents)
                            raw_csv = base64.b64decode(heartbeat_data.haproxy_stats_csv).decode('utf-8')
                            logger.info(f"HEARTBEAT: Decoded base64 CSV stats from agent '{agent_name}' ({len(raw_csv)} bytes)")
                        except Exception as decode_error:
                            # If base64 decode fails, treat as plain text (for old agents)
                            logger.info(f"HEARTBEAT: Base64 decode failed, treating as plain text CSV from agent '{agent_name}'")
                            raw_csv = heartbeat_data.haproxy_stats_csv
                        
                        if raw_csv:
                            logger.debug(f"HEARTBEAT: CSV preview: {raw_csv[:200]}...")
                    else:
                        logger.warning(f" HEARTBEAT: Agent '{agent_name}' sent NO haproxy_stats_csv!")
                    
                    await dashboard_stats_service.process_agent_stats(
                        agent_name=agent_name,
                        cluster_id=cluster_id,
                        raw_stats_csv=raw_csv,
                        server_statuses=heartbeat_data.server_statuses
                    )
                    logger.debug(f"STATS CACHE: Processed stats for agent '{agent_name}' cluster {cluster_id}")
                except Exception as stats_error:
                    logger.error(f"Failed to process stats for dashboard: {stats_error}")
                
                # Update database server statuses
                for backend_name, servers in heartbeat_data.server_statuses.items():
                    for server_name, status in servers.items():
                        try:
                            # Try to update by exact server_name first
                            result = await conn.execute("""
                                UPDATE backend_servers 
                                SET haproxy_status = $1, haproxy_status_updated_at = CURRENT_TIMESTAMP
                                WHERE backend_name = $2 AND server_name = $3 AND cluster_id = $4
                            """, status, backend_name, server_name, cluster_id)
                            
                            logger.info(f"SERVER STATUS UPDATE: {backend_name}/{server_name} = {status}, cluster_id={cluster_id}, rows_updated={result}")
                            
                            # If no exact match, try to update any server in the backend (agent parsing might be wrong)
                            if result == "UPDATE 0":
                                result2 = await conn.execute("""
                                    UPDATE backend_servers 
                                    SET haproxy_status = $1, haproxy_status_updated_at = CURRENT_TIMESTAMP
                                    WHERE backend_name = $2 AND cluster_id = $3
                                    AND id = (SELECT MIN(id) FROM backend_servers WHERE backend_name = $2 AND cluster_id = $3 LIMIT 1)
                                """, status, backend_name, cluster_id)
                                logger.info(f"SERVER STATUS FALLBACK: {backend_name}/ANY_SERVER = {status}, cluster_id={cluster_id}, rows_updated={result2}")
                            else:
                                logger.debug(f"Updated server status: {backend_name}/{server_name} = {status}")
                        except Exception as e:
                            logger.warning(f"Failed to update server status for {backend_name}/{server_name}: {e}")
            else:
                logger.warning(f"Could not determine cluster_id for agent '{agent_name}' to update server statuses")
                # NOTE: Pool assignment is now handled above in the cluster_id lookup logic

        await close_database_connection(conn)
        
        return {"status": "ok", "message": "Heartbeat received", "agent_id": agent_id}
        
    except Exception as e:
        logger.error(f"Heartbeat processing failed for agent '{heartbeat_data.name}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error during heartbeat processing for agent '{heartbeat_data.name}'")

@router.get("/{agent_name}/config")
async def get_agent_config(agent_name: str, x_api_key: Optional[str] = Header(None)):
    """Get HAProxy configuration for specific agent"""
    try:
        conn = await get_database_connection()
        
        # Get agent info first to check pool
        agent_info = await conn.fetchrow("""
            SELECT a.id, a.name, a.pool_id, hc.id as cluster_id, hc.name as cluster_name,
                   COALESCE(a.enabled, TRUE) as enabled
            FROM agents a
            LEFT JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
            WHERE a.name = $1
        """, agent_name)
        
        if not agent_info:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")
        
        # Validate agent API key
        # API key is global - can be used for multiple agents
        if x_api_key:
            from auth_middleware import validate_agent_api_key
            agent_auth = await validate_agent_api_key(x_api_key)
            
            if not agent_auth:
                await close_database_connection(conn)
                logger.warning(f"Invalid API key provided for agent '{agent_name}' config fetch")
                raise HTTPException(status_code=401, detail="Invalid API key")
            
            # Log which agent's API key was used (for audit trail)
            if agent_auth['name'] == agent_name:
                logger.info(f"Agent '{agent_name}' fetching config using its own API key")
            else:
                logger.info(f"Agent '{agent_name}' fetching config using API key from agent '{agent_auth['name']}'")
            
            logger.debug(f"Config fetch authorized for agent '{agent_name}'")
        
        if not agent_info['enabled']:
            await close_database_connection(conn)
            return {
                "agent_name": agent_name,
                "cluster_id": agent_info['cluster_id'],
                "cluster_name": agent_info['cluster_name'],
                "config_content": "# Agent is disabled - no configuration available\n",
                "version": "disabled",
                "status": "disabled"
            }
        
        cluster_id = agent_info['cluster_id']
        if not cluster_id:
            await close_database_connection(conn)
            return {
                "agent_name": agent_name,
                "cluster_id": None,
                "cluster_name": None,
                "config_content": "# No cluster assigned to this agent\n",
                "version": "no-cluster",
                "status": "no_cluster"
            }
        
        config_version = await conn.fetchrow("""
            SELECT version_name, config_content, checksum, is_active
            FROM config_versions 
            WHERE cluster_id = $1 AND status = 'APPLIED' AND is_active = TRUE
            ORDER BY created_at DESC
            LIMIT 1
        """, cluster_id)
        
        if not config_version:
            config_version = await conn.fetchrow("""
                SELECT version_name, config_content, checksum, is_active
                FROM config_versions 
                WHERE cluster_id = $1 AND is_active = TRUE
                ORDER BY created_at DESC
                LIMIT 1
            """, cluster_id)
        
        if not config_version:
            await close_database_connection(conn)
            return {
                "agent_name": agent_name,
                "cluster_id": cluster_id,
                "cluster_name": agent_info['cluster_name'],
                "config_content": "# No configuration available for this cluster\n",
                "version": "no-config",
                "status": "no_config"
            }
        
        await conn.execute("""
            UPDATE agents 
            SET config_version = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $2
        """, config_version['version_name'], agent_info['id'])
        
        await close_database_connection(conn)
        
        return {
            "agent_name": agent_name,
            "cluster_id": cluster_id,
            "cluster_name": agent_info['cluster_name'],
            "config_content": config_version['config_content'],
            "version": config_version['version_name'],
            "checksum": config_version['checksum'],
            "status": "available"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Config retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{agent_name}/ssl-certificates")
async def get_agent_ssl_certificates(agent_name: str, since: Optional[str] = None, x_api_key: Optional[str] = Header(None)):
    """Get SSL certificates for specific agent's cluster"""
    try:
        conn = await get_database_connection()
        
        # Get agent and cluster info first
        agent_info = await conn.fetchrow("""
            SELECT a.id, a.name, a.pool_id, hc.id as cluster_id, hc.name as cluster_name,
                   COALESCE(a.enabled, TRUE) as enabled
            FROM agents a
            LEFT JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
            WHERE a.name = $1
        """, agent_name)
        
        if not agent_info:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")
        
        # Validate agent API key
        # API key is global - can be used for multiple agents
        if x_api_key:
            from auth_middleware import validate_agent_api_key
            agent_auth = await validate_agent_api_key(x_api_key)
            
            if not agent_auth:
                await close_database_connection(conn)
                logger.warning(f"Invalid API key provided for agent '{agent_name}' SSL certificates")
                raise HTTPException(status_code=401, detail="Invalid API key")
            
            # Log which agent's API key was used (for audit trail)
            if agent_auth['name'] == agent_name:
                logger.info(f"Agent '{agent_name}' fetching SSL certificates using its own API key")
            else:
                logger.info(f"Agent '{agent_name}' fetching SSL certificates using API key from agent '{agent_auth['name']}'")
            
            logger.debug(f"SSL fetch authorized for agent '{agent_name}'")
        
        if not agent_info['enabled']:
            await close_database_connection(conn)
            return {
                "agent_name": agent_name,
                "cluster_id": agent_info['cluster_id'],
                "ssl_certificates": [],
                "status": "disabled"
            }
        
        cluster_id = agent_info['cluster_id']
        if not cluster_id:
            await close_database_connection(conn)
            return {
                "agent_name": agent_name,
                "cluster_id": None,
                "ssl_certificates": [],
                "status": "no_cluster"
            }
        
        # Build SSL certificates query with optional timestamp filtering
        ssl_query = """
            SELECT DISTINCT s.id, s.name, s.primary_domain as domain, s.certificate_content, 
                   s.private_key_content, s.chain_content, s.expiry_date, s.status, s.fingerprint, 
                   s.usage_type, s.created_at, s.updated_at, s.last_config_status
            FROM ssl_certificates s
            LEFT JOIN ssl_certificate_clusters scc ON s.id = scc.ssl_certificate_id
            WHERE s.is_active = TRUE 
            AND (
                -- Global SSLs: No cluster associations (not in junction table)
                NOT EXISTS (SELECT 1 FROM ssl_certificate_clusters WHERE ssl_certificate_id = s.id)
                -- Cluster-specific SSLs: Only for this specific cluster
                OR scc.cluster_id = $1
            )
            -- Only return SSL certificates that have been APPLIED (not PENDING)
            AND (s.last_config_status = 'APPLIED' OR s.last_config_status IS NULL)
        """
        
        params = [cluster_id]
        
        # Add timestamp filter if provided (for incremental updates)
        if since:
            try:
                from datetime import datetime
                import pytz
                
                # Parse the ISO timestamp and convert to UTC naive datetime for database comparison
                since_datetime = datetime.fromisoformat(since.replace('Z', '+00:00'))
                since_naive = since_datetime.astimezone(pytz.UTC).replace(tzinfo=None)
                
                ssl_query += " AND (s.updated_at > $2 OR s.created_at > $2)"
                params.append(since_naive)
                logger.info(f"SSL INCREMENTAL: Filtering SSL certificates since {since_naive} UTC")
            except (ValueError, ImportError) as e:
                logger.warning(f"SSL INCREMENTAL: Invalid timestamp format '{since}' or timezone error: {e}, ignoring filter")
        
        ssl_query += " ORDER BY s.created_at DESC"
        
        # Get SSL certificates for this cluster (both global and cluster-specific)
        # Only return SSL certificates that have been APPLIED (not PENDING)
        logger.info(f"SSL QUERY DEBUG: cluster_id={cluster_id}, params={params}")
        logger.info(f"SSL QUERY: {ssl_query}")
        ssl_certificates = await conn.fetch(ssl_query, *params)
        logger.info(f"SSL RESULTS: Found {len(ssl_certificates)} certificates")
        
        await close_database_connection(conn)
        
        # Format SSL certificates for agent deployment
        ssl_certs_data = []
        latest_timestamp = None
        
        for cert in ssl_certificates:
            # Track the latest timestamp for incremental updates
            cert_timestamp = max(cert['created_at'], cert['updated_at']) if cert['updated_at'] else cert['created_at']
            if not latest_timestamp or cert_timestamp > latest_timestamp:
                latest_timestamp = cert_timestamp
                
            cert_data = {
                "id": cert['id'],
                "name": cert['name'],
                "domain": cert['domain'],
                "certificate_content": cert['certificate_content'],
                "private_key_content": cert['private_key_content'],
                "chain_content": cert['chain_content'],
                "usage_type": cert.get('usage_type', 'frontend'),  # Default to frontend for backward compatibility
                "file_path": f"/etc/ssl/haproxy/{cert['name']}.pem",
                "expiry_date": cert['expiry_date'].isoformat() if cert['expiry_date'] else None,
                "status": cert['status'],
                "fingerprint": cert['fingerprint'],
                "created_at": cert['created_at'].isoformat() if cert['created_at'] else None,
                "updated_at": cert['updated_at'].isoformat() if cert['updated_at'] else None
            }
            ssl_certs_data.append(cert_data)
        
        response_data = {
            "agent_name": agent_name,
            "cluster_id": cluster_id,
            "cluster_name": agent_info['cluster_name'],
            "ssl_certificates": ssl_certs_data,
            "status": "available",
            "total_certificates": len(ssl_certs_data),
            "latest_update": latest_timestamp.isoformat() if latest_timestamp else None,
            "incremental_since": since
        }
        
        if since and ssl_certs_data:
            logger.info(f"SSL INCREMENTAL: Returned {len(ssl_certs_data)} updated certificates since {since}")
        elif since:
            logger.info(f"SSL INCREMENTAL: No certificates updated since {since}")
            
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SSL certificates retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/script-version")
async def get_latest_script_version(platform: str = "macos"):
    """Get the latest available agent script version for specified platform"""
    try:
        conn = await get_database_connection()
        
        # Get latest version for platform
        version_info = await conn.fetchrow("""
            SELECT version, release_date, changelog
            FROM agent_versions 
            WHERE platform = $1 AND is_active = true
            ORDER BY created_at DESC
            LIMIT 1
        """, platform.lower())
        
        await close_database_connection(conn)
        
        if version_info:
            return {
                "latest_version": version_info['version'],
                "release_date": version_info['release_date'].isoformat() if version_info['release_date'] else None,
                "changelog": version_info['changelog'] or []
            }
        else:
            # Fallback to default if no database entry
            # Use global version storage
            latest_version = AGENT_VERSIONS.get(platform.lower(), 'unknown')
            return {
                "latest_version": latest_version,
                "release_date": "2024-01-23",
                "changelog": ["Version from global storage"]
            }
            
    except Exception as e:
        logger.error(f"Error getting script version: {e}")
        # Fallback to hardcoded version
        # Use global version storage as fallback
        latest_version = AGENT_VERSIONS.get(platform.lower(), 'unknown')
        return {
            "latest_version": latest_version,
            "release_date": "2024-01-23", 
            "changelog": ["Fallback version from global storage"]
        }

@router.get("/{agent_name}/upgrade-status")
async def get_agent_upgrade_status(agent_name: str, x_api_key: Optional[str] = Header(None)):
    """Get agent upgrade status - used by agents to check if they should upgrade"""
    try:
        conn = await get_database_connection()
        
        # Check if agent has upgrade pending (include platform and pool for validation)
        agent = await conn.fetchrow("""
            SELECT status, version as current_version, platform, pool_id
            FROM agents 
            WHERE name = $1
        """, agent_name)
        
        if not agent:
            await close_database_connection(conn)
            return {
                "should_upgrade": False,
                "target_version": "",
                "message": "Agent not found"
            }
        
        # Validate agent API key
        # API key is global - can be used for multiple agents
        if x_api_key:
            from auth_middleware import validate_agent_api_key
            agent_auth = await validate_agent_api_key(x_api_key)
            
            if not agent_auth:
                await close_database_connection(conn)
                logger.warning(f"Invalid API key provided for agent '{agent_name}' upgrade status")
                raise HTTPException(status_code=401, detail="Invalid API key")
            
            # Log which agent's API key was used (for audit trail)
            if agent_auth['name'] == agent_name:
                logger.debug(f"Agent '{agent_name}' checking upgrade status using its own API key")
            else:
                logger.info(f"Agent '{agent_name}' checking upgrade status using API key from agent '{agent_auth['name']}'")
            
            logger.debug(f"Upgrade status check authorized for agent '{agent_name}'")
        
        await close_database_connection(conn)
        
        # Agent should upgrade if status is 'upgrading'
        should_upgrade = agent['status'] == 'upgrading'
        
        # Debug logging for upgrade status
        logger.info(f"UPGRADE STATUS: agent='{agent_name}', status='{agent['status']}', current_version='{agent['current_version']}', should_upgrade={should_upgrade}")
        
        # Get target version from global storage based on agent platform
        try:
            if should_upgrade:
                agent_platform = agent.get('platform', 'unknown')
                target_version = await get_version_for_platform(agent_platform)
                platform_key = get_platform_key(agent_platform)
                logger.info(f"UPGRADE TARGET: agent='{agent_name}', platform='{platform_key}', target_version='{target_version}', current_version='{agent['current_version']}'")
            else:
                target_version = ""
                logger.info(f"NO UPGRADE: agent='{agent_name}' status is '{agent['status']}' (not 'upgrading')")
        except Exception as version_error:
            logger.warning(f"Could not get target version for agent {agent_name}: {version_error}")
            target_version = "unknown" if should_upgrade else ""
        
        return {
            "should_upgrade": should_upgrade,
            "target_version": target_version,
            "current_version": agent['current_version'],
            "message": "Upgrade required" if should_upgrade else "No upgrade needed"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking upgrade status for agent {agent_name}: {e}")
        raise HTTPException(status_code=500, detail="Failed to check upgrade status")

@router.post("/{agent_name}/upgrade-complete")
async def agent_upgrade_complete(agent_name: str, completion_data: dict, x_api_key: Optional[str] = Header(None)):
    """Receive notification when agent completes or fails upgrade"""
    try:
        # Validate agent API key for security
        from auth_middleware import validate_agent_api_key
        agent_auth = await validate_agent_api_key(x_api_key)
        
        if x_api_key and not agent_auth:
            logger.warning(f"Invalid API key provided by agent '{agent_name}' for upgrade complete")
            raise HTTPException(status_code=401, detail="Invalid API key")
        # GLOBAL TOKEN: Token can be used by multiple agents across different pools/clusters
        
        conn = await get_database_connection()
        
        upgrade_status = completion_data.get("status", "unknown")
        new_version = completion_data.get("version", "")
        
        if upgrade_status == "completed":
            # Update agent version and reset status to online
            await conn.execute("""
                UPDATE agents 
                SET version = $1, status = 'online', updated_at = CURRENT_TIMESTAMP
                WHERE name = $2
            """, new_version, agent_name)
            
            logger.info(f"AGENT UPGRADE: Agent '{agent_name}' completed upgrade to version '{new_version}'")
            
            # Log activity (always "upgrade")
            await log_agent_activity(agent_name, 'upgrade', {"version": new_version, "status": "completed"})
        elif upgrade_status == "failed":
            # Reset status to online but don't update version
            await conn.execute("""
                UPDATE agents 
                SET status = 'online', updated_at = CURRENT_TIMESTAMP
                WHERE name = $1
            """, agent_name)
            
            logger.error(f"AGENT UPGRADE: Agent '{agent_name}' failed to upgrade to version '{new_version}'")
        
        await close_database_connection(conn)
        
        return {"status": "ok", "message": f"Upgrade completion status received: {upgrade_status}"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing upgrade completion for agent {agent_name}: {e}")
        return {"status": "error", "message": str(e)}

@router.post("/{agent_id}/upgrade")
async def upgrade_agent(agent_id: int, authorization: str = Header(None)):
    """Initiate agent upgrade process"""
    try:
        # Get current user and check permission
        current_user = await get_current_user_from_token(authorization)
        has_permission = await check_user_permission(current_user["id"], "agents", "upgrade")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: agents.upgrade required"
            )
        
        conn = await get_database_connection()
        
        # Get agent info including cluster relationship and platform
        agent = await conn.fetchrow("""
            SELECT a.name, a.pool_id, a.version as current_version, a.platform, hc.id as cluster_id
            FROM agents a
            LEFT JOIN haproxy_clusters hc ON a.pool_id = hc.pool_id
            WHERE a.id = $1
        """, agent_id)
        
        if not agent:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Validate cluster access if agent belongs to a cluster
        if agent['cluster_id']:
            await validate_user_cluster_access(current_user['id'], agent['cluster_id'], conn)
        
        # Get latest version from global storage based on agent platform
        try:
            agent_platform = agent.get('platform', 'unknown')
            logger.info(f"AGENT PLATFORM DEBUG: Raw platform='{agent_platform}', agent_name='{agent['name']}'")
            
            latest_version = await get_version_for_platform(agent_platform)
            platform_key = get_platform_key(agent_platform)
            logger.info(f"VERSION: Using global version {latest_version} for {platform_key} upgrade (platform: {agent_platform})")
        except Exception as version_error:
            logger.warning(f"Could not get latest version: {version_error}")
            latest_version = "unknown"  # No fallback
        
        # SIMPLIFIED: No upgrade/downgrade distinction - just sync to latest version
        # If versions differ, agent needs to sync to the latest script from database
        if agent['current_version'] == latest_version:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Agent is already on this version")
        
        # Update agent status to 'upgrading' with full upgrade tracking
        await conn.execute("""
            UPDATE agents 
            SET status = 'upgrading', 
                upgrade_status = 'upgrading',
                upgrade_target_version = $2,
                upgraded_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP 
            WHERE id = $1
        """, agent_id, latest_version)
        
        await close_database_connection(conn)
        
        # Log the upgrade activity (always "upgrade", regardless of version direction)
        await log_user_activity(
            user_id=current_user["id"],
            action='upgrade',
            resource_type='agent',
            resource_id=str(agent_id),
            details={'agent_name': agent['name'], 'from_version': agent['current_version'], 'to_version': latest_version}
        )
        
        return {
            "message": f"Agent '{agent['name']}' upgrade initiated",
            "agent_id": agent_id,
            "from_version": agent['current_version'],
            "to_version": latest_version,
            "status": "upgrading"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error upgrading agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to initiate agent upgrade")

@router.put("/{agent_id}/toggle", summary="Toggle Agent Status", response_description="Agent status toggled")
async def toggle_agent(agent_id: int, toggle_data: AgentToggle, authorization: str = Header(None)):
    """
    # Toggle Agent Enabled/Disabled Status
    
    Enable or disable an agent. Disabled agents will not receive configuration tasks but remain registered.
    
    ## Path Parameters
    - **agent_id**: Agent ID to toggle
    
    ## Request Body
    - **enabled**: Boolean (true to enable, false to disable)
    
    ## Example Request - Disable Agent
    ```bash
    curl -X PUT "{BASE_URL}/api/agents/1/toggle" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..." \\
      -H "Content-Type: application/json" \\
      -d '{"enabled": false}'
    ```
    
    ## Example Response
    ```json
    {
      "message": "Agent 'production-agent-01' disabled successfully",
      "enabled": false
    }
    ```
    
    ## Use Cases
    - **Disable**: Temporarily stop sending config to agent during maintenance
    - **Enable**: Resume normal operation
    
    Note: Agent service keeps running but won't receive new tasks when disabled.
    
    ## Error Responses
    - **403**: Insufficient permissions
    - **404**: Agent not found
    - **500**: Server error
    """
    try:
        # Get current user for cluster validation
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get agent info including cluster relationship
        agent = await conn.fetchrow("""
            SELECT a.name, a.pool_id, hc.id as cluster_id
            FROM agents a
            LEFT JOIN haproxy_clusters hc ON a.pool_id = hc.pool_id
            WHERE a.id = $1
        """, agent_id)
        if not agent:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Validate cluster access if agent belongs to a cluster
        if agent['cluster_id']:
            await validate_user_cluster_access(current_user['id'], agent['cluster_id'], conn)
        
        agent = await conn.fetchrow("SELECT * FROM agents WHERE id = $1", agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        await conn.execute(
            "UPDATE agents SET enabled = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
            toggle_data.enabled, agent_id
        )
        
        await close_database_connection(conn)
        
        return {
            "success": True,
            "message": f"Agent {'enabled' if toggle_data.enabled else 'disabled'} successfully",
            "agent_id": agent_id,
            "enabled": toggle_data.enabled
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to toggle agent status")

# ==== AGENT VERSION MANAGEMENT ENDPOINTS ====

@router.get("/versions")
async def get_agent_versions(authorization: str = Header(None)):
    """Get all agent versions by platform"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        # Get versions from database
        conn = await get_database_connection()
        
        versions = await conn.fetch("""
            SELECT platform, version, release_date, changelog, is_active, created_at
            FROM agent_versions 
            WHERE is_active = true
            ORDER BY platform, created_at DESC
        """)
        
        await close_database_connection(conn)
        
        # Group by platform
        result = {}
        for version_row in versions:
            platform = version_row['platform']
            if platform not in result:
                result[platform] = []
            
            result[platform].append({
                "version": version_row['version'],
                "release_date": version_row['release_date'].isoformat() if version_row['release_date'] else "2024-01-23",
                "changelog": version_row['changelog'] or [
                    "Database-driven version management",
                    "Self-updating agent scripts", 
                    "Production-ready upgrade system"
                ],
                "is_active": version_row['is_active'],
                "created_at": version_row['created_at'].isoformat() if version_row['created_at'] else "2024-01-23T00:00:00Z"
            })
        
        # Add fallback for platforms not in database
        for platform, version in AGENT_VERSIONS.items():
            if platform not in result:
                result[platform] = [{
                    "version": version,
                    "release_date": "2024-01-23",
                    "changelog": ["Fallback from global storage"],
                    "is_active": True,
                    "created_at": "2024-01-23T00:00:00Z"
                }]
        
        return {"platforms": result}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting agent versions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/versions")
async def create_agent_version(version_data: dict, authorization: str = Header(None)):
    """Create new agent version for specified platform"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for agent version management
        has_permission = await check_user_permission(current_user["id"], "agents", "version")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: agents.version required"
            )
        
        platform = version_data.get('platform', '').lower()
        version = version_data.get('version', '')
        changelog = version_data.get('changelog', [])
        
        if not platform or not version:
            raise HTTPException(status_code=400, detail="Platform and version are required")
        
        # Save to database
        conn = await get_database_connection()
        
        # Insert new version (or update if exists)
        await conn.execute("""
            INSERT INTO agent_versions (platform, version, changelog, is_active)
            VALUES ($1, $2, $3, true)
            ON CONFLICT (platform, version) 
            DO UPDATE SET 
                changelog = EXCLUDED.changelog,
                is_active = true,
                updated_at = CURRENT_TIMESTAMP
        """, platform, version, changelog or [])
        
        # Deactivate old versions for this platform
        await conn.execute("""
            UPDATE agent_versions 
            SET is_active = false 
            WHERE platform = $1 AND version != $2
        """, platform, version)
        
        await close_database_connection(conn)
        
        # Also update global storage for backward compatibility
        global AGENT_VERSIONS
        AGENT_VERSIONS[platform] = version
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='create',
            resource_type='agent_version',
            resource_id=f"{platform}-{version}",
            details={
                'platform': platform,
                'version': version,
                'changelog_items': len(changelog)
            }
        )
        
        logger.info(f"VERSION UPDATE: {platform} version updated to {version}")
        
        return {
            "message": f"Agent version {version} created for {platform}",
            "platform": platform,
            "version": version,
            "current_versions": AGENT_VERSIONS
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating agent version: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==== AGENT SCRIPT TEMPLATE MANAGEMENT ENDPOINTS ====

@router.get("/script-templates/{platform}")
async def get_agent_script_template(platform: str, authorization: str = Header(None)):
    """Get the latest script template for specified platform from database"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get latest script template for platform
        template = await conn.fetchrow("""
            SELECT ast.script_content, ast.version, av.changelog
            FROM agent_script_templates ast
            JOIN agent_versions av ON ast.platform = av.platform AND ast.version = av.version
            WHERE ast.platform = $1 AND ast.is_active = true AND av.is_active = true
            ORDER BY ast.created_at DESC
            LIMIT 1
        """, platform.lower())
        
        await close_database_connection(conn)
        
        if template:
            return {
                "platform": platform,
                "version": template['version'],
                "script_content": template['script_content'],
                "changelog": template['changelog'] or []
            }
        else:
            # Fallback to file-based template if not in database
            import os
            script_template_path = os.path.join(os.path.dirname(__file__), '..', 'utils', 'agent_scripts', f"{platform.lower()}_install.sh")
            
            if os.path.exists(script_template_path):
                with open(script_template_path, 'r') as f:
                    script_content = f.read()
                
                return {
                    "platform": platform,
                    "version": "1.0.0",
                    "script_content": script_content,
                    "changelog": ["Loaded from file template"]
                }
            else:
                raise HTTPException(status_code=404, detail=f"Script template not found for platform: {platform}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting script template for {platform}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/script-templates/{platform}")
async def save_agent_script_template(platform: str, template_data: dict, authorization: str = Header(None)):
    """Save updated script template to database using shared helper function"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        script_content = template_data.get('script_content', '')
        version = template_data.get('version', '')
        
        if not script_content or not version:
            raise HTTPException(status_code=400, detail="Script content and version are required")
        
        conn = await get_database_connection()
        
        # Use the same update logic as Reset to Default operation
        await update_agent_script_in_database(
            conn=conn,
            platform=platform.lower(),
            version=version,
            script_content=script_content,
            changelog=['Script template updated via UI editor']
        )
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='update',
            resource_type='agent_script_template',
            resource_id=f"{platform}-{version}",
            details={
                'platform': platform,
                'version': version,
                'script_size': len(script_content),
                'source': 'ui_editor'
            }
        )
        
        logger.info(f"SCRIPT TEMPLATE: {platform} template updated to version {version}")
        
        return {
            "message": f"Script template saved for {platform}",
            "platform": platform,
            "version": version
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error saving script template for {platform}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==== AGENT ACTIVITY LOGGING ====

async def log_agent_activity(agent_name: str, action_type: str, action_details: dict = None):
    """Log meaningful agent actions to database"""
    try:
        conn = await get_database_connection()
        
        # Get agent_id
        agent = await conn.fetchrow("""
            SELECT id FROM agents WHERE name = $1
        """, agent_name)
        
        if not agent:
            logger.warning(f"Cannot log activity for unknown agent: {agent_name}")
            await close_database_connection(conn)
            return
        
        # Insert activity log
        await conn.execute("""
            INSERT INTO agent_activity_logs (agent_id, agent_name, action_type, action_details, timestamp)
            VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
        """, agent['id'], agent_name, action_type, json.dumps(action_details) if action_details else None)
        
        # Update last_action_time in agents table
        await conn.execute("""
            UPDATE agents SET last_action_time = CURRENT_TIMESTAMP WHERE name = $1
        """, agent_name)
        
        await close_database_connection(conn)
        logger.info(f"ACTIVITY LOG: {agent_name} - {action_type}")
        
    except Exception as e:
        logger.error(f"Failed to log agent activity: {e}")
        # Don't raise - logging failure shouldn't break the main flow

@router.get("/{agent_name}/activity-logs")
async def get_agent_activity_logs(agent_name: str, limit: int = 50, authorization: str = Header(None)):
    """Get activity logs for an agent"""
    try:
        from auth_middleware import check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for agent logs
        has_permission = await check_user_permission(current_user["id"], "agents", "logs")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: agents.logs required"
            )
        
        conn = await get_database_connection()
        
        # Get agent to validate it exists and get cluster for access control
        agent = await conn.fetchrow("""
            SELECT a.id, a.pool_id, hc.id as cluster_id
            FROM agents a
            LEFT JOIN haproxy_clusters hc ON a.pool_id = hc.pool_id
            WHERE a.name = $1
        """, agent_name)
        
        if not agent:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail=f"Agent {agent_name} not found")
        
        # Validate cluster access
        if agent['cluster_id']:
            await validate_user_cluster_access(current_user['id'], agent['cluster_id'], conn)
        
        # Get activity logs
        logs = await conn.fetch("""
            SELECT 
                id,
                action_type,
                action_details,
                timestamp,
                created_at
            FROM agent_activity_logs
            WHERE agent_name = $1
            ORDER BY timestamp DESC
            LIMIT $2
        """, agent_name, limit)
        
        await close_database_connection(conn)
        
        # Format logs
        activity_logs = []
        for log in logs:
            activity_logs.append({
                "id": log['id'],
                "action_type": log['action_type'],
                "action_details": json.loads(log['action_details']) if log['action_details'] else {},
                "timestamp": log['timestamp'].isoformat().replace('+00:00', 'Z') if log['timestamp'] else None,
                "created_at": log['created_at'].isoformat().replace('+00:00', 'Z') if log['created_at'] else None
            })
        
        return {
            "agent_name": agent_name,
            "logs": activity_logs,
            "total": len(activity_logs)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting activity logs for {agent_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==== HELPER FUNCTION FOR SCRIPT UPDATES ====

async def update_agent_script_in_database(conn, platform: str, version: str, script_content: str, changelog: list = None):
    """
    Helper function to update agent script in database
    Used by both Edit and Reset to Default operations
    """
    # Deactivate all existing versions for this platform in agent_script_templates
    await conn.execute("""
        UPDATE agent_script_templates 
        SET is_active = false 
        WHERE platform = $1
    """, platform)
    
    # Insert/update version with script content in agent_script_templates
    await conn.execute("""
        INSERT INTO agent_script_templates (platform, version, script_content, is_active)
        VALUES ($1, $2, $3, true)
        ON CONFLICT (platform, version) DO UPDATE SET
            script_content = EXCLUDED.script_content,
            is_active = true,
            updated_at = CURRENT_TIMESTAMP
    """, platform, version, script_content)
    
    # CRITICAL: Also update agent_versions table for UI to display correct Available version
    # Deactivate all existing versions in agent_versions
    await conn.execute("""
        UPDATE agent_versions 
        SET is_active = false 
        WHERE platform = $1
    """, platform)
    
    # Insert/update version in agent_versions table
    # CRITICAL: ON CONFLICT must update both is_active and updated_at
    # updated_at is used for version ordering in get_version_for_platform
    if changelog is None:
        changelog = ['Script template updated']
    
    await conn.execute("""
        INSERT INTO agent_versions (platform, version, release_date, changelog, is_active, created_at, updated_at)
        VALUES ($1, $2, CURRENT_DATE, $3, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (platform, version) DO UPDATE SET
            is_active = true,
            updated_at = CURRENT_TIMESTAMP,
            changelog = EXCLUDED.changelog,
            release_date = CURRENT_DATE
    """, platform, version, changelog)
    
    # Also update global storage for backward compatibility
    global AGENT_VERSIONS
    AGENT_VERSIONS[platform] = version

@router.post("/sync-scripts-from-files")
async def sync_scripts_from_files(
    target_version: Optional[str] = None,
    authorization: str = Header(None),
    current_user: dict = Depends(authenticate_user)
):
    """
    Force sync agent scripts from files to database
    This will UPDATE database with latest file versions using the same Edit logic
    
    Use cases:
    - After updating linux_install.sh or macos_install.sh in code
    - To reset scripts to file-based versions (1.0.0)
    - To apply bug fixes from code to database
    """
    try:
        # Admin check - include super_admin and admin roles from user_roles table
        conn = await get_database_connection()
        
        # Check if user has admin role in database (consistent with config.py)
        user_roles = await conn.fetch("""
            SELECT r.name 
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.is_active = true
        """, current_user["id"])
        
        role_names = [role['name'] for role in user_roles]
        is_admin = (
            current_user.get("role") in ["super_admin", "admin"] or
            "super_admin" in role_names or
            "admin" in role_names
        )
        
        if not is_admin:
            await close_database_connection(conn)
            logger.warning(f"User {current_user.get('username')} (role: {current_user.get('role')}, roles: {role_names}) denied access to sync scripts - admin access required")
            raise HTTPException(status_code=403, detail="Admin access required")
        
        logger.info(f"User {current_user.get('username')} (role: {current_user.get('role')}, roles: {role_names}) initiating agent script sync from files")
        
        script_files = {
            'linux': 'linux_install.sh',
            'macos': 'macos_install.sh'
        }
        
        sync_results = []
        
        for platform_key, filename in script_files.items():
            # Read file from project
            script_path = os.path.join(os.path.dirname(__file__), '..', 'utils', 'agent_scripts', filename)
            
            if not os.path.exists(script_path):
                sync_results.append({
                    "platform": platform_key,
                    "status": "error",
                    "message": f"File not found: {filename}"
                })
                continue
            
            with open(script_path, 'r') as f:
                file_content = f.read()
            
            # CRITICAL DEBUG: Log file content size and check for "local listen_lines"
            has_bug = "local listen_lines" in file_content
            logger.info(f"FILE READ: {filename} -> {len(file_content)} bytes, has_bug={has_bug}, path={script_path}")
            
            # Determine version to use
            if target_version:
                # User explicitly specified version (from UI)
                new_version = target_version
                logger.info(f"USER VERSION: Using specified version {new_version} for {platform_key}")
            else:
                # Auto-increment current version to trigger upgrades
                current_version_row = await conn.fetchrow("""
                    SELECT version FROM agent_versions 
                    WHERE platform = $1 AND is_active = true
                    ORDER BY updated_at DESC LIMIT 1
                """, platform_key)
                
                if current_version_row:
                    current_version = current_version_row['version']
                    # Auto-increment patch version (e.g., 1.0.0 → 1.0.1)
                    try:
                        parts = current_version.split('.')
                        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                        new_version = f"{major}.{minor}.{patch + 1}"
                        logger.info(f"AUTO VERSION BUMP: {current_version} → {new_version} for {platform_key}")
                    except:
                        # Fallback if version format is unexpected
                        new_version = "1.0.1"
                else:
                    # First time sync
                    new_version = "1.0.0"
            
            # Use the same update logic as Edit operation
            await update_agent_script_in_database(
                conn=conn,
                platform=platform_key,
                version=new_version,
                script_content=file_content,
                changelog=["Reset to file-based defaults", "Original stable version"]
            )
            
            sync_results.append({
                "platform": platform_key,
                "status": "success",
                "version": new_version,
                "message": f"Synced {filename} to database as version {new_version}"
            })
            
            logger.info(f"SCRIPT SYNC: Synced {platform_key} from file to database (version {new_version})")
            
            # Log activity
            await log_user_activity(
                user_id=current_user["id"],
                action='reset_to_default',
                resource_type='agent_script_template',
                resource_id=f"{platform_key}-{new_version}",
                details={
                    'platform': platform_key,
                    'version': new_version,
                    'script_size': len(file_content),
                    'source': 'project_file'
                }
            )
        
        await close_database_connection(conn)
        
        return {
            "status": "success",
            "message": "Scripts synced from files to database",
            "results": sync_results
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error syncing scripts from files: {e}")
        raise HTTPException(status_code=500, detail=str(e))
