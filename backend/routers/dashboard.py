from fastapi import APIRouter, HTTPException, Header
from typing import Optional
from datetime import datetime
import logging

from models import PoolCreate, PoolUpdate
from database.connection import get_database_connection, close_database_connection
from utils.activity_log import log_user_activity
from agent_notifications import get_cluster_agents_status

router = APIRouter(prefix="/api", tags=["dashboard", "pools"])
logger = logging.getLogger(__name__)

@router.get("/dashboard/overview")
async def get_dashboard_overview(cluster_id: Optional[int] = None, authorization: str = Header(None)):
    """Get dashboard overview with comprehensive statistics, optionally filtered by cluster"""
    try:
        # Get current user for cluster validation
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization) if authorization else None
        
        conn = await get_database_connection()
        
        # Validate cluster access if cluster_id provided
        if cluster_id and current_user:
            cluster_exists = await conn.fetchval("SELECT id FROM haproxy_clusters WHERE id = $1", cluster_id)
            if not cluster_exists:
                raise HTTPException(status_code=404, detail="Cluster not found")
        
        # Build cluster filter condition
        cluster_filter = ""
        cluster_params = []
        if cluster_id:
            cluster_filter = " WHERE cluster_id = $1"
            cluster_params = [cluster_id]
        
        # Get basic dashboard statistics (safer queries with fallbacks)
        try:
            # Basic counts with error handling
            if cluster_id:
                clusters_count = 1  # Single cluster view
                active_clusters = await conn.fetchval("SELECT COUNT(*) FROM haproxy_clusters WHERE id = $1 AND is_active = TRUE", cluster_id) or 0
            else:
                clusters_count = await conn.fetchval("SELECT COUNT(*) FROM haproxy_clusters") or 0
                active_clusters = await conn.fetchval("SELECT COUNT(*) FROM haproxy_clusters WHERE is_active = TRUE") or 0
            
            pools_count = await conn.fetchval("SELECT COUNT(*) FROM haproxy_cluster_pools") or 0
            active_pools = await conn.fetchval("SELECT COUNT(*) FROM haproxy_cluster_pools WHERE is_active = TRUE") or 0
            
            agents_count = await conn.fetchval("SELECT COUNT(*) FROM agents") or 0
            online_agents = await conn.fetchval("SELECT COUNT(*) FROM agents WHERE status = 'online'") or 0
            
            # Try to get frontend/backend counts, fallback to 0 if tables don't exist
            try:
                frontends_count = await conn.fetchval(f"SELECT COUNT(*) FROM frontends{cluster_filter}", *cluster_params) or 0
                active_frontends = await conn.fetchval(f"SELECT COUNT(*) FROM frontends WHERE is_active = TRUE{' AND cluster_id = $1' if cluster_id else ''}", *cluster_params) or 0
            except:
                frontends_count = 0
                active_frontends = 0
            
            try:
                backends_count = await conn.fetchval(f"SELECT COUNT(*) FROM backends{cluster_filter}", *cluster_params) or 0
                active_backends = await conn.fetchval(f"SELECT COUNT(*) FROM backends WHERE is_active = TRUE{' AND cluster_id = $1' if cluster_id else ''}", *cluster_params) or 0
            except:
                backends_count = 0
                active_backends = 0
                
            try:
                servers_count = await conn.fetchval("SELECT COUNT(*) FROM backend_servers") or 0
            except:
                servers_count = 0
                
            try:
                waf_rules_count = await conn.fetchval("SELECT COUNT(*) FROM waf_rules") or 0
            except:
                waf_rules_count = 0
                
            try:
                ssl_certs_count = await conn.fetchval("SELECT COUNT(*) FROM ssl_certificates") or 0
            except:
                ssl_certs_count = 0
                
            try:
                pending_configs = await conn.fetchval("SELECT COUNT(*) FROM config_versions WHERE status = 'PENDING'") or 0
                active_configs = await conn.fetchval("SELECT COUNT(*) FROM config_versions WHERE status = 'APPLIED' AND is_active = TRUE") or 0
            except:
                # Fallback for older schema without status column
                try:
                    pending_configs = 0
                    active_configs = await conn.fetchval("SELECT COUNT(*) FROM config_versions WHERE is_active = TRUE") or 0
                except:
                    pending_configs = 0
                    active_configs = 0
            
            stats = {
                'total_clusters': clusters_count,
                'active_clusters': active_clusters,
                'total_pools': pools_count,
                'active_pools': active_pools,
                'total_agents': agents_count,
                'online_agents': online_agents,
                'offline_agents': agents_count - online_agents,
                'warning_agents': 0,  # Simplified for now
                'total_frontends': frontends_count,
                'active_frontends': active_frontends,
                'total_backends': backends_count,
                'active_backends': active_backends,
                'total_servers': servers_count,
                'total_waf_rules': waf_rules_count,
                'total_ssl_certs': ssl_certs_count,
                'pending_configs': pending_configs,
                'active_configs': active_configs
            }
            
        except Exception as stats_error:
            logger.error(f"Error fetching basic stats: {stats_error}")
            # Return empty stats as fallback
            stats = {
                'total_clusters': 0, 'active_clusters': 0,
                'total_pools': 0, 'active_pools': 0,
                'total_agents': 0, 'online_agents': 0, 'offline_agents': 0, 'warning_agents': 0,
                'total_frontends': 0, 'active_frontends': 0,
                'total_backends': 0, 'active_backends': 0,
                'total_servers': 0, 'total_waf_rules': 0, 'total_ssl_certs': 0,
                'pending_configs': 0, 'active_configs': 0
            }
        
        # Get recent activity (simplified with error handling)
        recent_activity = []
        try:
            recent_activity = await conn.fetch("""
                SELECT resource_type, action, COUNT(*) as count
                FROM user_activity_logs 
                WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
                GROUP BY resource_type, action
                ORDER BY count DESC
                LIMIT 10
            """)
        except Exception as activity_error:
            logger.warning(f"Could not fetch recent activity: {activity_error}")
            recent_activity = []
        
        # Get cluster health summary (simplified)
        cluster_health = []
        try:
            cluster_health = await conn.fetch("""
                SELECT 
                    hc.id,
                    hc.name,
                    hc.connection_status,
                    hc.is_active
                FROM haproxy_clusters hc
                WHERE hc.is_active = TRUE
                ORDER BY hc.name
            """)
        except Exception as cluster_error:
            logger.warning(f"Could not fetch cluster health: {cluster_error}")
            cluster_health = []
        
        # Simplified alerts (only check basic agent status)
        alerts = []
        try:
            offline_agents = await conn.fetch("""
                SELECT name, last_seen 
                FROM agents 
                WHERE status = 'offline'
                LIMIT 5
            """)
            
            for agent in offline_agents:
                alerts.append({
                    "type": "warning",
                    "category": "agent",
                    "message": f"Agent '{agent['name']}' is offline",
                    "details": f"Last seen: {agent['last_seen']}" if agent['last_seen'] else "Never connected"
                })
        except Exception as alerts_error:
            logger.warning(f"Could not fetch alerts: {alerts_error}")
            alerts = []
        
        await close_database_connection(conn)
        
        return {
            "overview": {
                "clusters": {
                    "active": stats.get("active_clusters", 0),
                    "total": stats.get("total_clusters", 0)
                },
                "pools": {
                    "active": stats.get("active_pools", 0),
                    "total": stats.get("total_pools", 0)
                },
                "agents": {
                    "online": stats.get("online_agents", 0),
                    "offline": stats.get("offline_agents", 0),
                    "warning": stats.get("warning_agents", 0),
                    "total": stats.get("total_agents", 0)
                },
                "configurations": {
                    "frontends": {
                        "active": stats.get("active_frontends", 0),
                        "total": stats.get("total_frontends", 0)
                    },
                    "backends": {
                        "active": stats.get("active_backends", 0),
                        "total": stats.get("total_backends", 0)
                    },
                    "servers": stats.get("total_servers", 0),
                    "waf_rules": stats.get("total_waf_rules", 0),
                    "ssl_certificates": stats.get("total_ssl_certs", 0)
                },
                "config_versions": {
                    "pending": stats.get("pending_configs", 0),
                    "active": stats.get("active_configs", 0)
                }
            },
            "recent_activity": [
                {
                    "resource_type": activity["resource_type"],
                    "action": activity["action"],
                    "count": activity["count"]
                }
                for activity in recent_activity
            ],
            "cluster_health": [
                {
                    "id": cluster["id"],
                    "name": cluster["name"],
                    "status": cluster.get("connection_status", "unknown"),
                    "is_active": cluster.get("is_active", False)
                }
                for cluster in cluster_health
            ],
            "alerts": alerts[:20]  # Limit to 20 most important alerts
        }
        
    except Exception as e:
        logger.error(f"Error fetching dashboard overview: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        conn = await get_database_connection()
        
        # Get basic counts
        stats = await conn.fetchrow("""
            SELECT 
                (SELECT COUNT(*) FROM haproxy_clusters WHERE is_active = TRUE) as active_clusters,
                (SELECT COUNT(*) FROM haproxy_cluster_pools WHERE is_active = TRUE) as active_pools,
                (SELECT COUNT(*) FROM agents) as total_agents,
                (SELECT COUNT(*) FROM agents WHERE status = 'online') as online_agents,
                (SELECT COUNT(*) FROM frontends WHERE is_active = TRUE) as active_frontends,
                (SELECT COUNT(*) FROM backends WHERE is_active = TRUE) as active_backends
        """)
        
        await close_database_connection(conn)
        
        return {
            "clusters": {
                "active": stats["active_clusters"] or 0,
                "total": stats["active_clusters"] or 0
            },
            "pools": {
                "active": stats["active_pools"] or 0,
                "total": stats["active_pools"] or 0
            },
            "agents": {
                "online": stats["online_agents"] or 0,
                "total": stats["total_agents"] or 0,
                "offline": (stats["total_agents"] or 0) - (stats["online_agents"] or 0)
            },
            "configurations": {
                "frontends": stats["active_frontends"] or 0,
                "backends": stats["active_backends"] or 0
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/pools")
async def get_pools():
    """Get all HAProxy cluster pools"""
    try:
        conn = await get_database_connection()
        
        # Schema-safe pools query
        try:
            pools = await conn.fetch("""
                SELECT p.id, p.name, p.description, p.environment, p.location, 
                       p.is_active, p.created_at, p.updated_at,
                       COUNT(c.id) as cluster_count,
                       COUNT(a.id) as agent_count,
                       COUNT(CASE WHEN a.status = 'online' THEN 1 END) as online_agents,
                       COUNT(CASE WHEN a.status = 'offline' THEN 1 END) as offline_agents,
                       COUNT(CASE WHEN a.status = 'warning' THEN 1 END) as warning_agents
                FROM haproxy_cluster_pools p
                LEFT JOIN haproxy_clusters c ON c.pool_id = p.id AND c.is_active = TRUE
                LEFT JOIN agents a ON a.pool_id = p.id
                WHERE p.is_active = TRUE
                GROUP BY p.id, p.name, p.description, p.environment, p.location, 
                         p.is_active, p.created_at, p.updated_at
                ORDER BY p.name
            """)
        except Exception as schema_error:
            logger.warning(f"Schema error in pools query, using fallback: {schema_error}")
            # Fallback query without location column
            pools = await conn.fetch("""
                SELECT p.id, p.name, p.description, p.environment,
                       p.is_active, p.created_at, p.updated_at,
                       COUNT(c.id) as cluster_count,
                       COUNT(a.id) as agent_count,
                       COUNT(CASE WHEN a.status = 'online' THEN 1 END) as online_agents,
                       COUNT(CASE WHEN a.status = 'offline' THEN 1 END) as offline_agents,
                       COUNT(CASE WHEN a.status = 'warning' THEN 1 END) as warning_agents
                FROM haproxy_cluster_pools p
                LEFT JOIN haproxy_clusters c ON c.pool_id = p.id AND c.is_active = TRUE
                LEFT JOIN agents a ON a.pool_id = p.id
                WHERE p.is_active = TRUE
                GROUP BY p.id, p.name, p.description, p.environment,
                         p.is_active, p.created_at, p.updated_at
                ORDER BY p.name
            """)
        
        await close_database_connection(conn)
        
        return {
            "pools": [
                {
                    "id": pool["id"],
                    "name": pool["name"],
                    "description": pool.get("description"),
                    "environment": pool.get("environment"),
                    "location": pool.get("location", "unspecified"),
                    "is_active": pool.get("is_active", True),
                    "created_at": pool["created_at"].isoformat() if pool.get("created_at") else None,
                    "updated_at": pool["updated_at"].isoformat() if pool.get("updated_at") else None,
                    "cluster_count": pool.get("cluster_count", 0) or 0,
                    "agent_count": pool.get("agent_count", 0) or 0,
                    "online_agents": pool.get("online_agents", 0) or 0,
                    "offline_agents": pool.get("offline_agents", 0) or 0,
                    "warning_agents": pool.get("warning_agents", 0) or 0
                }
                for pool in pools
            ]
        }
        
    except Exception as e:
        logger.error(f"Error fetching pools: {e}")
        return {"pools": []}

@router.get("/haproxy-cluster-pools")
async def get_haproxy_cluster_pools():
    """Get all HAProxy cluster pools (legacy endpoint)"""
    # Just call the main pools endpoint
    return await get_pools()

@router.post("/pools")
async def create_pool(pool: PoolCreate, authorization: str = Header(None)):
    """Create a new HAProxy cluster pool"""
    try:
        # Get current user for activity logging
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Check if pool name already exists
        existing = await conn.fetchrow("SELECT id FROM haproxy_cluster_pools WHERE name = $1", pool.name)
        if existing:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail=f"Pool '{pool.name}' already exists")
        
        # Insert new pool
        pool_id = await conn.fetchval("""
            INSERT INTO haproxy_cluster_pools 
            (name, description, environment, location, is_active)
            VALUES ($1, $2, $3, $4, $5) 
            RETURNING id
        """, pool.name, pool.description, pool.environment, pool.location, pool.is_active)
        
        # Automatically grant the creating user admin access to the new pool
        try:
            # Check if user_pool_access table exists
            table_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_name = 'user_pool_access'
                )
            """)
            
            if table_exists:
                await conn.execute("""
                    INSERT INTO user_pool_access (user_id, pool_id, access_level, granted_by)
                    VALUES ($1, $2, 'admin', $1)
                    ON CONFLICT (user_id, pool_id) DO NOTHING
                """, current_user['id'], pool_id)
                logger.info(f"Granted admin access to user {current_user['username']} for new pool '{pool.name}'")
            else:
                logger.warning("user_pool_access table not found, skipping automatic access grant")
                
        except Exception as e:
            logger.error(f"Failed to grant pool access to user: {e}")
            # Don't fail the pool creation, just log the error
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='create',
                resource_type='pool',
                resource_id=str(pool_id),
                details={
                    'pool_name': pool.name,
                    'environment': pool.environment,
                    'location': pool.location
                }
            )
        
        return {
            "message": f"Pool '{pool.name}' created successfully",
            "id": pool_id,
            "pool": pool.dict()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/haproxy-cluster-pools/{pool_id}")
async def update_pool(pool_id: int, pool: PoolUpdate, authorization: str = Header(None)):
    """Update an existing HAProxy cluster pool"""
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Check if pool exists
        existing_pool = await conn.fetchrow("SELECT name FROM haproxy_cluster_pools WHERE id = $1", pool_id)
        if not existing_pool:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Pool not found")
        
        # Update pool
        await conn.execute("""
            UPDATE haproxy_cluster_pools 
            SET name = $2, description = $3, location = $4, is_active = $5, environment = $6
            WHERE id = $1
        """, pool_id, pool.name, pool.description, pool.location, pool.is_active, pool.environment)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='update',
            resource_type='pool',
            resource_id=str(pool_id),
            details={
                'pool_name': pool.name,
                'old_name': existing_pool['name']
            }
        )
        
        return {"message": f"Pool '{pool.name}' updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update pool: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update pool: {str(e)}")

@router.get("/haproxy-cluster-pools/{pool_id}/agents")
async def get_pool_agents(pool_id: int):
    """Get all agents for a specific pool"""
    try:
        conn = await get_database_connection()
        
        # First verify pool exists
        pool = await conn.fetchrow("SELECT id, name FROM haproxy_cluster_pools WHERE id = $1", pool_id)
        if not pool:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Pool not found")
        
        # Get agents for this pool
        agents = await conn.fetch("""
            SELECT a.id, a.name, a.pool_id, a.platform, a.architecture, a.version,
                   a.hostname, a.ip_address, a.operating_system, a.kernel_version,
                   a.uptime, a.cpu_count, a.memory_total, a.disk_space,
                   a.network_interfaces, a.capabilities, a.status, a.last_seen,
                   a.haproxy_status, a.haproxy_version, a.config_version,
                   COALESCE(a.enabled, TRUE) as enabled,
                   a.created_at, a.updated_at,
                   p.name as pool_name, p.environment as pool_environment
            FROM agents a
            LEFT JOIN haproxy_cluster_pools p ON a.pool_id = p.id
            WHERE a.pool_id = $1
            ORDER BY a.name
        """, pool_id)
        
        await close_database_connection(conn)
        
        # Calculate health status for each agent
        agent_list = []
        for agent in agents:
            # Calculate health based on status and last_seen
            health = "offline"
            if agent["status"] == "online" and agent["last_seen"]:
                time_diff = datetime.utcnow() - agent["last_seen"]
                if time_diff.total_seconds() < 60:  # Less than 1 minute
                    health = "healthy"
                elif time_diff.total_seconds() < 300:  # Less than 5 minutes
                    health = "warning"
            
            agent_list.append({
                "id": agent["id"],
                "name": agent["name"],
                "pool_id": agent["pool_id"],
                "platform": agent["platform"],
                "architecture": agent["architecture"],
                "version": agent["version"],
                "hostname": agent["hostname"],
                "ip_address": agent["ip_address"],
                "operating_system": agent["operating_system"],
                "kernel_version": agent["kernel_version"],
                "uptime": agent["uptime"],
                "cpu_count": agent["cpu_count"],
                "memory_total": agent["memory_total"],
                "disk_space": agent["disk_space"],
                "network_interfaces": agent["network_interfaces"],
                "capabilities": agent["capabilities"],
                "status": agent["status"],
                "health": health,
                "last_seen": agent["last_seen"].isoformat() if agent["last_seen"] else None,
                "haproxy_status": agent["haproxy_status"],
                "haproxy_version": agent["haproxy_version"],
                "config_version": agent["config_version"],
                "enabled": agent["enabled"],
                "created_at": agent["created_at"].isoformat() if agent["created_at"] else None,
                "updated_at": agent["updated_at"].isoformat() if agent["updated_at"] else None,
                "pool_name": agent["pool_name"],
                "pool_environment": agent["pool_environment"]
            })
        
        return {
            "pool": {
                "id": pool["id"],
                "name": pool["name"]
            },
            "agents": agent_list,
            "total_agents": len(agent_list)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching pool agents: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch pool agents: {str(e)}")

@router.get("/haproxy/stats")
async def get_haproxy_stats(cluster_id: Optional[int] = None):
    """Get HAProxy statistics"""
    try:
        conn = await get_database_connection()
        
        # Get cluster info if cluster_id provided
        cluster_info = None
        if cluster_id:
            cluster_info = await conn.fetchrow("""
                SELECT id, name, connection_type, is_active 
                FROM haproxy_clusters 
                WHERE id = $1
            """, cluster_id)
            
            if not cluster_info:
                await close_database_connection(conn)
                raise HTTPException(status_code=404, detail="Cluster not found")
        
        await close_database_connection(conn)
        
        # Generate realistic mock stats for now
        # In production, this would connect to HAProxy stats socket
        import random
        import time
        
        base_requests = random.randint(50000, 200000)
        current_time = int(time.time())
        
        # Frontend stats (mocked)
        frontend_stats = {
            "requests_total": base_requests + random.randint(0, 1000),
            "requests_rate": random.randint(50, 200),
            "status": random.choice(["UP", "UNKNOWN"]),
            "current_sessions": random.randint(10, 100),
            "max_sessions": random.randint(200, 500),
            "bytes_in": base_requests * random.randint(1000, 5000),
            "bytes_out": base_requests * random.randint(2000, 8000),
            "response_time_avg": random.randint(50, 200),
            "error_rate": round(random.uniform(0.1, 2.0), 2)
        }
        
        # Backend stats (mocked)
        backend_stats = []
        backend_names = ["web_servers", "api_servers", "database_servers", "cache_servers"]
        
        for backend_name in backend_names[:random.randint(2, 4)]:
            backend_stats.append({
                "name": backend_name,
                "status": random.choice(["UP", "DOWN", "MAINT"]),
                "current_sessions": random.randint(0, 50),
                "max_sessions": random.randint(100, 300),
                "queue_current": random.randint(0, 10),
                "queue_max": random.randint(0, 50),
                "servers_active": random.randint(1, 4),
                "servers_total": random.randint(2, 6),
                "bytes_in": random.randint(10000, 100000),
                "bytes_out": random.randint(20000, 200000),
                "response_time": random.randint(30, 150),
                "error_rate": round(random.uniform(0.0, 1.5), 2)
            })
        
        # Server stats (mocked)
        server_stats = []
        for backend in backend_stats:
            for i in range(backend["servers_total"]):
                server_name = f"{backend['name']}_server_{i+1}"
                server_stats.append({
                    "backend": backend["name"],
                    "name": server_name,
                    "status": random.choice(["UP", "DOWN", "MAINT"]) if i < backend["servers_active"] else "DOWN",
                    "weight": random.randint(50, 100),
                    "current_sessions": random.randint(0, 20),
                    "max_sessions": random.randint(50, 150),
                    "check_status": random.choice(["L7OK", "L4OK", "L6OK", "DOWN"]),
                    "last_check": f"{random.randint(0, 1000)}ms",
                    "downtime": random.randint(0, 3600) if random.choice([True, False]) else 0
                })
        
        # Traffic distribution (mocked)
        traffic_distribution = []
        for i in range(24):  # 24 hours of data
            hour = (current_time - (23-i) * 3600)
            traffic_distribution.append({
                "timestamp": hour,
                "requests": random.randint(1000, 5000),
                "bandwidth": random.randint(50000, 200000),
                "errors": random.randint(5, 50)
            })
        
        # Overall cluster health
        overall_health = {
            "status": "healthy" if random.choice([True, True, True, False]) else "warning",
            "total_frontends": len(frontend_stats),
            "total_backends": len(backend_stats),
            "total_servers": len(server_stats),
            "servers_up": len([s for s in server_stats if s["status"] == "UP"]),
            "cpu_usage": round(random.uniform(20, 80), 1),
            "memory_usage": round(random.uniform(30, 70), 1),
            "uptime_seconds": random.randint(100000, 1000000)
        }
        
        return {
            "cluster_id": cluster_id,
            "cluster_name": cluster_info["name"] if cluster_info else "Global",
            "timestamp": current_time,
            "frontend_stats": frontend_stats,
            "backend_stats": backend_stats,
            "server_stats": server_stats,
            "traffic_distribution": traffic_distribution,
            "overall_health": overall_health,
            "data_source": "mock" # In production this would be "haproxy_socket"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get HAProxy stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get HAProxy stats: {str(e)}")


@router.delete("/haproxy-cluster-pools/{pool_id}")  # Fixed route path
async def delete_pool(pool_id: int, authorization: str = Header(None)):
    """Delete a HAProxy cluster pool"""
    try:
        # Get current user for activity logging
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get pool info before deletion
        pool = await conn.fetchrow("SELECT name FROM haproxy_cluster_pools WHERE id = $1", pool_id)
        if not pool:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Pool not found")
        
        # Check for dependencies before deletion
        dependencies = []
        
        # Check clusters
        clusters_count = await conn.fetchval("SELECT COUNT(*) FROM haproxy_clusters WHERE pool_id = $1", pool_id)
        if clusters_count > 0:
            dependencies.append(f"{clusters_count} cluster(s)")
        
        # Check agents
        agents_count = await conn.fetchval("SELECT COUNT(*) FROM agents WHERE pool_id = $1", pool_id)
        if agents_count > 0:
            dependencies.append(f"{agents_count} agent(s)")
        
        # If dependencies exist, prevent deletion
        if dependencies:
            await close_database_connection(conn)
            deps_text = ", ".join(dependencies)
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot delete pool: it has {deps_text}. Please remove these dependencies first."
            )
        
        # Delete the pool
        await conn.execute("DELETE FROM haproxy_cluster_pools WHERE id = $1", pool_id)
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='delete',
                resource_type='pool',
                resource_id=str(pool_id),
                details={'pool_name': pool['name']}
            )
        
        return {"message": f"Pool '{pool['name']}' deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/pools/grant-current-user-access")
async def grant_current_user_pool_access(authorization: str = Header(None)):
    """Grant current user access to all pools - emergency access for testing"""
    try:
        # Get current user
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Check if user_pool_access table exists
        table_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'user_pool_access'
            )
        """)
        
        if not table_exists:
            await close_database_connection(conn)
            raise HTTPException(status_code=500, detail="user_pool_access table not found")
        
        # Grant access to all pools
        await conn.execute("""
            INSERT INTO user_pool_access (user_id, pool_id, access_level, granted_by)
            SELECT $1, p.id, 'admin', $1
            FROM haproxy_cluster_pools p
            ON CONFLICT (user_id, pool_id) 
            DO UPDATE SET 
                access_level = 'admin',
                granted_by = EXCLUDED.granted_by,
                granted_at = CURRENT_TIMESTAMP,
                is_active = TRUE
        """, current_user['id'])
        
        await close_database_connection(conn)
        
        return {
            "message": f"Access granted to all pools for user {current_user['username']}",
            "user_id": current_user['id']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to grant current user pool access: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to grant current user pool access: {str(e)}") 