"""
Production-Ready Health Check and Monitoring Endpoints
Provides comprehensive system health monitoring for Kubernetes and production environments
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
import logging
import asyncio
import time
from datetime import datetime, timedelta
import psutil
import os

from database.connection import get_database_connection, close_database_connection, redis_client
from config import DATABASE_URL, REDIS_URL

router = APIRouter(prefix="/api/health", tags=["Health Checks"])
logger = logging.getLogger(__name__)

# Health check cache to avoid overwhelming database
_health_cache = {"last_check": None, "status": None, "details": None}
CACHE_DURATION = 30  # seconds

@router.get("/")
async def health_check():
    """Basic health check endpoint for load balancers"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@router.get("/liveness")
async def liveness_probe():
    """Kubernetes liveness probe - checks if application is running"""
    try:
        # Basic app functionality check
        current_time = datetime.utcnow()
        
        return {
            "status": "alive",
            "timestamp": current_time.isoformat(),
            "uptime_seconds": time.time() - psutil.Process().create_time()
        }
    except Exception as e:
        logger.error(f"Liveness probe failed: {e}")
        raise HTTPException(status_code=503, detail="Application not responding")

@router.get("/readiness")
async def readiness_probe():
    """Kubernetes readiness probe - checks if app is ready to serve traffic"""
    try:
        # Check database connectivity
        conn = await get_database_connection()
        db_status = await conn.fetchval("SELECT 1")
        await close_database_connection(conn)
        
        if db_status != 1:
            raise Exception("Database connectivity failed")
        
        # Check Redis connectivity (if available)
        redis_status = "healthy"
        try:
            redis_client.ping()
        except:
            redis_status = "unavailable"
            logger.warning("Redis not accessible for readiness check")
        
        return {
            "status": "ready",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "healthy",
            "redis": redis_status
        }
        
    except Exception as e:
        logger.error(f"Readiness probe failed: {e}")
        raise HTTPException(status_code=503, detail=f"Not ready: {str(e)}")

@router.get("/deep")
async def deep_health_check():
    """Comprehensive health check with detailed system information"""
    global _health_cache
    
    # Use cache if recent check available
    now = time.time()
    if (_health_cache["last_check"] and 
        now - _health_cache["last_check"] < CACHE_DURATION and
        _health_cache["status"]):
        return _health_cache["status"]
    
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "environment": os.getenv("ENVIRONMENT", "production"),
            "services": {},
            "system": {},
            "application": {}
        }
        
        # Database health
        try:
            start_time = time.time()
            conn = await get_database_connection()
            
            # Test basic query
            db_version = await conn.fetchval("SELECT version()")
            
            # Count agents and clusters
            agent_count = await conn.fetchval("SELECT COUNT(*) FROM agents WHERE status = 'online'")
            cluster_count = await conn.fetchval("SELECT COUNT(*) FROM haproxy_clusters WHERE is_active = true")
            
            await close_database_connection(conn)
            
            db_response_time = round((time.time() - start_time) * 1000, 2)
            
            health_status["services"]["database"] = {
                "status": "healthy",
                "response_time_ms": db_response_time,
                "version": db_version.split()[1] if db_version else "unknown",
                "active_agents": agent_count,
                "active_clusters": cluster_count
            }
        except Exception as e:
            health_status["services"]["database"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            health_status["status"] = "degraded"
        
        # Redis health
        try:
            start_time = time.time()
            redis_client.ping()
            redis_response_time = round((time.time() - start_time) * 1000, 2)
            
            health_status["services"]["redis"] = {
                "status": "healthy", 
                "response_time_ms": redis_response_time,
                "connected": True
            }
        except Exception as e:
            health_status["services"]["redis"] = {
                "status": "unhealthy",
                "error": str(e),
                "connected": False
            }
            # Redis is optional, don't mark system as degraded
        
        # System metrics
        try:
            process = psutil.Process()
            health_status["system"] = {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "process_memory_mb": round(process.memory_info().rss / 1024 / 1024, 2),
                "process_cpu_percent": process.cpu_percent(),
                "uptime_seconds": round(time.time() - process.create_time(), 2)
            }
        except Exception as e:
            health_status["system"] = {"error": str(e)}
        
        # Application metrics
        try:
            health_status["application"] = {
                "python_version": os.sys.version.split()[0],
                "platform": os.sys.platform,
                "process_id": os.getpid(),
                "thread_count": process.num_threads() if 'process' in locals() else "unknown"
            }
        except Exception as e:
            health_status["application"] = {"error": str(e)}
        
        # Cache the result
        _health_cache = {
            "last_check": now,
            "status": health_status,
            "details": None
        }
        
        return health_status
        
    except Exception as e:
        logger.error(f"Deep health check failed: {e}")
        error_response = {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }
        
        # Cache error response for shorter duration
        _health_cache = {
            "last_check": now,
            "status": error_response,
            "details": None
        }
        
        raise HTTPException(status_code=503, detail=error_response)

@router.get("/agents")
async def agents_health():
    """Monitor agent connectivity and health status"""
    try:
        conn = await get_database_connection()
        
        # Get agent statistics
        agent_stats = await conn.fetchrow("""
            SELECT 
                COUNT(*) as total_agents,
                COUNT(*) FILTER (WHERE status = 'online') as online_agents,
                COUNT(*) FILTER (WHERE status = 'offline') as offline_agents,
                COUNT(*) FILTER (WHERE haproxy_status = 'running') as haproxy_running,
                COUNT(*) FILTER (WHERE haproxy_status = 'stopped') as haproxy_stopped,
                COUNT(*) FILTER (WHERE haproxy_status = 'unknown') as haproxy_unknown,
                COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '5 minutes') as recently_active
            FROM agents
        """)
        
        # Get recently offline agents
        recently_offline = await conn.fetch("""
            SELECT name, hostname, last_seen, 
                   EXTRACT(EPOCH FROM (NOW() - last_seen)) as seconds_since_last_seen
            FROM agents 
            WHERE status = 'offline' 
            AND last_seen > NOW() - INTERVAL '1 hour'
            ORDER BY last_seen DESC
            LIMIT 10
        """)
        
        await close_database_connection(conn)
        
        # Determine overall agent health
        total = agent_stats['total_agents']
        online = agent_stats['online_agents']
        
        if total == 0:
            agent_health_status = "no_agents"
        elif online == total:
            agent_health_status = "healthy"
        elif online > total * 0.8:  # 80% online threshold  
            agent_health_status = "warning"
        else:
            agent_health_status = "critical"
        
        return {
            "status": agent_health_status,
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": dict(agent_stats),
            "recently_offline": [
                {
                    "name": agent['name'],
                    "hostname": agent['hostname'],
                    "last_seen": agent['last_seen'].isoformat() if agent['last_seen'] else None,
                    "offline_duration_seconds": int(agent['seconds_since_last_seen']) if agent['seconds_since_last_seen'] else None
                }
                for agent in recently_offline
            ]
        }
        
    except Exception as e:
        logger.error(f"Agent health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Agent health check failed: {str(e)}")

@router.get("/clusters")
async def clusters_health():
    """Monitor HAProxy cluster health and configuration status"""
    try:
        conn = await get_database_connection()
        
        # Get cluster statistics
        cluster_stats = await conn.fetchrow("""
            SELECT 
                COUNT(*) as total_clusters,
                COUNT(*) FILTER (WHERE is_active = true) as active_clusters,
                COUNT(*) FILTER (WHERE connection_status = 'connected') as connected_clusters,
                COUNT(*) FILTER (WHERE last_connected_at > NOW() - INTERVAL '10 minutes') as recently_connected
            FROM haproxy_clusters
        """)
        
        # Get pending changes count
        pending_changes = await conn.fetchval("""
            SELECT COUNT(*) FROM config_versions WHERE status = 'PENDING'
        """)
        
        # Get cluster details
        cluster_details = await conn.fetch("""
            SELECT name, is_active, connection_status, last_connected_at, haproxy_version,
                   EXTRACT(EPOCH FROM (NOW() - last_connected_at)) as seconds_since_connection
            FROM haproxy_clusters 
            WHERE is_active = true
            ORDER BY last_connected_at DESC NULLS LAST
        """)
        
        await close_database_connection(conn)
        
        # Determine overall cluster health
        total = cluster_stats['total_clusters']
        active = cluster_stats['active_clusters']
        connected = cluster_stats['connected_clusters']
        
        if total == 0:
            cluster_health_status = "no_clusters"
        elif connected == active and pending_changes == 0:
            cluster_health_status = "healthy"
        elif connected > active * 0.7 or pending_changes < 10:  # 70% connected or few pending changes
            cluster_health_status = "warning"
        else:
            cluster_health_status = "critical"
        
        return {
            "status": cluster_health_status,
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": dict(cluster_stats),
            "pending_changes": pending_changes,
            "clusters": [
                {
                    "name": cluster['name'],
                    "active": cluster['is_active'],
                    "connection_status": cluster['connection_status'],
                    "last_connected": cluster['last_connected_at'].isoformat() if cluster['last_connected_at'] else None,
                    "haproxy_version": cluster['haproxy_version'],
                    "connection_age_seconds": int(cluster['seconds_since_connection']) if cluster['seconds_since_connection'] else None
                }
                for cluster in cluster_details
            ]
        }
        
    except Exception as e:
        logger.error(f"Cluster health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cluster health check failed: {str(e)}")

@router.get("/errors")
async def error_statistics():
    """Get application error statistics and metrics"""
    try:
        from middleware.error_handler import get_error_statistics
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error_metrics": get_error_statistics()
        }
        
    except Exception as e:
        logger.error(f"Error statistics check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Error statistics unavailable: {str(e)}")