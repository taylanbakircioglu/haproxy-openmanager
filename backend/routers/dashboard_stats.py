"""
Dashboard Stats Router
API endpoints for HAProxy statistics dashboard
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List
import logging

from services.dashboard_stats_service import dashboard_stats_service

router = APIRouter(prefix="/api/dashboard-stats", tags=["dashboard-stats"])
logger = logging.getLogger(__name__)


@router.get("/stats")
async def get_dashboard_stats(
    cluster_id: int = Query(..., description="Cluster ID to fetch stats for"),
    frontends: Optional[str] = Query(None, description="Comma-separated list of frontend names to filter"),
    backends: Optional[str] = Query(None, description="Comma-separated list of backend names to filter")
):
    """
    Get comprehensive HAProxy statistics for dashboard
    
    This endpoint provides real-time statistics from Redis cache including:
    - Frontend metrics (requests, sessions, response codes)
    - Backend metrics (health, response times, queues)
    - Server status and health
    - Aggregated KPIs
    """
    try:
        # Parse filters
        frontend_filter = frontends.split(',') if frontends else None
        backend_filter = backends.split(',') if backends else None
        
        # Get stats from service
        stats = await dashboard_stats_service.get_cluster_stats(
            cluster_id=cluster_id,
            frontend_filter=frontend_filter,
            backend_filter=backend_filter
        )
        
        return stats
    
    except Exception as e:
        logger.error(f"Failed to get dashboard stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/frontends")
async def get_frontend_list(
    cluster_id: int = Query(..., description="Cluster ID")
):
    """Get list of available frontends for a cluster"""
    try:
        frontends = await dashboard_stats_service.get_frontend_list(cluster_id)
        return {
            "cluster_id": cluster_id,
            "frontends": frontends,
            "count": len(frontends)
        }
    except Exception as e:
        logger.error(f"Failed to get frontend list: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/backends")
async def get_backend_list(
    cluster_id: int = Query(..., description="Cluster ID")
):
    """Get list of available backends for a cluster"""
    try:
        backends = await dashboard_stats_service.get_backend_list(cluster_id)
        return {
            "cluster_id": cluster_id,
            "backends": backends,
            "count": len(backends)
        }
    except Exception as e:
        logger.error(f"Failed to get backend list: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/backend-health")
async def get_backend_health(
    cluster_id: int = Query(..., description="Cluster ID")
):
    """Get backend health matrix for visualization"""
    try:
        health_matrix = await dashboard_stats_service.get_backend_health_matrix(cluster_id)
        return {
            "cluster_id": cluster_id,
            "backends": health_matrix,
            "count": len(health_matrix)
        }
    except Exception as e:
        logger.error(f"Failed to get backend health: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/slowest-backends")
async def get_slowest_backends(
    cluster_id: int = Query(..., description="Cluster ID"),
    limit: int = Query(5, description="Number of results to return", ge=1, le=20)
):
    """Get the slowest backends by response time"""
    try:
        slowest = await dashboard_stats_service.get_slowest_backends(cluster_id, limit)
        return {
            "cluster_id": cluster_id,
            "slowest_backends": slowest,
            "count": len(slowest)
        }
    except Exception as e:
        logger.error(f"Failed to get slowest backends: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/timeseries")
async def get_timeseries_data(
    cluster_id: int = Query(..., description="Cluster ID"),
    metric: str = Query(..., description="Metric name (e.g., 'frontend:web:requests')"),
    hours: int = Query(24, description="Number of hours to look back", ge=1, le=168)
):
    """
    Get time series data for a specific metric
    
    Metric naming convention:
    - Frontend requests: "frontend:{name}:requests"
    - Backend requests: "backend:{name}:requests"
    - Backend response time: "backend:{name}:response_time"
    """
    try:
        data = await dashboard_stats_service.get_timeseries_data(
            cluster_id=cluster_id,
            metric_name=metric,
            hours=hours
        )
        
        return {
            "cluster_id": cluster_id,
            "metric": metric,
            "hours": hours,
            "data_points": len(data),
            "data": data
        }
    except Exception as e:
        logger.error(f"Failed to get timeseries data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary")
async def get_summary_stats(
    cluster_id: int = Query(..., description="Cluster ID")
):
    """Get summary statistics for quick overview"""
    try:
        from utils.haproxy_stats_cache import haproxy_stats_cache
        
        summary = haproxy_stats_cache.get_summary_stats(cluster_id)
        
        if not summary:
            return {
                "cluster_id": cluster_id,
                "message": "No stats available yet. Waiting for agent data...",
                "frontends": {"count": 0},
                "backends": {"count": 0},
                "servers": {"total": 0, "up": 0, "down": 0}
            }
        
        return summary
    
    except Exception as e:
        logger.error(f"Failed to get summary stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/overview")
async def get_overview_metrics(
    cluster_id: int = Query(..., description="Cluster ID")
):
    """
    Get overview metrics for the dashboard header
    Returns: frontends_count, backends_count, servers_total, servers_up, ssl_certificates, waf_rules
    """
    try:
        from database.connection import get_database_connection, close_database_connection
        from utils.haproxy_stats_cache import haproxy_stats_cache
        
        # Get cached server stats
        all_servers = haproxy_stats_cache.get_all_server_stats(cluster_id)
        servers_total = len(all_servers)
        servers_up = len([s for s in all_servers if s.get('status') == 'UP'])
        
        # Get frontend/backend counts from cache
        frontends = haproxy_stats_cache.get_all_frontend_stats(cluster_id)
        backends = haproxy_stats_cache.get_all_backend_stats(cluster_id)
        
        # Get SSL and WAF counts from database
        conn = await get_database_connection()
        
        # Count SSL certificates for this cluster
        # Include: Global SSL (cluster_id IS NULL) + Cluster-specific SSL (junction table)
        ssl_count = await conn.fetchval("""
            SELECT COUNT(DISTINCT s.id)
            FROM ssl_certificates s
            LEFT JOIN ssl_certificate_clusters scc ON s.id = scc.ssl_certificate_id
            WHERE s.is_active = TRUE 
              AND (s.cluster_id IS NULL OR scc.cluster_id = $1)
        """, cluster_id) or 0
        
        # Count WAF rules for this cluster
        # Include: Global WAF (cluster_id IS NULL) + Cluster-specific WAF
        waf_count = await conn.fetchval("""
            SELECT COUNT(*)
            FROM waf_rules
            WHERE is_active = TRUE 
              AND (cluster_id IS NULL OR cluster_id = $1)
        """, cluster_id) or 0
        
        await close_database_connection(conn)
        
        return {
            "cluster_id": cluster_id,
            "frontends_count": len(frontends),
            "backends_count": len(backends),
            "servers_total": servers_total,
            "servers_up": servers_up,
            "servers_down": servers_total - servers_up,
            "ssl_certificates": ssl_count,
            "waf_rules": waf_count
        }
    
    except Exception as e:
        logger.error(f"Failed to get overview metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/timeseries/requests")
async def get_requests_timeseries(
    cluster_id: int = Query(..., description="Cluster ID"),
    hours: int = Query(24, description="Number of hours to look back", ge=1, le=168),
    frontends: Optional[str] = Query(None, description="Comma-separated list of frontend names"),
    limit: Optional[int] = Query(None, description="Max number of data points to return", ge=10, le=500)
):
    """
    Get request rate time series data for frontends (optimized with limit)
    Returns data points with timestamp and request counts
    """
    try:
        frontend_list = frontends.split(',') if frontends else None
        data = await dashboard_stats_service.get_requests_timeseries(
            cluster_id=cluster_id,
            hours=hours,
            frontend_filter=frontend_list,
            limit=limit
        )
        
        return {
            "cluster_id": cluster_id,
            "hours": hours,
            "frontends": frontend_list,
            "limit": limit,
            "data_points": len(data),
            "data": data
        }
    except Exception as e:
        logger.error(f"Failed to get requests timeseries: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/timeseries/response-time")
async def get_response_time_timeseries(
    cluster_id: int = Query(..., description="Cluster ID"),
    hours: int = Query(24, description="Number of hours to look back", ge=1, le=168),
    backends: Optional[str] = Query(None, description="Comma-separated list of backend names"),
    limit: Optional[int] = Query(None, description="Max number of data points to return", ge=10, le=10000)
):
    """
    Get response time trends (P50, P95, P99) for backends (optimized with limit)
    Returns percentile data over time
    """
    try:
        backend_list = backends.split(',') if backends else None
        data = await dashboard_stats_service.get_response_time_timeseries(
            cluster_id=cluster_id,
            hours=hours,
            backend_filter=backend_list,
            limit=limit
        )
        
        return {
            "cluster_id": cluster_id,
            "hours": hours,
            "backends": backend_list,
            "limit": limit,
            "data_points": len(data),
            "data": data
        }
    except Exception as e:
        logger.error(f"Failed to get response time timeseries: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/timeseries/errors")
async def get_error_timeseries(
    cluster_id: int = Query(..., description="Cluster ID"),
    hours: int = Query(24, description="Number of hours to look back", ge=1, le=168),
    limit: Optional[int] = Query(None, description="Max number of data points to return", ge=10, le=500)
):
    """
    Get error rate trends (4xx and 5xx) over time (optimized with limit)
    Returns HTTP error code distribution
    """
    try:
        data = await dashboard_stats_service.get_error_timeseries(
            cluster_id=cluster_id,
            hours=hours,
            limit=limit
        )
        
        return {
            "cluster_id": cluster_id,
            "hours": hours,
            "limit": limit,
            "data_points": len(data),
            "data": data
        }
    except Exception as e:
        logger.error(f"Failed to get error timeseries: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/realtime/throughput")
async def get_realtime_throughput(
    cluster_id: int = Query(..., description="Cluster ID")
):
    """
    Get current bytes in/out rates and totals
    Returns real-time throughput metrics
    """
    try:
        data = await dashboard_stats_service.get_realtime_throughput(cluster_id)
        
        return {
            "cluster_id": cluster_id,
            "throughput": data
        }
    except Exception as e:
        logger.error(f"Failed to get realtime throughput: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/timeseries/sessions")
async def get_sessions_timeseries(
    cluster_id: int = Query(..., description="Cluster ID"),
    hours: int = Query(24, description="Number of hours to look back", ge=1, le=168),
    limit: Optional[int] = Query(None, description="Max number of data points to return", ge=10, le=500)
):
    """
    Get active sessions over time (optimized with limit)
    Returns session count trends
    """
    try:
        data = await dashboard_stats_service.get_sessions_timeseries(
            cluster_id=cluster_id,
            hours=hours,
            limit=limit
        )
        
        return {
            "cluster_id": cluster_id,
            "hours": hours,
            "data_points": len(data),
            "data": data
        }
    except Exception as e:
        logger.error(f"Failed to get sessions timeseries: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/status")
async def get_agents_status(
    cluster_id: int = Query(..., description="Cluster ID")
):
    """
    Get real-time agent health status for cluster
    Returns agent names, last seen, health status
    """
    try:
        from database.connection import get_database_connection, close_database_connection
        import time
        from datetime import datetime
        
        conn = await get_database_connection()
        
        # Get agents for this cluster
        agents = await conn.fetch("""
            SELECT 
                a.id, a.name, a.platform, a.version, a.status,
                a.last_seen, a.enabled, a.pool_id
            FROM agents a
            JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
            WHERE hc.id = $1
            ORDER BY a.name
        """, cluster_id)
        
        await close_database_connection(conn)
        
        # Calculate health for each agent
        agent_status_list = []
        for agent in agents:
            last_seen = agent['last_seen']
            status = agent['status']
            
            # Calculate time difference
            if last_seen:
                time_diff = time.time() - last_seen.timestamp()
                seconds_ago = int(time_diff)
                
                # Determine health status
                if status == "online" and time_diff < 30:
                    health = "healthy"
                    health_percentage = 100
                elif status == "online" and time_diff < 60:
                    health = "warning"
                    health_percentage = 75
                elif status == "online" and time_diff < 120:
                    health = "degraded"
                    health_percentage = 50
                else:
                    health = "offline"
                    health_percentage = 0
            else:
                health = "unknown"
                health_percentage = 0
                seconds_ago = None
            
            agent_status_list.append({
                "id": agent['id'],
                "name": agent['name'],
                "platform": agent['platform'],
                "version": agent['version'],
                "status": status,
                "health": health,
                "health_percentage": health_percentage,
                "last_seen": last_seen.isoformat() if last_seen else None,
                "seconds_ago": seconds_ago,
                "enabled": agent['enabled']
            })
        
        return {
            "cluster_id": cluster_id,
            "agents": agent_status_list,
            "total_agents": len(agent_status_list),
            "healthy_agents": len([a for a in agent_status_list if a['health'] == 'healthy']),
            "warning_agents": len([a for a in agent_status_list if a['health'] == 'warning']),
            "offline_agents": len([a for a in agent_status_list if a['health'] == 'offline'])
        }
    
    except Exception as e:
        logger.error(f"Failed to get agent status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

