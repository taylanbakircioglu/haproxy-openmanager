"""
HAProxy Stats Cache Manager
Handles caching of HAProxy statistics in Redis for performance optimization
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from database.connection import redis_client

logger = logging.getLogger(__name__)

# Redis key prefixes
STATS_PREFIX = "haproxy:stats"
METRICS_PREFIX = "haproxy:metrics"

# TTL values (in seconds)
# Agent sends heartbeat every 30s, so TTL must be 3x to avoid race conditions
TTL_REALTIME = 90  # 90 seconds for real-time stats (3x agent heartbeat)
TTL_SHORT = 600  # 10 minutes for short-term data
TTL_MEDIUM = 3600  # 1 hour for medium-term data
TTL_LONG = 86400  # 24 hours for long-term data


class HAProxyStatsCache:
    """Manager for HAProxy statistics caching in Redis"""
    
    def __init__(self):
        self.redis = redis_client
    
    def _get_key(self, key_type: str, cluster_id: int, suffix: str = "") -> str:
        """Generate Redis key with consistent format"""
        base_key = f"{STATS_PREFIX}:{cluster_id}:{key_type}"
        return f"{base_key}:{suffix}" if suffix else base_key
    
    def _safe_json_encode(self, data: Any) -> str:
        """Safely encode data to JSON"""
        try:
            return json.dumps(data, default=str)
        except Exception as e:
            logger.error(f"JSON encoding error: {e}")
            return json.dumps({})
    
    def _safe_json_decode(self, data: str) -> Any:
        """Safely decode JSON data"""
        try:
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"JSON decoding error: {e}")
            return None
    
    # ============ Summary Stats ============
    
    def cache_summary_stats(self, cluster_id: int, stats: Dict[str, Any], ttl: int = TTL_REALTIME):
        """Cache summary statistics for a cluster"""
        try:
            key = self._get_key("summary", cluster_id)
            value = self._safe_json_encode(stats)
            self.redis.setex(key, ttl, value)
            logger.debug(f"Cached summary stats for cluster {cluster_id}")
        except Exception as e:
            logger.error(f"Failed to cache summary stats: {e}")
    
    def get_summary_stats(self, cluster_id: int) -> Optional[Dict[str, Any]]:
        """Get cached summary statistics"""
        try:
            key = self._get_key("summary", cluster_id)
            data = self.redis.get(key)
            return self._safe_json_decode(data) if data else None
        except Exception as e:
            logger.error(f"Failed to get summary stats: {e}")
            return None
    
    # ============ Frontend Stats ============
    
    def cache_frontend_stats(self, cluster_id: int, frontend_name: str, stats: Dict[str, Any], ttl: int = TTL_REALTIME):
        """Cache frontend statistics"""
        try:
            key = self._get_key("frontend", cluster_id, frontend_name)
            value = self._safe_json_encode(stats)
            self.redis.setex(key, ttl, value)
            
            # Also add to frontend list
            list_key = self._get_key("frontends", cluster_id)
            self.redis.sadd(list_key, frontend_name)
            self.redis.expire(list_key, ttl)
            
            bytes_in = stats.get('bytes_in', 0)
            bytes_out = stats.get('bytes_out', 0)
            logger.info(f"✍️  CACHE WRITE: Frontend '{frontend_name}' (cluster {cluster_id}) - bytes_in={bytes_in}, bytes_out={bytes_out}, key='{key}'")
        except Exception as e:
            logger.error(f"Failed to cache frontend stats: {e}")
    
    def get_frontend_stats(self, cluster_id: int, frontend_name: str) -> Optional[Dict[str, Any]]:
        """Get cached frontend statistics"""
        try:
            key = self._get_key("frontend", cluster_id, frontend_name)
            data = self.redis.get(key)
            return self._safe_json_decode(data) if data else None
        except Exception as e:
            logger.error(f"Failed to get frontend stats: {e}")
            return None
    
    def get_all_frontend_stats(self, cluster_id: int) -> Dict[str, Dict[str, Any]]:
        """Get all cached frontend statistics for a cluster"""
        try:
            list_key = self._get_key("frontends", cluster_id)
            frontend_names = self.redis.smembers(list_key)
            
            logger.info(f"🔍 CACHE READ: Cluster {cluster_id} - list_key='{list_key}', found {len(frontend_names)} frontend names")
            
            result = {}
            for name in frontend_names:
                name_str = name.decode('utf-8') if isinstance(name, bytes) else name
                stats = self.get_frontend_stats(cluster_id, name_str)
                if stats:
                    bytes_in = stats.get('bytes_in', 0)
                    bytes_out = stats.get('bytes_out', 0)
                    logger.debug(f"🔍 CACHE READ: Frontend '{name_str}' - bytes_in={bytes_in}, bytes_out={bytes_out}")
                    result[name_str] = stats
                else:
                    logger.warning(f"🔍 CACHE READ: Frontend '{name_str}' - NO STATS FOUND")
            
            return result
        except Exception as e:
            logger.error(f"Failed to get all frontend stats: {e}")
            return {}
    
    # ============ Backend Stats ============
    
    def cache_backend_stats(self, cluster_id: int, backend_name: str, stats: Dict[str, Any], ttl: int = TTL_REALTIME):
        """Cache backend statistics"""
        try:
            key = self._get_key("backend", cluster_id, backend_name)
            value = self._safe_json_encode(stats)
            self.redis.setex(key, ttl, value)
            
            # Also add to backend list
            list_key = self._get_key("backends", cluster_id)
            self.redis.sadd(list_key, backend_name)
            self.redis.expire(list_key, ttl)
            
            logger.debug(f"Cached backend stats for {backend_name} in cluster {cluster_id}")
        except Exception as e:
            logger.error(f"Failed to cache backend stats: {e}")
    
    def get_backend_stats(self, cluster_id: int, backend_name: str) -> Optional[Dict[str, Any]]:
        """Get cached backend statistics"""
        try:
            key = self._get_key("backend", cluster_id, backend_name)
            data = self.redis.get(key)
            return self._safe_json_decode(data) if data else None
        except Exception as e:
            logger.error(f"Failed to get backend stats: {e}")
            return None
    
    def get_all_backend_stats(self, cluster_id: int) -> Dict[str, Dict[str, Any]]:
        """Get all cached backend statistics for a cluster"""
        try:
            list_key = self._get_key("backends", cluster_id)
            backend_names = self.redis.smembers(list_key)
            
            result = {}
            for name in backend_names:
                name_str = name.decode('utf-8') if isinstance(name, bytes) else name
                stats = self.get_backend_stats(cluster_id, name_str)
                if stats:
                    result[name_str] = stats
            
            return result
        except Exception as e:
            logger.error(f"Failed to get all backend stats: {e}")
            return {}
    
    # ============ Server Stats ============
    
    def cache_server_stats(self, cluster_id: int, backend_name: str, server_name: str, 
                          stats: Dict[str, Any], ttl: int = TTL_REALTIME):
        """Cache server statistics"""
        try:
            key = self._get_key("server", cluster_id, f"{backend_name}:{server_name}")
            value = self._safe_json_encode(stats)
            self.redis.setex(key, ttl, value)
            
            # Also add to server list for the backend
            list_key = self._get_key("servers", cluster_id, backend_name)
            self.redis.sadd(list_key, server_name)
            self.redis.expire(list_key, ttl)
            
            logger.debug(f"Cached server stats for {backend_name}/{server_name} in cluster {cluster_id}")
        except Exception as e:
            logger.error(f"Failed to cache server stats: {e}")
    
    def get_server_stats(self, cluster_id: int, backend_name: str, server_name: str) -> Optional[Dict[str, Any]]:
        """Get cached server statistics"""
        try:
            key = self._get_key("server", cluster_id, f"{backend_name}:{server_name}")
            data = self.redis.get(key)
            return self._safe_json_decode(data) if data else None
        except Exception as e:
            logger.error(f"Failed to get server stats: {e}")
            return None
    
    def get_all_server_stats(self, cluster_id: int) -> List[Dict[str, Any]]:
        """Get all cached server statistics for a cluster"""
        try:
            # Get all backends
            backends_key = self._get_key("backends", cluster_id)
            backend_names = self.redis.smembers(backends_key)
            
            result = []
            for backend_name in backend_names:
                backend_str = backend_name.decode('utf-8') if isinstance(backend_name, bytes) else backend_name
                
                # Get servers for this backend
                servers_key = self._get_key("servers", cluster_id, backend_str)
                server_names = self.redis.smembers(servers_key)
                
                for server_name in server_names:
                    server_str = server_name.decode('utf-8') if isinstance(server_name, bytes) else server_name
                    stats = self.get_server_stats(cluster_id, backend_str, server_str)
                    if stats:
                        stats['backend'] = backend_str
                        stats['name'] = server_str
                        result.append(stats)
            
            return result
        except Exception as e:
            logger.error(f"Failed to get all server stats: {e}")
            return []
    
    # ============ Time Series Metrics ============
    
    def add_timeseries_metric(self, cluster_id: int, metric_name: str, value: float, 
                             timestamp: Optional[datetime] = None, ttl: int = TTL_LONG):
        """Add a time series metric point"""
        try:
            if timestamp is None:
                timestamp = datetime.utcnow()
            
            key = self._get_key("timeseries", cluster_id, metric_name)
            score = timestamp.timestamp()
            member = json.dumps({"value": value, "timestamp": timestamp.isoformat()})
            
            # Add to sorted set
            self.redis.zadd(key, {member: score})
            self.redis.expire(key, ttl)
            
            # Cleanup old entries (keep last 24 hours)
            cutoff = (datetime.utcnow() - timedelta(hours=24)).timestamp()
            self.redis.zremrangebyscore(key, 0, cutoff)
            
            logger.debug(f"Added timeseries metric {metric_name} for cluster {cluster_id}")
        except Exception as e:
            logger.error(f"Failed to add timeseries metric: {e}")
    
    def get_timeseries_metrics(self, cluster_id: int, metric_name: str, 
                              start_time: Optional[datetime] = None,
                              end_time: Optional[datetime] = None,
                              limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get time series metrics for a given time range with optional limit"""
        try:
            key = self._get_key("timeseries", cluster_id, metric_name)
            
            # Default to last 24 hours if no time range specified
            if end_time is None:
                end_time = datetime.utcnow()
            if start_time is None:
                start_time = end_time - timedelta(hours=24)
            
            min_score = start_time.timestamp()
            max_score = end_time.timestamp()
            
            # Get data from sorted set (in reverse order to get most recent first if limiting)
            if limit and limit > 0:
                # Get most recent N points
                data = self.redis.zrevrangebyscore(key, max_score, min_score, start=0, num=limit)
                data = list(reversed(data))  # Reverse back to chronological order
            else:
                data = self.redis.zrangebyscore(key, min_score, max_score)
            
            result = []
            for item in data:
                try:
                    decoded = item.decode('utf-8') if isinstance(item, bytes) else item
                    point = json.loads(decoded)
                    result.append(point)
                except Exception as e:
                    logger.warning(f"Failed to decode timeseries point: {e}")
            
            return result
        except Exception as e:
            logger.error(f"Failed to get timeseries metrics: {e}")
            return []
    
    # ============ Raw Stats Storage ============
    
    def cache_raw_stats(self, cluster_id: int, agent_name: str, raw_stats: str, ttl: int = TTL_SHORT):
        """Cache raw HAProxy stats CSV output"""
        try:
            key = self._get_key("raw", cluster_id, agent_name)
            self.redis.setex(key, ttl, raw_stats)
            logger.debug(f"Cached raw stats for agent {agent_name} in cluster {cluster_id}")
        except Exception as e:
            logger.error(f"Failed to cache raw stats: {e}")
    
    def get_raw_stats(self, cluster_id: int, agent_name: str) -> Optional[str]:
        """Get cached raw HAProxy stats"""
        try:
            key = self._get_key("raw", cluster_id, agent_name)
            data = self.redis.get(key)
            return data.decode('utf-8') if data else None
        except Exception as e:
            logger.error(f"Failed to get raw stats: {e}")
            return None
    
    # ============ Aggregation Helpers ============
    
    def aggregate_cluster_stats(self, cluster_id: int) -> Dict[str, Any]:
        """Aggregate all stats for a cluster"""
        try:
            # Get all frontend stats
            frontends = self.get_all_frontend_stats(cluster_id)
            
            # Get all backend stats
            backends = self.get_all_backend_stats(cluster_id)
            
            # Get all server stats
            servers = self.get_all_server_stats(cluster_id)
            
            # Calculate aggregated metrics
            total_requests = sum(f.get('requests_total', 0) for f in frontends.values())
            total_sessions = sum(f.get('current_sessions', 0) for f in frontends.values())
            total_bytes_in = sum(f.get('bytes_in', 0) for f in frontends.values())
            total_bytes_out = sum(f.get('bytes_out', 0) for f in frontends.values())
            
            # Server health
            servers_total = len(servers)
            servers_up = len([s for s in servers if s.get('status') == 'UP'])
            
            # Calculate average response time
            response_times = [s.get('response_time', 0) for s in servers if s.get('response_time', 0) > 0]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
            
            return {
                'cluster_id': cluster_id,
                'timestamp': datetime.utcnow().isoformat(),
                'frontends': {
                    'count': len(frontends),
                    'data': list(frontends.values())
                },
                'backends': {
                    'count': len(backends),
                    'data': list(backends.values())
                },
                'servers': {
                    'total': servers_total,
                    'up': servers_up,
                    'down': servers_total - servers_up,
                    'data': servers
                },
                'metrics': {
                    'total_requests': total_requests,
                    'total_sessions': total_sessions,
                    'total_bytes_in': total_bytes_in,
                    'total_bytes_out': total_bytes_out,
                    'avg_response_time': round(avg_response_time, 2)
                }
            }
        except Exception as e:
            logger.error(f"Failed to aggregate cluster stats: {e}")
            return {}
    
    # ============ Cleanup ============
    
    def clear_cluster_stats(self, cluster_id: int):
        """Clear all cached stats for a cluster"""
        try:
            pattern = f"{STATS_PREFIX}:{cluster_id}:*"
            keys = self.redis.keys(pattern)
            if keys:
                self.redis.delete(*keys)
                logger.info(f"Cleared {len(keys)} cache keys for cluster {cluster_id}")
        except Exception as e:
            logger.error(f"Failed to clear cluster stats: {e}")


# Global instance
haproxy_stats_cache = HAProxyStatsCache()

