"""
Dashboard Stats Service
Service layer for HAProxy dashboard statistics
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from utils.haproxy_stats_cache import haproxy_stats_cache
from utils.haproxy_stats_parser import haproxy_stats_parser
from database.connection import get_database_connection, close_database_connection

logger = logging.getLogger(__name__)


class DashboardStatsService:
    """Service for managing dashboard statistics"""
    
    def __init__(self):
        self.cache = haproxy_stats_cache
        self.parser = haproxy_stats_parser
    
    async def process_agent_stats(self, agent_name: str, cluster_id: int, 
                                  raw_stats_csv: Optional[str] = None,
                                  server_statuses: Optional[Dict[str, Dict[str, str]]] = None):
        """
        Process HAProxy stats from agent heartbeat
        
        Args:
            agent_name: Name of the agent
            cluster_id: Cluster ID
            raw_stats_csv: Raw CSV stats from HAProxy stats socket (optional)
            server_statuses: Server statuses from agent {backend: {server: status}} (optional)
        """
        try:
            # Log what we received from agent
            logger.info(f"📊 DASHBOARD STATS: Processing stats from agent '{agent_name}' (cluster {cluster_id})")
            logger.info(f"📊 DASHBOARD STATS: Has raw_stats_csv: {raw_stats_csv is not None and len(raw_stats_csv) > 0}")
            logger.info(f"📊 DASHBOARD STATS: Has server_statuses: {server_statuses is not None and len(server_statuses) > 0}")
            
            # If we have raw CSV stats, parse and cache them
            if raw_stats_csv:
                parsed = self.parser.parse_csv_stats(raw_stats_csv)
                logger.info(f"📊 DASHBOARD STATS: Parsed {len(parsed.get('frontends', {}))} frontends, "
                           f"{len(parsed.get('backends', {}))} backends, "
                           f"{len(parsed.get('servers', []))} servers")
                
                if parsed.get('frontends'):
                    logger.info(f"📊 DASHBOARD STATS: Frontend names: {list(parsed.get('frontends', {}).keys())}")
                if parsed.get('backends'):
                    logger.info(f"📊 DASHBOARD STATS: Backend names: {list(parsed.get('backends', {}).keys())}")
                
                # Cache frontends
                for frontend_name, frontend_stats in parsed.get('frontends', {}).items():
                    self.cache.cache_frontend_stats(cluster_id, frontend_name, frontend_stats)
                    
                    # Add to timeseries - requests
                    requests_total = frontend_stats.get('requests_total', 0)
                    logger.info(f"📊 REDIS WRITE: frontend:{frontend_name}:requests = {requests_total}")
                    self.cache.add_timeseries_metric(
                        cluster_id, 
                        f"frontend:{frontend_name}:requests",
                        requests_total
                    )
                    
                    # Add to timeseries - sessions
                    self.cache.add_timeseries_metric(
                        cluster_id,
                        f"frontend:{frontend_name}:sessions",
                        frontend_stats.get('current_sessions', 0)
                    )
                    
                    # Add to timeseries - errors
                    self.cache.add_timeseries_metric(
                        cluster_id,
                        f"frontend:{frontend_name}:errors_4xx",
                        frontend_stats.get('hrsp_4xx', 0)
                    )
                    self.cache.add_timeseries_metric(
                        cluster_id,
                        f"frontend:{frontend_name}:errors_5xx",
                        frontend_stats.get('hrsp_5xx', 0)
                    )
                    
                    # Add to timeseries - bytes
                    self.cache.add_timeseries_metric(
                        cluster_id,
                        f"frontend:{frontend_name}:bytes_in",
                        frontend_stats.get('bytes_in', 0)
                    )
                    self.cache.add_timeseries_metric(
                        cluster_id,
                        f"frontend:{frontend_name}:bytes_out",
                        frontend_stats.get('bytes_out', 0)
                    )
                
                # Cache backends
                for backend_name, backend_stats in parsed.get('backends', {}).items():
                    self.cache.cache_backend_stats(cluster_id, backend_name, backend_stats)
                    
                    # Add to timeseries - requests
                    backend_requests = backend_stats.get('requests_total', 0)
                    logger.info(f"📊 REDIS WRITE: backend:{backend_name}:requests = {backend_requests}")
                    self.cache.add_timeseries_metric(
                        cluster_id,
                        f"backend:{backend_name}:requests",
                        backend_requests
                    )
                    
                    # Add to timeseries - response time
                    backend_rtime = backend_stats.get('response_time_avg', 0)
                    logger.info(f"📊 REDIS WRITE: backend:{backend_name}:response_time = {backend_rtime}")
                    self.cache.add_timeseries_metric(
                        cluster_id,
                        f"backend:{backend_name}:response_time",
                        backend_rtime
                    )
                    
                    # Add to timeseries - sessions
                    self.cache.add_timeseries_metric(
                        cluster_id,
                        f"backend:{backend_name}:sessions",
                        backend_stats.get('current_sessions', 0)
                    )
                    
                    # Add to timeseries - queue
                    self.cache.add_timeseries_metric(
                        cluster_id,
                        f"backend:{backend_name}:queue",
                        backend_stats.get('queue_current', 0)
                    )
                
                # Cache servers
                for server in parsed.get('servers', []):
                    self.cache.cache_server_stats(
                        cluster_id,
                        server['backend'],
                        server['name'],
                        server
                    )
                
                # Cache raw stats
                self.cache.cache_raw_stats(cluster_id, agent_name, raw_stats_csv)
                
                # Update summary stats
                await self._update_summary_stats(cluster_id, parsed)
                
                logger.debug(f"Processed stats from agent {agent_name} for cluster {cluster_id}")
            
            # If we have server statuses from heartbeat, cache them
            elif server_statuses:
                servers = self.parser.parse_agent_heartbeat_stats(server_statuses)
                for server in servers:
                    self.cache.cache_server_stats(
                        cluster_id,
                        server['backend'],
                        server['name'],
                        server
                    )
                
                logger.debug(f"Processed server statuses from agent {agent_name} for cluster {cluster_id}")
        
        except Exception as e:
            logger.error(f"Failed to process agent stats: {e}")
    
    async def _update_summary_stats(self, cluster_id: int, parsed_data: Dict[str, Any]):
        """Update summary statistics for a cluster"""
        try:
            frontends = parsed_data.get('frontends', {})
            backends = parsed_data.get('backends', {})
            servers = parsed_data.get('servers', [])
            
            # Aggregate stats
            frontend_agg = self.parser.aggregate_frontend_stats(frontends)
            backend_agg = self.parser.aggregate_backend_stats(backends)
            
            # Server health
            servers_total = len(servers)
            servers_up = len([s for s in servers if s.get('status') == 'UP'])
            
            summary = {
                'cluster_id': cluster_id,
                'timestamp': datetime.utcnow().isoformat(),
                'frontends': {
                    'count': len(frontends),
                    'total_requests': frontend_agg.get('total_requests', 0),
                    'total_sessions': frontend_agg.get('total_sessions', 0),
                    'error_rate': frontend_agg.get('error_rate', 0)
                },
                'backends': {
                    'count': len(backends),
                    'total_requests': backend_agg.get('total_requests', 0),
                    'total_sessions': backend_agg.get('total_sessions', 0),
                    'avg_response_time': backend_agg.get('avg_response_time', 0)
                },
                'servers': {
                    'total': servers_total,
                    'up': servers_up,
                    'down': servers_total - servers_up,
                    'health_percentage': round((servers_up / servers_total * 100) if servers_total > 0 else 0, 1)
                }
            }
            
            self.cache.cache_summary_stats(cluster_id, summary)
            
        except Exception as e:
            logger.error(f"Failed to update summary stats: {e}")
    
    async def get_cluster_stats(self, cluster_id: int, 
                               frontend_filter: Optional[List[str]] = None,
                               backend_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Get comprehensive stats for a cluster with optional filters
        
        Args:
            cluster_id: Cluster ID
            frontend_filter: List of frontend names to filter (None = all)
            backend_filter: List of backend names to filter (None = all)
        
        Returns:
            Comprehensive stats dictionary
        """
        try:
            # Get summary stats from cache
            summary = self.cache.get_summary_stats(cluster_id)
            
            # Get all frontends
            all_frontends = self.cache.get_all_frontend_stats(cluster_id)
            
            # Apply frontend filter
            if frontend_filter:
                frontends = {k: v for k, v in all_frontends.items() if k in frontend_filter}
            else:
                frontends = all_frontends
            
            # Get all backends
            all_backends = self.cache.get_all_backend_stats(cluster_id)
            
            # Apply backend filter
            if backend_filter:
                backends = {k: v for k, v in all_backends.items() if k in backend_filter}
            else:
                backends = all_backends
            
            # Get servers (filter by backend if needed)
            all_servers = self.cache.get_all_server_stats(cluster_id)
            if backend_filter:
                servers = [s for s in all_servers if s.get('backend') in backend_filter]
            else:
                servers = all_servers
            
            # Get additional counts from database
            conn = await get_database_connection()
            
            # Get SSL certificate count
            ssl_count = await conn.fetchval(
                "SELECT COUNT(*) FROM ssl_certificates WHERE cluster_id = $1",
                cluster_id
            ) or 0
            
            # Get WAF rules count
            waf_count = await conn.fetchval(
                "SELECT COUNT(*) FROM waf_rules WHERE cluster_id = $1",
                cluster_id
            ) or 0
            
            await close_database_connection(conn)
            
            # Calculate aggregated metrics
            frontend_agg = self.parser.aggregate_frontend_stats(frontends)
            backend_agg = self.parser.aggregate_backend_stats(backends)
            
            # Response time percentiles
            response_time_percentiles = self.parser.calculate_response_time_percentiles(servers)
            
            # HTTP response code distribution
            total_2xx = sum(f.get('hrsp_2xx', 0) for f in frontends.values())
            total_3xx = sum(f.get('hrsp_3xx', 0) for f in frontends.values())
            total_4xx = sum(f.get('hrsp_4xx', 0) for f in frontends.values())
            total_5xx = sum(f.get('hrsp_5xx', 0) for f in frontends.values())
            total_responses = total_2xx + total_3xx + total_4xx + total_5xx
            
            return {
                'cluster_id': cluster_id,
                'timestamp': datetime.utcnow().isoformat(),
                'summary': summary or {},
                'kpi': {
                    'frontends_count': len(all_frontends),
                    'backends_count': len(all_backends),
                    'servers_total': len(all_servers),
                    'servers_up': len([s for s in all_servers if s.get('status') == 'UP']),
                    'ssl_certificates': ssl_count,
                    'waf_rules': waf_count
                },
                'frontends': {
                    'count': len(frontends),
                    'data': list(frontends.values()),
                    'aggregated': frontend_agg
                },
                'backends': {
                    'count': len(backends),
                    'data': list(backends.values()),
                    'aggregated': backend_agg
                },
                'servers': {
                    'count': len(servers),
                    'data': servers
                },
                'metrics': {
                    'response_time': response_time_percentiles,
                    'http_responses': {
                        '2xx': total_2xx,
                        '3xx': total_3xx,
                        '4xx': total_4xx,
                        '5xx': total_5xx,
                        'total': total_responses,
                        'distribution': {
                            '2xx_pct': round((total_2xx / total_responses * 100) if total_responses > 0 else 0, 1),
                            '3xx_pct': round((total_3xx / total_responses * 100) if total_responses > 0 else 0, 1),
                            '4xx_pct': round((total_4xx / total_responses * 100) if total_responses > 0 else 0, 1),
                            '5xx_pct': round((total_5xx / total_responses * 100) if total_responses > 0 else 0, 1)
                        }
                    },
                    'error_rate': frontend_agg.get('error_rate', 0)
                },
                'filters_applied': {
                    'frontends': frontend_filter,
                    'backends': backend_filter
                }
            }
        
        except Exception as e:
            logger.error(f"Failed to get cluster stats: {e}")
            return {
                'cluster_id': cluster_id,
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e)
            }
    
    async def get_timeseries_data(self, cluster_id: int, 
                                  metric_name: str,
                                  hours: int = 24,
                                  limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get time series data for a specific metric
        
        Args:
            cluster_id: Cluster ID
            metric_name: Metric name (e.g., "frontend:web:requests")
            hours: Number of hours to look back
            limit: Maximum number of data points to return (most recent)
        
        Returns:
            List of time series data points
        """
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            data = self.cache.get_timeseries_metrics(
                cluster_id,
                metric_name,
                start_time,
                end_time,
                limit
            )
            
            return data
        
        except Exception as e:
            logger.error(f"Failed to get timeseries data: {e}")
            return []
    
    async def get_frontend_list(self, cluster_id: int) -> List[str]:
        """Get list of available frontends for a cluster"""
        try:
            frontends = self.cache.get_all_frontend_stats(cluster_id)
            return list(frontends.keys())
        except Exception as e:
            logger.error(f"Failed to get frontend list: {e}")
            return []
    
    async def get_backend_list(self, cluster_id: int) -> List[str]:
        """Get list of available backends for a cluster"""
        try:
            backends = self.cache.get_all_backend_stats(cluster_id)
            return list(backends.keys())
        except Exception as e:
            logger.error(f"Failed to get backend list: {e}")
            return []
    
    async def get_slowest_backends(self, cluster_id: int, limit: int = 5) -> List[Dict[str, Any]]:
        """Get the slowest backends by response time"""
        try:
            backends = self.cache.get_all_backend_stats(cluster_id)
            
            # Sort by response time
            sorted_backends = sorted(
                backends.items(),
                key=lambda x: x[1].get('response_time_avg', 0),
                reverse=True
            )
            
            return [
                {
                    'name': name,
                    'response_time': stats.get('response_time_avg', 0),
                    'status': stats.get('status', 'UNKNOWN')
                }
                for name, stats in sorted_backends[:limit]
            ]
        
        except Exception as e:
            logger.error(f"Failed to get slowest backends: {e}")
            return []
    
    async def get_backend_health_matrix(self, cluster_id: int) -> List[Dict[str, Any]]:
        """Get backend health matrix for visualization"""
        try:
            backends = self.cache.get_all_backend_stats(cluster_id)
            
            health_matrix = []
            for name, stats in backends.items():
                health_matrix.append({
                    'name': name,
                    'status': stats.get('status', 'UNKNOWN'),
                    'health_percentage': stats.get('health_percentage', 0),
                    'servers_active': stats.get('servers_active', 0),
                    'servers_total': stats.get('servers_total', 0),
                    'response_time': stats.get('response_time_avg', 0),
                    'queue_current': stats.get('queue_current', 0),
                    'queue_max': stats.get('queue_max', 0)
                })
            
            return health_matrix
        
        except Exception as e:
            logger.error(f"Failed to get backend health matrix: {e}")
            return []
    
    async def get_requests_timeseries(self, cluster_id: int, hours: int = 24,
                                     frontend_filter: Optional[List[str]] = None,
                                     limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get request rate time series data for frontends"""
        try:
            # Get all frontends if no filter specified
            if not frontend_filter:
                frontends = self.cache.get_all_frontend_stats(cluster_id)
                frontend_filter = list(frontends.keys())
            
            # Collect timeseries data for each frontend
            all_data = []
            for frontend_name in frontend_filter:
                metric_name = f"frontend:{frontend_name}:requests"
                data = await self.get_timeseries_data(cluster_id, metric_name, hours, limit)
                
                # Add frontend name to each data point
                for point in data:
                    point['frontend'] = frontend_name
                    all_data.append(point)
            
            # Sort by timestamp
            all_data.sort(key=lambda x: x.get('timestamp', ''))
            
            return all_data
        
        except Exception as e:
            logger.error(f"Failed to get requests timeseries: {e}")
            return []
    
    async def get_response_time_timeseries(self, cluster_id: int, hours: int = 24,
                                          backend_filter: Optional[List[str]] = None,
                                          limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get response time trends (P50, P95, P99) for backends"""
        try:
            # Get all backends if no filter specified
            if not backend_filter:
                backends = self.cache.get_all_backend_stats(cluster_id)
                backend_filter = list(backends.keys())
            
            # Collect timeseries data for each backend
            all_data = []
            for backend_name in backend_filter:
                metric_name = f"backend:{backend_name}:response_time"
                data = await self.get_timeseries_data(cluster_id, metric_name, hours, limit)
                
                # Add backend name to each data point
                for point in data:
                    point['backend'] = backend_name
                    all_data.append(point)
            
            # Sort by timestamp
            all_data.sort(key=lambda x: x.get('timestamp', ''))
            
            return all_data
        
        except Exception as e:
            logger.error(f"Failed to get response time timeseries: {e}")
            return []
    
    async def get_error_timeseries(self, cluster_id: int, hours: int = 24, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get error rate trends (4xx and 5xx) over time"""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            # Get all frontends to aggregate error data
            frontends = self.cache.get_all_frontend_stats(cluster_id)
            
            # Collect error metrics from timeseries
            error_4xx_data = []
            error_5xx_data = []
            
            for frontend_name in frontends.keys():
                # Get 4xx errors
                metric_4xx = f"frontend:{frontend_name}:errors_4xx"
                data_4xx = self.cache.get_timeseries_metrics(cluster_id, metric_4xx, start_time, end_time, limit)
                error_4xx_data.extend(data_4xx)
                
                # Get 5xx errors
                metric_5xx = f"frontend:{frontend_name}:errors_5xx"
                data_5xx = self.cache.get_timeseries_metrics(cluster_id, metric_5xx, start_time, end_time, limit)
                error_5xx_data.extend(data_5xx)
            
            # Aggregate by timestamp
            from collections import defaultdict
            aggregated = defaultdict(lambda: {'errors_4xx': 0, 'errors_5xx': 0})
            
            for point in error_4xx_data:
                ts = point.get('timestamp')
                aggregated[ts]['errors_4xx'] += point.get('value', 0)
                aggregated[ts]['timestamp'] = ts
            
            for point in error_5xx_data:
                ts = point.get('timestamp')
                aggregated[ts]['errors_5xx'] += point.get('value', 0)
                aggregated[ts]['timestamp'] = ts
            
            # Convert to list and sort
            result = list(aggregated.values())
            result.sort(key=lambda x: x.get('timestamp', ''))
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to get error timeseries: {e}")
            return []
    
    async def get_realtime_throughput(self, cluster_id: int) -> Dict[str, Any]:
        """Get current bytes in/out rates and totals"""
        try:
            # Get all frontends for throughput calculation
            frontends = self.cache.get_all_frontend_stats(cluster_id)
            
            logger.info(f"THROUGHPUT: Cluster {cluster_id} - Found {len(frontends)} frontends in cache")
            
            total_bytes_in = 0
            total_bytes_out = 0
            
            for frontend_name, frontend_stats in frontends.items():
                bytes_in = frontend_stats.get('bytes_in', 0)
                bytes_out = frontend_stats.get('bytes_out', 0)
                total_bytes_in += bytes_in
                total_bytes_out += bytes_out
                logger.debug(f"THROUGHPUT: Frontend '{frontend_name}' - bytes_in={bytes_in}, bytes_out={bytes_out}")
            
            # Convert to MB and GB
            bytes_in_mb = round(total_bytes_in / (1024 * 1024), 2)
            bytes_out_mb = round(total_bytes_out / (1024 * 1024), 2)
            bytes_in_gb = round(total_bytes_in / (1024 * 1024 * 1024), 2)
            bytes_out_gb = round(total_bytes_out / (1024 * 1024 * 1024), 2)
            
            # Calculate rate (approximate based on last update)
            # This is a simplified calculation - for production, you'd want to track deltas
            rate_in_mbps = round(bytes_in_mb / 60, 2)  # Rough estimate per minute
            rate_out_mbps = round(bytes_out_mb / 60, 2)
            
            result = {
                'bytes_in': total_bytes_in,
                'bytes_out': total_bytes_out,
                'bytes_in_mb': bytes_in_mb,
                'bytes_out_mb': bytes_out_mb,
                'bytes_in_gb': bytes_in_gb,
                'bytes_out_gb': bytes_out_gb,
                'rate_in_mbps': rate_in_mbps,
                'rate_out_mbps': rate_out_mbps,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info(f"THROUGHPUT: Cluster {cluster_id} - Result: {bytes_in_gb}GB in, {bytes_out_gb}GB out, {rate_in_mbps}MB/s in, {rate_out_mbps}MB/s out")
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to get realtime throughput: {e}")
            return {}
    
    async def get_sessions_timeseries(self, cluster_id: int, hours: int = 24, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get active sessions over time"""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            # Get all frontends
            frontends = self.cache.get_all_frontend_stats(cluster_id)
            
            # Collect session metrics from timeseries
            all_session_data = []
            
            for frontend_name in frontends.keys():
                metric_name = f"frontend:{frontend_name}:sessions"
                data = self.cache.get_timeseries_metrics(cluster_id, metric_name, start_time, end_time, limit)
                all_session_data.extend(data)
            
            # Aggregate by timestamp
            from collections import defaultdict
            aggregated = defaultdict(lambda: {'sessions': 0, 'count': 0})
            
            for point in all_session_data:
                ts = point.get('timestamp')
                aggregated[ts]['sessions'] += point.get('value', 0)
                aggregated[ts]['count'] += 1
                aggregated[ts]['timestamp'] = ts
            
            # Convert to list and calculate averages
            result = []
            for data in aggregated.values():
                result.append({
                    'timestamp': data['timestamp'],
                    'sessions': data['sessions'],
                    'avg_sessions': round(data['sessions'] / data['count'], 2) if data['count'] > 0 else 0
                })
            
            # Sort by timestamp
            result.sort(key=lambda x: x.get('timestamp', ''))
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to get sessions timeseries: {e}")
            return []


# Global service instance
dashboard_stats_service = DashboardStatsService()

