"""
HAProxy Stats Parser
Parses HAProxy statistics from CSV format (from stats socket output)
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import csv
import io

logger = logging.getLogger(__name__)


class HAProxyStatsParser:
    """Parser for HAProxy stats socket CSV output"""
    
    # HAProxy stat types
    TYPE_FRONTEND = 0
    TYPE_BACKEND = 1
    TYPE_SERVER = 2
    TYPE_LISTENER = 3
    
    def __init__(self):
        """Initialize the parser"""
        self.parsed_data = {
            'frontends': {},
            'backends': {},
            'servers': []
        }
    
    def parse_csv_stats(self, csv_data: str) -> Dict[str, Any]:
        """
        Parse HAProxy stats CSV output
        
        CSV Format from 'show stat' command:
        # pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,
        status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,
        type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,
        hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,
        comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,...
        """
        try:
            if not csv_data or not csv_data.strip():
                logger.warning("Empty CSV data received")
                return self._empty_result()
            
            # Parse CSV
            reader = csv.DictReader(io.StringIO(csv_data))
            
            frontends = {}
            backends = {}
            servers = []
            
            for row in reader:
                try:
                    # Skip comment lines
                    if not row or row.get('# pxname', '').startswith('#'):
                        continue
                    
                    pxname = row.get('# pxname') or row.get('pxname', '')
                    svname = row.get('svname', '')
                    stat_type = self._safe_int(row.get('type'))
                    
                    if stat_type == self.TYPE_FRONTEND:
                        frontends[pxname] = self._parse_frontend(row)
                    
                    elif stat_type == self.TYPE_BACKEND:
                        backends[pxname] = self._parse_backend(row)
                    
                    elif stat_type == self.TYPE_SERVER:
                        server = self._parse_server(row)
                        if server:
                            servers.append(server)
                
                except Exception as e:
                    logger.warning(f"Failed to parse stats row: {e}")
                    continue
            
            return {
                'frontends': frontends,
                'backends': backends,
                'servers': servers,
                'timestamp': datetime.utcnow().isoformat(),
                'parsed_at': datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to parse HAProxy stats CSV: {e}")
            return self._empty_result()
    
    def _parse_frontend(self, row: Dict[str, str]) -> Dict[str, Any]:
        """Parse frontend statistics"""
        pxname = row.get('# pxname') or row.get('pxname', '')
        
        return {
            'name': pxname,
            'status': row.get('status', 'UNKNOWN'),
            'requests_total': self._safe_int(row.get('stot', 0)),
            'requests_rate': self._safe_int(row.get('req_rate', 0)),
            'requests_rate_max': self._safe_int(row.get('req_rate_max', 0)),
            'requests_total_http': self._safe_int(row.get('req_tot', 0)),
            'current_sessions': self._safe_int(row.get('scur', 0)),
            'max_sessions': self._safe_int(row.get('smax', 0)),
            'session_limit': self._safe_int(row.get('slim', 0)),
            'session_rate': self._safe_int(row.get('rate', 0)),
            'session_rate_max': self._safe_int(row.get('rate_max', 0)),
            'bytes_in': self._safe_int(row.get('bin', 0)),
            'bytes_out': self._safe_int(row.get('bout', 0)),
            'requests_denied': self._safe_int(row.get('dreq', 0)),
            'responses_denied': self._safe_int(row.get('dresp', 0)),
            'request_errors': self._safe_int(row.get('ereq', 0)),
            'hrsp_1xx': self._safe_int(row.get('hrsp_1xx', 0)),
            'hrsp_2xx': self._safe_int(row.get('hrsp_2xx', 0)),
            'hrsp_3xx': self._safe_int(row.get('hrsp_3xx', 0)),
            'hrsp_4xx': self._safe_int(row.get('hrsp_4xx', 0)),
            'hrsp_5xx': self._safe_int(row.get('hrsp_5xx', 0)),
            'hrsp_other': self._safe_int(row.get('hrsp_other', 0)),
            'connection_errors': self._safe_int(row.get('econ', 0)),
            'response_errors': self._safe_int(row.get('eresp', 0)),
            'type': 'frontend'
        }
    
    def _parse_backend(self, row: Dict[str, str]) -> Dict[str, Any]:
        """Parse backend statistics"""
        pxname = row.get('# pxname') or row.get('pxname', '')
        
        # Calculate health percentage
        active = self._safe_int(row.get('act', 0))
        backup = self._safe_int(row.get('bck', 0))
        total_servers = active + backup
        health_percentage = (active / total_servers * 100) if total_servers > 0 else 0
        
        return {
            'name': pxname,
            'status': row.get('status', 'UNKNOWN'),
            'requests_total': self._safe_int(row.get('stot', 0)),
            'current_sessions': self._safe_int(row.get('scur', 0)),
            'max_sessions': self._safe_int(row.get('smax', 0)),
            'session_limit': self._safe_int(row.get('slim', 0)),
            'session_rate': self._safe_int(row.get('rate', 0)),
            'queue_current': self._safe_int(row.get('qcur', 0)),
            'queue_max': self._safe_int(row.get('qmax', 0)),
            'servers_active': active,
            'servers_backup': backup,
            'servers_total': total_servers,
            'health_percentage': round(health_percentage, 1),
            'bytes_in': self._safe_int(row.get('bin', 0)),
            'bytes_out': self._safe_int(row.get('bout', 0)),
            'requests_denied': self._safe_int(row.get('dreq', 0)),
            'responses_denied': self._safe_int(row.get('dresp', 0)),
            'connection_errors': self._safe_int(row.get('econ', 0)),
            'response_errors': self._safe_int(row.get('eresp', 0)),
            'retry_warnings': self._safe_int(row.get('wretr', 0)),
            'redispatch_warnings': self._safe_int(row.get('wredis', 0)),
            'hrsp_1xx': self._safe_int(row.get('hrsp_1xx', 0)),
            'hrsp_2xx': self._safe_int(row.get('hrsp_2xx', 0)),
            'hrsp_3xx': self._safe_int(row.get('hrsp_3xx', 0)),
            'hrsp_4xx': self._safe_int(row.get('hrsp_4xx', 0)),
            'hrsp_5xx': self._safe_int(row.get('hrsp_5xx', 0)),
            'hrsp_other': self._safe_int(row.get('hrsp_other', 0)),
            'client_aborts': self._safe_int(row.get('cli_abrt', 0)),
            'server_aborts': self._safe_int(row.get('srv_abrt', 0)),
            'last_session': self._safe_int(row.get('lastsess', 0)),
            'response_time_avg': self._safe_int(row.get('rtime', 0)),
            'connect_time_avg': self._safe_int(row.get('ctime', 0)),
            'queue_time_avg': self._safe_int(row.get('qtime', 0)),
            'total_time_avg': self._safe_int(row.get('ttime', 0)),
            'type': 'backend'
        }
    
    def _parse_server(self, row: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Parse server statistics"""
        pxname = row.get('# pxname') or row.get('pxname', '')
        svname = row.get('svname', '')
        
        if not svname or svname == 'BACKEND' or svname == 'FRONTEND':
            return None
        
        status = row.get('status', 'UNKNOWN')
        
        return {
            'backend': pxname,
            'name': svname,
            'status': status,
            'weight': self._safe_int(row.get('weight', 0)),
            'current_sessions': self._safe_int(row.get('scur', 0)),
            'max_sessions': self._safe_int(row.get('smax', 0)),
            'session_limit': self._safe_int(row.get('slim', 0)),
            'requests_total': self._safe_int(row.get('stot', 0)),
            'bytes_in': self._safe_int(row.get('bin', 0)),
            'bytes_out': self._safe_int(row.get('bout', 0)),
            'requests_denied': self._safe_int(row.get('dreq', 0)),
            'responses_denied': self._safe_int(row.get('dresp', 0)),
            'connection_errors': self._safe_int(row.get('econ', 0)),
            'response_errors': self._safe_int(row.get('eresp', 0)),
            'check_status': row.get('check_status', ''),
            'check_code': row.get('check_code', ''),
            'check_duration': self._safe_int(row.get('check_duration', 0)),
            'last_check': row.get('last_chk', ''),
            'downtime': self._safe_int(row.get('downtime', 0)),
            'downtime_total': self._safe_int(row.get('downtime', 0)),
            'check_fail': self._safe_int(row.get('chkfail', 0)),
            'check_down': self._safe_int(row.get('chkdown', 0)),
            'last_change': self._safe_int(row.get('lastchg', 0)),
            'throttle': self._safe_int(row.get('throttle', 0)),
            'selected_total': self._safe_int(row.get('lbtot', 0)),
            'hrsp_1xx': self._safe_int(row.get('hrsp_1xx', 0)),
            'hrsp_2xx': self._safe_int(row.get('hrsp_2xx', 0)),
            'hrsp_3xx': self._safe_int(row.get('hrsp_3xx', 0)),
            'hrsp_4xx': self._safe_int(row.get('hrsp_4xx', 0)),
            'hrsp_5xx': self._safe_int(row.get('hrsp_5xx', 0)),
            'hrsp_other': self._safe_int(row.get('hrsp_other', 0)),
            'client_aborts': self._safe_int(row.get('cli_abrt', 0)),
            'server_aborts': self._safe_int(row.get('srv_abrt', 0)),
            'last_session': self._safe_int(row.get('lastsess', 0)),
            'response_time': self._safe_int(row.get('rtime', 0)),
            'connect_time': self._safe_int(row.get('ctime', 0)),
            'queue_time': self._safe_int(row.get('qtime', 0)),
            'total_time': self._safe_int(row.get('ttime', 0)),
            'address': row.get('addr', ''),
            'cookie': row.get('cookie', ''),
            'mode': row.get('mode', ''),
            'algorithm': row.get('algo', ''),
            'type': 'server'
        }
    
    def parse_agent_heartbeat_stats(self, server_statuses: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Parse server statuses from agent heartbeat
        Format: {backend_name: {server_name: status}}
        """
        servers = []
        
        try:
            for backend_name, backend_servers in server_statuses.items():
                for server_name, status in backend_servers.items():
                    servers.append({
                        'backend': backend_name,
                        'name': server_name,
                        'status': status,
                        'source': 'agent_heartbeat'
                    })
            
            return servers
        
        except Exception as e:
            logger.error(f"Failed to parse agent heartbeat stats: {e}")
            return []
    
    def calculate_error_rate(self, stats: Dict[str, Any]) -> float:
        """Calculate error rate from HTTP response codes
        
        Returns error rate only if there are enough responses to be meaningful.
        For very low traffic (< 100 responses), error rate can be misleading.
        """
        try:
            total_responses = (
                stats.get('hrsp_1xx', 0) +
                stats.get('hrsp_2xx', 0) +
                stats.get('hrsp_3xx', 0) +
                stats.get('hrsp_4xx', 0) +
                stats.get('hrsp_5xx', 0) +
                stats.get('hrsp_other', 0)
            )
            
            # Return 0 if no traffic
            if total_responses == 0:
                return 0.0
            
            # For very low traffic, error rate can be misleading
            # Example: 1 error out of 1 request = 100% error rate (not meaningful)
            if total_responses < 100:
                return 0.0  # Don't show error rate for low traffic
            
            error_responses = (
                stats.get('hrsp_4xx', 0) +
                stats.get('hrsp_5xx', 0)
            )
            
            error_rate = (error_responses / total_responses) * 100
            return round(error_rate, 2)
        
        except Exception as e:
            logger.error(f"Failed to calculate error rate: {e}")
            return 0.0
    
    def calculate_response_time_percentiles(self, servers: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate response time percentiles from server data"""
        try:
            response_times = [
                s.get('response_time', 0) 
                for s in servers 
                if s.get('response_time', 0) > 0
            ]
            
            if not response_times:
                return {'p50': 0, 'p95': 0, 'p99': 0, 'avg': 0}
            
            response_times.sort()
            count = len(response_times)
            
            return {
                'p50': response_times[int(count * 0.5)],
                'p95': response_times[int(count * 0.95)] if count > 1 else response_times[0],
                'p99': response_times[int(count * 0.99)] if count > 1 else response_times[0],
                'avg': round(sum(response_times) / count, 2)
            }
        
        except Exception as e:
            logger.error(f"Failed to calculate percentiles: {e}")
            return {'p50': 0, 'p95': 0, 'p99': 0, 'avg': 0}
    
    def aggregate_frontend_stats(self, frontends: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate statistics across multiple frontends"""
        try:
            if not frontends:
                return self._empty_aggregate()
            
            total_requests = sum(f.get('requests_total', 0) for f in frontends.values())
            total_sessions = sum(f.get('current_sessions', 0) for f in frontends.values())
            total_bytes_in = sum(f.get('bytes_in', 0) for f in frontends.values())
            total_bytes_out = sum(f.get('bytes_out', 0) for f in frontends.values())
            total_errors = sum(f.get('request_errors', 0) + f.get('connection_errors', 0) for f in frontends.values())
            
            # HTTP response code totals
            hrsp_2xx = sum(f.get('hrsp_2xx', 0) for f in frontends.values())
            hrsp_3xx = sum(f.get('hrsp_3xx', 0) for f in frontends.values())
            hrsp_4xx = sum(f.get('hrsp_4xx', 0) for f in frontends.values())
            hrsp_5xx = sum(f.get('hrsp_5xx', 0) for f in frontends.values())
            
            total_http_responses = hrsp_2xx + hrsp_3xx + hrsp_4xx + hrsp_5xx
            
            return {
                'total_requests': total_requests,
                'total_sessions': total_sessions,
                'total_bytes_in': total_bytes_in,
                'total_bytes_out': total_bytes_out,
                'total_errors': total_errors,
                'hrsp_2xx': hrsp_2xx,
                'hrsp_3xx': hrsp_3xx,
                'hrsp_4xx': hrsp_4xx,
                'hrsp_5xx': hrsp_5xx,
                'total_http_responses': total_http_responses,
                'error_rate': self.calculate_error_rate({
                    'hrsp_2xx': hrsp_2xx,
                    'hrsp_3xx': hrsp_3xx,
                    'hrsp_4xx': hrsp_4xx,
                    'hrsp_5xx': hrsp_5xx
                }),
                'frontend_count': len(frontends)
            }
        
        except Exception as e:
            logger.error(f"Failed to aggregate frontend stats: {e}")
            return self._empty_aggregate()
    
    def aggregate_backend_stats(self, backends: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate statistics across multiple backends"""
        try:
            if not backends:
                return self._empty_aggregate()
            
            total_requests = sum(b.get('requests_total', 0) for b in backends.values())
            total_sessions = sum(b.get('current_sessions', 0) for b in backends.values())
            total_queue = sum(b.get('queue_current', 0) for b in backends.values())
            total_servers = sum(b.get('servers_total', 0) for b in backends.values())
            total_active = sum(b.get('servers_active', 0) for b in backends.values())
            
            # Calculate average response time
            response_times = [b.get('response_time_avg', 0) for b in backends.values() if b.get('response_time_avg', 0) > 0]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
            
            return {
                'total_requests': total_requests,
                'total_sessions': total_sessions,
                'total_queue': total_queue,
                'total_servers': total_servers,
                'total_active_servers': total_active,
                'avg_response_time': round(avg_response_time, 2),
                'backend_count': len(backends)
            }
        
        except Exception as e:
            logger.error(f"Failed to aggregate backend stats: {e}")
            return self._empty_aggregate()
    
    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        """Safely convert value to integer"""
        try:
            if value is None or value == '':
                return default
            return int(value)
        except (ValueError, TypeError):
            return default
    
    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        """Safely convert value to float"""
        try:
            if value is None or value == '':
                return default
            return float(value)
        except (ValueError, TypeError):
            return default
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure"""
        return {
            'frontends': {},
            'backends': {},
            'servers': [],
            'timestamp': datetime.utcnow().isoformat(),
            'parsed_at': datetime.utcnow().isoformat()
        }
    
    def _empty_aggregate(self) -> Dict[str, Any]:
        """Return empty aggregate structure"""
        return {
            'total_requests': 0,
            'total_sessions': 0,
            'total_bytes_in': 0,
            'total_bytes_out': 0,
            'total_errors': 0,
            'error_rate': 0.0
        }


# Global parser instance
haproxy_stats_parser = HAProxyStatsParser()

