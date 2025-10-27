from pydantic import BaseModel
from typing import Optional, List

class HAProxyClusterCreate(BaseModel):
    name: str
    description: Optional[str] = None
    connection_type: str = "agent"  # Only "agent" supported now
    stats_socket_path: str = "/run/haproxy/admin.sock"
    haproxy_config_path: str = "/etc/haproxy/haproxy.cfg"
    haproxy_bin_path: str = "/usr/sbin/haproxy"  # HAProxy binary path
    pool_id: Optional[int] = None  # Which pool this cluster belongs to

class HAProxyClusterUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    connection_type: Optional[str] = None
    stats_socket_path: Optional[str] = None
    haproxy_config_path: Optional[str] = None
    haproxy_bin_path: Optional[str] = None
    pool_id: Optional[int] = None
    is_active: Optional[bool] = None

class HAProxyClusterResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    
    # Installation options
    installation_type: str
    deployment_type: str
    
    # Connection details
    host: str
    port: int
    connection_type: str
    
    # Status info
    is_active: bool
    is_default: bool
    last_connected_at: Optional[str] = None
    connection_status: str
    connection_error: Optional[str] = None
    haproxy_version: Optional[str] = None
    created_at: str

class HAProxyGlobalConfig(BaseModel):
    max_connections: int = 4096
    timeout_connect: int = 10000
    timeout_client: int = 60000
    timeout_server: int = 60000
    log_level: str = "info"
    stats_enabled: bool = True
    stats_uri: str = "/stats"
    stats_port: int = 8404

class ConfigVersion(BaseModel):
    version_name: str
    description: Optional[str] = None
    config_content: Optional[str] = None
    cluster_id: Optional[int] = None 