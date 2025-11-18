from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class AgentCreate(BaseModel):
    name: str
    pool_id: int
    platform: str = "linux"
    architecture: str = "amd64"
    version: str = "1.0.0"

class AgentRegister(BaseModel):
    name: str
    pool_id: int
    platform: str = "linux"
    architecture: str = "amd64"
    version: str = "1.0.0"
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    kernel_version: Optional[str] = None
    uptime: Optional[int] = None
    cpu_count: Optional[int] = None
    memory_total: Optional[int] = None  # in MB
    disk_space: Optional[int] = None  # in MB
    network_interfaces: Optional[List[str]] = None
    capabilities: Optional[List[str]] = None

class AgentHeartbeat(BaseModel):
    name: str
    status: str = "online"
    
    # Optional system info from agent
    hostname: Optional[str] = None
    platform: Optional[str] = None
    architecture: Optional[str] = None
    version: Optional[str] = None  # Agent version
    cluster_id: Optional[int] = None
    
    # Detailed system information (flat format - for backward compatibility with old agents)
    operating_system: Optional[str] = None
    kernel_version: Optional[str] = None
    uptime: Optional[int] = None  # in seconds
    cpu_count: Optional[int] = None
    memory_total: Optional[int] = None  # in bytes
    disk_space: Optional[int] = None  # in bytes
    network_interfaces: Optional[List[str]] = None
    capabilities: Optional[List[str]] = None
    ip_address: Optional[str] = None

    # Optional performance metrics
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    load_average: Optional[List[float]] = None
    network_io: Optional[Dict[str, Any]] = None
    
    # HAProxy info
    haproxy_status: Optional[str] = None
    haproxy_version: Optional[str] = None
    
    # Server status from HAProxy stats socket
    server_statuses: Optional[Dict[str, Dict[str, str]]] = None  # {backend_name: {server_name: status}}
    
    # Full HAProxy stats CSV (base64 encoded) for dashboard metrics
    haproxy_stats_csv: Optional[str] = None
    
    # Config sync tracking (agent reports what it successfully applied)
    applied_config_version: Optional[str] = None
    
    # System info collected by agent (JSON object - nested format for new agents)
    system_info: Optional[Dict[str, Any]] = None
    
    # Other optional fields
    last_config_update: Optional[str] = None
    errors: Optional[List[str]] = None
    
    class Config:
        # Allow extra fields from agents (for forward compatibility and tolerance)
        extra = "allow"

class AgentToggle(BaseModel):
    enabled: bool

class AgentPoolCreate(BaseModel):
    name: str
    description: Optional[str] = None
    environment: str = "development"  # development, staging, production
    location: Optional[str] = None
    default_config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = True

class AgentPoolUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    environment: Optional[str] = None
    location: Optional[str] = None
    default_config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

# Aliases for pool management
PoolCreate = AgentPoolCreate
PoolUpdate = AgentPoolUpdate

class AgentScriptRequest(BaseModel):
    platform: str
    architecture: str
    pool_id: int
    cluster_id: int  # ✅ FIXED: Added cluster_id field
    agent_name: str
    hostname_prefix: str
    haproxy_bin_path: str
    haproxy_config_path: str
    stats_socket_path: str

class AgentUpgradeRequest(BaseModel):
    agent_id: int 