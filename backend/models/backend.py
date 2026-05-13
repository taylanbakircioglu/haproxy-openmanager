from pydantic import BaseModel, validator
from typing import Literal, Optional, List

class ServerConfig(BaseModel):
    server_name: str
    server_address: str
    server_port: int
    weight: int = 100
    max_connections: Optional[int] = None
    check_enabled: bool = True
    check_port: Optional[int] = None
    backup_server: bool = False
    ssl_enabled: bool = False
    # PR-2 (R11.B): tighten to strict Literal aligned with HAProxy's
    # `server ... ssl verify <none|required>` semantics. Backend-side
    # `verify optional` is NOT supported by HAProxy (only frontend
    # bind-side accepts it) — pre-PR-2 the field accepted arbitrary
    # strings (`'optional'`, `'true'`, etc.) and the generator
    # rendered them verbatim, producing parser errors. Empty strings
    # from the React form are coerced to None by
    # `coerce_ssl_verify_empty_to_none` below.
    ssl_verify: Optional[Literal["none", "required"]] = None
    ssl_certificate_id: Optional[int] = None  # SSL certificate for backend server
    
    # SSL Advanced Options (server SSL parameters)
    ssl_sni: Optional[str] = None  # SNI hostname for backend SSL connections
    ssl_min_ver: Optional[str] = None  # Minimum TLS version (TLSv1.2, TLSv1.3)
    ssl_max_ver: Optional[str] = None  # Maximum TLS version
    ssl_ciphers: Optional[str] = None  # Cipher suite list for backend connections
    
    cookie_value: Optional[str] = None
    inter: Optional[int] = None
    fall: Optional[int] = None
    rise: Optional[int] = None
    is_active: bool = True
    
    @validator('ssl_min_ver', 'ssl_max_ver')
    def validate_tls_version(cls, v):
        if v is not None:
            valid_versions = ['SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
            if v not in valid_versions:
                raise ValueError(f'Invalid TLS version: {v}. Must be one of: {", ".join(valid_versions)}')
        return v

    @validator('ssl_verify', pre=True)
    def coerce_ssl_verify_empty_to_none(cls, v):
        """PR-2 (R11.B): React form Select widgets clear to '' (empty
        string) but the strict Literal would reject that. Coerce the
        empty string and the legacy sentinels written by older
        clients into None. Note: server-side mTLS only accepts
        ``none`` or ``required`` (HAProxy's `server ... verify`
        keyword has no `optional` mode); a legacy `'optional'`
        value is also coerced to None to fail-safe rather than
        rendering an invalid directive.
        """
        if v is None:
            return None
        if isinstance(v, str):
            stripped = v.strip().lower()
            if stripped in ("", "[]", "{}", "null"):
                return None
            if stripped == "none":
                return "none"
            if stripped == "required":
                return "required"
            if stripped == "optional":
                # Server-side `verify optional` is invalid HAProxy.
                # Coerce to None so the generator simply omits the
                # directive instead of producing a parser-fatal line.
                return None
        return v

class BackendConfig(BaseModel):
    name: str
    cluster_id: int
    balance_method: str = 'roundrobin'
    mode: str = 'http'

    @validator('name')
    def reject_system_prefix(cls, v):
        # R18 audit fix (round 3 #5): manual backend create previously
        # accepted leading-underscore names (e.g. `_my_backend`). The
        # agent's `_should_sync_backend` filter then dropped any such
        # row from the agent->backend reverse-sync, producing silent
        # control-plane drift between DB and on-disk haproxy.cfg. The
        # wizard's BackendStep already rejected this; align the manual
        # path so the constraint is uniform across entry points.
        if isinstance(v, str) and v.startswith('_'):
            raise ValueError(
                "Backend name must not start with '_' (reserved for "
                "system-managed entities such as the ACME challenge "
                "backend)."
            )
        return v
    health_check_uri: Optional[str] = None
    health_check_interval: Optional[int] = 2000
    health_check_expected_status: Optional[int] = 200
    fullconn: Optional[int] = None
    cookie_name: Optional[str] = None
    cookie_options: Optional[str] = None
    default_server_inter: Optional[int] = None
    default_server_fall: Optional[int] = None
    default_server_rise: Optional[int] = None
    request_headers: Optional[str] = None
    response_headers: Optional[str] = None
    timeout_connect: Optional[int] = 10000
    timeout_server: Optional[int] = 60000
    timeout_queue: Optional[int] = 60000
    options: Optional[str] = None
    servers: List[ServerConfig] = []

    # Bulgu #68 (round-22 audit) — wizard's BackendStep declares
    # `fullconn: Optional[int] = Field(default=None, ge=0, ...)`
    # (0 == HAProxy "fullconn disabled" sentinel). The manual
    # BackendConfig pre-fix used a single `check_positive` that
    # rejected `<= 0` for ALL of `health_check_interval`,
    # `timeout_connect`, `timeout_server`, `timeout_queue`, AND
    # `fullconn` — so a wizard-created backend with
    # `fullconn=0` (or one persisted before fullconn was
    # introduced and now defaults to 0) would 422 on every PUT,
    # even when the operator was only changing the balance
    # method or adding a server. Same Bulgu #62 "wizard
    # accepted / manual rejects" lockout pattern.
    #
    # Split into two validators: the four timeout/interval fields
    # keep `> 0` (HAProxy parser hard requirement), while
    # `fullconn` switches to `>= 0` mirroring the wizard.
    @validator('health_check_interval', 'timeout_connect', 'timeout_server', 'timeout_queue')
    def check_positive(cls, v):
        if v is not None and v <= 0:
            raise ValueError('Timeout, interval, and connection values must be positive')
        return v

    @validator('fullconn')
    def check_fullconn_non_negative(cls, v):
        if v is not None and v < 0:
            raise ValueError('fullconn must be >= 0 (0 disables the directive)')
        return v

    @validator('health_check_expected_status')
    def check_http_status(cls, v):
        if v is not None and (v < 100 or v > 599):
            raise ValueError('HTTP status code must be between 100 and 599')
        return v

class BackendConfigUpdate(BaseModel):
    name: Optional[str] = None
    balance_method: Optional[str] = None
    mode: Optional[str] = None

    @validator('name')
    def reject_system_prefix_update(cls, v):
        # R18 audit fix (round 3 #5): rename guard. Without it an
        # operator could `PUT` a backend's name to `_anything`, which
        # would then be filtered out by the agent reverse-sync.
        if v is not None and isinstance(v, str) and v.startswith('_'):
            raise ValueError(
                "Backend name must not start with '_' (reserved for "
                "system-managed entities)."
            )
        return v
    health_check_uri: Optional[str] = None
    health_check_interval: Optional[int] = None
    health_check_expected_status: Optional[int] = None
    fullconn: Optional[int] = None
    cookie_name: Optional[str] = None
    cookie_options: Optional[str] = None
    default_server_inter: Optional[int] = None
    default_server_fall: Optional[int] = None
    default_server_rise: Optional[int] = None
    request_headers: Optional[str] = None
    response_headers: Optional[str] = None
    timeout_connect: Optional[int] = None
    timeout_server: Optional[int] = None
    timeout_queue: Optional[int] = None
    options: Optional[str] = None
    servers: Optional[List[ServerConfig]] = None

    # Bulgu #68 (round-22 audit) — same alignment as BackendConfig
    # above. Update path is where the wizard-created `fullconn=0`
    # row most often blows up.
    @validator('health_check_interval', 'timeout_connect', 'timeout_server', 'timeout_queue')
    def check_positive_update(cls, v):
        if v is not None and v <= 0:
            raise ValueError('Timeout, interval, and connection values must be positive')
        return v

    @validator('fullconn')
    def check_fullconn_non_negative_update(cls, v):
        if v is not None and v < 0:
            raise ValueError('fullconn must be >= 0 (0 disables the directive)')
        return v

    @validator('health_check_expected_status')
    def check_http_status_update(cls, v):
        if v is not None and (v < 100 or v > 599):
            raise ValueError('HTTP status code must be between 100 and 599')
        return v 