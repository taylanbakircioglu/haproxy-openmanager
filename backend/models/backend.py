from pydantic import BaseModel, validator
from typing import Optional, List

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
    ssl_verify: Optional[str] = None
    cookie_value: Optional[str] = None
    inter: Optional[int] = None
    fall: Optional[int] = None
    rise: Optional[int] = None
    is_active: bool = True

class BackendConfig(BaseModel):
    name: str
    cluster_id: int
    balance_method: str = 'roundrobin'
    mode: str = 'http'
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
    servers: List[ServerConfig] = []

    @validator('health_check_interval', 'timeout_connect', 'timeout_server', 'timeout_queue', 'fullconn')
    def check_positive(cls, v):
        if v is not None and v <= 0:
            raise ValueError('Timeout, interval, and connection values must be positive')
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
    servers: Optional[List[ServerConfig]] = None

    @validator('health_check_interval', 'timeout_connect', 'timeout_server', 'timeout_queue', 'fullconn')
    def check_positive_update(cls, v):
        if v is not None and v <= 0:
            raise ValueError('Timeout, interval, and connection values must be positive')
        return v
    
    @validator('health_check_expected_status')
    def check_http_status_update(cls, v):
        if v is not None and (v < 100 or v > 599):
            raise ValueError('HTTP status code must be between 100 and 599')
        return v 