from pydantic import BaseModel, validator, ValidationError
from typing import List, Optional, Any
import re
import ipaddress
import os
import json

class FrontendConfig(BaseModel):
    name: str
    bind_address: str = "*"
    bind_port: int
    default_backend: Optional[str] = None
    mode: str = "http"
    ssl_enabled: bool = False
    ssl_certificate_id: Optional[int] = None  # DEPRECATED: Use ssl_certificate_ids instead (backward compatibility)
    ssl_certificate_ids: Optional[List[int]] = None  # PREFERRED: Multiple SSL certificates support
    ssl_port: Optional[int] = None  # DEPRECATED: SSL uses bind_port now (backward compatibility)
    ssl_cert_path: Optional[str] = None
    ssl_cert: Optional[str] = None
    ssl_verify: Optional[str] = "optional"
    
    # SSL Advanced Options (bind SSL parameters)
    ssl_alpn: Optional[str] = None  # Application-Layer Protocol Negotiation (e.g., "h2,http/1.1")
    ssl_npn: Optional[str] = None   # Next Protocol Negotiation (legacy)
    ssl_ciphers: Optional[str] = None  # Cipher suite list
    ssl_ciphersuites: Optional[str] = None  # TLS 1.3 cipher suites
    ssl_min_ver: Optional[str] = None  # Minimum TLS version (SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3)
    ssl_max_ver: Optional[str] = None  # Maximum TLS version
    ssl_strict_sni: Optional[bool] = False  # Strict SNI requirement
    acl_rules: Any = []
    redirect_rules: Any = []
    use_backend_rules: Any = []  # Changed from Optional[str] to Any for list support
    request_headers: Optional[str] = None
    response_headers: Optional[str] = None
    options: Optional[str] = None
    tcp_request_rules: Optional[str] = None
    timeout_client: Optional[int] = None
    timeout_http_request: Optional[int] = None
    rate_limit: Optional[int] = None
    compression: bool = False
    log_separate: bool = False
    monitor_uri: Optional[str] = None
    cluster_id: Optional[int] = None
    maxconn: Optional[int] = None
    
    # Data transformation to handle string arrays from frontend
    @validator('acl_rules', pre=True, always=True)  
    def parse_acl_rules(cls, v):
        if isinstance(v, str):
            v = v.strip()
            # Handle JSON string (e.g., "[]" or "[\"rule1\", \"rule2\"]")
            if v.startswith('[') and v.endswith(']'):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return parsed
                except (json.JSONDecodeError, ValueError):
                    pass
            # Handle newline-separated string
            if v:
                return [rule.strip() for rule in v.split('\n') if rule.strip()]
        elif isinstance(v, list):
            return v
        return []
    
    @validator('redirect_rules', pre=True, always=True)  
    def parse_redirect_rules(cls, v):
        if isinstance(v, str):
            v = v.strip()
            # Handle JSON string (e.g., "[]" or "[\"rule1\", \"rule2\"]")
            if v.startswith('[') and v.endswith(']'):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return parsed
                except (json.JSONDecodeError, ValueError):
                    pass
            # Handle newline-separated string
            if v:
                return [rule.strip() for rule in v.split('\n') if rule.strip()]
        elif isinstance(v, list):
            return v
        return []
    
    @validator('use_backend_rules', pre=True, always=True)
    def parse_use_backend_rules(cls, v):
        if isinstance(v, str):
            v = v.strip()
            # Handle JSON string (e.g., "[]" or "[\"rule1\", \"rule2\"]")
            if v.startswith('[') and v.endswith(']'):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return parsed
                except (json.JSONDecodeError, ValueError):
                    pass
            # Handle newline-separated string
            if v:
                return [rule.strip() for rule in v.split('\n') if rule.strip()]
        elif isinstance(v, list):
            return v
        return []
    
    # CRITICAL VALIDATION RULES FOR HAPROXY
    @validator('name')
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError('Frontend name cannot be empty')
        
        # HAProxy names cannot contain spaces or special characters
        if not re.match(r'^[a-zA-Z0-9_-]+$', v.strip()):
            raise ValueError('Frontend name can only contain letters, numbers, underscore (_) and dash (-). Spaces and special characters are not allowed.')
        
        if len(v.strip()) > 50:
            raise ValueError('Frontend name cannot exceed 50 characters')
            
        return v.strip()
    
    @validator('bind_address')
    def validate_bind_address(cls, v):
        if not v or v.strip() == '*':
            return '*'  # Wildcard is valid
        
        v = v.strip()
        
        # Check if it's a valid IPv4 or IPv6 address
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            # Check if it's a hostname (basic validation)
            if re.match(r'^[a-zA-Z0-9.-]+$', v) and len(v) <= 253:
                return v
            raise ValueError(f'Invalid bind address: {v}. Must be a valid IP address, hostname, or * for wildcard.')
    
    @validator('bind_port')
    def validate_bind_port(cls, v):
        if not isinstance(v, int) or v < 1 or v > 65535:
            raise ValueError('Port must be between 1 and 65535')
        
        # Check for commonly problematic ports
        if v < 1024:
            # This is just a warning, not an error - some setups might need privileged ports
            pass
            
        return v
    
    @validator('default_backend')
    def validate_default_backend(cls, v):
        if v and not re.match(r'^[a-zA-Z0-9_-]+$', v.strip()):
            raise ValueError('Default backend name can only contain letters, numbers, underscore (_) and dash (-)')
        return v.strip() if v else None
    
    @validator('ssl_certificate_id')
    def validate_ssl_certificate_id(cls, v):
        if v is not None and (not isinstance(v, int) or v < 1):
            raise ValueError('SSL certificate ID must be a positive integer')
        return v
    
    @validator('ssl_certificate_ids', pre=True, always=True)
    def validate_ssl_certificate_ids(cls, v, values):
        """
        Validate multiple SSL certificate IDs and handle backward compatibility
        If ssl_certificate_ids is None but ssl_certificate_id exists, convert to array
        """
        # If ssl_certificate_ids provided, validate it
        if v is not None:
            if isinstance(v, list):
                # Validate each ID
                for cert_id in v:
                    if not isinstance(cert_id, int) or cert_id < 1:
                        raise ValueError(f'SSL certificate ID must be a positive integer, got: {cert_id}')
                return v
            elif isinstance(v, int):
                # Single ID provided as int, convert to array
                if v < 1:
                    raise ValueError('SSL certificate ID must be a positive integer')
                return [v]
            else:
                raise ValueError('ssl_certificate_ids must be a list of integers or a single integer')
        
        # Backward compatibility: If ssl_certificate_ids is None but ssl_certificate_id exists, convert it
        ssl_cert_id = values.get('ssl_certificate_id')
        if ssl_cert_id is not None and ssl_cert_id > 0:
            return [ssl_cert_id]
        
        return []
    
    @validator('ssl_port')
    def validate_ssl_port(cls, v):
        """DEPRECATED: ssl_port is maintained for backward compatibility only"""
        if v is not None and (not isinstance(v, int) or v < 1 or v > 65535):
            raise ValueError('SSL port must be between 1 and 65535')
        return v
    
    @validator('ssl_cert_path')
    def validate_ssl_cert_path(cls, v):
        if not v:
            return None
        
        v = v.strip()
        
        # Basic path validation
        if not v.startswith('/'):
            raise ValueError('SSL certificate path must be an absolute path starting with /')
        
        # Check for dangerous characters
        if '..' in v or ';' in v or '|' in v:
            raise ValueError('SSL certificate path contains invalid characters')
            
        return v
    
    @validator('timeout_client')
    def validate_timeout_client(cls, v):
        if v is not None and (v < 1000 or v > 3600000):  # 1s to 1h in ms
            raise ValueError('Client timeout must be between 1000ms (1s) and 3600000ms (1h)')
        return v
    
    @validator('timeout_http_request')
    def validate_timeout_http_request(cls, v):
        if v is not None and (v < 1000 or v > 300000):  # 1s to 5min in ms
            raise ValueError('HTTP request timeout must be between 1000ms (1s) and 300000ms (5min)')
        return v
    
    @validator('rate_limit')
    def validate_rate_limit(cls, v):
        if v is not None and (v < 1 or v > 10000):
            raise ValueError('Rate limit must be between 1 and 10000 requests')
        return v
    
    @validator('maxconn')
    def validate_maxconn(cls, v):
        if v is not None and (v < 1 or v > 100000):
            raise ValueError('Max connections must be between 1 and 100000')
        return v
    
    @validator('ssl_min_ver', 'ssl_max_ver')
    def validate_tls_version(cls, v):
        if v is not None:
            valid_versions = ['SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
            if v not in valid_versions:
                raise ValueError(f'Invalid TLS version: {v}. Must be one of: {", ".join(valid_versions)}')
        return v
    
    @validator('ssl_alpn')
    def validate_alpn(cls, v):
        if v is not None and v.strip():
            # ALPN protocols are comma-separated
            protocols = [p.strip() for p in v.split(',')]
            valid_protocols = ['h2', 'http/1.1', 'http/1.0', 'h2c', 'spdy/3', 'spdy/2', 'spdy/1']
            for proto in protocols:
                if proto and proto not in valid_protocols:
                    raise ValueError(f'Invalid ALPN protocol: {proto}. Valid protocols: {", ".join(valid_protocols)}')
        return v
    
    @validator('ssl_npn')
    def validate_npn(cls, v):
        if v is not None and v.strip():
            # NPN protocols are comma-separated (legacy)
            protocols = [p.strip() for p in v.split(',')]
            valid_protocols = ['http/1.1', 'http/1.0', 'spdy/3', 'spdy/2', 'spdy/1']
            for proto in protocols:
                if proto and proto not in valid_protocols:
                    raise ValueError(f'Invalid NPN protocol: {proto}. Valid protocols: {", ".join(valid_protocols)}')
        return v
        
    @validator('acl_rules')
    def validate_acl_rules(cls, v):
        if not v:
            return []
        
        validated_rules = []
        for rule in v:
            rule = rule.strip()
            if not rule:
                continue
                
            # Basic ACL syntax validation
            if not re.match(r'^[a-zA-Z0-9_-]+\s+', rule):
                raise ValueError(f'Invalid ACL rule syntax: "{rule}". Must start with ACL name followed by condition.')
            
            # Check for dangerous patterns
            if any(dangerous in rule.lower() for dangerous in ['system', 'exec', 'eval', '$(', '`']):
                raise ValueError(f'ACL rule contains potentially dangerous content: "{rule}"')
                
            validated_rules.append(rule)
            
        return validated_rules
    
    @validator('redirect_rules')
    def validate_redirect_rules_syntax(cls, v):
        if not v:
            return []
        
        validated_rules = []
        for rule in v:
            rule = rule.strip()
            if not rule:
                continue
                
            # Basic redirect syntax validation
            valid_redirects = ['location', 'prefix', 'scheme']
            if not any(rule.startswith(redirect_type) for redirect_type in valid_redirects):
                raise ValueError(f'Invalid redirect rule: "{rule}". Must start with: location, prefix, or scheme.')
                
            validated_rules.append(rule)
            
        return validated_rules 