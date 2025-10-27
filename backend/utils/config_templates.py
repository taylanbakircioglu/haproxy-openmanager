"""
Production-Ready HAProxy Configuration Templates
Provides pre-configured templates for common use cases and best practices
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("haproxy_openmanager.config_templates")

class TemplateCategory(Enum):
    """Template categories"""
    BASIC = "basic"
    LOAD_BALANCER = "load_balancer"
    SSL_TERMINATION = "ssl_termination"
    HIGH_AVAILABILITY = "high_availability"
    MICROSERVICES = "microservices"
    CDN_ORIGIN = "cdn_origin"
    API_GATEWAY = "api_gateway"

@dataclass
class ConfigTemplate:
    """Configuration template definition"""
    id: str
    name: str
    description: str
    category: TemplateCategory
    config_content: str
    variables: Dict[str, Any]
    tags: List[str]
    difficulty: str  # beginner, intermediate, advanced
    use_cases: List[str]

class HAProxyTemplateManager:
    """Manages HAProxy configuration templates"""
    
    def __init__(self):
        self.templates = {}
        self._initialize_templates()
    
    def _initialize_templates(self):
        """Initialize built-in templates"""
        
        # Basic Web Server Template
        self.add_template(ConfigTemplate(
            id="basic_web_server",
            name="Basic Web Server",
            description="Simple HTTP load balancer for web applications",
            category=TemplateCategory.BASIC,
            config_content=self._get_basic_web_template(),
            variables={
                "frontend_port": 80,
                "backend_servers": [
                    {"name": "web1", "host": "192.168.1.10", "port": 80},
                    {"name": "web2", "host": "192.168.1.11", "port": 80}
                ],
                "balance_method": "roundrobin",
                "health_check_uri": "/health"
            },
            tags=["web", "http", "basic"],
            difficulty="beginner",
            use_cases=[
                "Simple web application load balancing",
                "Development environment setup",
                "Basic high availability"
            ]
        ))
        
        # SSL Termination Template
        self.add_template(ConfigTemplate(
            id="ssl_termination",
            name="SSL Termination Proxy",
            description="HTTPS termination with HTTP backend servers",
            category=TemplateCategory.SSL_TERMINATION,
            config_content=self._get_ssl_termination_template(),
            variables={
                "frontend_port_http": 80,
                "frontend_port_https": 443,
                "ssl_certificate_path": "/etc/ssl/certs/server.pem",
                "backend_servers": [
                    {"name": "app1", "host": "10.0.1.10", "port": 8080},
                    {"name": "app2", "host": "10.0.1.11", "port": 8080}
                ],
                "force_https": True,
                "security_headers": True
            },
            tags=["ssl", "https", "security"],
            difficulty="intermediate",
            use_cases=[
                "HTTPS website hosting",
                "SSL certificate management",
                "Security header implementation"
            ]
        ))
        
        # API Gateway Template
        self.add_template(ConfigTemplate(
            id="api_gateway",
            name="API Gateway",
            description="Advanced API gateway with path-based routing",
            category=TemplateCategory.API_GATEWAY,
            config_content=self._get_api_gateway_template(),
            variables={
                "frontend_port": 443,
                "ssl_certificate_path": "/etc/ssl/certs/api.pem",
                "api_services": [
                    {"path": "/auth", "backend": "auth_service", "servers": [
                        {"name": "auth1", "host": "10.0.2.10", "port": 3000}
                    ]},
                    {"path": "/users", "backend": "user_service", "servers": [
                        {"name": "user1", "host": "10.0.2.20", "port": 3001}
                    ]},
                    {"path": "/orders", "backend": "order_service", "servers": [
                        {"name": "order1", "host": "10.0.2.30", "port": 3002}
                    ]}
                ],
                "rate_limiting": True,
                "cors_enabled": True
            },
            tags=["api", "microservices", "gateway", "routing"],
            difficulty="advanced",
            use_cases=[
                "Microservices architecture",
                "API rate limiting and security",
                "Path-based service routing"
            ]
        ))
        
        # High Availability Template
        self.add_template(ConfigTemplate(
            id="high_availability",
            name="High Availability Setup",
            description="Production-ready HA configuration with monitoring",
            category=TemplateCategory.HIGH_AVAILABILITY,
            config_content=self._get_high_availability_template(),
            variables={
                "frontend_ports": [80, 443],
                "ssl_certificate_path": "/etc/ssl/certs/ha.pem",
                "backend_servers": [
                    {"name": "prod1", "host": "10.0.1.10", "port": 80, "backup": False},
                    {"name": "prod2", "host": "10.0.1.11", "port": 80, "backup": False},
                    {"name": "backup1", "host": "10.0.1.20", "port": 80, "backup": True}
                ],
                "health_check_interval": "2s",
                "stats_enabled": True,
                "stats_port": 8404,
                "log_level": "info"
            },
            tags=["ha", "production", "monitoring", "stats"],
            difficulty="advanced",
            use_cases=[
                "Production web applications",
                "Critical service availability",
                "Advanced health monitoring"
            ]
        ))
        
        # Microservices Template
        self.add_template(ConfigTemplate(
            id="microservices_proxy",
            name="Microservices Proxy",
            description="Load balancer optimized for microservices architecture",
            category=TemplateCategory.MICROSERVICES,
            config_content=self._get_microservices_template(),
            variables={
                "frontend_port": 80,
                "services": [
                    {
                        "name": "auth",
                        "path": "/auth/",
                        "servers": [
                            {"host": "auth-service-1", "port": 3000},
                            {"host": "auth-service-2", "port": 3000}
                        ]
                    },
                    {
                        "name": "api",
                        "path": "/api/",
                        "servers": [
                            {"host": "api-service-1", "port": 4000},
                            {"host": "api-service-2", "port": 4000}
                        ]
                    }
                ],
                "service_discovery": True,
                "circuit_breaker": True
            },
            tags=["microservices", "docker", "kubernetes", "service-discovery"],
            difficulty="intermediate",
            use_cases=[
                "Docker Swarm deployments",
                "Kubernetes ingress",
                "Service mesh integration"
            ]
        ))
    
    def add_template(self, template: ConfigTemplate):
        """Add a new template"""
        self.templates[template.id] = template
        logger.info(f"Added configuration template: {template.name}")
    
    def get_template(self, template_id: str) -> Optional[ConfigTemplate]:
        """Get template by ID"""
        return self.templates.get(template_id)
    
    def list_templates(self, category: Optional[TemplateCategory] = None) -> List[ConfigTemplate]:
        """List all templates, optionally filtered by category"""
        templates = list(self.templates.values())
        
        if category:
            templates = [t for t in templates if t.category == category]
        
        return sorted(templates, key=lambda x: (x.difficulty, x.name))
    
    def generate_config(self, template_id: str, variables: Dict[str, Any]) -> Optional[str]:
        """Generate configuration from template with custom variables"""
        template = self.get_template(template_id)
        if not template:
            return None
        
        # Merge template variables with custom variables
        merged_vars = {**template.variables, **variables}
        
        try:
            # Apply variable substitution
            config = self._apply_variables(template.config_content, merged_vars)
            return config
        except Exception as e:
            logger.error(f"Error generating config from template {template_id}: {e}")
            return None
    
    def _apply_variables(self, config_content: str, variables: Dict[str, Any]) -> str:
        """Apply variable substitution to configuration template"""
        result = config_content
        
        # Handle simple variable substitution
        for key, value in variables.items():
            placeholder = f"{{{key}}}"
            if isinstance(value, (list, dict)):
                continue  # Complex types handled separately
            result = result.replace(placeholder, str(value))
        
        # Handle complex variables (servers, services, etc.)
        result = self._handle_server_variables(result, variables)
        result = self._handle_service_variables(result, variables)
        
        return result
    
    def _handle_server_variables(self, config: str, variables: Dict[str, Any]) -> str:
        """Handle server list variable substitution"""
        if "backend_servers" in variables:
            servers = variables["backend_servers"]
            server_lines = []
            
            for server in servers:
                line = f"    server {server['name']} {server['host']}:{server['port']}"
                if server.get('backup'):
                    line += " backup"
                line += " check"
                server_lines.append(line)
            
            config = config.replace("{backend_servers_list}", "\n".join(server_lines))
        
        return config
    
    def _handle_service_variables(self, config: str, variables: Dict[str, Any]) -> str:
        """Handle microservices variable substitution"""
        if "services" in variables:
            services = variables["services"]
            
            # Generate ACLs and use_backend rules
            acl_rules = []
            use_backend_rules = []
            backend_sections = []
            
            for service in services:
                service_name = service["name"]
                path = service["path"]
                
                # ACL rule
                acl_rules.append(f"    acl is_{service_name} path_beg {path}")
                
                # use_backend rule
                use_backend_rules.append(f"    use_backend {service_name}_backend if is_{service_name}")
                
                # Backend section
                backend_lines = [f"\nbackend {service_name}_backend"]
                backend_lines.append("    balance roundrobin")
                
                for i, server in enumerate(service["servers"], 1):
                    backend_lines.append(f"    server {service_name}_{i} {server['host']}:{server['port']} check")
                
                backend_sections.append("\n".join(backend_lines))
            
            config = config.replace("{service_acls}", "\n".join(acl_rules))
            config = config.replace("{service_backends}", "\n".join(use_backend_rules))
            config = config.replace("{backend_sections}", "\n".join(backend_sections))
        
        return config
    
    # Template content methods
    def _get_basic_web_template(self) -> str:
        return """# Basic Web Server HAProxy Configuration
# Generated from template: Basic Web Server

global
    daemon
    log stdout local0 info
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option log-health-checks
    option forwardfor
    option http-server-close
    timeout connect 5000
    timeout client 50000
    timeout server 50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

frontend web_frontend
    bind *:{frontend_port}
    default_backend web_backend

backend web_backend
    balance {balance_method}
    option httpchk GET {health_check_uri}
{backend_servers_list}"""
    
    def _get_ssl_termination_template(self) -> str:
        return """# SSL Termination HAProxy Configuration
# Generated from template: SSL Termination Proxy

global
    daemon
    log stdout local0 info
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    user haproxy
    group haproxy
    
    # SSL Configuration
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option forwardfor
    option http-server-close
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend web_frontend
    bind *:{frontend_port_http}
    bind *:{frontend_port_https} ssl crt {ssl_certificate_path}
    
    # Force HTTPS redirect
    redirect scheme https unless {{ ssl_fc }}
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    http-response set-header X-Frame-Options "SAMEORIGIN"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-XSS-Protection "1; mode=block"
    
    default_backend web_backend

backend web_backend
    balance roundrobin
    option httpchk GET /health
{backend_servers_list}"""
    
    def _get_api_gateway_template(self) -> str:
        return """# API Gateway HAProxy Configuration
# Generated from template: API Gateway

global
    daemon
    log stdout local0 info
    stats socket /run/haproxy/admin.sock mode 660 level admin
    user haproxy
    group haproxy

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option forwardfor
    timeout connect 5000
    timeout client 30000
    timeout server 30000

frontend api_gateway
    bind *:{frontend_port} ssl crt {ssl_certificate_path}
    
    # CORS headers
    http-response set-header Access-Control-Allow-Origin "*"
    http-response set-header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    http-response set-header Access-Control-Allow-Headers "Content-Type, Authorization"
    
    # Rate limiting (basic)
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request reject if {{ sc_http_req_rate(0) gt 20 }}
    
    # Service routing
{service_acls}
    
    # Route to backends
{service_backends}
    
    # Default fallback
    default_backend api_default

{backend_sections}

backend api_default
    http-request return status 404 content-type "application/json" string '{{"error":"Service not found"}}'"""
    
    def _get_high_availability_template(self) -> str:
        return """# High Availability HAProxy Configuration
# Generated from template: High Availability Setup

global
    daemon
    master-worker
    log stdout local0 {log_level}
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    user haproxy
    group haproxy
    
    # Performance tuning
    maxconn 4096
    spread-checks 3
    tune.ssl.default-dh-param 2048

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option log-health-checks
    option forwardfor
    option http-server-close
    timeout connect 5s
    timeout client 1m
    timeout server 1m
    timeout check {health_check_interval}
    retries 3
    
    # Load balancing
    balance roundrobin

# Statistics interface
listen stats
    bind *:{stats_port}
    stats enable
    stats uri /stats
    stats refresh 30s
    stats show-node

frontend web_frontend
    bind *:80
    bind *:443 ssl crt {ssl_certificate_path}
    
    # Redirect HTTP to HTTPS
    redirect scheme https unless {{ ssl_fc }}
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000"
    http-response set-header X-Frame-Options "DENY"
    
    default_backend web_backend

backend web_backend
    option httpchk GET /health HTTP/1.1\r\nHost:\ localhost
    
{backend_servers_list}"""
    
    def _get_microservices_template(self) -> str:
        return """# Microservices HAProxy Configuration
# Generated from template: Microservices Proxy

global
    daemon
    log stdout local0 info
    stats socket /run/haproxy/admin.sock mode 660 level admin
    user haproxy
    group haproxy

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option forwardfor
    timeout connect 3s
    timeout client 30s
    timeout server 30s
    
    # Circuit breaker configuration
    timeout queue 5s
    retries 2

frontend microservices_frontend
    bind *:{frontend_port}
    
    # Service discovery ACLs
{service_acls}
    
    # Route to appropriate backends
{service_backends}
    
    # Health check endpoint
    acl health_check path /health
    http-request return status 200 content-type "text/plain" string "OK" if health_check

{backend_sections}"""

# Global template manager instance
template_manager = HAProxyTemplateManager()

def get_template_manager() -> HAProxyTemplateManager:
    """Get the global template manager instance"""
    return template_manager

def list_available_templates() -> List[Dict[str, Any]]:
    """Get list of available templates for API"""
    templates = template_manager.list_templates()
    
    return [
        {
            "id": t.id,
            "name": t.name,
            "description": t.description,
            "category": t.category.value,
            "difficulty": t.difficulty,
            "tags": t.tags,
            "use_cases": t.use_cases,
            "variables": list(t.variables.keys())
        }
        for t in templates
    ]

def generate_config_from_template(template_id: str, variables: Dict[str, Any]) -> Optional[str]:
    """Generate configuration from template"""
    return template_manager.generate_config(template_id, variables)