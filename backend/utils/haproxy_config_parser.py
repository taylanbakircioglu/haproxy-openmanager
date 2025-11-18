"""
HAProxy Configuration Parser
Parses HAProxy config files and extracts frontend, backend, and server definitions
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ParsedServer:
    """Parsed server definition"""
    server_name: str
    server_address: str
    server_port: int
    weight: int = 100
    max_connections: Optional[int] = None
    check_enabled: bool = True
    check_port: Optional[int] = None  # Health check port (different from server port)
    backup_server: bool = False
    ssl_enabled: bool = False
    ssl_verify: Optional[str] = None  # SSL verification (none, required)
    
    # SSL Advanced Options (server SSL parameters)
    ssl_sni: Optional[str] = None  # SNI hostname for backend SSL connections
    ssl_min_ver: Optional[str] = None  # Minimum TLS version
    ssl_max_ver: Optional[str] = None  # Maximum TLS version
    ssl_ciphers: Optional[str] = None  # Cipher suite list
    
    cookie_value: Optional[str] = None  # Cookie value for session persistence
    inter: Optional[int] = None  # Health check interval
    fall: Optional[int] = None  # Number of failed checks before marking down
    rise: Optional[int] = None  # Number of successful checks before marking up


@dataclass
class ParsedBackend:
    """Parsed backend definition"""
    name: str
    mode: str = "http"
    balance_method: str = "roundrobin"
    health_check_uri: Optional[str] = None
    health_check_interval: Optional[int] = 2000
    health_check_expected_status: Optional[int] = None  # Expected HTTP status code for health checks (only for HTTP mode)
    fullconn: Optional[int] = None  # Maximum concurrent connections
    cookie_name: Optional[str] = None  # Cookie name for session persistence
    cookie_options: Optional[str] = None  # Cookie options (insert, indirect, nocache, etc.)
    default_server_inter: Optional[int] = None  # Default health check interval for all servers
    default_server_fall: Optional[int] = None  # Default fall value for all servers
    default_server_rise: Optional[int] = None  # Default rise value for all servers
    request_headers: Optional[str] = None  # HTTP request headers (backend level)
    response_headers: Optional[str] = None  # HTTP response headers (backend level)
    options: Optional[str] = None  # HAProxy backend options (option http-keep-alive, option forwardfor, etc.)
    timeout_connect: Optional[int] = 10000
    timeout_server: Optional[int] = 60000
    timeout_queue: Optional[int] = 60000
    servers: List[ParsedServer] = None

    def __post_init__(self):
        if self.servers is None:
            self.servers = []


@dataclass
class ParsedFrontend:
    """Parsed frontend definition"""
    name: str
    bind_address: str = "*"
    bind_port: int = 80
    default_backend: Optional[str] = None
    mode: str = "http"
    ssl_enabled: bool = False
    ssl_port: Optional[int] = None
    ssl_certificate_id: Optional[int] = None
    ssl_cert_path: Optional[str] = None
    ssl_cert: Optional[str] = None
    ssl_verify: Optional[str] = None
    
    # SSL Advanced Options (bind SSL parameters)
    ssl_alpn: Optional[str] = None  # Application-Layer Protocol Negotiation (e.g., "h2,http/1.1")
    ssl_npn: Optional[str] = None   # Next Protocol Negotiation (legacy)
    ssl_ciphers: Optional[str] = None  # Cipher suite list
    ssl_ciphersuites: Optional[str] = None  # TLS 1.3 cipher suites
    ssl_min_ver: Optional[str] = None  # Minimum TLS version
    ssl_max_ver: Optional[str] = None  # Maximum TLS version
    ssl_strict_sni: Optional[bool] = False  # Strict SNI requirement
    
    timeout_client: Optional[int] = None
    timeout_http_request: Optional[int] = None
    maxconn: Optional[int] = None
    rate_limit: Optional[int] = None
    compression: bool = False
    log_separate: bool = False
    monitor_uri: Optional[str] = None
    acl_rules: Optional[list] = None
    use_backend_rules: Optional[list] = None  # Changed from str to list for consistency
    redirect_rules: Optional[list] = None
    request_headers: Optional[str] = None
    response_headers: Optional[str] = None
    options: Optional[str] = None  # HAProxy frontend options (option httplog, option forwardfor, etc.)
    tcp_request_rules: Optional[str] = None  # TCP request directives (for TCP mode)


@dataclass
class ParseResult:
    """Result of parsing HAProxy config"""
    frontends: List[ParsedFrontend]
    backends: List[ParsedBackend]
    errors: List[str]
    warnings: List[str]


class HAProxyConfigParser:
    """Parser for HAProxy configuration files"""

    def __init__(self):
        self.frontends = []
        self.backends = []
        self.errors = []
        self.warnings = []

    def parse(self, config_content: str) -> ParseResult:
        """
        Parse HAProxy configuration content
        
        Args:
            config_content: HAProxy configuration file content
            
        Returns:
            ParseResult with parsed frontends, backends, and any errors/warnings
        """
        self.frontends = []
        self.backends = []
        self.errors = []
        self.warnings = []

        try:
            lines = config_content.strip().split('\n')
            self._parse_lines(lines)
            
            # Post-parse validation
            self._validate_parsed_config()
            
        except Exception as e:
            self.errors.append(f"Failed to parse config: {str(e)}")
            logger.error(f"Config parsing error: {e}")

        return ParseResult(
            frontends=self.frontends,
            backends=self.backends,
            errors=self.errors,
            warnings=self.warnings
        )

    def _parse_lines(self, lines: List[str]):
        """Parse config lines and extract sections"""
        current_section = None
        current_section_type = None
        current_section_lines = []

        for line_num, line in enumerate(lines, 1):
            # Remove comments and strip whitespace
            line = re.sub(r'#.*$', '', line).strip()
            
            if not line:
                continue

            # Check for section headers
            frontend_match = re.match(r'^frontend\s+(\S+)', line, re.IGNORECASE)
            backend_match = re.match(r'^backend\s+(\S+)', line, re.IGNORECASE)

            if frontend_match:
                # Process previous section if exists
                if current_section and current_section_type == 'frontend':
                    self._parse_frontend_section(current_section, current_section_lines)
                elif current_section and current_section_type == 'backend':
                    self._parse_backend_section(current_section, current_section_lines)

                # Start new frontend section
                current_section = frontend_match.group(1)
                current_section_type = 'frontend'
                current_section_lines = []
                logger.debug(f"Found frontend section: {current_section}")

            elif backend_match:
                # Process previous section if exists
                if current_section and current_section_type == 'frontend':
                    self._parse_frontend_section(current_section, current_section_lines)
                elif current_section and current_section_type == 'backend':
                    self._parse_backend_section(current_section, current_section_lines)

                # Start new backend section
                current_section = backend_match.group(1)
                current_section_type = 'backend'
                current_section_lines = []
                logger.debug(f"Found backend section: {current_section}")

            elif re.match(r'^(global|defaults|listen)\s*(\S*)', line, re.IGNORECASE):
                # Process previous section if exists
                if current_section and current_section_type == 'frontend':
                    self._parse_frontend_section(current_section, current_section_lines)
                elif current_section and current_section_type == 'backend':
                    self._parse_backend_section(current_section, current_section_lines)

                # Detect unsupported section type and add warning
                section_match = re.match(r'^(global|defaults|listen)\s*(\S*)', line, re.IGNORECASE)
                section_type = section_match.group(1).lower()
                section_name = section_match.group(2) or ''
                
                if section_type == 'global':
                    self.warnings.append(
                        "Global section detected and skipped. Global directives are managed at cluster level."
                    )
                elif section_type == 'defaults':
                    self.warnings.append(
                        "Defaults section detected and skipped. Default values are managed at cluster level."
                    )
                elif section_type == 'listen':
                    listen_name_info = f" '{section_name}'" if section_name else ""
                    self.warnings.append(
                        f"Listen section{listen_name_info} detected and skipped. "
                        "Please convert 'listen' sections to separate 'frontend' and 'backend' sections for bulk import."
                    )
                
                # Skip unsupported sections
                current_section = None
                current_section_type = None
                current_section_lines = []

            elif current_section:
                # Add line to current section
                current_section_lines.append(line)

        # Process last section
        if current_section and current_section_type == 'frontend':
            self._parse_frontend_section(current_section, current_section_lines)
        elif current_section and current_section_type == 'backend':
            self._parse_backend_section(current_section, current_section_lines)

    def _parse_frontend_section(self, name: str, lines: List[str]):
        """Parse frontend section"""
        try:
            frontend = ParsedFrontend(name=name)
            ssl_cert_found = False
            
            # Collect HTTP headers, ACL rules, use_backend rules, TCP rules, and options
            request_headers_list = []
            response_headers_list = []
            options_list = []
            acl_rules_list = []
            use_backend_rules_list = []
            tcp_request_rules_list = []

            for line in lines:
                # Parse bind directive
                # IMPORTANT: Handle multiple bind lines correctly
                # Example: bind *:1002 (HTTP) and bind *:443 ssl (HTTPS)
                # Also support bind :80 (no address, defaults to all interfaces)
                bind_match = re.match(r'^bind\s+([^:\s]*):(\d+)', line, re.IGNORECASE)
                if bind_match:
                    port = int(bind_match.group(2))
                    address = bind_match.group(1).strip() if bind_match.group(1) else '*'
                    
                    # Check for SSL in this bind line
                    if 'ssl' in line.lower():
                        # This is an SSL bind - store SSL port separately
                        frontend.ssl_enabled = True
                        frontend.ssl_port = port
                        
                        # CRITICAL FIX: If this is the ONLY bind (no HTTP bind exists),
                        # set bind_port too so SSL-disabled import works correctly
                        if frontend.bind_port == 80:  # Still default, no non-SSL bind found yet
                            frontend.bind_address = address if address != '*' else '*'
                            frontend.bind_port = port  # Preserve port for SSL-disabled scenarios
                        
                        # Check if SSL certificate path is specified in bind directive
                        if 'crt ' in line:
                            ssl_cert_found = True
                            # Extract certificate paths and SSL parameters
                            # CRITICAL FIX: Parse multiple crt paths even with alpn/other params after them
                            cert_paths = []
                            ssl_params_detected = []
                            parts = line.split()
                            
                            i = 0
                            while i < len(parts):
                                part = parts[i]
                                
                                # Extract SSL certificate paths
                                if part == 'crt' and i + 1 < len(parts):
                                    cert_path = parts[i + 1]
                                    # Stop if we hit SSL parameters
                                    if not cert_path.startswith(('alpn', 'npn', 'ca-file', 'ca-ignore-err', 'ca-sign-file', 
                                                                  'ciphers', 'ciphersuites', 'crl-file', 'curves', 
                                                                  'ecdhe', 'force-sslv3', 'force-tlsv10', 'force-tlsv11',
                                                                  'force-tlsv12', 'force-tlsv13', 'generate-certificates',
                                                                  'no-sslv3', 'no-tls-tickets', 'no-tlsv10', 'no-tlsv11',
                                                                  'no-tlsv12', 'no-tlsv13', 'prefer-client-ciphers',
                                                                  'ssl-max-ver', 'ssl-min-ver', 'strict-sni', 'tls-ticket-keys',
                                                                  'verify', 'accept-proxy', 'v4v6', 'v6only')):
                                        cert_paths.append(cert_path)
                                
                                # Parse SSL parameters and store them in frontend object
                                if part == 'alpn' and i + 1 < len(parts):
                                    frontend.ssl_alpn = parts[i + 1]
                                    ssl_params_detected.append(f"alpn {parts[i + 1]}")
                                    i += 1  # Skip the value
                                elif part == 'npn' and i + 1 < len(parts):
                                    frontend.ssl_npn = parts[i + 1]
                                    ssl_params_detected.append(f"npn {parts[i + 1]}")
                                    i += 1
                                elif part == 'ciphers' and i + 1 < len(parts):
                                    frontend.ssl_ciphers = parts[i + 1]
                                    ssl_params_detected.append(f"ciphers {parts[i + 1]}")
                                    i += 1
                                elif part == 'ciphersuites' and i + 1 < len(parts):
                                    frontend.ssl_ciphersuites = parts[i + 1]
                                    ssl_params_detected.append(f"ciphersuites {parts[i + 1]}")
                                    i += 1
                                elif part == 'ssl-min-ver' and i + 1 < len(parts):
                                    frontend.ssl_min_ver = parts[i + 1]
                                    ssl_params_detected.append(f"ssl-min-ver {parts[i + 1]}")
                                    i += 1
                                elif part == 'ssl-max-ver' and i + 1 < len(parts):
                                    frontend.ssl_max_ver = parts[i + 1]
                                    ssl_params_detected.append(f"ssl-max-ver {parts[i + 1]}")
                                    i += 1
                                elif part == 'strict-sni':
                                    frontend.ssl_strict_sni = True
                                    ssl_params_detected.append("strict-sni")
                                
                                i += 1
                            
                            if cert_paths:
                                # CRITICAL: Store first cert path for SSL auto-matching in bulk import
                                frontend.ssl_cert_path = cert_paths[0]
                                
                                self.warnings.append(
                                    f"Frontend '{name}': SSL certificates detected in config ({', '.join(cert_paths)}). "
                                    "SSL certificates should be managed through the SSL Management page, not in the config file."
                                )
                            
                            # Info message about SSL parameters that WERE imported
                            if ssl_params_detected:
                                self.warnings.append(
                                    f"Frontend '{name}': SSL parameters imported: {', '.join(ssl_params_detected)}. "
                                    "You can edit these in Frontend Management after import."
                                )
                    else:
                        # This is a regular HTTP bind - only set if not already set
                        # (to preserve the first non-SSL bind as primary)
                        if frontend.bind_port == 80:  # Default value, not set yet
                            frontend.bind_address = address if address != '*' else '*'
                            frontend.bind_port = port

                # Parse default_backend
                backend_match = re.match(r'^default_backend\s+(\S+)', line, re.IGNORECASE)
                if backend_match:
                    frontend.default_backend = backend_match.group(1)

                # Parse use_backend (also used for default backend in simple configs)
                use_backend_match = re.match(r'^use_backend\s+(\S+)', line, re.IGNORECASE)
                if use_backend_match and not frontend.default_backend:
                    # If no default_backend is set yet, use first use_backend as default
                    frontend.default_backend = use_backend_match.group(1)

                # Parse mode
                mode_match = re.match(r'^mode\s+(\S+)', line, re.IGNORECASE)
                if mode_match:
                    frontend.mode = mode_match.group(1).lower()

                # Parse timeout client
                timeout_client_match = re.match(r'^timeout\s+client\s+(\d+)(ms|s|m|h)?', line, re.IGNORECASE)
                if timeout_client_match:
                    frontend.timeout_client = self._parse_timeout(
                        timeout_client_match.group(1),
                        timeout_client_match.group(2) or ''
                    )

                # Parse maxconn
                maxconn_match = re.match(r'^maxconn\s+(\d+)', line, re.IGNORECASE)
                if maxconn_match:
                    frontend.maxconn = int(maxconn_match.group(1))
                
                # Parse options (httplog, forwardfor, etc.) - NEW for frontend support
                # Note: option httpchk is NOT applicable to frontends (health checks are for backends)
                if line.startswith('option ') and 'httpchk' not in line:
                    # Validate option directive - check for known HAProxy options
                    option_match = re.match(r'^option\s+(\S+)', line, re.IGNORECASE)
                    if option_match:
                        option_name = option_match.group(1)
                        # List of valid HAProxy frontend options
                        valid_options = [
                            'httplog', 'tcplog', 'dontlognull', 'http-keep-alive', 'http-server-close',
                            'forwardfor', 'redispatch', 'http-use-proxy-header', 'tcp-check',
                            'contstats', 'http-pretend-keepalive', 'logasap', 'nolinger', 'persist',
                            'prefer-last-server', 'splice-auto', 'splice-request', 'splice-response',
                            'transparent', 'abortonclose', 'allbackups', 'checkcache', 'clitcpka',
                            'srvtcpka', 'http-no-delay', 'socket-stats', 'tcp-smart-accept',
                            'tcp-smart-connect', 'independant-streams', 'log-separate-errors',
                            'log-health-checks', 'accept-invalid-http-request', 'accept-invalid-http-response'
                        ]
                        
                        if option_name not in valid_options:
                            # Unknown/invalid option - add warning but still collect it
                            self.warnings.append(
                                f"Frontend '{name}': Unknown or invalid option '{option_name}' detected. "
                                "Please verify this directive is supported by your HAProxy version."
                            )
                        
                        # Collect option for frontend.options field
                        options_list.append(line.strip())
                    continue  # Skip options - don't add to request_headers
                elif line.startswith('option ') and 'httpchk' in line:
                    # Warn user that httpchk is not applicable to frontends
                    self.warnings.append(
                        f"Frontend '{name}': 'option httpchk' is not applicable to frontends and will be skipped. "
                        "Health checks are configured in backend definitions."
                    )
                    continue
                
                # Parse HTTP request headers
                if line.startswith('http-request '):
                    # Check for unsupported capture directives
                    if 'capture.req.hdr' in line or 'capture.res.hdr' in line:
                        self.warnings.append(
                            f"Frontend '{name}': Capture directive detected and skipped: '{line.strip()}'. "
                            "Request/response capture directives require additional setup and are not supported in bulk import. "
                            "Please configure these manually after import."
                        )
                        continue  # Skip this directive
                    
                    # Check for use-service directives (ANY service)
                    # Services require specific HAProxy features, Lua scripts, or compile-time options
                    # Cannot be safely imported without knowing agent's HAProxy capabilities
                    if 'use-service' in line:
                        self.warnings.append(
                            f"Frontend '{name}': Service directive detected and skipped: '{line.strip()}'. "
                            "HAProxy services (prometheus-exporter, lua services, custom services) require "
                            "specific features, scripts, or compile-time options that may not be available. "
                            "Please configure service directives manually after import."
                        )
                        continue  # Skip this directive
                    
                    request_headers_list.append(line)
                
                # Parse HTTP response headers
                if line.startswith('http-response '):
                    # Check for unsupported capture references using regex for flexible matching
                    # Matches: %[capture.req.hdr(0)], %[capture.res.hdr(1)], capture.req.hdr, etc.
                    capture_pattern = r'(%\[)?capture\.(req|res)\.hdr(\(\d+\))?(\])?'
                    if re.search(capture_pattern, line):
                        self.warnings.append(
                            f"Frontend '{name}': Response header using capture reference detected and skipped: '{line.strip()}'. "
                            "This requires 'http-request capture' directive which is not supported in bulk import. "
                            "Please configure these manually after import."
                        )
                        continue  # Skip this directive
                    response_headers_list.append(line)
                
                # Parse ACL rules
                if line.startswith('acl '):
                    acl_rules_list.append(line)
                
                # Parse use_backend rules
                if line.startswith('use_backend '):
                    use_backend_rules_list.append(line)
                
                # Parse options (httplog, http-keep-alive, etc.)
                # CRITICAL FIX: Do NOT add option directives to request_headers
                # Options are separate HAProxy config directives, not HTTP headers
                # They are skipped during bulk import as they need special handling
                if line.startswith('option '):
                    # Validate option directive - check for known HAProxy options
                    option_match = re.match(r'^option\s+(\S+)', line, re.IGNORECASE)
                    if option_match:
                        option_name = option_match.group(1)
                        # List of valid HAProxy options (not exhaustive but covers common ones)
                        valid_options = [
                            'httplog', 'tcplog', 'dontlognull', 'http-keep-alive', 'http-server-close',
                            'forwardfor', 'redispatch', 'http-use-proxy-header', 'httpchk', 'tcp-check',
                            'contstats', 'http-pretend-keepalive', 'logasap', 'nolinger', 'persist',
                            'prefer-last-server', 'splice-auto', 'splice-request', 'splice-response',
                            'transparent', 'abortonclose', 'allbackups', 'checkcache', 'clitcpka',
                            'srvtcpka', 'http-no-delay', 'socket-stats', 'tcp-smart-accept',
                            'tcp-smart-connect', 'independant-streams', 'log-separate-errors',
                            'log-health-checks', 'accept-invalid-http-request', 'accept-invalid-http-response',
                            'idle-close-on-response'
                        ]
                        
                        if option_name not in valid_options:
                            # Unknown/invalid option - add warning and skip
                            self.warnings.append(
                                f"Frontend '{name}': Unknown or invalid option '{option_name}' detected and skipped. "
                                "Please verify this directive is supported by your HAProxy version."
                            )
                        else:
                            # Valid option but skip it - bulk import doesn't support custom options yet
                            self.warnings.append(
                                f"Frontend '{name}': HAProxy option '{option_name}' detected and skipped. "
                                f"Custom HAProxy options are not supported in bulk import. "
                                f"Configure options manually after import if needed."
                            )
                    continue  # Always skip options - don't add to request_headers
                
                # Parse TCP request directives
                if line.startswith('tcp-request '):
                    tcp_request_rules_list.append(line)
            
            # Combine collected headers, rules, and options
            if request_headers_list:
                frontend.request_headers = '\n'.join(request_headers_list)
            
            if response_headers_list:
                frontend.response_headers = '\n'.join(response_headers_list)
            
            # NEW: Assign collected options to frontend
            if options_list:
                frontend.options = '\n'.join(options_list)
            
            if acl_rules_list:
                frontend.acl_rules = acl_rules_list
            
            if use_backend_rules_list:
                frontend.use_backend_rules = use_backend_rules_list
            
            if tcp_request_rules_list:
                frontend.tcp_request_rules = '\n'.join(tcp_request_rules_list)

            self.frontends.append(frontend)
            logger.info(f"Parsed frontend: {name} -> {frontend.default_backend}")

        except Exception as e:
            self.errors.append(f"Failed to parse frontend '{name}': {str(e)}")
            logger.error(f"Frontend parsing error: {e}")

    def _parse_backend_section(self, name: str, lines: List[str]):
        """Parse backend section"""
        try:
            backend = ParsedBackend(name=name, servers=[])
            
            # Collect HTTP headers and options
            request_headers_list = []
            response_headers_list = []
            options_list = []

            for line in lines:
                # Parse mode
                mode_match = re.match(r'^mode\s+(\S+)', line, re.IGNORECASE)
                if mode_match:
                    backend.mode = mode_match.group(1).lower()

                # Parse balance method
                balance_match = re.match(r'^balance\s+(\S+)', line, re.IGNORECASE)
                if balance_match:
                    backend.balance_method = balance_match.group(1)

                # Parse timeout directives
                timeout_connect_match = re.match(r'^timeout\s+connect\s+(\d+)(ms|s|m|h)?', line, re.IGNORECASE)
                if timeout_connect_match:
                    backend.timeout_connect = self._parse_timeout(
                        timeout_connect_match.group(1),
                        timeout_connect_match.group(2) or ''
                    )

                timeout_server_match = re.match(r'^timeout\s+server\s+(\d+)(ms|s|m|h)?', line, re.IGNORECASE)
                if timeout_server_match:
                    backend.timeout_server = self._parse_timeout(
                        timeout_server_match.group(1),
                        timeout_server_match.group(2) or ''
                    )

                # Parse health check
                httpchk_match = re.match(r'^option\s+httpchk\s+(?:GET\s+)?(\S+)', line, re.IGNORECASE)
                if httpchk_match:
                    backend.health_check_uri = httpchk_match.group(1)
                
                # Parse http-check expect status
                http_check_expect_match = re.match(r'^http-check\s+expect\s+status\s+(\d+)', line, re.IGNORECASE)
                if http_check_expect_match:
                    backend.health_check_expected_status = int(http_check_expect_match.group(1))
                
                # Parse fullconn
                fullconn_match = re.match(r'^fullconn\s+(\d+)', line, re.IGNORECASE)
                if fullconn_match:
                    backend.fullconn = int(fullconn_match.group(1))
                
                # Parse cookie directive
                cookie_match = re.match(r'^cookie\s+(\S+)\s+(.*)', line, re.IGNORECASE)
                if cookie_match:
                    backend.cookie_name = cookie_match.group(1)
                    backend.cookie_options = cookie_match.group(2).strip()
                
                # Parse default-server directive
                default_server_match = re.match(r'^default-server\s+(.*)', line, re.IGNORECASE)
                if default_server_match:
                    options = default_server_match.group(1)
                    # Parse inter, fall, rise from default-server
                    inter_match = re.search(r'inter\s+(\d+)(ms|s)?', options)
                    if inter_match:
                        backend.default_server_inter = self._parse_timeout(
                            inter_match.group(1),
                            inter_match.group(2) or 'ms'
                        )
                    
                    fall_match = re.search(r'fall\s+(\d+)', options)
                    if fall_match:
                        backend.default_server_fall = int(fall_match.group(1))
                    
                    rise_match = re.search(r'rise\s+(\d+)', options)
                    if rise_match:
                        backend.default_server_rise = int(rise_match.group(1))
                
                # Parse options (http-keep-alive, tcp-check, etc.)
                # Note: option httpchk is handled separately above
                # NEW: Collect options for backend.options field
                if line.startswith('option ') and 'httpchk' not in line:
                    # Validate option directive - check for known HAProxy options
                    option_match = re.match(r'^option\s+(\S+)', line, re.IGNORECASE)
                    if option_match:
                        option_name = option_match.group(1)
                        # List of valid HAProxy options
                        valid_options = [
                            'httplog', 'tcplog', 'dontlognull', 'http-keep-alive', 'http-server-close',
                            'forwardfor', 'redispatch', 'http-use-proxy-header', 'httpchk', 'tcp-check',
                            'contstats', 'http-pretend-keepalive', 'logasap', 'nolinger', 'persist',
                            'prefer-last-server', 'splice-auto', 'splice-request', 'splice-response',
                            'transparent', 'abortonclose', 'allbackups', 'checkcache', 'clitcpka',
                            'srvtcpka', 'http-no-delay', 'socket-stats', 'tcp-smart-accept',
                            'tcp-smart-connect', 'independant-streams', 'log-separate-errors',
                            'log-health-checks', 'accept-invalid-http-request', 'accept-invalid-http-response'
                        ]
                        
                        if option_name not in valid_options:
                            # Unknown/invalid option - add warning but still collect it
                            self.warnings.append(
                                f"Backend '{name}': Unknown or invalid option '{option_name}' detected. "
                                "Please verify this directive is supported by your HAProxy version."
                            )
                        
                        # Collect option for backend.options field
                        options_list.append(line.strip())
                    continue  # Skip options - don't add to request_headers
                
                # Parse HTTP request headers
                if line.startswith('http-request '):
                    # Check for unsupported capture directives
                    if 'capture.req.hdr' in line or 'capture.res.hdr' in line:
                        self.warnings.append(
                            f"Backend '{name}': Capture directive detected and skipped: '{line.strip()}'. "
                            "Request/response capture directives require additional setup and are not supported in bulk import. "
                            "Please configure these manually after import."
                        )
                        continue  # Skip this directive
                    
                    # Check for use-service directives (consistent with frontend parser)
                    # Services require specific HAProxy features, Lua scripts, or compile-time options
                    # Cannot be safely imported without knowing agent's HAProxy capabilities
                    if 'use-service' in line:
                        self.warnings.append(
                            f"Backend '{name}': Service directive detected and skipped: '{line.strip()}'. "
                            "HAProxy services (prometheus-exporter, lua services, custom services) require "
                            "specific features, scripts, or compile-time options that may not be available. "
                            "Please configure service directives manually after import."
                        )
                        continue  # Skip this directive
                    
                    request_headers_list.append(line)
                
                # Parse HTTP response headers
                if line.startswith('http-response '):
                    # Check for unsupported capture references
                    if 'capture.req.hdr' in line or 'capture.res.hdr' in line or '%[capture.req.hdr' in line or '%[capture.res.hdr' in line:
                        self.warnings.append(
                            f"Backend '{name}': Response header using capture reference detected and skipped: '{line.strip()}'. "
                            "This requires 'http-request capture' directive which is not supported in bulk import. "
                            "Please configure these manually after import."
                        )
                        continue  # Skip this directive
                    response_headers_list.append(line)

                # Parse server definitions
                # CRITICAL FIX: Port is optional in HAProxy (defaults to backend's default port)
                # Match both "server name addr:port" and "server name addr"
                server_match = re.match(
                    r'^server\s+(\S+)\s+([^:\s]+)(?::(\d+))?(?:\s+(.*))?',
                    line,
                    re.IGNORECASE
                )
                if server_match:
                    # Port is optional - if not specified, use None (backend will use default)
                    port_str = server_match.group(3)
                    port = port_str if port_str else None
                    
                    server = self._parse_server_line(
                        server_match.group(1),  # server name
                        server_match.group(2),  # address
                        port,  # port (can be None)
                        server_match.group(4) or ""  # options
                    )
                    backend.servers.append(server)
            
            # Combine collected headers
            if request_headers_list:
                backend.request_headers = '\n'.join(request_headers_list)
            
            if response_headers_list:
                backend.response_headers = '\n'.join(response_headers_list)
            
            # CRITICAL FIX: Filter out portless servers in TCP backends
            # TCP backends REQUIRE explicit port specification
            if backend.mode == 'tcp' and backend.servers:
                original_count = len(backend.servers)
                portless_servers = [s for s in backend.servers if s.server_port == 0]
                
                if portless_servers:
                    # Remove portless servers from TCP backend
                    backend.servers = [s for s in backend.servers if s.server_port != 0]
                    
                    # Add WARNING (not error) - allow backend creation with 0 servers
                    # User can add servers later via UI
                    portless_names = ', '.join([s.server_name for s in portless_servers[:5]])
                    if len(portless_servers) > 5:
                        portless_names += f" (and {len(portless_servers) - 5} more)"
                    
                    self.warnings.append(
                        f"Backend '{name}' (TCP mode): {len(portless_servers)} server(s) without port specification "
                        f"({portless_names}). These servers have been EXCLUDED from import. "
                        f"Backend will be created with {len(backend.servers)} server(s). "
                        f"Add missing servers with ports via Backend Management page after import."
                    )
                    
                    logger.warning(f"Backend '{name}': Excluded {len(portless_servers)} portless servers (TCP mode requires ports)")

            # Assign collected options to backend (NEW)
            if options_list:
                backend.options = '\n'.join(options_list)
            
            # DNS HOSTNAME DETECTION: Warn if servers use hostnames instead of IPs
            if backend.servers:
                hostname_servers = []
                for server in backend.servers:
                    # Check if server_address is NOT an IP address (simple IPv4 check)
                    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', server.server_address):
                        hostname_servers.append(f"{server.server_name} ({server.server_address})")
                
                if hostname_servers:
                    hostname_list = ', '.join(hostname_servers[:3])
                    if len(hostname_servers) > 3:
                        hostname_list += f" (and {len(hostname_servers) - 3} more)"
                    
                    self.warnings.append(
                        f"🌐 DNS: Backend '{name}' uses hostname(s): {hostname_list}. "
                        f"Ensure DNS resolution is configured on target servers. "
                        f"HAProxy will fail to start if hostnames cannot be resolved. "
                        f"Consider adding entries to /etc/hosts or configuring DNS server."
                    )

            self.backends.append(backend)
            logger.info(f"Parsed backend: {name} with {len(backend.servers)} servers")

        except Exception as e:
            self.errors.append(f"Failed to parse backend '{name}': {str(e)}")
            logger.error(f"Backend parsing error: {e}")

    def _parse_server_line(
        self,
        name: str,
        address: str,
        port: str,  # Can be None if port not specified
        options: str
    ) -> ParsedServer:
        """Parse server line and extract options"""
        # CRITICAL FIX: Port can be None in HAProxy (uses backend default)
        # If port is not specified, use 0 as placeholder (will use backend's default port)
        server_port = int(port) if port else 0
        
        server = ParsedServer(
            server_name=name,
            server_address=address,
            server_port=server_port
        )

        # Parse options
        if 'check' in options.lower():
            server.check_enabled = True
        
        if 'backup' in options.lower():
            server.backup_server = True
        
        if 'ssl' in options.lower():
            server.ssl_enabled = True

        # Parse weight
        weight_match = re.search(r'weight\s+(\d+)', options, re.IGNORECASE)
        if weight_match:
            server.weight = int(weight_match.group(1))

        # Parse maxconn
        maxconn_match = re.search(r'maxconn\s+(\d+)', options, re.IGNORECASE)
        if maxconn_match:
            server.max_connections = int(maxconn_match.group(1))
        
        # Parse check port
        check_port_match = re.search(r'check\s+port\s+(\d+)', options, re.IGNORECASE)
        if check_port_match:
            server.check_port = int(check_port_match.group(1))
        
        # Parse SSL verification
        verify_match = re.search(r'verify\s+(none|required)', options, re.IGNORECASE)
        ca_file_match = re.search(r'ca-file\s+(\S+)', options, re.IGNORECASE)
        
        # CRITICAL FIX: HAProxy validation requires ca-file when verify=required
        # If ca-file exists, we remove it but must also change verify to 'none'
        # Otherwise HAProxy validation fails: "verify required but no CA file"
        if verify_match and ca_file_match:
            # Both verify and ca-file exist
            ca_file_path = ca_file_match.group(1)
            # Change verify to 'none' since we're removing ca-file
            server.ssl_verify = 'none'
            self.warnings.append(
                f"SSL: Server '{name}' has 'verify required' with ca-file '{ca_file_path}'. "
                f"CA file has been REMOVED and verify changed to 'none' to pass HAProxy validation. "
                f"After import, edit this server, select SSL certificate from dropdown, then set verify to 'required'."
            )
        elif verify_match:
            # Only verify exists (no ca-file)
            server.ssl_verify = verify_match.group(1).lower()
        elif ca_file_match:
            # Only ca-file exists (no verify) - this is rare but handle it
            ca_file_path = ca_file_match.group(1)
            server.ssl_verify = 'none'  # Default to none when ca-file removed
            self.warnings.append(
                f"SSL: Server '{name}' has ca-file '{ca_file_path}' which has been REMOVED. "
                f"SSL verify set to 'none'. After import, select SSL certificate and configure verify."
            )
        
        # Parse SSL Advanced Options (server SSL parameters)
        sni_match = re.search(r'sni\s+(\S+)', options, re.IGNORECASE)
        if sni_match:
            server.ssl_sni = sni_match.group(1)
        
        ssl_min_ver_match = re.search(r'ssl-min-ver\s+(\S+)', options, re.IGNORECASE)
        if ssl_min_ver_match:
            server.ssl_min_ver = ssl_min_ver_match.group(1)
        
        ssl_max_ver_match = re.search(r'ssl-max-ver\s+(\S+)', options, re.IGNORECASE)
        if ssl_max_ver_match:
            server.ssl_max_ver = ssl_max_ver_match.group(1)
        
        ciphers_match = re.search(r'ciphers\s+([^\s]+)', options, re.IGNORECASE)
        if ciphers_match:
            server.ssl_ciphers = ciphers_match.group(1)
        
        # Parse cookie value
        cookie_match = re.search(r'cookie\s+(\S+)', options, re.IGNORECASE)
        if cookie_match:
            server.cookie_value = cookie_match.group(1)
        
        # Parse inter (health check interval)
        inter_match = re.search(r'inter\s+(\d+)(ms|s)?', options, re.IGNORECASE)
        if inter_match:
            server.inter = self._parse_timeout(
                inter_match.group(1),
                inter_match.group(2) or 'ms'
            )
        
        # Parse fall
        fall_match = re.search(r'fall\s+(\d+)', options, re.IGNORECASE)
        if fall_match:
            server.fall = int(fall_match.group(1))
        
        # Parse rise
        rise_match = re.search(r'rise\s+(\d+)', options, re.IGNORECASE)
        if rise_match:
            server.rise = int(rise_match.group(1))

        return server

    def _parse_timeout(self, value: str, unit: str) -> int:
        """Convert timeout value to milliseconds
        
        HAProxy timeout units:
        - ms: milliseconds (default if no unit)
        - s: seconds
        - m: minutes
        - h: hours
        """
        value = int(value)
        
        if unit == 'ms' or unit == '':
            # Milliseconds (explicit or default)
            return value
        elif unit == 's':
            return value * 1000
        elif unit == 'm':
            return value * 60 * 1000
        elif unit == 'h':
            return value * 3600 * 1000
        else:
            # Fallback: treat as milliseconds
            return value

    def _validate_parsed_config(self):
        """
        Post-parse validation of parsed configuration
        Removes invalid entities and adds warnings for skipped items
        """
        # Check for duplicate frontend names - remove duplicates keeping first occurrence
        frontend_names_seen = set()
        valid_frontends = []
        for frontend in self.frontends:
            if frontend.name in frontend_names_seen:
                self.warnings.append(
                    f"⚠️ SKIPPED: Duplicate frontend '{frontend.name}' - keeping first occurrence only."
                )
            else:
                frontend_names_seen.add(frontend.name)
                valid_frontends.append(frontend)
        
        # Check for duplicate backend names - remove duplicates keeping first occurrence
        backend_names_seen = set()
        valid_backends = []
        for backend in self.backends:
            if backend.name in backend_names_seen:
                self.warnings.append(
                    f"⚠️ SKIPPED: Duplicate backend '{backend.name}' - keeping first occurrence only."
                )
            else:
                backend_names_seen.add(backend.name)
                valid_backends.append(backend)
        
        # Update lists with deduplicated entities
        self.frontends = valid_frontends
        self.backends = valid_backends
        
        # Build set of valid backend names for reference checking
        backend_names = {b.name for b in self.backends}
        
        # CRITICAL VALIDATION: Remove backends without servers (HAProxy requirement)
        backends_to_keep = []
        removed_backend_names = set()
        
        for backend in self.backends:
            # Check if backend has no servers
            if not backend.servers or len(backend.servers) == 0:
                removed_backend_names.add(backend.name)
                
                # Check if this backend had portless servers that were excluded
                has_portless_warning = any(
                    f"Backend '{backend.name}'" in w and "EXCLUDED" in w 
                    for w in self.warnings
                )
                
                if has_portless_warning:
                    self.warnings.append(
                        f"⚠️ SKIPPED: Backend '{backend.name}' has NO VALID SERVERS (all servers excluded due to missing port). "
                        f"HAProxy requires explicit port specification for TCP backends. This backend will NOT be created."
                    )
                else:
                    self.warnings.append(
                        f"⚠️ SKIPPED: Backend '{backend.name}' has NO SERVERS. "
                        f"HAProxy requires at least one server per backend. This backend will NOT be created."
                    )
            else:
                # Backend has servers, but check if TCP backend still has portless servers (shouldn't happen but be safe)
                if backend.mode == 'tcp':
                    portless_count = sum(1 for s in backend.servers if s.server_port == 0)
                    if portless_count > 0:
                        # This shouldn't happen (should be filtered during parse)
                        # but if it does, exclude those servers now
                        backend.servers = [s for s in backend.servers if s.server_port != 0]
                        self.warnings.append(
                            f"⚠️ Backend '{backend.name}' (TCP): Removed {portless_count} server(s) with missing port during validation."
                        )
                        
                        # If no servers left after filtering, skip backend
                        if len(backend.servers) == 0:
                            removed_backend_names.add(backend.name)
                            self.warnings.append(
                                f"⚠️ SKIPPED: Backend '{backend.name}' has NO VALID SERVERS after port validation. "
                                f"This backend will NOT be created."
                            )
                            continue
                
                backends_to_keep.append(backend)
        
        self.backends = backends_to_keep
        backend_names = {b.name for b in self.backends}  # Update valid backend names
        
        # CRITICAL VALIDATION: Remove or fix frontends with missing backends
        frontends_to_keep = []
        
        for frontend in self.frontends:
            # Check for valid bind configuration
            if not frontend.bind_port or frontend.bind_port == 0:
                # If SSL port exists, use that instead
                if frontend.ssl_enabled and frontend.ssl_port and frontend.ssl_port > 0:
                    # Frontend only has SSL bind, this is valid
                    pass
                else:
                    self.warnings.append(
                        f"⚠️ SKIPPED: Frontend '{frontend.name}' has invalid bind port ({frontend.bind_port}) "
                        f"and no valid SSL port. This frontend will NOT be created."
                    )
                    continue
            
            # Check if frontend has any backend routing
            has_default_backend = frontend.default_backend is not None
            # CRITICAL FIX: use_backend_rules is now a list, not a string
            has_use_backend_rules = bool(frontend.use_backend_rules)
            
            if not has_default_backend and not has_use_backend_rules:
                # Frontend has no routing - check if it has redirect rules
                has_redirect = frontend.request_headers and 'redirect' in frontend.request_headers.lower()
                
                if has_redirect:
                    # Frontend only does redirects - this is valid, keep it
                    self.warnings.append(
                        f"✓ Frontend '{frontend.name}': No backend routing (redirect-only frontend). This is valid."
                    )
                    frontends_to_keep.append(frontend)
                else:
                    # Frontend has no routing at all - skip it
                    self.warnings.append(
                        f"⚠️ SKIPPED: Frontend '{frontend.name}' has NO default_backend and NO routing rules. "
                        f"This frontend will NOT be created."
                    )
                continue
            
            # Check if referenced backend exists
            if has_default_backend:
                if frontend.default_backend in removed_backend_names:
                    self.warnings.append(
                        f"⚠️ SKIPPED: Frontend '{frontend.name}' references backend '{frontend.default_backend}' "
                        f"which was skipped (no servers). This frontend will NOT be created."
                    )
                    continue
                elif frontend.default_backend not in backend_names:
                    self.warnings.append(
                        f"⚠️ WARNING: Frontend '{frontend.name}' references backend '{frontend.default_backend}' "
                        f"which is not defined in this config. Make sure this backend exists in your cluster, "
                        f"or the frontend will fail validation."
                    )
                    # Still keep the frontend - backend might exist in cluster
            
            # Frontend passed all checks
            frontends_to_keep.append(frontend)
        
        self.frontends = frontends_to_keep
        
        # Check for portless servers in HTTP mode
        for backend in self.backends:
            if backend.servers and backend.mode != 'tcp':
                portless_servers = [s for s in backend.servers if s.server_port == 0]
                if portless_servers:
                    server_names = ', '.join([s.server_name for s in portless_servers[:3]])
                    if len(portless_servers) > 3:
                        server_names += f" (and {len(portless_servers) - 3} more)"
                    
                    self.warnings.append(
                        f"⚠️ Backend '{backend.name}' (HTTP): Servers without port: {server_names}. "
                        f"Default port 80 (or 443 for SSL) will be used."
                    )
            
            # Check for invalid mode + health check combinations
            if backend.mode == 'tcp' and backend.health_check_expected_status:
                self.warnings.append(
                    f"⚠️ Backend '{backend.name}': HTTP health check status removed (TCP mode incompatible)."
                )
        
        # Check if all entities were filtered out
        if len(self.frontends) == 0 and len(self.backends) == 0:
            self.warnings.append(
                "⚠️ No valid frontends or backends could be parsed. "
                "Check the warnings above for details on what was skipped."
            )


def parse_haproxy_config(config_content: str) -> ParseResult:
    """
    Parse HAProxy configuration content
    
    Args:
        config_content: HAProxy configuration file content
        
    Returns:
        ParseResult with parsed entities
    """
    parser = HAProxyConfigParser()
    return parser.parse(config_content)

