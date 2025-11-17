import asyncio
import logging
import hashlib
import time
import json
from typing import Optional, List, Dict, Any
from database.connection import get_database_connection, close_database_connection

logger = logging.getLogger(__name__)

async def _get_ssl_certificate_path(frontend: Dict[str, Any], cluster_id: int, db_conn: Any) -> Optional[str]:
    """
    Get SSL certificate path for frontend based on ssl_certificate_id
    Returns the path where agent should place the certificate file
    """
    try:
        ssl_cert_id = frontend.get('ssl_certificate_id')
        logger.info(f"SSL PATH DEBUG: Frontend '{frontend.get('name')}' ssl_certificate_id: {ssl_cert_id}, cluster_id: {cluster_id}")
        if not ssl_cert_id:
            logger.warning(f"SSL PATH DEBUG: No ssl_certificate_id found for frontend '{frontend.get('name')}'")
            return None
        
        # Get SSL certificate info - Check both global and cluster-specific certificates
        ssl_cert = await db_conn.fetchrow("""
            SELECT DISTINCT s.name, s.primary_domain as domain, s.fingerprint
            FROM ssl_certificates s
            LEFT JOIN ssl_certificate_clusters scc ON s.id = scc.ssl_certificate_id
            WHERE s.id = $1 AND s.is_active = TRUE
            AND (s.cluster_id IS NULL OR scc.cluster_id = $2)
        """, ssl_cert_id, cluster_id)
        
        logger.info(f"SSL PATH DEBUG: Query result for cert_id {ssl_cert_id}, cluster {cluster_id}: {ssl_cert}")
        
        if not ssl_cert:
            logger.warning(f"SSL certificate with ID {ssl_cert_id} not found for cluster {cluster_id}")
            return None
        
        # Generate certificate file path that agent will use
        # Format: /etc/ssl/haproxy/{cert_name}.pem
        cert_filename = f"{ssl_cert['name']}.pem"
        cert_path = f"/etc/ssl/haproxy/{cert_filename}"
        
        logger.debug(f"SSL certificate path for frontend '{frontend['name']}': {cert_path}")
        return cert_path
        
    except Exception as e:
        logger.error(f"Error getting SSL certificate path: {e}")
        return None

async def generate_haproxy_config_for_cluster(cluster_id: int, conn: Optional[Any] = None) -> str:
    """
    Generates a complete HAProxy configuration for a given cluster ID.
    It can optionally use an existing database connection to operate within a transaction.
    """
    db_conn = None
    try:
        # Use the provided connection if available, otherwise create a new one
        db_conn = conn or await get_database_connection()
        
        # Get cluster-specific settings
        cluster_info = await db_conn.fetchrow("SELECT * FROM haproxy_clusters WHERE id = $1", cluster_id)
        if not cluster_info:
            logger.error(f"Config Generation: Cluster with ID {cluster_id} not found.")
            return "# Error: Cluster not found"
            
        stats_socket_path = cluster_info.get('stats_socket_path', '/run/haproxy/admin.sock')
        
        # Check if any agents in this cluster are running on macOS/Darwin
        darwin_agents = await db_conn.fetchrow("""
            SELECT COUNT(*) as count FROM agents 
            WHERE (platform = 'darwin' OR operating_system LIKE '%macOS%' OR operating_system LIKE '%Darwin%')
            AND pool_id IN (SELECT pool_id FROM haproxy_clusters WHERE id = $1)
        """, cluster_id)
        
        is_macos_cluster = darwin_agents['count'] > 0 if darwin_agents else False

        # Get all active frontends for this cluster
        frontends = await db_conn.fetch(
            "SELECT * FROM frontends WHERE cluster_id = $1 AND is_active = TRUE ORDER BY name", 
            cluster_id
        )
        
        # Get all active backends for this cluster
        backends = await db_conn.fetch(
            "SELECT * FROM backends WHERE cluster_id = $1 AND is_active = TRUE ORDER BY name", 
            cluster_id
        )
        
        # Get all active WAF rules associated with frontends in this cluster
        # CRITICAL: Include both APPLIED and PENDING rules during config generation
        # CRITICAL: Exclude WAF rules marked for deletion (is_active = FALSE)
        waf_rules_records = await db_conn.fetch("""
            SELECT w.*, array_agg(fw.frontend_id) as frontend_ids
            FROM waf_rules w
            JOIN frontend_waf_rules fw ON w.id = fw.waf_rule_id
            WHERE w.is_active = TRUE AND fw.frontend_id IN (SELECT id FROM frontends WHERE cluster_id = $1)
            GROUP BY w.id
        """, cluster_id)

        # Get cluster-global WAF rules (no explicit frontend assignments). Apply to all frontends.
        # CRITICAL: Include both APPLIED and PENDING rules during config generation
        # CRITICAL: Exclude WAF rules marked for deletion (is_active = FALSE)
        cluster_global_waf_rules = await db_conn.fetch(
            """
            SELECT w.*
            FROM waf_rules w
            WHERE w.is_active = TRUE
              AND (w.cluster_id = $1 OR w.cluster_id IS NULL)
              AND NOT EXISTS (
                    SELECT 1 FROM frontend_waf_rules fwr WHERE fwr.waf_rule_id = w.id
              )
            ORDER BY w.priority, w.name
            """,
            cluster_id,
        )

        # CRITICAL FIX: Check for pending delete operations and exclude those WAF rules
        # Find WAF rules that are marked for deletion but still active in database
        pending_delete_waf_ids = set()
        try:
            pending_delete_versions = await db_conn.fetch("""
                SELECT version_name FROM config_versions 
                WHERE cluster_id = $1 AND status = 'PENDING' AND version_name ~ '^waf-[0-9]+-delete-'
            """, cluster_id)
            import re
            for version in pending_delete_versions:
                match = re.search(r'^waf-(\d+)-delete-', version['version_name'])
                if match:
                    pending_delete_waf_ids.add(int(match.group(1)))
            
            if pending_delete_waf_ids:
                logger.info(f"Config Generation: Excluding {len(pending_delete_waf_ids)} WAF rules pending deletion: {pending_delete_waf_ids}")
        except Exception as e:
            logger.warning(f"Config Generation: Failed to check pending delete WAF rules: {e}")

        # Filter out WAF rules that are pending deletion
        if pending_delete_waf_ids:
            waf_rules_records = [rule for rule in waf_rules_records if rule['id'] not in pending_delete_waf_ids]
            cluster_global_waf_rules = [rule for rule in cluster_global_waf_rules if rule['id'] not in pending_delete_waf_ids]

        # CRITICAL DESIGN CHANGE: DO NOT generate global or defaults sections
        # Agent will preserve existing global and defaults from local haproxy.cfg
        # We ONLY generate: frontends + backends
        # This ensures:
        # 1. Bulk imports never touch global/defaults configuration
        # 2. Entity updates (frontend/backend/SSL) never modify global/defaults
        # 3. Agent maintains control over platform-specific settings (chroot, user, stats socket, etc.)
        logger.info("📝 CONFIG GENERATION: Generating PARTIAL config (frontends + backends only)")
        logger.info("📝 CONFIG GENERATION: Agent will preserve existing global + defaults sections")
        
        config_lines = [
            "# ═══════════════════════════════════════════════════════════════════════",
            "# Generated by HAProxy Open Manager - Partial Configuration",
            "# ═══════════════════════════════════════════════════════════════════════",
            "# This is a PARTIAL configuration containing only:",
            "#   - Frontends (user-defined + stats)",
            "#   - Backends (user-defined)",
            "#",
            "# NOT INCLUDED (preserved from existing haproxy.cfg):",
            "#   - global section",
            "#   - defaults section", 
            "#",
            "# Agent will merge this with existing global/defaults sections",
            "# ═══════════════════════════════════════════════════════════════════════",
            ""
        ]
        
        # CRITICAL: Build backend mode lookup for validation
        backend_modes = {backend['name']: backend['mode'] for backend in backends}
        
        # Add frontends with comprehensive configuration
        for frontend in frontends:
            # Validate required fields
            if not frontend.get('name'):
                logger.error("Frontend with missing name detected - skipping")
                continue
            if not frontend.get('bind_port') or not frontend.get('bind_address'):
                logger.error(f"Frontend '{frontend['name']}' has invalid bind configuration (address: {frontend.get('bind_address')}, port: {frontend.get('bind_port')}) - skipping")
                continue
            
            config_lines.append(f"frontend {frontend['name']}")
            
            # BIND DIRECTIVE - Single bind line with conditional SSL
            # SSL Configuration - ENTERPRISE DUAL-MODE SUPPORT
            # NEW WAY (Preferred): ssl_certificate_ids (multiple certs on bind_port)
            # OLD WAY (Deprecated): ssl_certificate_id + ssl_port (separate HTTPS port)
            
            bind_added = False  # Track if bind line was added
            
            if frontend.get('ssl_enabled', False):
                ssl_cert_ids = frontend.get('ssl_certificate_ids')
                
                # CRITICAL: Parse JSONB string from database
                # PostgreSQL returns JSONB as string: '[1, 2, 3]' → need to parse it
                if ssl_cert_ids and isinstance(ssl_cert_ids, str):
                    try:
                        import json
                        ssl_cert_ids = json.loads(ssl_cert_ids)
                    except (json.JSONDecodeError, ValueError):
                        logger.warning(f"Failed to parse ssl_certificate_ids for frontend '{frontend['name']}': {ssl_cert_ids}")
                        ssl_cert_ids = None
                
                # NEW WAY: Multiple SSL certificates on single bind (preferred)
                if ssl_cert_ids and isinstance(ssl_cert_ids, list) and len(ssl_cert_ids) > 0:
                    logger.info(f"🆕 SSL NEW MODE: Processing {len(ssl_cert_ids)} certificate(s) for frontend '{frontend['name']}'")
                    
                    # Get all certificate paths
                    cert_paths = []
                    for cert_id in ssl_cert_ids:
                        # Create temp frontend dict for each cert
                        temp_fe = {'ssl_certificate_id': cert_id, 'name': frontend['name']}
                        cert_path = await _get_ssl_certificate_path(temp_fe, cluster_id, db_conn)
                        if cert_path:
                            cert_paths.append(cert_path)
                    
                    if cert_paths:
                        # Generate single bind with SSL and multiple certificates
                        # Format: bind :443 ssl crt file1.pem crt file2.pem crt file3.pem
                        crt_clause = ' '.join([f"crt {path}" for path in cert_paths])
                        config_lines.append(f"    bind {frontend['bind_address']}:{frontend['bind_port']} ssl {crt_clause}")
                        bind_added = True
                        logger.info(f"SSL NEW MODE: Added {len(cert_paths)} certificate(s) on port {frontend['bind_port']}")
                    else:
                        logger.warning(f"SSL enabled but no valid certificates found for frontend '{frontend['name']}'")
                
                # OLD WAY: Single SSL certificate on separate port (backward compatibility)
                elif frontend.get('ssl_certificate_id'):
                    logger.info(f"SSL OLD MODE (DEPRECATED): Single cert for frontend '{frontend['name']}'")
                    ssl_cert_path = await _get_ssl_certificate_path(frontend, cluster_id, db_conn)
                    if ssl_cert_path:
                        # Use explicit SSL port or default to 443
                        https_port = frontend.get('ssl_port') or 443
                        config_lines.append(f"    bind {frontend['bind_address']}:{https_port} ssl crt {ssl_cert_path}")
                        bind_added = True
                        logger.info(f"SSL OLD MODE: Separate HTTPS port {https_port} with single cert")
                    else:
                        logger.warning(f"SSL enabled but certificate not found for frontend '{frontend['name']}'")
                else:
                    logger.warning(f"SSL enabled but no certificates configured for frontend '{frontend['name']}'")
            
            # If no SSL bind was added (SSL disabled or failed), add plain HTTP bind
            if not bind_added:
                config_lines.append(f"    bind {frontend['bind_address']}:{frontend['bind_port']}")
            
            config_lines.append(f"    mode {frontend['mode']}")
            
            # Frontend Options (option httplog, option forwardfor, etc.)
            # Place options early as per HAProxy best practice
            if frontend.get('options'):
                for line in frontend['options'].split('\n'):
                    line_stripped = line.strip()
                    # Skip empty strings, "[]", or invalid rules
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        # Lines are complete HAProxy option directives
                        # Examples: "option httplog", "option forwardfor", "option dontlognull"
                        config_lines.append(f"    {line_stripped}")
            
            # CRITICAL: Validate frontend-backend mode compatibility
            if frontend.get('default_backend'):
                default_backend_name = frontend['default_backend'].strip() if frontend['default_backend'] else ''
                # Skip empty strings, "[]", or invalid backend names
                if default_backend_name and default_backend_name not in ('[]', '{}', 'null', 'None'):
                    backend_mode = backend_modes.get(default_backend_name)
                    
                    if backend_mode and backend_mode != frontend['mode']:
                        # Mode mismatch - this will cause HAProxy validation to fail!
                        logger.error(f"CONFIG ERROR: Frontend '{frontend['name']}' mode '{frontend['mode']}' does not match backend '{default_backend_name}' mode '{backend_mode}'")
                        config_lines.append(f"    # WARNING: Backend '{default_backend_name}' has mode '{backend_mode}' but frontend has mode '{frontend['mode']}'")
                        config_lines.append(f"    # WARNING: HAProxy will reject this configuration! Please fix the mode mismatch in UI.")
                    
                    config_lines.append(f"    default_backend {default_backend_name}")
                else:
                    logger.warning(f"CONFIG WARNING: Frontend '{frontend['name']}' has invalid default_backend: '{frontend.get('default_backend')}' - skipping")
            
            # Timeouts - CRITICAL FIX: Append 'ms' suffix
            if frontend.get('timeout_client'):
                config_lines.append(f"    timeout client {frontend['timeout_client']}ms")
            if frontend.get('timeout_http_request'):
                config_lines.append(f"    timeout http-request {frontend['timeout_http_request']}ms")
                
            # Max connections
            if frontend.get('maxconn'):
                config_lines.append(f"    maxconn {frontend['maxconn']}")
                
            # Rate limiting
            if frontend.get('rate_limit'):
                config_lines.append(f"    stick-table type ip size 100k expire 30s store http_req_rate(10s)")
                config_lines.append(f"    http-request track-sc0 src")
                config_lines.append(f"    http-request deny if {{ sc_http_req_rate(0) gt {frontend['rate_limit']} }}")
            
            # Compression
            if frontend.get('compression', False):
                config_lines.append("    compression algo gzip")
                config_lines.append("    compression type text/html text/plain text/css text/javascript application/javascript")
            
            # Monitor URI
            if frontend.get('monitor_uri'):
                monitor_uri = frontend['monitor_uri'].strip() if frontend['monitor_uri'] else ''
                # Skip empty strings, "[]", or invalid values
                if monitor_uri and monitor_uri not in ('[]', '{}', 'null', 'None'):
                    config_lines.append(f"    monitor-uri {monitor_uri}")
            
            # HTTP Request Headers
            if frontend.get('request_headers'):
                for line in frontend['request_headers'].split('\n'):
                    line_stripped = line.strip()
                    # Skip empty strings, "[]", or invalid rules
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        # Lines are already complete directives (e.g., "http-request set-header X-Test 1")
                        config_lines.append(f"    {line_stripped}")
            
            # HTTP Response Headers
            if frontend.get('response_headers'):
                for line in frontend['response_headers'].split('\n'):
                    line_stripped = line.strip()
                    # Skip empty strings, "[]", or invalid rules
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        # Lines are already complete directives (e.g., "http-response add-header X-Frame-Options DENY")
                        config_lines.append(f"    {line_stripped}")
            
            # TCP Request Rules (for TCP mode frontends)
            if frontend.get('tcp_request_rules'):
                for line in frontend['tcp_request_rules'].split('\n'):
                    line_stripped = line.strip()
                    # Skip empty strings, "[]", or invalid rules
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        # Lines are already complete directives (e.g., "tcp-request inspect-delay 5s")
                        config_lines.append(f"    {line_stripped}")
            
            # ACL Rules
            if frontend.get('acl_rules'):
                acl_rules = frontend['acl_rules']
                # Parse JSON string if needed
                if isinstance(acl_rules, str):
                    try:
                        acl_rules = json.loads(acl_rules)
                    except:
                        acl_rules = []
                
                if isinstance(acl_rules, list):
                    for acl in acl_rules:
                        if acl and acl.strip():
                            acl_text = acl.strip()
                            # Skip empty strings, "[]", or invalid ACL rules
                            if acl_text and acl_text not in ('[]', '{}', 'null', 'None'):
                                # CRITICAL FIX: ACL rules from parser already include "acl" keyword
                                # Don't add it again! Parser stores: "acl name condition value"
                                # If ACL doesn't start with "acl ", add it (for manual entries)
                                if not acl_text.startswith('acl '):
                                    acl_text = f"acl {acl_text}"
                                config_lines.append(f"    {acl_text}")
            
            # Redirect Rules
            if frontend.get('redirect_rules'):
                redirect_rules = frontend['redirect_rules']
                # Parse JSON string if needed
                if isinstance(redirect_rules, str):
                    try:
                        redirect_rules = json.loads(redirect_rules)
                    except:
                        # Legacy format: newline-separated string
                        redirect_rules = [r.strip() for r in redirect_rules.split('\n') if r.strip()]
                
                if isinstance(redirect_rules, list):
                    for redirect in redirect_rules:
                        if redirect:
                            redirect_text = str(redirect).strip() if redirect else ''
                            # Skip empty strings, "[]", or invalid redirect rules
                            if redirect_text and redirect_text not in ('[]', '{}', 'null', 'None'):
                                # Redirect rules don't need prefix (e.g., "scheme https if !{ ssl_fc }")
                                config_lines.append(f"    redirect {redirect_text}")
            
            # Use Backend Rules
            if frontend.get('use_backend_rules'):
                use_backend_rules = frontend['use_backend_rules']
                # Parse JSON string if needed
                if isinstance(use_backend_rules, str):
                    try:
                        use_backend_rules = json.loads(use_backend_rules)
                    except:
                        # Legacy format: newline-separated string
                        use_backend_rules = [r.strip() for r in use_backend_rules.split('\n') if r.strip()]
                
                if isinstance(use_backend_rules, list):
                    for rule in use_backend_rules:
                        if rule and rule.strip():
                            rule_text = rule.strip()
                            # Skip empty strings, "[]", or invalid use_backend rules
                            if rule_text and rule_text not in ('[]', '{}', 'null', 'None'):
                                # CRITICAL FIX: use_backend rules from parser already include "use_backend" keyword
                                # Don't add it again! Parser stores: "use_backend BackendName if condition"
                                # If rule doesn't start with "use_backend ", add it (for manual entries)
                                if not rule_text.startswith('use_backend '):
                                    rule_text = f"use_backend {rule_text}"
                                config_lines.append(f"    {rule_text}")
            
            # Default backend (already added at the beginning of frontend section)
            
            # Separate logging
            if frontend.get('log_separate', False):
                config_lines.append(f"    log 127.0.0.1:514 local0 info")
            
            # Add WAF rules for this frontend
            assigned_waf_rules = [rule for rule in waf_rules_records if frontend['id'] in rule['frontend_ids']]
            # Combine with cluster-global rules
            effective_waf_rules = list(assigned_waf_rules) + list(cluster_global_waf_rules)
            # Sort by priority then name if available
            try:
                effective_waf_rules.sort(key=lambda r: (r.get('priority', 100), r.get('name', '')))
            except Exception:
                pass

            for waf_rule in effective_waf_rules:
                # Merge JSONB config payload into top-level dict for generator compatibility
                merged_rule = dict(waf_rule)
                cfg = waf_rule.get('config')
                if cfg:
                    try:
                        if isinstance(cfg, str):
                            import json as _json
                            cfg = _json.loads(cfg)
                    except Exception as e:
                        logger.warning(f"Config Generation: Failed to parse WAF rule {waf_rule['id']} config: {e}")
                        cfg = {}
                    if isinstance(cfg, dict):
                        merged_rule.update(cfg)
                
                waf_config_lines = _generate_waf_config_lines(merged_rule)
                if waf_config_lines:
                    logger.debug(f"Config Generation: Added {len(waf_config_lines)} lines for WAF rule '{waf_rule['name']}' (ID: {waf_rule['id']}, Status: {waf_rule.get('last_config_status', 'N/A')})")
                    config_lines.extend(waf_config_lines)
                else:
                    logger.warning(f"Config Generation: No config lines generated for WAF rule '{waf_rule['name']}' (ID: {waf_rule['id']}, Type: {waf_rule['rule_type']})")
            
            config_lines.append("")
        
        # Add backends
        for backend in backends:
            # Validate required fields
            if not backend.get('name'):
                logger.error("Backend with missing name detected - skipping")
                continue
            
            # CRITICAL PRE-CHECK: Get servers BEFORE starting backend config
            # This allows us to skip backends with no servers before writing anything
            # CRITICAL FIX: Handle servers with NULL cluster_id (legacy data)
            # CRITICAL: Select ssl_certificate_id for SSL ca-file path generation
            servers_precheck = await db_conn.fetch("""
                SELECT id FROM backend_servers 
                WHERE backend_name = $1 AND (cluster_id = $2 OR cluster_id IS NULL) AND is_active = TRUE
            """, backend["name"], cluster_id)
            
            if not servers_precheck or len(servers_precheck) == 0:
                logger.info(f"CONFIG GENERATION: Backend '{backend['name']}' has NO ACTIVE SERVERS. Writing backend block (will show as DOWN until servers added).")
            
            config_lines.append(f"backend {backend['name']}")
            
            # --- HAProxy Configuration Best Practice Order ---
            # 1. Mode and balance method
            if backend.get('balance_method'):
                config_lines.append(f"    balance {backend['balance_method']}")
            if backend.get('mode'):
                config_lines.append(f"    mode {backend['mode']}")
            
            # 2. Backend Options (option http-keep-alive, option forwardfor, etc.)
            # Place options early as per HAProxy best practice
            if backend.get('options'):
                for line in backend['options'].split('\n'):
                    line_stripped = line.strip()
                    # Skip empty strings, "[]", or invalid rules
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        # Lines are complete HAProxy option directives
                        # Examples: "option http-keep-alive", "option forwardfor"
                        config_lines.append(f"    {line_stripped}")
            
            # 3. Health check configuration
            if backend.get('health_check_uri'):
                health_check_uri = backend['health_check_uri'].strip() if backend['health_check_uri'] else ''
                # Skip empty strings, "[]", or invalid values
                if health_check_uri and health_check_uri not in ('[]', '{}', 'null', 'None'):
                    config_lines.append(f"    option httpchk GET {health_check_uri}")
            
            # HTTP Check Expect Status (new field) - ONLY for HTTP mode!
            # TCP backends cannot use http-check directives
            if backend.get('health_check_expected_status') and backend.get('mode') == 'http':
                config_lines.append(f"    http-check expect status {backend['health_check_expected_status']}")

            # 4. Timeouts
            if backend.get('timeout_connect'):
                config_lines.append(f"    timeout connect {backend.get('timeout_connect')}ms")
            if backend.get('timeout_server'):
                config_lines.append(f"    timeout server {backend.get('timeout_server')}ms")
            if backend.get('timeout_queue'):
                config_lines.append(f"    timeout queue {backend.get('timeout_queue')}ms")
            
            # 5. Cookie Persistence
            if backend.get('cookie_name'):
                cookie_name = backend['cookie_name'].strip() if backend['cookie_name'] else ''
                # Skip empty strings, "[]", or invalid values
                if cookie_name and cookie_name not in ('[]', '{}', 'null', 'None'):
                    cookie_line = f"    cookie {cookie_name}"
                    cookie_opts = backend.get('cookie_options', '').strip()
                    # Skip empty strings, "[]", or invalid values
                    if cookie_opts and cookie_opts not in ('[]', '{}', 'null', 'None'):
                        cookie_line += f" {cookie_opts}"
                    config_lines.append(cookie_line)
            
            # 6. Full Connections
            if backend.get('fullconn'):
                config_lines.append(f"    fullconn {backend['fullconn']}")
            
            # 7. Default Server Options
            if backend.get('default_server_inter') or backend.get('default_server_fall') or backend.get('default_server_rise'):
                default_server_line = "    default-server"
                if backend.get('default_server_inter'):
                    default_server_line += f" inter {backend['default_server_inter']}ms"
                if backend.get('default_server_fall'):
                    default_server_line += f" fall {backend['default_server_fall']}"
                if backend.get('default_server_rise'):
                    default_server_line += f" rise {backend['default_server_rise']}"
                config_lines.append(default_server_line)
            
            # 8. HTTP Request Headers
            if backend.get('request_headers'):
                for line in backend['request_headers'].split('\n'):
                    line_stripped = line.strip()
                    # Skip empty strings, "[]", or invalid rules
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        # Lines are already complete directives (e.g., "http-request set-header X-Backend test")
                        config_lines.append(f"    {line_stripped}")
            
            # 9. HTTP Response Headers
            if backend.get('response_headers'):
                for line in backend['response_headers'].split('\n'):
                    line_stripped = line.strip()
                    # Skip empty strings, "[]", or invalid rules
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        # Lines are already complete directives (e.g., "http-response add-header X-Powered-By Backend")
                        config_lines.append(f"    {line_stripped}")

            # Get all servers for this backend (including inactive ones for commenting)
            # CRITICAL FIX: Handle servers with NULL cluster_id (legacy data)
            # Some servers might not have cluster_id set, so we also check for NULL cluster_id
            # CRITICAL: Select ssl_certificate_id for SSL ca-file path generation
            servers = await db_conn.fetch("""
                SELECT id, backend_name, server_name, server_address, server_port, weight, maxconn,
                       check_enabled, check_port, backup_server, ssl_enabled, ssl_verify, ssl_certificate_id,
                       cookie_value, inter, fall, rise, is_active, cluster_id, last_config_status
                FROM backend_servers 
                WHERE backend_name = $1 AND (cluster_id = $2 OR cluster_id IS NULL)
                ORDER BY COALESCE(server_name, 'server_' || id), id
            """, backend["name"], cluster_id)
            
            logger.info(f"CONFIG DEBUG: Found {len(servers)} servers for backend '{backend['name']}' in cluster {cluster_id}")
            for i, server in enumerate(servers):
                logger.info(f"CONFIG DEBUG: Server {i+1}: id={server.get('id')}, name={server.get('server_name')}, address={server.get('server_address')}:{server.get('server_port')}")
            
            for server in servers:
                # CRITICAL FIX: Handle NULL server_name by using a fallback or skipping
                server_name = server.get('server_name', '').strip() if server.get('server_name') else ''
                # Skip invalid server names
                if not server_name or server_name in ('[]', '{}', 'null', 'None'):
                    server_name = f"server_{server['id']}"
                
                # Validate server address (critical - server without address is invalid)
                server_address = server.get('server_address', '').strip() if server.get('server_address') else ''
                if not server_address or server_address in ('[]', '{}', 'null', 'None'):
                    logger.error(f"Server '{server_name}' in backend '{backend['name']}' has no address - skipping")
                    continue
                
                logger.info(f"CONFIG DEBUG: Processing server {server_name} - address={server_address}:{server.get('server_port')}, weight={server.get('weight')}, active={server.get('is_active')}")
                
                # CRITICAL FIX: Port 0 means no port specified (use backend default)
                # In HAProxy, "server name addr" without port uses backend's default port
                server_port = server.get('server_port')
                if server_port and server_port != 0:
                    server_line = f"    server {server_name} {server_address}:{server_port}"
                else:
                    # No port specified - HAProxy will use backend's default port based on mode
                    server_line = f"    server {server_name} {server_address}"
                
                server_line += f" weight {server['weight']}"
                
                if server.get('max_connections'):
                    server_line += f" maxconn {server['max_connections']}"
                
                # SSL Configuration (new field: ssl_verify and ssl_certificate_id)
                if server.get('ssl_enabled', False):
                    server_line += " ssl"
                    ssl_verify = server.get('ssl_verify', '').strip() if server.get('ssl_verify') else ''
                    # Skip empty strings, "[]", or invalid values
                    if ssl_verify and ssl_verify not in ('[]', '{}', 'null', 'None'):
                        server_line += f" verify {ssl_verify}"
                    
                    # Add ca-file path if SSL certificate is selected
                    if server.get('ssl_certificate_id'):
                        ssl_cert_id = server['ssl_certificate_id']
                        # Get SSL certificate name to generate path
                        ssl_cert = await db_conn.fetchrow("""
                            SELECT name FROM ssl_certificates 
                            WHERE id = $1 AND is_active = TRUE
                        """, ssl_cert_id)
                        
                        if ssl_cert:
                            cert_filename = f"{ssl_cert['name']}.pem"
                            cert_path = f"/etc/ssl/haproxy/{cert_filename}"
                            server_line += f" ca-file {cert_path}"
                            logger.info(f"🔒 CONFIG SSL: Added ca-file for server {server_name}: {cert_path}")
                
                # Health Check (with new field: check_port)
                if server.get('check_enabled', True):
                    server_line += " check"
                    if server.get('check_port'):
                        server_line += f" port {server['check_port']}"
                
                # Health Check Timings (new fields: inter, fall, rise)
                if server.get('inter'):
                    server_line += f" inter {server['inter']}ms"
                if server.get('fall'):
                    server_line += f" fall {server['fall']}"
                if server.get('rise'):
                    server_line += f" rise {server['rise']}"
                
                # Cookie Value (new field)
                cookie_val = server.get('cookie_value', '').strip() if server.get('cookie_value') else ''
                # Skip empty strings, "[]", or invalid values
                if cookie_val and cookie_val not in ('[]', '{}', 'null', 'None'):
                    server_line += f" cookie {cookie_val}"
                
                # Backup Server
                if server.get('backup_server', False):
                    server_line += " backup"
                
                # Skip servers marked for deletion (last_config_status = 'DELETION')
                if server.get('last_config_status') == 'DELETION':
                    # Server is marked for deletion - skip it completely
                    logger.debug(f"Config Generation: Skipping server {server_name} marked for deletion")
                    continue
                
                # If server is disabled (but not deleted), comment it out
                if not server.get('is_active', True):
                    server_line = f"    # DISABLED: {server_line.strip()}"
                    logger.info(f"CONFIG DEBUG: Server {server_name} marked as DISABLED")
                else:
                    logger.info(f"CONFIG DEBUG: Server {server_name} is ACTIVE - adding to config")
                
                config_lines.append(server_line)
                logger.info(f"CONFIG DEBUG: Added server line: {server_line}")
            
            config_lines.append("")
        
        # Only close the connection if it was created within this function
        if not conn:
            await close_database_connection(db_conn)
        
        # Join all lines
        config_content = "\n".join(config_lines)
        
        # Log summary for debugging
        excluded_count = len(pending_delete_waf_ids) if 'pending_delete_waf_ids' in locals() and pending_delete_waf_ids else 0
        logger.info(f"Config Generation: Generated {len(config_lines)} lines for cluster {cluster_id} with {len(frontends)} frontends, {len(backends)} backends, {len(waf_rules_records)} assigned WAF rules, {len(cluster_global_waf_rules)} global WAF rules (excluded {excluded_count} pending-delete WAF rules)")
        
        return config_content
        
    except Exception as e:
        logger.error(f"Failed to generate HAProxy config for cluster {cluster_id}: {e}")
        # Ensure connection is closed on error if it was created here
        if not conn and db_conn:
            await close_database_connection(db_conn)
        return f"# Error generating configuration: {str(e)}"

def _is_valid_haproxy_condition(condition: str) -> bool:
    """Basic validation for HAProxy condition syntax"""
    if not condition or not condition.strip():
        return False
    
    condition = condition.strip()
    
    # Allow complete HAProxy directives
    if condition.startswith(('http-request', 'http-response', 'acl')):
        return True
    
    # Basic ACL condition validation - should contain braces for HAProxy expressions
    # Valid examples: { req.hdr(user-agent) -m sub bot }, { src -f /path/file }
    if '{' in condition and '}' in condition:
        return True
    
    # Allow simple conditions that will be wrapped in braces
    # Valid examples: req.hdr(user-agent) -m sub bot, src -f /path/file
    if any(keyword in condition for keyword in ['req.', 'res.', 'src', 'dst', '-m', '-f', '-i']):
        return True
    
    # Reject obviously invalid conditions (single words, numbers, etc.)
    if len(condition.split()) < 2:
        return False
    
    return False

def _generate_waf_config_lines(waf_rule: Dict[str, Any]) -> List[str]:
    """Generate HAProxy configuration lines for a WAF rule"""
    lines = []
    rule_name = waf_rule['name'].replace(' ', '_').lower()
    
    # Add comment header with rule info for debugging
    priority = waf_rule.get('priority', 100)
    action = waf_rule.get('action', 'block')
    lines.append(f"    # WAF Rule: {waf_rule['name']} (Priority: {priority}, Action: {action})")
    
    if waf_rule['rule_type'] == 'ip_filter' and waf_rule.get('ip_addresses'):
        acl_name = f"waf_{rule_name}_ips"
        ip_list = ' '.join(waf_rule['ip_addresses'])
        lines.append(f"    acl {acl_name} src {ip_list}")
        
        # Use ip_action if available, otherwise fall back to general action
        action_type = waf_rule.get('ip_action', action)
        if action_type in ['blacklist', 'block']:
            lines.append(f"    http-request deny if {acl_name}")
        elif action_type in ['whitelist', 'allow']:
            lines.append(f"    http-request allow if {acl_name}")
        
        # Handle Custom Log Message and Custom HAProxy Condition for IP Filter
        log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
        if log_msg:
            lines.append(f"    # IP Filter Log: {log_msg}")
        
        custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
        if custom_condition:
            custom_condition = custom_condition.strip()
            # Skip empty strings, "[]", or invalid values
            if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    # Custom IP Filter Condition for {waf_rule['name']}")
                if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                    custom_condition = f"http-request deny if {custom_condition}"
                lines.append(f"    {custom_condition}")
    
    elif waf_rule['rule_type'] == 'rate_limit' and waf_rule.get('rate_limit_requests'):
        lines.append(f"    stick-table type ip size 100k expire {waf_rule.get('rate_limit_window', 60)}s store http_req_rate(10s)")
        lines.append(f"    http-request track-sc0 src")
        # Apply action for rate limit violations
        if action == 'block':
            lines.append(f"    http-request deny if {{ sc_http_req_rate(0) gt {waf_rule['rate_limit_requests']} }}")
        elif action == 'log':
            lines.append(f"    http-request capture req.hdr(User-Agent) len 64 if {{ sc_http_req_rate(0) gt {waf_rule['rate_limit_requests']} }}")
        
        # Handle Custom Log Message and Custom HAProxy Condition for Rate Limit
        log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
        if log_msg:
            lines.append(f"    # Rate Limit Log: {log_msg}")
        
        custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
        if custom_condition:
            custom_condition = custom_condition.strip()
            # Skip empty strings, "[]", or invalid values
            if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    # Custom Rate Limit Condition for {waf_rule['name']}")
                
                if not _is_valid_haproxy_condition(custom_condition):
                    lines.append(f"    # WARNING: Invalid HAProxy condition syntax: {custom_condition}")
                else:
                    if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                        custom_condition = f"http-request deny if {custom_condition}"
                    lines.append(f"    {custom_condition}")
    
    elif waf_rule['rule_type'] == 'header_filter' and waf_rule.get('header_name'):
        header_name = waf_rule.get('header_name', '').strip()
        header_value = waf_rule.get('header_value', '').strip()
        # Skip if header_name or header_value are invalid
        if not header_name or header_name in ('[]', '{}', 'null', 'None'):
            lines.append(f"    # WARNING: Invalid header_name for WAF rule '{waf_rule['name']}' - skipped")
        elif not header_value or header_value in ('[]', '{}', 'null', 'None'):
            lines.append(f"    # WARNING: Invalid header_value for WAF rule '{waf_rule['name']}' - skipped")
        else:
            acl_name = f"waf_{rule_name}_header"
            header_condition = waf_rule.get('header_condition', 'equals')
            
            if header_condition == 'equals':
                lines.append(f"    acl {acl_name} hdr({header_name}) {header_value}")
            elif header_condition == 'contains':
                lines.append(f"    acl {acl_name} hdr_sub({header_name}) {header_value}")
            elif header_condition == 'regex':
                lines.append(f"    acl {acl_name} hdr_reg({header_name}) {header_value}")
        
        # Apply action based on rule configuration
        if action == 'block':
            lines.append(f"    http-request deny if {acl_name}")
        elif action == 'allow':
            lines.append(f"    http-request allow if {acl_name}")
        elif action == 'log':
            lines.append(f"    http-request capture req.hdr({waf_rule['header_name']}) len 64 if {acl_name}")
        
        # Handle Custom Log Message and Custom HAProxy Condition for Header Filter
        log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
        if log_msg:
            lines.append(f"    # Header Filter Log: {log_msg}")
        
        custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
        if custom_condition:
            custom_condition = custom_condition.strip()
            # Skip empty strings, "[]", or invalid values
            if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    # Custom Header Filter Condition for {waf_rule['name']}")
                if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                    custom_condition = f"http-request deny if {custom_condition}"
                lines.append(f"    {custom_condition}")
    
    elif waf_rule['rule_type'] == 'request_filter' and (waf_rule.get('path_pattern') or waf_rule.get('http_method')):
        # Handle path pattern filtering
        acl_conditions = []
        if waf_rule.get('path_pattern'):
            path_pattern = waf_rule.get('path_pattern', '').strip()
            # Skip if path_pattern is invalid
            if path_pattern and path_pattern not in ('[]', '{}', 'null', 'None'):
                acl_name_path = f"waf_{rule_name}_path"
                lines.append(f"    acl {acl_name_path} path_reg {path_pattern}")
                acl_conditions.append(acl_name_path)
            else:
                lines.append(f"    # WARNING: Invalid path_pattern for WAF rule '{waf_rule['name']}' - skipped")
        
        # Handle HTTP method filtering
        if waf_rule.get('http_method') and waf_rule['http_method'] != '':
            http_method = waf_rule.get('http_method', '').strip()
            # Skip if http_method is invalid
            if http_method and http_method not in ('[]', '{}', 'null', 'None'):
                acl_name_method = f"waf_{rule_name}_method"
                lines.append(f"    acl {acl_name_method} method {http_method}")
                acl_conditions.append(acl_name_method)
            else:
                lines.append(f"    # WARNING: Invalid http_method for WAF rule '{waf_rule['name']}' - skipped")
        
        # Combine ACL conditions
        if acl_conditions:
            combined_acl = ' '.join(acl_conditions)
            
            # Apply action based on rule configuration
            if action == 'block':
                lines.append(f"    http-request deny if {combined_acl}")
            elif action == 'allow':
                lines.append(f"    http-request allow if {combined_acl}")
            elif action == 'redirect':
                redirect_url = waf_rule.get('redirect_url', '').strip() if waf_rule.get('redirect_url') else ''
                # Skip empty strings, "[]", or invalid values
                if redirect_url and redirect_url not in ('[]', '{}', 'null', 'None'):
                    lines.append(f"    http-request redirect location {redirect_url} if {combined_acl}")
        
        # Handle Custom Log Message and Custom HAProxy Condition for Request Filter
        log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
        if log_msg:
            lines.append(f"    # Request Filter Log: {log_msg}")
        
        custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
        if custom_condition:
            custom_condition = custom_condition.strip()
            # Skip empty strings, "[]", or invalid values
            if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    # Custom Request Filter Condition for {waf_rule['name']}")
                if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                    custom_condition = f"http-request deny if {custom_condition}"
                lines.append(f"    {custom_condition}")
    
    # Legacy path_filter support (for backward compatibility)
    elif waf_rule['rule_type'] == 'path_filter' and waf_rule.get('path_pattern'):
        path_pattern = waf_rule.get('path_pattern', '').strip()
        # Skip if path_pattern is invalid
        if not path_pattern or path_pattern in ('[]', '{}', 'null', 'None'):
            lines.append(f"    # WARNING: Invalid path_pattern for WAF rule '{waf_rule['name']}' - skipped")
        else:
            acl_name = f"waf_{rule_name}_path"
            lines.append(f"    acl {acl_name} path_reg {path_pattern}")
        
        # Apply action based on rule configuration
        if action == 'block':
            lines.append(f"    http-request deny if {acl_name}")
        elif action == 'allow':
            lines.append(f"    http-request allow if {acl_name}")
        elif action == 'redirect':
            redirect_url = waf_rule.get('redirect_url', '').strip() if waf_rule.get('redirect_url') else ''
            # Skip empty strings, "[]", or invalid values
            if redirect_url and redirect_url not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    http-request redirect location {redirect_url} if {acl_name}")
    
    elif waf_rule['rule_type'] == 'size_limit':
        # Handle Max Request Size limit
        if waf_rule.get('max_request_size'):
            if action == 'block':
                lines.append(f"    http-request deny if {{ req.body_size gt {waf_rule['max_request_size']} }}")
            elif action == 'log':
                log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message', 'Request size limit exceeded')
                lines.append(f"    http-request capture req.hdr(Content-Length) len 16 if {{ req.body_size gt {waf_rule['max_request_size']} }}")
                lines.append(f"    # Log Message: {log_msg}")
        
        # Handle Max Header Size limit
        if waf_rule.get('max_header_size'):
            if action == 'block':
                lines.append(f"    http-request deny if {{ req.hdr_cnt() gt 50 }} || {{ req.hdr_val(content-length) gt {waf_rule['max_header_size']} }}")
            elif action == 'log':
                log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message', 'Header size limit exceeded')
                lines.append(f"    http-request capture req.hdr(User-Agent) len 32 if {{ req.hdr_cnt() gt 50 }}")
                lines.append(f"    # Log Message: {log_msg}")
        
        # Handle Custom HAProxy Condition if provided
        custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
        if custom_condition:
            custom_condition = custom_condition.strip()
            # Skip empty strings, "[]", or invalid values
            if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    # Custom Condition for {waf_rule['name']}")
                
                # Basic validation for HAProxy condition syntax
                if not _is_valid_haproxy_condition(custom_condition):
                    lines.append(f"    # WARNING: Invalid HAProxy condition syntax: {custom_condition}")
                    lines.append(f"    # Example valid conditions: {{ req.hdr(user-agent) -m sub bot }}, {{ src -f /etc/haproxy/whitelist.lst }}")
                else:
                    # Ensure condition starts with proper HAProxy directive
                    if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                        custom_condition = f"http-request deny if {custom_condition}"
                    lines.append(f"    {custom_condition}")
            
            log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
            if log_msg:
                lines.append(f"    # Custom Log: {log_msg}")
    
    elif waf_rule['rule_type'] == 'geo_block' and waf_rule.get('countries'):
        # Handle Geo Block filtering
        countries = waf_rule['countries']
        if isinstance(countries, str):
            countries_list = [c.strip().upper() for c in countries.split(',') if c.strip()]
        else:
            countries_list = countries
        
        if countries_list:
            acl_name = f"waf_{rule_name}_geo"
            # Note: This requires HAProxy with GeoIP support or external GeoIP database
            # For basic implementation, we'll use a comment-based approach
            lines.append(f"    # GeoIP filtering for countries: {', '.join(countries_list)}")
            lines.append(f"    # Note: Requires HAProxy with GeoIP support")
            
            geo_action = waf_rule.get('geo_action', 'block')
            if geo_action == 'block':
                lines.append(f"    # http-request deny if {{ src,map_ip(/etc/haproxy/geoip.map,unknown) -m str {' '.join(countries_list)} }}")
                lines.append(f"    # Alternative: Use external GeoIP service or MaxMind database")
            elif geo_action == 'allow':
                lines.append(f"    # http-request allow if {{ src,map_ip(/etc/haproxy/geoip.map,unknown) -m str {' '.join(countries_list)} }}")
                lines.append(f"    # http-request deny # deny all others")
            
            # Handle Custom Log Message and Custom HAProxy Condition for Geo Block
            log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
            if log_msg:
                lines.append(f"    # Geo Block Log: {log_msg}")
            
            custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
            if custom_condition:
                custom_condition = custom_condition.strip()
                # Skip empty strings, "[]", or invalid values
                if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                    lines.append(f"    # Custom Geo Block Condition for {waf_rule['name']}")
                    if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                        custom_condition = f"http-request deny if {custom_condition}"
                    lines.append(f"    {custom_condition}")
    
    # Handle custom rule type or unsupported config
    elif waf_rule['rule_type'] == 'custom' and waf_rule.get('custom_condition'):
        lines.append(f"    # Custom WAF rule: {waf_rule['name']}")
        lines.append(f"    {waf_rule['custom_condition']}")
    
    return lines

async def create_config_version(
    cluster_id: int, 
    version_name: str, 
    description: Optional[str] = None,
    user_id: Optional[int] = None,
    status: str = 'PENDING'
) -> int:
    """Create a new configuration version"""
    try:
        conn = await get_database_connection()
        
        # Generate config content
        config_content = await generate_haproxy_config_for_cluster(cluster_id)
        
        # Create checksum
        config_hash = hashlib.sha256(config_content.encode()).hexdigest()
        
        # Insert new version
        version_id = await conn.fetchval("""
            INSERT INTO config_versions 
            (cluster_id, version_name, description, config_content, checksum, created_by, is_active, status)
            VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7)
            RETURNING id
        """, cluster_id, version_name, description, config_content, config_hash, user_id, status)
        
        await close_database_connection(conn)
        return version_id
        
    except Exception as e:
        logger.error(f"Failed to create config version: {e}")
        raise

async def create_pending_config_version(
    cluster_id: int,
    change_description: str,
    user_id: Optional[int] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None
) -> Dict[str, Any]:
    """Create a pending configuration version for Apply Changes workflow"""
    try:
        # Generate version name with timestamp and entity info
        timestamp = int(time.time())
        if entity_type and entity_id:
            version_name = f"{entity_type}-{entity_id}-delete-{timestamp}"
        else:
            version_name = f"pending-{timestamp}"
        
        # Create the config version
        version_id = await create_config_version(
            cluster_id=cluster_id,
            version_name=version_name,
            description=change_description,
            user_id=user_id,
            status='PENDING'
        )
        
        logger.info(f"✅ CONFIG VERSION: Created pending version {version_name} (ID: {version_id}) for cluster {cluster_id}")
        
        return {
            'version_id': version_id,
            'version': version_name,
            'status': 'PENDING',
            'description': change_description
        }
        
    except Exception as e:
        logger.error(f"❌ CONFIG VERSION: Failed to create pending version for cluster {cluster_id}: {e}")
        raise 