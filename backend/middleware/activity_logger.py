"""
Enterprise Activity Logging Middleware
Automatically logs all user actions across the system
"""

import json
import logging
from typing import Optional, Dict, Any
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from utils.activity_log import log_user_activity
from auth_middleware import get_current_user_from_token

logger = logging.getLogger(__name__)

# Actions that should be logged
LOGGABLE_ACTIONS = {
    'POST': 'create',
    'PUT': 'update', 
    'PATCH': 'update',
    'DELETE': 'delete'
}

# Resource type mapping from URL paths
RESOURCE_MAPPING = {
    '/api/frontends': 'frontend',
    '/api/backends': 'backend',
    '/api/waf/rules': 'waf_rule',
    '/api/ssl': 'ssl_certificate',
    '/api/clusters': 'cluster',
    '/api/agents': 'agent',
    '/api/users': 'user',
    '/api/roles': 'role',
    '/api/auth/login': 'auth',
    '/api/auth/logout': 'auth',
    '/api/configuration': 'configuration',
    '/api/security/agent-tokens': 'agent_token',
    '/api/maintenance': 'maintenance',
    # Audit Tur 4/5 / Commit 8: ACME endpoint coverage
    '/api/letsencrypt': 'letsencrypt_order',
    # v1.5.0 Feature B (Issue #14): site setup wizard
    '/api/sites': 'site',
    # Backward-compat alias for the legacy URL slug. The wizard router's
    # primary mount is `/api/sites`; main.py also registers a hidden
    # 308-redirect alias on `/api/proxied-hosts/*` so external
    # integrators still pointing at the old slug keep working. The 308
    # response is filtered out below (only 2xx is logged), so this map
    # entry is here only for the rare in-flight pre-redirect call that
    # somehow lands as a 2xx (edge case).
    '/api/proxied-hosts': 'site',
}

# Special action mappings
SPECIAL_ACTIONS = {
    '/api/clusters/{cluster_id}/apply-changes': 'apply_changes',
    '/api/waf/rules/{rule_id}/toggle': 'toggle_waf_rule',
    '/api/frontends/{frontend_id}/toggle': 'toggle_frontend',
    '/api/backends/{backend_id}/toggle': 'toggle_backend',
    '/api/agents/{agent_id}/toggle': 'toggle_agent',
    '/api/users/{user_id}/password': 'change_password',
    '/api/users/{user_id}/roles': 'assign_roles',
    # Audit Tur 5/6 / Commit 8: discrete ACME actions for compliance audit
    '/api/letsencrypt/certificates': 'acme_certificate_requested',
    '/api/letsencrypt/certificates/{cert_id}/revoke': 'acme_certificate_revoked',
    '/api/letsencrypt/import-ca-chain': 'acme_ca_chain_imported',
    '/api/letsencrypt/accounts': 'acme_account_created',
    '/api/letsencrypt/accounts/{account_id}': 'acme_account_deactivated',
    '/api/letsencrypt/accounts/{account_id}/permanent': 'acme_account_purged',
    '/api/letsencrypt/orders/{order_id}/retry': 'acme_order_retried',
    '/api/letsencrypt/orders/{order_id}': 'acme_order_cancelled',
    # v1.5.0 Feature A (Issue #13): ACME diagnostics
    '/api/letsencrypt/orders/{order_id}/diagnostics': 'acme_diagnostics_run',
    '/api/letsencrypt/orders/{order_id}/diagnostics/{check_id}/rerun': 'acme_diagnostic_check_rerun',
    # v1.5.0 Feature B (Issue #14): site setup wizard.
    # R18c audit fix (round 1 #9): the wizard CREATE endpoint
    # (POST /api/sites) emits a richer `wizard_create_site` row
    # with wizard_status / cluster_id / domains / ssl_mode /
    # apply_error / acme_staging_error directly from the router
    # (R18b round 6 #15). If we ALSO log `site_created` here,
    # every successful wizard create produces TWO
    # user_activity_logs rows for the same operator action and
    # dashboards counting "creates" by verb double-count. Drop
    # that entry so the wizard owns its own audit row, while the
    # other paths (preview, preflight, draft) still log via the
    # middleware.
    '/api/sites/preview': 'site_previewed',
    '/api/sites/preflight-acme': 'site_acme_preflight',
    '/api/sites/drafts': 'site_draft_saved',
    '/api/sites/drafts/{draft_id}': 'site_draft_deleted',
    # Backward-compat aliases for the legacy URL slug — the 308
    # redirect should consume these in practice, but if a 2xx ever
    # leaks through directly the action map is still correct.
    '/api/proxied-hosts/preview': 'site_previewed',
    '/api/proxied-hosts/preflight-acme': 'site_acme_preflight',
    '/api/proxied-hosts/drafts': 'site_draft_saved',
    '/api/proxied-hosts/drafts/{draft_id}': 'site_draft_deleted',
}

def extract_resource_info(path: str, method: str) -> tuple[str, str, Optional[str]]:
    """Extract resource type, action, and resource ID from request path and method"""

    # R18c audit fix (round 1 #9): the wizard CREATE endpoint
    # (POST /api/sites, exact path) emits its OWN richer audit
    # row from the router (`wizard_create_site`). Skip middleware
    # logging for that single endpoint so we don't produce
    # duplicate user_activity_logs rows per successful wizard
    # create. Subpaths (`/preview`, `/preflight-acme`, `/drafts`,
    # `/drafts/{id}`) still log via SPECIAL_ACTIONS below. The
    # legacy `/api/proxied-hosts` slug is also covered for
    # parity (the 308 redirect typically intercepts it before
    # this point, but safety net).
    if path in ('/api/sites', '/api/proxied-hosts') and method == 'POST':
        return 'unknown', method.lower(), None

    # Check for special actions first
    for pattern, action in SPECIAL_ACTIONS.items():
        if matches_pattern(path, pattern):
            resource_type = extract_resource_type_from_path(path)
            resource_id = extract_id_from_path(path, pattern)
            return resource_type, action, resource_id
    
    # Check standard CRUD operations
    if method in LOGGABLE_ACTIONS:
        for url_pattern, resource_type in RESOURCE_MAPPING.items():
            if path.startswith(url_pattern):
                action = LOGGABLE_ACTIONS[method]
                resource_id = extract_id_from_path(path, url_pattern)
                return resource_type, action, resource_id
    
    # Default for unmatched paths
    return 'unknown', method.lower(), None

def matches_pattern(path: str, pattern: str) -> bool:
    """Check if path matches a pattern with variables like {id}"""
    path_parts = path.split('/')
    pattern_parts = pattern.split('/')
    
    if len(path_parts) != len(pattern_parts):
        return False
    
    for path_part, pattern_part in zip(path_parts, pattern_parts):
        if pattern_part.startswith('{') and pattern_part.endswith('}'):
            # This is a variable, skip comparison
            continue
        elif path_part != pattern_part:
            return False
    
    return True

def extract_resource_type_from_path(path: str) -> str:
    """Extract resource type from path"""
    # Bulgu #40: include v1.5.0 wizard path so audit rows aren't logged with
    # resource_type='unknown'. Order matters — '/sites' / '/proxied-hosts'
    # must be checked BEFORE generic '/frontends'/'/backends' fallbacks.
    # Legacy `/proxied-hosts` slug is preserved for backward compat.
    if '/sites' in path or '/proxied-hosts' in path:
        return 'site'
    if '/letsencrypt' in path:
        return 'letsencrypt_order'
    elif '/frontends' in path:
        return 'frontend'
    elif '/backends' in path:
        return 'backend'
    elif '/waf' in path:
        return 'waf_rule'
    elif '/ssl' in path:
        return 'ssl_certificate'
    elif '/clusters' in path:
        return 'cluster'
    elif '/agents' in path:
        return 'agent'
    elif '/users' in path:
        return 'user'
    elif '/roles' in path:
        return 'role'
    elif '/configuration' in path:
        return 'configuration'
    elif '/security/agent-tokens' in path:
        return 'agent_token'
    elif '/maintenance' in path:
        return 'maintenance'
    else:
        return 'unknown'

def extract_id_from_path(path: str, pattern: str) -> Optional[str]:
    """Extract resource ID from path"""
    path_parts = path.split('/')
    
    # Look for numeric IDs in the path
    for part in path_parts:
        if part.isdigit():
            return part
    
    return None

async def log_activity_middleware(request: Request, call_next):
    """Middleware to automatically log user activities"""
    
    # Skip logging for GET requests and health checks
    if request.method == 'GET' or request.url.path in ['/health', '/api/health', '/']:
        response = await call_next(request)
        return response

    # R18c audit fix (round 1 #9): the wizard CREATE endpoint owns
    # its own audit row; skip the middleware path for that exact
    # endpoint+method to prevent duplicate user_activity_logs rows.
    # See router site_wizard.py for the explicit log_user_activity
    # call with action='wizard_create_site'. The legacy
    # `/api/proxied-hosts` slug is also short-circuited so a 308
    # redirect doesn't double-log.
    if request.url.path in ('/api/sites', '/api/proxied-hosts') and request.method == 'POST':
        return await call_next(request)

    # Get user from token
    user = None
    try:
        authorization = request.headers.get('authorization')
        if authorization:
            user = await get_current_user_from_token(authorization)
    except Exception as e:
        logger.debug(f"Could not get user from token: {e}")
    
    # Process the request
    response = await call_next(request)
    
    # Only log successful operations (2xx status codes)
    if 200 <= response.status_code < 300 and user:
        try:
            # Extract resource information
            resource_type, action, resource_id = extract_resource_info(
                request.url.path, 
                request.method
            )
            
            # Get request body for details (if available)
            details = {}
            
            # Add request details
            details['method'] = request.method
            details['path'] = request.url.path
            details['status_code'] = response.status_code
            
            # Add query parameters if present
            if request.query_params:
                details['query_params'] = dict(request.query_params)
            
            # Get client IP
            client_ip = None
            if hasattr(request, 'client') and request.client:
                client_ip = str(request.client.host)
            
            # Get user agent
            user_agent = request.headers.get('user-agent')
            
            # Log the activity asynchronously (don't wait)
            import asyncio
            asyncio.create_task(log_user_activity(
                user_id=user['id'],
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                ip_address=client_ip,
                user_agent=user_agent
            ))
            
        except Exception as e:
            logger.error(f"Failed to log activity: {e}")
            # Don't fail the request because of logging issues
    
    return response

# Enhanced logging for specific operations
async def log_apply_changes(user_id: int, cluster_id: int, applied_entities: list, request: Request):
    """Enhanced logging for apply changes operations"""
    try:
        details = {
            'cluster_id': cluster_id,
            'applied_entities': applied_entities,
            'entity_count': len(applied_entities),
            'method': 'POST',
            'path': f'/api/clusters/{cluster_id}/apply-changes'
        }
        
        client_ip = str(request.client.host) if request.client else None
        user_agent = request.headers.get('user-agent')
        
        await log_user_activity(
            user_id=user_id,
            action='apply_changes',
            resource_type='cluster',
            resource_id=str(cluster_id),
            details=details,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        logger.info(f"🎯 ACTIVITY LOG: User {user_id} applied {len(applied_entities)} changes to cluster {cluster_id}")
        
    except Exception as e:
        logger.error(f"Failed to log apply changes activity: {e}")

async def log_entity_operation(user_id: int, action: str, entity_type: str, entity_id: int, entity_data: dict, request: Request):
    """Enhanced logging for entity operations (frontend, backend, waf, ssl)"""
    try:
        details = {
            'entity_type': entity_type,
            'entity_id': entity_id,
            'entity_name': entity_data.get('name', 'Unknown'),
            'method': request.method,
            'path': request.url.path
        }
        
        # Add specific details based on entity type
        if entity_type == 'frontend':
            details.update({
                'bind_port': entity_data.get('bind_port'),
                'ssl_enabled': entity_data.get('ssl_enabled', False)
            })
        elif entity_type == 'backend':
            details.update({
                'balance_method': entity_data.get('balance_method'),
                'server_count': len(entity_data.get('servers', []))
            })
        elif entity_type == 'waf_rule':
            details.update({
                'rule_type': entity_data.get('rule_type'),
                'action': entity_data.get('action'),
                'priority': entity_data.get('priority')
            })
        
        client_ip = str(request.client.host) if request.client else None
        user_agent = request.headers.get('user-agent')
        
        await log_user_activity(
            user_id=user_id,
            action=action,
            resource_type=entity_type,
            resource_id=str(entity_id),
            details=details,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        logger.info(f"🎯 ACTIVITY LOG: User {user_id} {action} {entity_type} {entity_id} ({entity_data.get('name', 'Unknown')})")
        
    except Exception as e:
        logger.error(f"Failed to log entity operation activity: {e}")
