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
    '/api/maintenance': 'maintenance'
}

# Special action mappings
SPECIAL_ACTIONS = {
    '/api/clusters/{cluster_id}/apply-changes': 'apply_changes',
    '/api/waf/rules/{rule_id}/toggle': 'toggle_waf_rule',
    '/api/frontends/{frontend_id}/toggle': 'toggle_frontend',
    '/api/backends/{backend_id}/toggle': 'toggle_backend',
    '/api/agents/{agent_id}/toggle': 'toggle_agent',
    '/api/users/{user_id}/password': 'change_password',
    '/api/users/{user_id}/roles': 'assign_roles'
}

def extract_resource_info(path: str, method: str) -> tuple[str, str, Optional[str]]:
    """Extract resource type, action, and resource ID from request path and method"""
    
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
    if '/frontends' in path:
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
