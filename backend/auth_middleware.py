from fastapi import HTTPException, status, Header
from typing import Optional, Dict, Any
from jose import jwt
import logging
from datetime import datetime, timedelta

from config import JWT_SECRET_KEY, JWT_ALGORITHM
from database.connection import get_database_connection, close_database_connection

logger = logging.getLogger(__name__)

async def get_current_user_from_token(authorization: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Extract and validate user from JWT token"""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing"
        )
    
    try:
        # Remove 'Bearer ' prefix if present
        token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
        
        # Handle the case where frontend sends the string 'null' instead of null
        if token == 'null' or token == 'undefined' or not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: null or undefined"
            )
        
        # Debug logging for token format issues
        logger.debug(f"Token received: {token[:50]}... (length: {len(token)})")
        
        # Check if token has proper JWT format (3 segments separated by dots)
        token_segments = token.split('.')
        if len(token_segments) != 3:
            logger.error(f"Invalid JWT format: token has {len(token_segments)} segments, expected 3")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token format: expected 3 segments, got {len(token_segments)}"
            )
        
        # Decode JWT token
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub") or payload.get("user_id")  # Support both formats
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing user ID"
            )
        
        # Get user from database
        conn = await get_database_connection()
        user = await conn.fetchrow("""
            SELECT id, username, email, full_name, role, is_active, is_admin
            FROM users 
            WHERE id = $1 AND is_active = TRUE
        """, int(user_id))
        await close_database_connection(conn)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        return {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "is_admin": user.get("is_admin", False)
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except (jwt.JWTError, AttributeError) as e:
        logger.error(f"JWT validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    except Exception as e:
        logger.error(f"Auth middleware error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

async def require_authenticated_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """FastAPI dependency: require a valid operator JWT, else 401.

    Reads the Authorization header itself, so it can be attached at router or
    route level to gate operator/UI endpoints that must not be public:
        APIRouter(..., dependencies=[Depends(require_authenticated_user)])
        @router.get(..., dependencies=[Depends(require_authenticated_user)])
    Any authenticated user passes (no fine-grained RBAC here) — this restores the
    pre-existing "logged-in users only" expectation without changing role access.
    """
    return await get_current_user_from_token(authorization)

async def get_current_user_from_token_no_exception(authorization: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Get current user from JWT token without raising HTTPException.
    Returns None if authentication fails. Used for optional authentication in agent endpoints.
    """
    if not authorization:
        return None
    
    try:
        # Remove 'Bearer ' prefix if present
        token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
        
        # Handle the case where frontend sends the string 'null' instead of null
        if token == 'null' or token == 'undefined' or not token:
            return None
        
        # Check if token has proper JWT format (3 segments separated by dots)
        token_segments = token.split('.')
        if len(token_segments) != 3:
            logger.debug(f"Invalid JWT format: token has {len(token_segments)} segments, expected 3")
            return None
        
        # Decode JWT token
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub") or payload.get("user_id")  # Support both formats
        
        if not user_id:
            return None
        
        # Get user from database
        conn = await get_database_connection()
        user = await conn.fetchrow("""
            SELECT id, username, email, full_name, is_active, is_admin
            FROM users 
            WHERE id = $1 AND is_active = TRUE
        """, int(user_id))
        await close_database_connection(conn)
        
        if not user:
            return None
        
        return {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "is_admin": user.get("is_admin", False)
        }
        
    except Exception as e:
        logger.debug(f"JWT validation failed (no exception): {e}")
        return None

async def validate_agent_api_key(api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Validate agent API key for secure agent authentication.
    Returns agent info if valid, None otherwise.
    """
    if not api_key:
        return None
    
    try:
        conn = await get_database_connection()
        
        # Check if API key exists and is valid
        agent = await conn.fetchrow("""
            SELECT id, name, pool_id, enabled, api_key_expires_at
            FROM agents 
            WHERE api_key = $1 AND enabled = TRUE
        """, api_key)
        
        await close_database_connection(conn)
        
        if not agent:
            logger.warning(f"Invalid agent API key attempted: {api_key[:10]}...")
            return None
        
        # Check if API key has expired
        if agent['api_key_expires_at'] and agent['api_key_expires_at'] < datetime.utcnow():
            logger.warning(f"Expired agent API key for agent: {agent['name']}")
            return None
        
        return {
            "id": agent["id"],
            "name": agent["name"],
            "pool_id": agent["pool_id"],
            "type": "agent"  # Mark as agent authentication
        }
        
    except Exception as e:
        logger.error(f"Agent API key validation error: {e}")
        return None

async def get_user_permissions(user_id: int) -> Dict[str, Dict[str, bool]]:
    """
    Get user permissions from their assigned roles
    Returns dict in format: {resource: {action: bool}}
    """
    try:
        conn = await get_database_connection()
        
        # Get user roles and their permissions
        user_roles = await conn.fetch("""
            SELECT r.permissions
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.is_active = true
        """, user_id)
        
        await close_database_connection(conn)
        
        # Combine all permissions from all roles
        combined_permissions = set()
        for role in user_roles:
            if role['permissions']:
                import json
                permissions = json.loads(role['permissions']) if isinstance(role['permissions'], str) else role['permissions']
                if isinstance(permissions, list):
                    combined_permissions.update(permissions)
        
        # Convert flat permission list to nested dict format
        permissions_dict = {}
        for permission in combined_permissions:
            if '.' in permission:
                resource, action = permission.split('.', 1)
                if resource not in permissions_dict:
                    permissions_dict[resource] = {}
                permissions_dict[resource][action] = True
        
        return permissions_dict
        
    except Exception as e:
        logger.error(f"Error getting user permissions for user {user_id}: {e}")
        return {}

async def check_user_permission(
    user_id: int,
    resource: str,
    action: str,
    *,
    current_user: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Check if user has specific permission.

    R18c round 7 (Bulgu 1): system-wide admin bypass. A user with
    ``users.is_admin = TRUE`` is the canonical super-admin and MUST pass
    every granular permission check, regardless of the role they're
    attached to. Otherwise enterprise admins were getting 403s on
    composite endpoints (e.g. wizard CREATE) when their role's
    ``permissions`` JSONB didn't enumerate every individual action
    (backend.create, frontend.create, ssl.create, apply.execute).

    Two short-circuit paths:

    1. Caller already has ``current_user`` resolved (typical FastAPI
       endpoint) — pass it via the kwarg-only ``current_user`` to skip
       the DB roundtrip entirely.
    2. Caller doesn't have it — we run a single
       ``SELECT is_admin FROM users WHERE id=$1 AND is_active=TRUE``
       before falling back to the role-based permission lookup.

    Backward-compat: positional 3-arg signature preserved.
    """
    try:
        # Path 1: caller-provided current_user dict
        if current_user is not None and current_user.get("is_admin") is True:
            logger.debug(
                "Admin bypass for %s.%s (user_id=%s, via current_user)",
                resource, action, user_id,
            )
            return True

        # Path 2: cheap is_admin lookup before role-permissions join
        conn = await get_database_connection()
        try:
            row = await conn.fetchrow(
                "SELECT is_admin FROM users WHERE id = $1 AND is_active = TRUE",
                int(user_id),
            )
        finally:
            await close_database_connection(conn)
        if row and row.get("is_admin") is True:
            logger.debug(
                "Admin bypass for %s.%s (user_id=%s, via DB lookup)",
                resource, action, user_id,
            )
            return True

        permissions = await get_user_permissions(user_id)
        return permissions.get(resource, {}).get(action, False)
    except Exception as e:
        logger.error(f"Error checking permission for user {user_id}: {e}")
        return False

async def get_current_user_with_permissions(authorization: Optional[str] = None) -> Dict[str, Any]:
    """
    Get current user with their permissions included
    """
    user = await get_current_user_from_token(authorization)
    permissions = await get_user_permissions(user["id"])
    
    return {
        **user,
        "permissions": permissions
    }

def require_permission(resource: str, action: str):
    """
    Decorator to require specific permission for endpoint access
    """
    def decorator(func):
        import functools
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract authorization header from kwargs or function signature
            authorization = kwargs.get('authorization')
            if not authorization:
                # Try to find authorization in function arguments
                import inspect
                sig = inspect.signature(func)
                for param_name, param in sig.parameters.items():
                    if param_name == 'authorization' and param_name in kwargs:
                        authorization = kwargs[param_name]
                        break
            
            # Get current user
            user = await get_current_user_from_token(authorization)
            
            # Check permission
            has_permission = await check_user_permission(user["id"], resource, action)
            if not has_permission:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions: {resource}.{action} required"
                )
            
            # Add user to kwargs for endpoint use
            kwargs['current_user'] = user
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator 