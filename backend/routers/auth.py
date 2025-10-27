from fastapi import APIRouter, HTTPException, Depends, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import logging
import hashlib
import time
from datetime import datetime, timedelta

# Import database and models
from database.connection import get_database_connection, close_database_connection
from models.user import LoginRequest, User, UserCreate, UserUpdate, UserPasswordUpdate
from utils.activity_log import log_user_activity
from auth_middleware import get_current_user_from_token

# Rate limiting temporarily disabled

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()

@router.post("/login", summary="User Login", response_description="JWT access token and user information")
async def login(login_request: LoginRequest, request: Request):
    """
    # User Login - Authenticate and Get Access Token
    
    Authenticate user with username and password. Returns a JWT access token valid for 24 hours.
    
    ## Request Body
    - **username**: User's username (required)
    - **password**: User's password (required)
    
    ## Response
    Returns JWT token, user information, roles, and permissions.
    
    ## Example Request
    ```bash
    curl -X POST "{BASE_URL}/api/auth/login" \\
      -H "Content-Type: application/json" \\
      -d '{
        "username": "admin",
        "password": "admin123"
      }'
    ```
    
    > Replace `{BASE_URL}` with your deployment URL
    
    ## Example Response
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "bearer",
      "expires_in": 86400,
      "user": {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "role": "admin",
        "is_active": true,
        "created_at": "2024-01-01T00:00:00",
        "last_login_at": "2024-01-15T10:30:00"
      },
      "roles": [
        {
          "id": 1,
          "name": "admin",
          "display_name": "Administrator"
        }
      ],
      "permissions": {
        "clusters": {"read": true, "write": true, "delete": true},
        "agents": {"read": true, "write": true, "delete": true}
      }
    }
    ```
    
    ## Using the Token
    Include the access token in subsequent requests:
    ```bash
    curl -X GET "{BASE_URL}/api/clusters" \\
      -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    ```
    
    ## Error Responses
    - **401**: Invalid credentials or inactive account
    - **500**: Server error during authentication
    """
    
    try:
        conn = await get_database_connection()
        
        # Find user by username (with safe column handling)
        try:
            user = await conn.fetchrow("""
                SELECT id, username, email, password_hash, is_active, role, 
                       created_at, updated_at, last_login_at
                FROM users 
                WHERE username = $1
            """, login_request.username)
        except Exception as schema_error:
            logger.warning(f"Schema error, trying fallback query: {schema_error}")
            # Fallback query without role column - try different column names
            try:
                user = await conn.fetchrow("""
                    SELECT id, username, email, password_hash, is_active,
                           created_at, updated_at, last_login_at
                    FROM users 
                    WHERE username = $1
                """, login_request.username)
            except Exception as column_error:
                logger.warning(f"last_login_at column error, trying last_login: {column_error}")
                # Try with last_login instead of last_login_at
                user = await conn.fetchrow("""
                    SELECT id, username, email, password_hash, is_active,
                           created_at, updated_at, last_login
                    FROM users 
                    WHERE username = $1
                """, login_request.username)
        
        if not user:
            await close_database_connection(conn)
            logger.warning(f"Failed login attempt for username: {login_request.username}")
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        if not user['is_active']:
            await close_database_connection(conn)
            logger.warning(f"Login attempt for inactive account: {login_request.username}")
            raise HTTPException(status_code=401, detail="Account is deactivated")
        
        # Verify password
        import bcrypt
        if not bcrypt.checkpw(login_request.password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            await close_database_connection(conn)
            logger.warning(f"Wrong password for user: {login_request.username}")
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        # Update last login (try different column names)
        try:
            await conn.execute("""
                UPDATE users SET last_login_at = CURRENT_TIMESTAMP 
                WHERE id = $1
            """, user['id'])
        except Exception as update_error:
            logger.warning(f"last_login_at update failed, trying last_login: {update_error}")
            try:
                await conn.execute("""
                    UPDATE users SET last_login = CURRENT_TIMESTAMP 
                    WHERE id = $1
                """, user['id'])
            except Exception as fallback_error:
                logger.warning(f"Could not update last login: {fallback_error}")
                # Continue without updating last_login
        
        # Get user roles and permissions before closing connection
        conn_for_roles = conn
        
        # Fetch user roles with their permissions
        user_roles = await conn_for_roles.fetch("""
            SELECT r.id, r.name, r.display_name, r.permissions
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND ur.is_active = TRUE AND r.is_active = TRUE
        """, user['id'])
        
        # Build permissions dictionary
        permissions = {}
        roles_list = []
        
        for role_row in user_roles:
            roles_list.append({
                'id': role_row['id'],
                'name': role_row['name'],
                'display_name': role_row['display_name']
            })
            
            # Parse permissions from JSON string if needed
            role_permissions = role_row['permissions']
            if isinstance(role_permissions, str):
                import json
                role_permissions = json.loads(role_permissions)
            
            # Merge permissions (resource.action format)
            if role_permissions:
                for perm in role_permissions:
                    if '.' in perm:
                        resource, action = perm.split('.', 1)
                        if resource not in permissions:
                            permissions[resource] = {}
                        permissions[resource][action] = True
        
        await close_database_connection(conn)
        
        # Create JWT token
        from jose import jwt
        from config import JWT_SECRET_KEY, JWT_ALGORITHM
        
        payload = {
            "user_id": user['id'],
            "username": user['username'],
            "email": user.get('email'),
            "role": user.get('role', 'admin'),  # Default to admin if role column doesn't exist
            "exp": datetime.utcnow() + timedelta(hours=24)  # 24 hour expiry
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        # Log login activity
        await log_user_activity(
            user_id=user['id'],
            action='login',
            resource_type='auth',
            resource_id=str(user['id']),
            details={
                'login_method': 'username_password',
                'success': True
            },
            ip_address=str(request.client.host) if request.client else None,
            user_agent=request.headers.get('user-agent')
        )
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 86400,  # 24 hours in seconds
            "user": {
                "id": user['id'],
                "username": user['username'],
                "email": user.get('email'),
                "role": user.get('role', 'admin'),
                "is_active": user.get('is_active', True),
                "created_at": user['created_at'].isoformat() if user.get('created_at') else None,
                "last_login_at": datetime.utcnow().isoformat()
            },
            "roles": roles_list,
            "permissions": permissions
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@router.post("/logout", summary="User Logout", response_description="Logout confirmation")
async def logout(request: Request, authorization: str = Header(None)):
    """
    # User Logout
    
    Logout current user and log activity. Requires valid JWT token.
    
    ## Headers
    - **Authorization**: Bearer {access_token}
    
    ## Example Request
    ```bash
    curl -X POST "{BASE_URL}/api/auth/logout" \\
      -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    ```
    
    ## Example Response
    ```json
    {
      "message": "Logout successful"
    }
    ```
    """
    try:
        # Get current user for activity logging
        current_user = await get_current_user_from_token(authorization)
        
        if current_user and current_user.get('id'):
            # Log logout activity
            await log_user_activity(
                user_id=current_user['id'],
                action='logout',
                resource_type='auth',
                resource_id=str(current_user['id']),
                details={
                    'logout_method': 'manual'
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        return {"message": "Logout successful"}
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        # Still return success even if logging fails
        return {"message": "Logout successful"}

@router.get("/me", summary="Get Current User", response_description="Current user information")
async def get_current_user(authorization: str = Header(None)):
    """
    # Get Current User Information
    
    Get authenticated user's profile information. Requires valid JWT token.
    
    ## Headers
    - **Authorization**: Bearer {access_token}
    
    ## Example Request
    ```bash
    curl -X GET "{BASE_URL}/api/auth/me" \\
      -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    ```
    
    ## Example Response
    ```json
    {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin",
      "is_active": true,
      "created_at": "2024-01-01T00:00:00",
      "updated_at": "2024-01-15T10:30:00",
      "last_login_at": "2024-01-15T10:30:00"
    }
    ```
    """
    try:
        current_user = await get_current_user_from_token(authorization)
        
        if not current_user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        conn = await get_database_connection()
        
        # Get fresh user data (with safe column handling)
        try:
            user = await conn.fetchrow("""
                SELECT id, username, email, role, is_active, 
                       created_at, updated_at, last_login_at
                FROM users 
                WHERE id = $1
            """, current_user['id'])
        except Exception as schema_error:
            logger.warning(f"Schema error in /me endpoint, trying fallback: {schema_error}")
            # Fallback query without role column - try different column names
            try:
                user = await conn.fetchrow("""
                    SELECT id, username, email, is_active,
                           created_at, updated_at, last_login_at
                    FROM users 
                    WHERE id = $1
                """, current_user['id'])
            except Exception as column_error:
                logger.warning(f"last_login_at column error in /me, trying last_login: {column_error}")
                # Try with last_login instead of last_login_at
                user = await conn.fetchrow("""
                    SELECT id, username, email, is_active,
                           created_at, updated_at, last_login
                    FROM users 
                    WHERE id = $1
                """, current_user['id'])
        
        await close_database_connection(conn)
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return {
            "id": user['id'],
            "username": user['username'],
            "email": user.get('email'),
            "role": user.get('role', 'admin'),
            "is_active": user.get('is_active', True),
            "created_at": user['created_at'].isoformat() if user.get('created_at') else None,
            "updated_at": user['updated_at'].isoformat() if user.get('updated_at') else None,
            "last_login_at": (user.get('last_login_at') or user.get('last_login', None)).isoformat() if (user.get('last_login_at') or user.get('last_login')) else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get current user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user info")

@router.post("/change-password", summary="Change Password", response_description="Password change confirmation")
async def change_password(password_update: UserPasswordUpdate, request: Request, authorization: str = Header(None)):
    """
    # Change User Password
    
    Change authenticated user's password. Requires current password for verification.
    
    ## Headers
    - **Authorization**: Bearer {access_token}
    
    ## Request Body
    - **current_password**: Current password for verification
    - **new_password**: New password (min 8 characters recommended)
    
    ## Example Request
    ```bash
    curl -X POST "{BASE_URL}/api/auth/change-password" \\
      -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \\
      -H "Content-Type: application/json" \\
      -d '{
        "current_password": "admin123",
        "new_password": "newSecurePassword456"
      }'
    ```
    
    ## Example Response
    ```json
    {
      "message": "Password changed successfully"
    }
    ```
    
    ## Error Responses
    - **400**: Current password is incorrect
    - **401**: Not authenticated
    - **404**: User not found
    """
    try:
        current_user = await get_current_user_from_token(authorization)
        
        if not current_user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        conn = await get_database_connection()
        
        # Get current user data
        user = await conn.fetchrow("""
            SELECT id, password_hash FROM users WHERE id = $1
        """, current_user['id'])
        
        if not user:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="User not found")
        
        # Verify current password
        import bcrypt
        if not bcrypt.checkpw(password_update.current_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        
        # Hash new password
        new_password_hash = bcrypt.hashpw(password_update.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password
        await conn.execute("""
            UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $2
        """, new_password_hash, current_user['id'])
        
        await close_database_connection(conn)
        
        # Log password change activity
        await log_user_activity(
            user_id=current_user['id'],
            action='update',
            resource_type='user',
            resource_id=str(current_user['id']),
            details={
                'action': 'password_change',
                'success': True
            },
            ip_address=str(request.client.host) if request.client else None,
            user_agent=request.headers.get('user-agent')
        )
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Change password error: {e}")
        raise HTTPException(status_code=500, detail="Failed to change password")

@router.get("/validate-token", summary="Validate Token", response_description="Token validation result")
async def validate_token(authorization: str = Header(None)):
    """
    # Validate JWT Token
    
    Check if a JWT token is valid and not expired.
    
    ## Headers
    - **Authorization**: Bearer {access_token}
    
    ## Example Request
    ```bash
    curl -X GET "{BASE_URL}/api/auth/validate-token" \\
      -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    ```
    
    ## Example Response
    ```json
    {
      "valid": true,
      "user": {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "role": "admin"
      }
    }
    ```
    
    ## Error Responses
    - **401**: Invalid or expired token
    """
    try:
        current_user = await get_current_user_from_token(authorization)
        
        if not current_user:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        return {
            "valid": True,
            "user": {
                "id": current_user['id'],
                "username": current_user['username'],
                "email": current_user.get('email'),
                "role": current_user.get('role', 'admin')
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        raise HTTPException(status_code=401, detail="Token validation failed") 