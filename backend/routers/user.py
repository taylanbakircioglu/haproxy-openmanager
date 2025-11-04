from fastapi import APIRouter, HTTPException, Header, Depends, Request
from typing import Optional, List
import logging
import json

from database.connection import get_database_connection, close_database_connection
from auth_middleware import get_current_user_from_token
from utils.activity_log import log_user_activity
from models.user import UserCreate, UserPasswordUpdate

router = APIRouter(prefix="/api", tags=["users", "servers"])
logger = logging.getLogger(__name__)

@router.get("/users")
async def get_users(authorization: str = Header(None)):
    """Get all users"""
    try:
        # Verify authentication
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get users with their roles (only active users)
        try:
            users = await conn.fetch("""
                SELECT u.id, u.username, u.email, u.full_name, u.phone, u.role, u.is_active, 
                       u.is_admin, u.is_verified, u.created_at, u.updated_at, u.last_login_at
                FROM users u
                WHERE u.is_active = TRUE
                ORDER BY u.username
            """)
        except Exception as schema_error:
            logger.warning(f"Schema error in users query, using fallback: {schema_error}")
            # Fallback query with minimal columns
            users = await conn.fetch("""
                SELECT id, username, email, is_active, is_admin, created_at
                FROM users 
                WHERE is_active = TRUE
                ORDER BY username
            """)
        
        # Get user roles for each user
        users_list = []
        for user in users:
            user_dict = dict(user)
            # Remove password_hash if it exists
            user_dict.pop('password_hash', None)
            
            # Format datetime fields with UTC timezone indicator
            if user_dict.get('created_at'):
                user_dict['created_at'] = user_dict['created_at'].isoformat().replace('+00:00', 'Z')
            if user_dict.get('updated_at'):
                user_dict['updated_at'] = user_dict['updated_at'].isoformat().replace('+00:00', 'Z')
            if user_dict.get('last_login_at'):
                user_dict['last_login_at'] = user_dict['last_login_at'].isoformat().replace('+00:00', 'Z')
            
            # Get user roles
            try:
                user_roles = await conn.fetch("""
                    SELECT r.id, r.name, r.display_name, r.description
                    FROM user_roles ur
                    JOIN roles r ON ur.role_id = r.id
                    WHERE ur.user_id = $1 AND r.is_active = true
                    ORDER BY r.display_name
                """, user['id'])
                
                user_dict['roles'] = [dict(role) for role in user_roles]
            except Exception as role_error:
                logger.warning(f"Could not fetch roles for user {user['id']}: {role_error}")
                user_dict['roles'] = []
            
            users_list.append(user_dict)
        
        await close_database_connection(conn)
        
        return {
            "users": users_list,
            "total": len(users_list)
        }
        
    except Exception as e:
        logger.error(f"Failed to get users: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get users: {str(e)}")

@router.get("/roles")
async def get_roles(authorization: str = Header(None)):
    """Get all roles"""
    try:
        # Verify authentication
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Check if roles table exists and get roles
        try:
            roles = await conn.fetch("""
                SELECT id, name, display_name, description, permissions, cluster_ids,
                       is_active, is_system, created_at, updated_at
                FROM roles 
                WHERE is_active = TRUE
                ORDER BY name
            """)
        except Exception as schema_error:
            logger.warning(f"Roles table not found or schema error: {schema_error}")
            # Return default roles if table doesn't exist
            roles = []
        
        await close_database_connection(conn)
        
        # Convert to list of dicts
        roles_list = [dict(role) for role in roles]
        
        return {
            "roles": roles_list,
            "total": len(roles_list)
        }
        
    except Exception as e:
        logger.error(f"Failed to get roles: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get roles: {str(e)}")

@router.post("/users", summary="Create User", response_description="User created successfully")
async def create_user(user_data: UserCreate, authorization: str = Header(None)):
    """
    # Create New User
    
    Create a new user account with role assignments.
    
    ## Request Body
    - **username**: Username (required, unique)
    - **email**: Email address (required)
    - **password**: Password (required, min 8 characters)
    - **is_active**: Active status (default: true)
    
    ## Example Request
    ```bash
    curl -X POST "{BASE_URL}/api/users/users" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..." \\
      -H "Content-Type: application/json" \\
      -d '{
        "username": "johndoe",
        "email": "john@example.com",
        "password": "securePass123",
        "is_active": true
      }'
    ```
    
    ## Example Response
    ```json
    {
      "message": "User 'johndoe' created successfully",
      "user_id": 2
    }
    ```
    """
    try:
        # Verify authentication
        current_user = await get_current_user_from_token(authorization)
        
        # SECURITY: Only admin users can create users
        if not current_user.get("is_admin", False):
            raise HTTPException(
                status_code=403, 
                detail="Only admin users can create new users"
            )
        
        conn = await get_database_connection()
        
        # Check if username already exists (only active users)
        existing = await conn.fetchrow(
            "SELECT id FROM users WHERE username = $1 AND is_active = TRUE", 
            user_data.username
        )
        if existing:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Check if email already exists (only active users)
        if user_data.email:
            existing_email = await conn.fetchrow(
                "SELECT id FROM users WHERE email = $1 AND is_active = TRUE", 
                user_data.email
            )
            if existing_email:
                await close_database_connection(conn)
                raise HTTPException(status_code=400, detail="Email already exists")
        
        # Hash password
        import bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), salt)
        
        # Check if user should be admin based on roles
        is_admin = False
        role_ids = getattr(user_data, 'role_ids', None)
        if role_ids:
            # Check if any of the assigned roles is super_admin
            admin_roles = await conn.fetch("""
                SELECT id FROM roles 
                WHERE id = ANY($1) AND name = 'super_admin'
            """, role_ids)
            is_admin = len(admin_roles) > 0
        
        # Create user
        user_id = await conn.fetchval("""
            INSERT INTO users (username, email, full_name, phone, password_hash, 
                             role, is_active, is_admin, is_verified)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
        """, user_data.username, user_data.email, user_data.full_name, user_data.phone,
            hashed_password.decode('utf-8'), 'user',  # Default role (actual roles assigned via role_ids)
            user_data.is_active, is_admin,  # is_admin determined by roles
            user_data.is_verified)
        
        # Assign roles if provided
        if role_ids:
            for role_id in role_ids:
                await conn.execute("""
                    INSERT INTO user_roles (user_id, role_id) 
                    VALUES ($1, $2)
                    ON CONFLICT (user_id, role_id) DO NOTHING
                """, user_id, role_id)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='create', 
            resource_type='user',
            resource_id=str(user_id),
            details={'username': user_data.username}
        )
        
        return {
            "message": f"User '{user_data.username}' created successfully",
            "user_id": user_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

@router.put("/users/{user_id}")
async def update_user(user_id: int, user_data: dict, authorization: str = Header(None)):
    """Update a user"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        # SECURITY: Only admin users can update other users
        if not current_user.get("is_admin", False):
            raise HTTPException(
                status_code=403, 
                detail="Only admin users can update user information"
            )
        
        conn = await get_database_connection()
        
        # Check if user exists
        existing_user = await conn.fetchrow("SELECT username, email FROM users WHERE id = $1", user_id)
        if not existing_user:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="User not found")
        
        # Build update query dynamically
        update_fields = []
        params = [user_id]
        param_count = 1
        
        if 'username' in user_data:
            param_count += 1
            update_fields.append(f"username = ${param_count}")
            params.append(user_data['username'])
            
        if 'email' in user_data:
            param_count += 1
            update_fields.append(f"email = ${param_count}")
            params.append(user_data['email'])
            
        if 'full_name' in user_data:
            param_count += 1
            update_fields.append(f"full_name = ${param_count}")
            params.append(user_data['full_name'])
            
        if 'phone' in user_data:
            param_count += 1
            update_fields.append(f"phone = ${param_count}")
            params.append(user_data['phone'])
            
        if 'role' in user_data:
            param_count += 1
            update_fields.append(f"role = ${param_count}")
            params.append(user_data['role'])
            
        if 'is_active' in user_data:
            param_count += 1
            update_fields.append(f"is_active = ${param_count}")
            params.append(user_data['is_active'])
            
        if 'is_admin' in user_data:
            param_count += 1
            update_fields.append(f"is_admin = ${param_count}")
            params.append(user_data['is_admin'])
            
        if 'password' in user_data and user_data['password']:
            import bcrypt
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(user_data['password'].encode('utf-8'), salt)
            param_count += 1
            update_fields.append(f"password_hash = ${param_count}")
            params.append(hashed_password.decode('utf-8'))
        
        # Handle role assignment if provided and auto-update is_admin flag
        if 'role_ids' in user_data:
            role_ids = user_data['role_ids'] or []
            
            # Check if user should be admin based on new roles
            if role_ids:
                admin_roles = await conn.fetch("""
                    SELECT id FROM roles 
                    WHERE id = ANY($1) AND name = 'super_admin'
                """, role_ids)
                is_admin = len(admin_roles) > 0
            else:
                is_admin = False
            
            # Add is_admin to update fields based on roles
            param_count += 1
            update_fields.append(f"is_admin = ${param_count}")
            params.append(is_admin)
            
            # Clear existing user roles
            await conn.execute("DELETE FROM user_roles WHERE user_id = $1", user_id)
            
            # Assign new roles
            if role_ids:
                for role_id in role_ids:
                    await conn.execute("""
                        INSERT INTO user_roles (user_id, role_id) 
                        VALUES ($1, $2)
                        ON CONFLICT (user_id, role_id) DO NOTHING
                    """, user_id, role_id)
        
        if not update_fields:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="No fields to update")
        
        # Add updated_at
        param_count += 1
        update_fields.append(f"updated_at = CURRENT_TIMESTAMP")
        
        # Execute update
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = $1"
        await conn.execute(query, *params)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='update',
            resource_type='user', 
            resource_id=str(user_id),
            details={'updated_fields': list(user_data.keys())}
        )
        
        return {"message": f"User updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update user: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update user: {str(e)}")

@router.put("/users/{user_id}/password")
async def change_user_password(
    user_id: int, 
    password_data: UserPasswordUpdate, 
    authorization: str = Header(None)
):
    """
    Change user password
    
    Users can change their own password by providing current password.
    Admins can change any user's password without current password.
    """
    try:
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Check if target user exists
        target_user = await conn.fetchrow(
            "SELECT id, username, password_hash, is_active FROM users WHERE id = $1", 
            user_id
        )
        if not target_user:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="User not found")
        
        if not target_user['is_active']:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="User is inactive")
        
        # Check permissions
        is_self = current_user["id"] == user_id
        is_admin = current_user.get("is_admin", False)
        
        if not is_self and not is_admin:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=403, 
                detail="You can only change your own password"
            )
        
        # If changing own password, verify current password
        if is_self:
            import bcrypt
            if not bcrypt.checkpw(
                password_data.current_password.encode('utf-8'), 
                target_user['password_hash'].encode('utf-8')
            ):
                await close_database_connection(conn)
                raise HTTPException(
                    status_code=400, 
                    detail="Current password is incorrect"
                )
        
        # Hash new password
        import bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(
            password_data.new_password.encode('utf-8'), 
            salt
        )
        
        # Update password
        await conn.execute("""
            UPDATE users 
            SET password_hash = $1, updated_at = CURRENT_TIMESTAMP
            WHERE id = $2
        """, hashed_password.decode('utf-8'), user_id)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='change_password',
            resource_type='user',
            resource_id=str(user_id),
            details={
                'target_username': target_user['username'],
                'changed_by_self': is_self
            }
        )
        
        return {
            "message": "Password changed successfully",
            "username": target_user['username']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to change password: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to change password: {str(e)}"
        )

@router.delete("/servers/{server_id}")
async def delete_server_global(server_id: int, request: Request, authorization: str = Header(None)):
    """Delete a server by ID - global endpoint for UI compatibility"""
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        # Get request body for cluster_id validation
        request_body = await request.json() if hasattr(request, 'json') else {}
        expected_cluster_id = request_body.get('cluster_id')
        
        conn = await get_database_connection()
        
        # Get server info before deletion
        server = await conn.fetchrow("""
            SELECT id, server_name, backend_name, server_address, server_port, cluster_id, is_active
            FROM backend_servers WHERE id = $1
        """, server_id)
        
        if not server:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Server not found")
        
        cluster_id = server['cluster_id']
        backend_name = server['backend_name']
        server_name = server['server_name']
        
        # Validate cluster ownership for multi-cluster security
        if expected_cluster_id and cluster_id != expected_cluster_id:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=403, 
                detail=f"Server belongs to cluster {cluster_id}, not cluster {expected_cluster_id}"
            )
        
        # Check if cluster exists
        cluster_exists = await conn.fetchval("""
            SELECT id FROM haproxy_clusters WHERE id = $1
        """, cluster_id)
        
        if not cluster_exists:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=404, 
                detail="Cluster not found"
            )
        
        # Check if user_pool_access table exists (for backward compatibility)
        table_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'user_pool_access'
            )
        """)
        
        if table_exists:
            # Check if expires_at column exists (for backward compatibility)
            expires_at_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'user_pool_access' AND column_name = 'expires_at'
                )
            """)
            
            # Proper user-pool access validation
            if expires_at_exists:
                user_access = await conn.fetchrow("""
                    SELECT upa.access_level, hc.id, hc.name
                    FROM haproxy_clusters hc
                    JOIN haproxy_cluster_pools hcp ON hc.pool_id = hcp.id
                    JOIN user_pool_access upa ON hcp.id = upa.pool_id
                    WHERE upa.user_id = $1 AND hc.id = $2 AND upa.is_active = TRUE
                    AND (upa.expires_at IS NULL OR upa.expires_at > CURRENT_TIMESTAMP)
                """, current_user['id'], cluster_id)
            else:
                # Fallback query without expires_at column
                user_access = await conn.fetchrow("""
                    SELECT upa.access_level, hc.id, hc.name
                    FROM haproxy_clusters hc
                    JOIN haproxy_cluster_pools hcp ON hc.pool_id = hcp.id
                    JOIN user_pool_access upa ON hcp.id = upa.pool_id
                    WHERE upa.user_id = $1 AND hc.id = $2 AND upa.is_active = TRUE
                """, current_user['id'], cluster_id)
            
            if not user_access:
                await close_database_connection(conn)
                raise HTTPException(
                    status_code=403, 
                    detail="You don't have access to this cluster"
                )
        
        logger.info(f"Global server delete: server_id={server_id}, name={server_name}, backend={backend_name}, cluster_id={cluster_id}")
        
        # 1. Soft delete the server (mark as inactive and pending for deletion)
        await conn.execute("""
            UPDATE backend_servers 
            SET is_active = FALSE, last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
        """, server_id)
        
        # 2. Don't mark backend as PENDING - let Agent Sync work based on server version
        # This matches the behavior of server add operations
        # await conn.execute("""
        #     UPDATE backends 
        #     SET last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP
        #     WHERE name = $1 AND cluster_id = $2
        # """, backend_name, cluster_id)
        
        # Create config version for server deletion (like frontend/SSL delete)
        sync_results = []
        if cluster_id:
            try:
                # Generate new HAProxy config without this server
                from services.haproxy_config import generate_haproxy_config_for_cluster
                import hashlib
                import time
                
                config_content = await generate_haproxy_config_for_cluster(cluster_id)
                
                logger.info(f"SERVER DELETE DEBUG (user.py): Generated config content length: {len(config_content) if config_content else 0}")
                if config_content:
                    logger.info(f"SERVER DELETE DEBUG (user.py): Config contains server line: {server_name in config_content}")
                    logger.info(f"SERVER DELETE DEBUG (user.py): Config contains 'DISABLED': {'DISABLED' in config_content}")
                    logger.info(f"SERVER DELETE DEBUG (user.py): Server marked for deletion - should be skipped in config")
                else:
                    logger.error(f"SERVER DELETE DEBUG (user.py): Config content is empty or None!")
                
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"server-{server_id}-delete-{int(time.time())}"
                
                # Get system admin user ID for created_by
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Create new config version
                config_version_id = await conn.fetchval("""
                    INSERT INTO config_versions 
                    (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                    VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                    RETURNING id
                """, cluster_id, version_name, config_content, config_hash, admin_user_id)
                
                logger.info(f"Created PENDING config version {version_name} for server delete")
                sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'Server deletion created. Click Apply to activate.'}]
                
            except Exception as e:
                logger.error(f"Cluster config update failed for server {server_name}: {e}")
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        await close_database_connection(conn)
        
        # Log user activity
        await log_user_activity(
            user_id=current_user['id'],
            action="delete_server", 
            resource_type="server",
            resource_id=str(server_id),
            details={
                "server_name": server_name,
                "backend_name": backend_name,
                "cluster_id": cluster_id
            }
        )
        
        return {
            "message": f"Server '{server_name}' deleted successfully from backend '{backend_name}'",
            "server": {
                "id": server_id,
                "name": server_name,
                "backend": backend_name
            },
            "sync_results": sync_results
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete server {server_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete server: {str(e)}")

@router.delete("/users/{user_id}")
async def delete_user(user_id: int, authorization: str = Header(None)):
    """Delete a user"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        # SECURITY: Only admin users can delete users
        if not current_user.get("is_admin", False):
            raise HTTPException(
                status_code=403, 
                detail="Only admin users can delete users"
            )
        
        conn = await get_database_connection()
        
        # Check if user exists and get details
        user_info = await conn.fetchrow("SELECT username, email FROM users WHERE id = $1", user_id)
        if not user_info:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="User not found")
        
        # Prevent self-deletion
        if current_user["id"] == user_id:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Cannot delete your own account")
        
        # Prevent deletion of admin user
        if user_info["username"] == "admin":
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Cannot delete admin user")
        
        # Soft delete - mark as inactive instead of hard delete
        await conn.execute("""
            UPDATE users 
            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
        """, user_id)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='delete',
            resource_type='user',
            resource_id=str(user_id),
            details={'username': user_info['username'], 'email': user_info['email']}
        )
        
        return {"message": f"User '{user_info['username']}' deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete user: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete user: {str(e)}")

@router.get("/users/{user_id}/pool-access")
async def get_user_pool_access(user_id: int, authorization: str = Header(None)):
    """Get user's pool access permissions"""
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        # Only admin users or the user themselves can view pool access
        if not current_user.get('is_admin') and current_user['id'] != user_id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        conn = await get_database_connection()
        
        # Check if user_pool_access table exists
        table_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'user_pool_access'
            )
        """)
        
        if not table_exists:
            await close_database_connection(conn)
            return {"pool_access": [], "message": "user_pool_access table not found"}
        
        # Get user's pool access
        pool_access = await conn.fetch("""
            SELECT upa.id, upa.pool_id, upa.access_level, upa.granted_at, upa.expires_at, upa.is_active,
                   hcp.name as pool_name, hcp.description as pool_description,
                   u.username as granted_by_username
            FROM user_pool_access upa
            JOIN haproxy_cluster_pools hcp ON upa.pool_id = hcp.id
            LEFT JOIN users u ON upa.granted_by = u.id
            WHERE upa.user_id = $1
            ORDER BY upa.granted_at DESC
        """, user_id)
        
        await close_database_connection(conn)
        
        return {
            "pool_access": [dict(row) for row in pool_access]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user pool access: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get user pool access: {str(e)}")

@router.post("/users/{user_id}/pool-access")
async def grant_user_pool_access(
    user_id: int, 
    access_data: dict, 
    authorization: str = Header(None)
):
    """Grant user access to pools"""
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        # Only admin users can grant pool access
        if not current_user.get('is_admin'):
            raise HTTPException(status_code=403, detail="Only admin users can grant pool access")
        
        pool_ids = access_data.get('pool_ids', [])
        access_level = access_data.get('access_level', 'read_write')
        
        if not pool_ids:
            raise HTTPException(status_code=400, detail="pool_ids is required")
        
        conn = await get_database_connection()
        
        # Check if user exists
        user_exists = await conn.fetchval("SELECT id FROM users WHERE id = $1", user_id)
        if not user_exists:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if user_pool_access table exists
        table_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'user_pool_access'
            )
        """)
        
        if not table_exists:
            await close_database_connection(conn)
            raise HTTPException(status_code=500, detail="user_pool_access table not found")
        
        # Grant access to multiple pools
        granted_pools = []
        for pool_id in pool_ids:
            # Check if pool exists
            pool_exists = await conn.fetchval("SELECT name FROM haproxy_cluster_pools WHERE id = $1", pool_id)
            if not pool_exists:
                continue
            
            # Grant access
            await conn.execute("""
                INSERT INTO user_pool_access (user_id, pool_id, access_level, granted_by)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (user_id, pool_id) 
                DO UPDATE SET 
                    access_level = EXCLUDED.access_level,
                    granted_by = EXCLUDED.granted_by,
                    granted_at = CURRENT_TIMESTAMP,
                    is_active = TRUE
            """, user_id, pool_id, access_level, current_user['id'])
            
            granted_pools.append({"pool_id": pool_id, "pool_name": pool_exists})
        
        await close_database_connection(conn)
        
        return {
            "message": f"Pool access granted successfully",
            "user_id": user_id,
            "granted_pools": granted_pools,
            "access_level": access_level
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to grant user pool access: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to grant user pool access: {str(e)}")

@router.delete("/users/{user_id}/pool-access/{pool_id}")
async def revoke_user_pool_access(
    user_id: int, 
    pool_id: int, 
    authorization: str = Header(None)
):
    """Revoke user access to a pool"""
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        # Only admin users can revoke pool access
        if not current_user.get('is_admin'):
            raise HTTPException(status_code=403, detail="Only admin users can revoke pool access")
        
        conn = await get_database_connection()
        
        # Check if user_pool_access table exists
        table_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = 'user_pool_access'
            )
        """)
        
        if not table_exists:
            await close_database_connection(conn)
            raise HTTPException(status_code=500, detail="user_pool_access table not found")
        
        # Revoke access (soft delete)
        result = await conn.execute("""
            UPDATE user_pool_access 
            SET is_active = FALSE 
            WHERE user_id = $1 AND pool_id = $2
        """, user_id, pool_id)
        
        await close_database_connection(conn)
        
        return {
            "message": f"Pool access revoked successfully",
            "user_id": user_id,
            "pool_id": pool_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke user pool access: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to revoke user pool access: {str(e)}")


@router.get("/user-activity")
async def get_user_activity(
    limit: int = 50,
    offset: int = 0,
    user_id: Optional[int] = None,
    authorization: str = Header(None)
):
    """Get user activity logs"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Build query with optional user filter
        where_clause = ""
        params = [limit, offset]
        if user_id:
            where_clause = "WHERE ua.user_id = $3"
            params.append(user_id)
        
        # Get activity logs
        activities = await conn.fetch(f"""
            SELECT ua.id, ua.user_id, ua.action, ua.resource_type, ua.resource_id,
                   ua.details, ua.created_at, ua.ip_address,
                   u.username, u.email
            FROM user_activity_logs ua
            LEFT JOIN users u ON ua.user_id = u.id
            {where_clause}
            ORDER BY ua.created_at DESC
            LIMIT $1 OFFSET $2
        """, *params)
        
        # Get total count
        count_query = f"SELECT COUNT(*) FROM user_activity_logs ua {where_clause}"
        if user_id:
            total = await conn.fetchval(count_query, user_id)
        else:
            total = await conn.fetchval(count_query)
        
        await close_database_connection(conn)
        
        return {
            "activities": [
                {
                    "id": activity["id"],
                    "user_id": activity["user_id"],
                    "username": activity["username"],
                    "email": activity["email"],
                    "action": activity["action"],
                    "resource_type": activity["resource_type"],
                    "resource_id": activity["resource_id"],
                    "details": activity["details"],
                    "created_at": activity["created_at"].isoformat() if activity["created_at"] else None,
                    "ip_address": activity["ip_address"]
                } for activity in activities
            ],
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user activity: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get user activity: {str(e)}")

# ==== ENHANCED ROLE MANAGEMENT ====

@router.post("/roles")
async def create_role(role_data: dict, authorization: str = Header(None)):
    """Create a new role with cluster-specific permissions"""
    try:
        # Verify authentication
        current_user = await get_current_user_from_token(authorization)
        
        # SECURITY: Only admin users can create roles
        if not current_user.get("is_admin", False):
            raise HTTPException(
                status_code=403, 
                detail="Only admin users can create roles"
            )
        
        conn = await get_database_connection()
        
        # Check if role name already exists
        existing = await conn.fetchrow("SELECT id FROM roles WHERE name = $1", role_data['name'])
        if existing:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Role name already exists")
        
        # Create role with cluster_ids support
        role_id = await conn.fetchval("""
            INSERT INTO roles (name, display_name, description, permissions, cluster_ids, is_active)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
        """, 
            role_data['name'],
            role_data['display_name'], 
            role_data.get('description'),
            json.dumps(role_data.get('permissions', [])) if isinstance(role_data.get('permissions'), list) else role_data.get('permissions', []),
            json.dumps(role_data.get('cluster_ids')) if role_data.get('cluster_ids') else None,
            role_data.get('is_active', True)
        )
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='create', 
            resource_type='role',
            resource_id=str(role_id),
            details={
                'role_name': role_data['name'],
                'display_name': role_data['display_name'],
                'permissions_count': len(role_data.get('permissions', [])),
                'cluster_specific': bool(role_data.get('cluster_ids'))
            }
        )
        
        return {
            "message": f"Role '{role_data['display_name']}' created successfully",
            "id": role_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create role: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create role: {str(e)}")

@router.put("/roles/{role_id}")
async def update_role(role_id: int, role_data: dict, authorization: str = Header(None)):
    """Update an existing role"""
    try:
        # Verify authentication
        current_user = await get_current_user_from_token(authorization)
        
        # SECURITY: Only admin users can update roles
        if not current_user.get("is_admin", False):
            raise HTTPException(
                status_code=403, 
                detail="Only admin users can update roles"
            )
        
        conn = await get_database_connection()
        
        # Check if role exists
        existing = await conn.fetchrow("SELECT * FROM roles WHERE id = $1", role_id)
        if not existing:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Role not found")
        
        # Check if new name conflicts with other roles
        if 'name' in role_data and role_data['name'] != existing['name']:
            name_conflict = await conn.fetchrow("SELECT id FROM roles WHERE name = $1 AND id != $2", role_data['name'], role_id)
            if name_conflict:
                await close_database_connection(conn)
                raise HTTPException(status_code=400, detail="Role name already exists")
        
        # Update role
        await conn.execute("""
            UPDATE roles SET 
                name = $1, display_name = $2, description = $3, 
                permissions = $4, cluster_ids = $5, is_active = $6,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $7
        """, 
            role_data.get('name', existing['name']),
            role_data.get('display_name', existing['display_name']),
            role_data.get('description', existing['description']),
            json.dumps(role_data.get('permissions', existing['permissions'])) if isinstance(role_data.get('permissions'), list) else role_data.get('permissions', existing['permissions']),
            json.dumps(role_data.get('cluster_ids')) if 'cluster_ids' in role_data and role_data.get('cluster_ids') else (existing['cluster_ids'] if existing['cluster_ids'] else None),
            role_data.get('is_active', existing['is_active']),
            role_id
        )
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='update', 
            resource_type='role',
            resource_id=str(role_id),
            details={
                'role_name': role_data.get('name', existing['name']),
                'display_name': role_data.get('display_name', existing['display_name']),
                'permissions_count': len(role_data.get('permissions', [])),
                'cluster_specific': bool(role_data.get('cluster_ids'))
            }
        )
        
        return {
            "message": f"Role updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update role: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update role: {str(e)}")

@router.delete("/roles/{role_id}")
async def delete_role(role_id: int, authorization: str = Header(None)):
    """Delete a role (soft delete by setting is_active = false)"""
    try:
        # Verify authentication
        current_user = await get_current_user_from_token(authorization)
        
        # SECURITY: Only admin users can delete roles
        if not current_user.get("is_admin", False):
            raise HTTPException(
                status_code=403, 
                detail="Only admin users can delete roles"
            )
        
        conn = await get_database_connection()
        
        # Check if role exists and is not system role
        role = await conn.fetchrow("SELECT * FROM roles WHERE id = $1", role_id)
        if not role:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Role not found")
        
        if role.get('is_system'):
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Cannot delete system roles")
        
        # Soft delete role
        await conn.execute("""
            UPDATE roles SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $1
        """, role_id)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='delete', 
            resource_type='role',
            resource_id=str(role_id),
            details={
                'role_name': role['name'],
                'display_name': role['display_name']
            }
        )
        
        return {
            "message": f"Role '{role['display_name']}' deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete role: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete role: {str(e)}")

# ==== USER ROLE ASSIGNMENT ENDPOINTS ====

@router.post("/users/{user_id}/roles")
async def assign_user_roles(user_id: int, role_data: dict, authorization: str = Header(None)):
    """Assign roles to a user"""
    try:
        # Verify authentication
        current_user = await get_current_user_from_token(authorization)
        
        # SECURITY: Only admin users can assign roles to users
        if not current_user.get("is_admin", False):
            raise HTTPException(
                status_code=403, 
                detail="Only admin users can assign roles to users"
            )
        
        conn = await get_database_connection()
        
        # Check if user exists
        user = await conn.fetchrow("SELECT id, username FROM users WHERE id = $1", user_id)
        if not user:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="User not found")
        
        role_ids = role_data.get('role_ids', [])
        
        # Clear existing user roles
        await conn.execute("DELETE FROM user_roles WHERE user_id = $1", user_id)
        
        # Assign new roles
        if role_ids:
            for role_id in role_ids:
                await conn.execute("""
                    INSERT INTO user_roles (user_id, role_id) 
                    VALUES ($1, $2)
                    ON CONFLICT (user_id, role_id) DO NOTHING
                """, user_id, role_id)
        
        await close_database_connection(conn)
        
        # Log activity
        await log_user_activity(
            user_id=current_user["id"],
            action='update', 
            resource_type='user_roles',
            resource_id=str(user_id),
            details={
                'target_user': user['username'],
                'assigned_roles': len(role_ids),
                'role_ids': role_ids
            }
        )
        
        return {
            "message": f"Roles assigned to user '{user['username']}' successfully",
            "assigned_roles": len(role_ids)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to assign roles to user {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to assign roles: {str(e)}")

@router.post("/user-roles")
async def assign_roles_legacy(role_assignment: dict, authorization: str = Header(None)):
    """Legacy endpoint for role assignment (for compatibility)"""
    try:
        user_id = role_assignment.get('user_id')
        role_ids = role_assignment.get('role_ids', [])
        
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID is required")
        
        return await assign_user_roles(user_id, {'role_ids': role_ids}, authorization)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to assign roles (legacy): {e}")
        raise HTTPException(status_code=500, detail=f"Failed to assign roles: {str(e)}")