"""
Maintenance and Database Cleanup Endpoints
Provides tools for cleaning up soft-deleted entities and old configuration versions
"""
from fastapi import APIRouter, HTTPException, Header
from database.connection import get_database_connection, close_database_connection
from database.migrations import run_all_migrations
from typing import Dict, Any
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/maintenance/check-migration-columns")
async def check_migration_columns(authorization: str = Header(None)):
    """
    Check if critical migration columns exist in database
    Helps diagnose migration failures
    """
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        # Only super_admin can check
        is_super_admin = False
        if current_user.get("role") == "super_admin":
            is_super_admin = True
        
        if not is_super_admin:
            conn_check = await get_database_connection()
            try:
                role_check = await conn_check.fetchval("""
                    SELECT COUNT(*) 
                    FROM user_roles ur
                    JOIN roles r ON ur.role_id = r.id
                    WHERE ur.user_id = $1 AND r.name = 'super_admin'
                """, current_user["id"])
                if role_check and role_check > 0:
                    is_super_admin = True
            finally:
                await close_database_connection(conn_check)
        
        if not is_super_admin:
            raise HTTPException(status_code=403, detail="Insufficient permissions: super_admin role required")
        
        conn = await get_database_connection()
        
        # Check config_versions columns
        config_versions_cols = await conn.fetch("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name='config_versions' 
            AND column_name IN ('validation_error', 'validation_error_reported_at')
            ORDER BY column_name
        """)
        
        # Check agents columns
        agents_cols = await conn.fetch("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name='agents' 
            AND column_name IN ('last_validation_error', 'last_validation_error_at', 'upgrade_status', 'upgrade_target_version', 'upgraded_at')
            ORDER BY column_name
        """)
        
        await close_database_connection(conn)
        
        return {
            "config_versions_table": {
                "columns_found": [dict(col) for col in config_versions_cols],
                "expected_columns": ["validation_error", "validation_error_reported_at"],
                "missing_columns": [
                    col for col in ["validation_error", "validation_error_reported_at"]
                    if col not in [c["column_name"] for c in config_versions_cols]
                ]
            },
            "agents_table": {
                "columns_found": [dict(col) for col in agents_cols],
                "expected_columns": ["last_validation_error", "last_validation_error_at", "upgrade_status", "upgrade_target_version", "upgraded_at"],
                "missing_columns": [
                    col for col in ["last_validation_error", "last_validation_error_at", "upgrade_status", "upgrade_target_version", "upgraded_at"]
                    if col not in [c["column_name"] for c in agents_cols]
                ]
            },
            "all_ok": (
                len(config_versions_cols) == 2 and 
                len(agents_cols) == 5
            )
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Column check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/maintenance/run-migrations")
async def run_migrations_endpoint(authorization: str = Header(None)):
    """
    Manually trigger database migrations
    Useful when automatic migrations fail during startup
    """
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        # Only super_admin can run migrations
        is_super_admin = False
        
        # Check direct role field
        if current_user.get("role") == "super_admin":
            is_super_admin = True
        
        # Check user_roles table (JOIN with roles)
        if not is_super_admin:
            conn_check = await get_database_connection()
            try:
                role_check = await conn_check.fetchval("""
                    SELECT COUNT(*) 
                    FROM user_roles ur
                    JOIN roles r ON ur.role_id = r.id
                    WHERE ur.user_id = $1 AND r.name = 'super_admin'
                """, current_user["id"])
                if role_check and role_check > 0:
                    is_super_admin = True
            finally:
                await close_database_connection(conn_check)
        
        if not is_super_admin:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: super_admin role required"
            )
        
        # Run migrations
        logger.info(f"User {current_user['username']} manually triggered database migrations")
        await run_all_migrations()
        logger.info("Database migrations completed successfully")
        
        # Check which columns are still missing after migration
        conn = await get_database_connection()
        config_versions_cols = await conn.fetch("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name='config_versions' 
            AND column_name IN ('validation_error', 'validation_error_reported_at')
        """)
        agents_cols = await conn.fetch("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name='agents' 
            AND column_name IN ('last_validation_error', 'last_validation_error_at', 'upgrade_status', 'upgrade_target_version', 'upgraded_at')
        """)
        await close_database_connection(conn)
        
        missing_config_cols = [
            col for col in ['validation_error', 'validation_error_reported_at']
            if col not in [c['column_name'] for c in config_versions_cols]
        ]
        missing_agent_cols = [
            col for col in ['last_validation_error', 'last_validation_error_at', 'upgrade_status', 'upgrade_target_version', 'upgraded_at']
            if col not in [c['column_name'] for c in agents_cols]
        ]
        
        return {
            "status": "success" if not missing_config_cols and not missing_agent_cols else "partial",
            "message": "Database migrations completed" + (" with warnings" if (missing_config_cols or missing_agent_cols) else " successfully"),
            "triggered_by": current_user["username"],
            "missing_columns": {
                "config_versions": missing_config_cols,
                "agents": missing_agent_cols
            } if (missing_config_cols or missing_agent_cols) else {}
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Migration failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, 
            detail=f"Migration failed: {str(e)}"
        )

@router.post("/maintenance/add-validation-columns")
async def add_validation_columns(authorization: str = Header(None)):
    """
    Specifically add validation_error columns that are missing
    This is a targeted fix for the migration issue
    """
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        # Only super_admin can run
        is_super_admin = False
        if current_user.get("role") == "super_admin":
            is_super_admin = True
        
        if not is_super_admin:
            conn_check = await get_database_connection()
            try:
                role_check = await conn_check.fetchval("""
                    SELECT COUNT(*) 
                    FROM user_roles ur
                    JOIN roles r ON ur.role_id = r.id
                    WHERE ur.user_id = $1 AND r.name = 'super_admin'
                """, current_user["id"])
                if role_check and role_check > 0:
                    is_super_admin = True
            finally:
                await close_database_connection(conn_check)
        
        if not is_super_admin:
            raise HTTPException(status_code=403, detail="Insufficient permissions: super_admin role required")
        
        conn = await get_database_connection()
        results = []
        
        # Add validation_error to config_versions
        try:
            col_exists = await conn.fetchval("""
                SELECT 1 FROM information_schema.columns 
                WHERE table_name='config_versions' AND column_name='validation_error'
            """)
            if not col_exists:
                await conn.execute("ALTER TABLE config_versions ADD COLUMN validation_error TEXT;")
                results.append("Added validation_error to config_versions")
                logger.info("Added validation_error column to config_versions")
            else:
                results.append("ℹ️  validation_error already exists in config_versions")
        except Exception as e:
            results.append(f"Failed to add validation_error to config_versions: {str(e)}")
            logger.error(f"Failed to add validation_error: {e}")
        
        # Add validation_error_reported_at to config_versions
        try:
            col_exists = await conn.fetchval("""
                SELECT 1 FROM information_schema.columns 
                WHERE table_name='config_versions' AND column_name='validation_error_reported_at'
            """)
            if not col_exists:
                await conn.execute("ALTER TABLE config_versions ADD COLUMN validation_error_reported_at TIMESTAMP;")
                results.append("Added validation_error_reported_at to config_versions")
                logger.info("Added validation_error_reported_at column to config_versions")
            else:
                results.append("ℹ️  validation_error_reported_at already exists in config_versions")
        except Exception as e:
            results.append(f"Failed to add validation_error_reported_at to config_versions: {str(e)}")
            logger.error(f"Failed to add validation_error_reported_at: {e}")
        
        # Add last_validation_error to agents
        try:
            col_exists = await conn.fetchval("""
                SELECT 1 FROM information_schema.columns 
                WHERE table_name='agents' AND column_name='last_validation_error'
            """)
            if not col_exists:
                await conn.execute("ALTER TABLE agents ADD COLUMN last_validation_error TEXT;")
                results.append("Added last_validation_error to agents")
                logger.info("Added last_validation_error column to agents")
            else:
                results.append("ℹ️  last_validation_error already exists in agents")
        except Exception as e:
            results.append(f"Failed to add last_validation_error to agents: {str(e)}")
            logger.error(f"Failed to add last_validation_error: {e}")
        
        # Add last_validation_error_at to agents
        try:
            col_exists = await conn.fetchval("""
                SELECT 1 FROM information_schema.columns 
                WHERE table_name='agents' AND column_name='last_validation_error_at'
            """)
            if not col_exists:
                await conn.execute("ALTER TABLE agents ADD COLUMN last_validation_error_at TIMESTAMP;")
                results.append("Added last_validation_error_at to agents")
                logger.info("Added last_validation_error_at column to agents")
            else:
                results.append("ℹ️  last_validation_error_at already exists in agents")
        except Exception as e:
            results.append(f"Failed to add last_validation_error_at to agents: {str(e)}")
            logger.error(f"Failed to add last_validation_error_at: {e}")
        
        await close_database_connection(conn)
        
        has_errors = any("❌" in r for r in results)
        
        return {
            "status": "error" if has_errors else "success",
            "message": "Validation columns migration completed",
            "triggered_by": current_user["username"],
            "results": results
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to add validation columns: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/maintenance/database-status")
async def get_database_status(authorization: str = Header(None)):
    """
    Get detailed database status showing soft-deleted entities
    Helps identify database bloat from bulk import tests
    """
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        # Only super_admin can access maintenance endpoints
        # Check both user.role field and user_roles table
        is_super_admin = False
        
        # Check direct role field
        if current_user.get("role") == "super_admin":
            is_super_admin = True
        
        # Check user_roles table (JOIN with roles)
        if not is_super_admin:
            conn_check = await get_database_connection()
            try:
                role_check = await conn_check.fetchval("""
                    SELECT COUNT(*) 
                    FROM user_roles ur
                    JOIN roles r ON ur.role_id = r.id
                    WHERE ur.user_id = $1 AND r.name = 'super_admin'
                """, current_user["id"])
                if role_check and role_check > 0:
                    is_super_admin = True
            finally:
                await close_database_connection(conn_check)
        
        if not is_super_admin:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: super_admin role required"
            )
        
        conn = await get_database_connection()
        
        # Count active and soft-deleted entities
        status = await conn.fetchrow("""
            SELECT 
                -- Frontends
                (SELECT COUNT(*) FROM frontends WHERE is_active = TRUE) as active_frontends,
                (SELECT COUNT(*) FROM frontends WHERE is_active = FALSE) as deleted_frontends,
                (SELECT COUNT(*) FROM frontends) as total_frontends,
                
                -- Backends
                (SELECT COUNT(*) FROM backends WHERE is_active = TRUE) as active_backends,
                (SELECT COUNT(*) FROM backends WHERE is_active = FALSE) as deleted_backends,
                (SELECT COUNT(*) FROM backends) as total_backends,
                
                -- Backend Servers
                (SELECT COUNT(*) FROM backend_servers WHERE is_active = TRUE) as active_servers,
                (SELECT COUNT(*) FROM backend_servers WHERE is_active = FALSE) as deleted_servers,
                (SELECT COUNT(*) FROM backend_servers) as total_servers,
                
                -- SSL Certificates
                (SELECT COUNT(*) FROM ssl_certificates WHERE is_active = TRUE) as active_ssl,
                (SELECT COUNT(*) FROM ssl_certificates WHERE is_active = FALSE) as deleted_ssl,
                (SELECT COUNT(*) FROM ssl_certificates) as total_ssl,
                
                -- WAF Rules
                (SELECT COUNT(*) FROM waf_rules WHERE is_active = TRUE) as active_waf,
                (SELECT COUNT(*) FROM waf_rules WHERE is_active = FALSE) as deleted_waf,
                (SELECT COUNT(*) FROM waf_rules) as total_waf,
                
                -- Clusters
                (SELECT COUNT(*) FROM haproxy_clusters WHERE is_active = TRUE) as active_clusters,
                (SELECT COUNT(*) FROM haproxy_clusters WHERE is_active = FALSE) as deleted_clusters,
                (SELECT COUNT(*) FROM haproxy_clusters) as total_clusters,
                
                -- Pools
                (SELECT COUNT(*) FROM haproxy_cluster_pools WHERE is_active = TRUE) as active_pools,
                (SELECT COUNT(*) FROM haproxy_cluster_pools WHERE is_active = FALSE) as deleted_pools,
                (SELECT COUNT(*) FROM haproxy_cluster_pools) as total_pools,
                
                -- Config Versions (no is_active flag, count all)
                (SELECT COUNT(*) FROM config_versions) as total_config_versions,
                (SELECT COUNT(*) FROM config_versions WHERE status = 'APPLIED') as applied_config_versions,
                (SELECT COUNT(*) FROM config_versions WHERE status != 'APPLIED') as pending_config_versions
        """)
        
        await close_database_connection(conn)
        
        # Calculate bloat percentages
        def calc_bloat(deleted, total):
            if total == 0:
                return 0
            return round((deleted / total) * 100, 2)
        
        return {
            "database_health": {
                "total_soft_deleted_entities": (
                    status["deleted_frontends"] +
                    status["deleted_backends"] +
                    status["deleted_servers"] +
                    status["deleted_ssl"] +
                    status["deleted_waf"] +
                    status["deleted_clusters"] +
                    status["deleted_pools"]
                ),
                "cleanup_recommended": (
                    status["deleted_frontends"] > 10 or
                    status["deleted_backends"] > 10 or
                    status["deleted_servers"] > 20
                )
            },
            "frontends": {
                "active": status["active_frontends"],
                "deleted": status["deleted_frontends"],
                "total": status["total_frontends"],
                "bloat_percentage": calc_bloat(status["deleted_frontends"], status["total_frontends"])
            },
            "backends": {
                "active": status["active_backends"],
                "deleted": status["deleted_backends"],
                "total": status["total_backends"],
                "bloat_percentage": calc_bloat(status["deleted_backends"], status["total_backends"])
            },
            "servers": {
                "active": status["active_servers"],
                "deleted": status["deleted_servers"],
                "total": status["total_servers"],
                "bloat_percentage": calc_bloat(status["deleted_servers"], status["total_servers"])
            },
            "ssl_certificates": {
                "active": status["active_ssl"],
                "deleted": status["deleted_ssl"],
                "total": status["total_ssl"],
                "bloat_percentage": calc_bloat(status["deleted_ssl"], status["total_ssl"])
            },
            "waf_rules": {
                "active": status["active_waf"],
                "deleted": status["deleted_waf"],
                "total": status["total_waf"],
                "bloat_percentage": calc_bloat(status["deleted_waf"], status["total_waf"])
            },
            "clusters": {
                "active": status["active_clusters"],
                "deleted": status["deleted_clusters"],
                "total": status["total_clusters"],
                "bloat_percentage": calc_bloat(status["deleted_clusters"], status["total_clusters"])
            },
            "pools": {
                "active": status["active_pools"],
                "deleted": status["deleted_pools"],
                "total": status["total_pools"],
                "bloat_percentage": calc_bloat(status["deleted_pools"], status["total_pools"])
            },
            "config_versions": {
                "total": status["total_config_versions"],
                "applied": status["applied_config_versions"],
                "pending": status["pending_config_versions"]
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database status check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/maintenance/cleanup-soft-deleted", summary="Cleanup Soft Deleted", response_description="Cleanup completed")
async def cleanup_soft_deleted_entities(
    dry_run: bool = True,
    authorization: str = Header(None)
) -> Dict[str, Any]:
    """
    Permanently delete all soft-deleted entities from database
    
    Parameters:
    - dry_run: If True, only show what would be deleted without actually deleting
    
    WARNING: This action is irreversible! Permanently deletes all is_active=FALSE records.
    """
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        # Only super_admin can perform cleanup
        # Check both user.role field and user_roles table
        is_super_admin = False
        
        # Check direct role field
        if current_user.get("role") == "super_admin":
            is_super_admin = True
        
        # Check user_roles table (JOIN with roles)
        if not is_super_admin:
            conn_check = await get_database_connection()
            try:
                role_check = await conn_check.fetchval("""
                    SELECT COUNT(*) 
                    FROM user_roles ur
                    JOIN roles r ON ur.role_id = r.id
                    WHERE ur.user_id = $1 AND r.name = 'super_admin'
                """, current_user["id"])
                if role_check and role_check > 0:
                    is_super_admin = True
            finally:
                await close_database_connection(conn_check)
        
        if not is_super_admin:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: super_admin role required"
            )
        
        conn = await get_database_connection()
        
        # Count what will be deleted
        counts_before = await conn.fetchrow("""
            SELECT 
                (SELECT COUNT(*) FROM frontends WHERE is_active = FALSE) as deleted_frontends,
                (SELECT COUNT(*) FROM backends WHERE is_active = FALSE) as deleted_backends,
                (SELECT COUNT(*) FROM backend_servers WHERE is_active = FALSE) as deleted_servers,
                (SELECT COUNT(*) FROM ssl_certificates WHERE is_active = FALSE) as deleted_ssl,
                (SELECT COUNT(*) FROM waf_rules WHERE is_active = FALSE) as deleted_waf,
                (SELECT COUNT(*) FROM haproxy_clusters WHERE is_active = FALSE) as deleted_clusters,
                (SELECT COUNT(*) FROM haproxy_cluster_pools WHERE is_active = FALSE) as deleted_pools
        """)
        
        result = {
            "dry_run": dry_run,
            "entities_to_delete": {
                "frontends": counts_before["deleted_frontends"],
                "backends": counts_before["deleted_backends"],
                "servers": counts_before["deleted_servers"],
                "ssl_certificates": counts_before["deleted_ssl"],
                "waf_rules": counts_before["deleted_waf"],
                "clusters": counts_before["deleted_clusters"],
                "pools": counts_before["deleted_pools"]
            },
            "total_entities": sum([
                counts_before["deleted_frontends"],
                counts_before["deleted_backends"],
                counts_before["deleted_servers"],
                counts_before["deleted_ssl"],
                counts_before["deleted_waf"],
                counts_before["deleted_clusters"],
                counts_before["deleted_pools"]
            ])
        }
        
        if not dry_run:
            # CRITICAL: Permanently delete soft-deleted entities
            # Order is important due to foreign key constraints
            
            # 1. Delete backend servers first (dependent on backends)
            await conn.execute("DELETE FROM backend_servers WHERE is_active = FALSE")
            
            # 2. Delete frontends (may reference backends, but FK is nullable)
            await conn.execute("DELETE FROM frontends WHERE is_active = FALSE")
            
            # 3. Delete backends
            await conn.execute("DELETE FROM backends WHERE is_active = FALSE")
            
            # 4. Delete SSL certificates
            await conn.execute("DELETE FROM ssl_certificates WHERE is_active = FALSE")
            
            # 5. Delete WAF rules
            await conn.execute("DELETE FROM waf_rules WHERE is_active = FALSE")
            
            # 6. Delete clusters (careful with FK dependencies)
            await conn.execute("DELETE FROM haproxy_clusters WHERE is_active = FALSE")
            
            # 7. Delete pools (careful with FK dependencies)
            await conn.execute("DELETE FROM haproxy_cluster_pools WHERE is_active = FALSE")
            
            result["status"] = "completed"
            result["message"] = f"Successfully deleted {result['total_entities']} soft-deleted entities from database"
            
            logger.warning(f"🗑️  CLEANUP: User {current_user['username']} permanently deleted {result['total_entities']} soft-deleted entities")
        else:
            result["status"] = "dry_run"
            result["message"] = f"DRY RUN: Would delete {result['total_entities']} soft-deleted entities. Call with dry_run=false to execute."
        
        await close_database_connection(conn)
        
        return result
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/maintenance/cleanup-old-config-versions")
async def cleanup_old_config_versions(
    keep_last_n: int = 10,
    dry_run: bool = True,
    authorization: str = Header(None)
) -> Dict[str, Any]:
    """
    Clean up old HAProxy configuration versions to reduce database size
    Keeps the most recent N versions per cluster
    
    Parameters:
    - keep_last_n: Number of most recent versions to keep per cluster (default: 10)
    - dry_run: If True, only show what would be deleted
    
    WARNING: Old versions cannot be recovered after deletion!
    """
    try:
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        # Only super_admin can perform cleanup
        # Check both user.role field and user_roles table
        is_super_admin = False
        
        # Check direct role field
        if current_user.get("role") == "super_admin":
            is_super_admin = True
        
        # Check user_roles table (JOIN with roles)
        if not is_super_admin:
            conn_check = await get_database_connection()
            try:
                role_check = await conn_check.fetchval("""
                    SELECT COUNT(*) 
                    FROM user_roles ur
                    JOIN roles r ON ur.role_id = r.id
                    WHERE ur.user_id = $1 AND r.name = 'super_admin'
                """, current_user["id"])
                if role_check and role_check > 0:
                    is_super_admin = True
            finally:
                await close_database_connection(conn_check)
        
        if not is_super_admin:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: super_admin role required"
            )
        
        conn = await get_database_connection()
        
        # Find old versions to delete (keep most recent N per cluster)
        old_versions = await conn.fetch("""
            WITH ranked_versions AS (
                SELECT 
                    id,
                    cluster_id,
                    version_name,
                    created_at,
                    ROW_NUMBER() OVER (PARTITION BY cluster_id ORDER BY created_at DESC) as row_num
                FROM config_versions
            )
            SELECT id, cluster_id, version_name, created_at
            FROM ranked_versions
            WHERE row_num > $1
            ORDER BY cluster_id, created_at DESC
        """, keep_last_n)
        
        version_ids = [v["id"] for v in old_versions]
        
        result = {
            "dry_run": dry_run,
            "keep_last_n_per_cluster": keep_last_n,
            "versions_to_delete": len(version_ids),
            "old_versions_details": [
                {
                    "id": v["id"],
                    "cluster_id": v["cluster_id"],
                    "version_name": v["version_name"],
                    "created_at": v["created_at"].isoformat() if v["created_at"] else None
                }
                for v in old_versions[:20]  # Show first 20 for preview
            ]
        }
        
        if not dry_run and version_ids:
            # Delete old versions
            deleted_count = await conn.execute(
                "DELETE FROM config_versions WHERE id = ANY($1)",
                version_ids
            )
            
            result["status"] = "completed"
            result["message"] = f"Successfully deleted {len(version_ids)} old configuration versions"
            
            logger.warning(f"🗑️  CLEANUP: User {current_user['username']} deleted {len(version_ids)} old config versions (kept last {keep_last_n} per cluster)")
        else:
            result["status"] = "dry_run"
            result["message"] = f"DRY RUN: Would delete {len(version_ids)} old versions. Call with dry_run=false to execute."
        
        await close_database_connection(conn)
        
        return result
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Config version cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/maintenance/fix-stuck-agent-upgrades")
async def fix_stuck_agent_upgrades(authorization: str = Header(None)):
    """
    Manual fix for agents stuck in 'upgrading' status.
    
    This endpoint fixes the issue where:
    - Agent status = 'upgrading' but upgrade_status = NULL
    - This creates a deadlock where heartbeat expects version change
    - But cleanup job has already reset upgrade_status
    
    ROOT CAUSE:
    1. Cleanup job resets upgrade_status but not status column
    2. Heartbeat endpoint sees status='upgrading' and waits for version change
    3. Version doesn't change, so status stays 'upgrading'
    4. Infinite loop!
    
    FIX:
    - Reset status='online' for agents where status='upgrading' but upgrade_status is NULL
    """
    try:
        # Permission check
        from utils.auth import verify_token
        current_user = verify_token(authorization)
        if not current_user:
            raise HTTPException(status_code=401, detail="Invalid authorization token")
        
        # Check if user has admin permissions
        if current_user.get("role") != "admin":
            raise HTTPException(
                status_code=403, 
                detail="Only admin users can manually fix stuck agent upgrades"
            )
        
        conn = await get_database_connection()
        
        # Find stuck agents
        stuck_agents = await conn.fetch("""
            SELECT id, name, status, upgrade_status, version, last_seen
            FROM agents 
            WHERE status = 'upgrading' 
            AND (upgrade_status IS NULL OR upgrade_status != 'upgrading')
        """)
        
        if not stuck_agents:
            await close_database_connection(conn)
            return {
                "status": "success",
                "message": "No stuck agents found",
                "fixed_count": 0,
                "agents": []
            }
        
        # Fix stuck agents
        result = await conn.execute("""
            UPDATE agents 
            SET status = 'online',
                upgrade_status = NULL,
                upgrade_target_version = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE status = 'upgrading' 
            AND (upgrade_status IS NULL OR upgrade_status != 'upgrading')
        """)
        
        fixed_agents = [
            {
                "id": agent["id"],
                "name": agent["name"],
                "previous_status": agent["status"],
                "previous_upgrade_status": agent["upgrade_status"],
                "version": agent["version"],
                "last_seen": agent["last_seen"].isoformat() if agent["last_seen"] else None
            }
            for agent in stuck_agents
        ]
        
        await close_database_connection(conn)
        
        logger.info(f"User {current_user['username']} manually fixed {len(stuck_agents)} stuck agent(s)")
        
        return {
            "status": "success",
            "message": f"Fixed {len(stuck_agents)} stuck agent(s)",
            "fixed_count": len(stuck_agents),
            "agents": fixed_agents,
            "triggered_by": current_user["username"]
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fix stuck agents: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

