from fastapi import APIRouter, HTTPException, Request, Header, Depends
from typing import List, Optional
import logging
import hashlib
import time
import json
from datetime import datetime, timezone

# Import database and models
from database.connection import get_database_connection, close_database_connection
from auth_middleware import get_current_user_from_token
from models.ssl import SSLCertificate, SSLCertificateCreate, SSLCertificateUpdate, SSLCertificateResponse
from utils.ssl_parser import parse_ssl_certificate, validate_private_key, validate_certificate_chain, format_certificate_info
from utils.activity_log import log_user_activity
from services.haproxy_config import generate_haproxy_config_for_cluster

router = APIRouter(prefix="/api/ssl", tags=["SSL Certificates"])
logger = logging.getLogger(__name__)

async def validate_user_cluster_access(user_id: int, cluster_id: int, conn):
    """Validate that user has access to the specified cluster"""
    # Check if cluster exists
    cluster_exists = await conn.fetchval("""
        SELECT id FROM haproxy_clusters WHERE id = $1
    """, cluster_id)
    
    if not cluster_exists:
        raise HTTPException(
            status_code=404, 
            detail="Cluster not found"
        )
    
    # Check if user is admin - admins can access everything
    is_admin = await conn.fetchval("""
        SELECT is_admin FROM users WHERE id = $1
    """, user_id)
    
    if is_admin:
        logger.info(f"Admin user {user_id} granted access to cluster {cluster_id}")
        return True
    
    # Check if user_pool_access table exists (for backward compatibility)
    table_exists = await conn.fetchval("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_name = 'user_pool_access'
        )
    """)
    
    if not table_exists:
        # Fallback to basic validation if table doesn't exist yet
        logger.warning("user_pool_access table not found, using basic cluster validation")
        return True
    
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
        """, user_id, cluster_id)
    else:
        # Fallback query without expires_at column
        user_access = await conn.fetchrow("""
            SELECT upa.access_level, hc.id, hc.name
            FROM haproxy_clusters hc
            JOIN haproxy_cluster_pools hcp ON hc.pool_id = hcp.id
            JOIN user_pool_access upa ON hcp.id = upa.pool_id
            WHERE upa.user_id = $1 AND hc.id = $2 AND upa.is_active = TRUE
        """, user_id, cluster_id)
    
    if not user_access:
        raise HTTPException(
            status_code=403, 
            detail="You don't have access to this cluster. Please contact your administrator."
        )
    
    logger.info(f"User {user_id} granted {user_access['access_level']} access to cluster {cluster_id}")
    return True

@router.get("/certificates", response_model=List[dict], summary="Get SSL Certificates", response_description="List of SSL certificates")
async def get_ssl_certificates(cluster_id: Optional[int] = None, usage_type: Optional[str] = None):
    """
    # Get SSL Certificates
    
    Retrieve all SSL/TLS certificates with validity information.
    
    ## Query Parameters
    - **cluster_id** (optional): Filter by cluster
    
    ## Example Request
    ```bash
    curl -X GET "{BASE_URL}/api/ssl/certificates?cluster_id=1" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Response
    ```json
    [
      {
        "id": 1,
        "name": "example.com-cert",
        "common_name": "*.example.com",
        "domains": ["example.com", "*.example.com"],
        "issuer": "Let's Encrypt",
        "valid_from": "2024-01-01T00:00:00Z",
        "valid_until": "2024-12-31T23:59:59Z",
        "cluster_ids": [1, 2]
      }
    ]
    ```
    """
    try:
        conn = await get_database_connection()
        
        # First check if ssl_certificates table exists
        try:
            table_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_name = 'ssl_certificates'
                )
            """)
            
            if not table_exists:
                await close_database_connection(conn)
                logger.info("SSL certificates table does not exist yet - returning empty list")
                return []
            
            # Query with new schema fields - show cluster-specific + global SSLs
            if cluster_id:
                # Build WHERE clause with optional usage_type filter
                where_clauses = ["s.is_active = TRUE"]
                where_clauses.append("""(
                    NOT EXISTS (SELECT 1 FROM ssl_certificate_clusters WHERE ssl_certificate_id = s.id)  -- Global SSLs (no cluster associations)
                    OR scc.cluster_id = $1  -- Cluster-specific SSLs for this cluster
                )""")
                
                params = [cluster_id]
                if usage_type:
                    where_clauses.append(f"s.usage_type = ${len(params) + 1}")
                    params.append(usage_type)
                
                where_clause = " AND ".join(where_clauses)
                
                certificates = await conn.fetch(f"""
                    SELECT DISTINCT s.id, s.name, s.primary_domain as domain, s.expiry_date, s.issuer, s.fingerprint, s.status, 
                           s.days_until_expiry, s.all_domains, s.is_active, s.cluster_id, s.usage_type,
                           s.created_at, s.updated_at,
                           CASE 
                               WHEN NOT EXISTS (SELECT 1 FROM ssl_certificate_clusters WHERE ssl_certificate_id = s.id) THEN 'Global'
                               ELSE 'Cluster-specific'
                           END as ssl_type,
                           COALESCE(
                               array_agg(DISTINCT c.name ORDER BY c.name) FILTER (WHERE c.name IS NOT NULL), 
                               ARRAY[]::text[]
                           ) as cluster_names,
                           -- Get latest config status for SSL-related versions
                           (SELECT cv.status 
                            FROM config_versions cv 
                            WHERE cv.cluster_id = $1 
                            AND cv.version_name LIKE 'ssl-' || s.id || '-%'
                            ORDER BY cv.created_at DESC 
                            LIMIT 1) as last_config_status,
                           -- Check if SSL has pending config changes
                           EXISTS (
                               SELECT 1 FROM config_versions cv2
                               WHERE cv2.cluster_id = $1 
                               AND cv2.version_name LIKE 'ssl-' || s.id || '-%'
                               AND cv2.status = 'PENDING'
                           ) as has_pending_config
                    FROM ssl_certificates s
                    LEFT JOIN ssl_certificate_clusters scc ON s.id = scc.ssl_certificate_id
                    LEFT JOIN haproxy_clusters c ON scc.cluster_id = c.id
                    WHERE {where_clause}
                    GROUP BY s.id, s.name, s.primary_domain, s.expiry_date, s.issuer, s.fingerprint, s.status, 
                             s.days_until_expiry, s.all_domains, s.is_active, s.cluster_id, s.usage_type, s.created_at, s.updated_at
                    ORDER BY s.created_at DESC
                """, *params)
            else:
                # Build WHERE clause with optional usage_type filter
                where_clauses = ["is_active = TRUE"]
                params = []
                
                if usage_type:
                    where_clauses.append(f"usage_type = ${len(params) + 1}")
                    params.append(usage_type)
                
                where_clause = " AND ".join(where_clauses)
                
                certificates = await conn.fetch(f"""
                    SELECT id, name, domain, expiry_date, issuer, fingerprint, status, 
                           days_until_expiry, all_domains, is_active, cluster_id, usage_type,
                           created_at, updated_at
                    FROM ssl_certificates
                    WHERE {where_clause}
                    ORDER BY created_at DESC
                """, *params)
            
            await close_database_connection(conn)
            
            # Convert to list of dicts with new schema fields
            result = []
            for cert in certificates:
                # Parse all_domains JSON safely
                all_domains = []
                try:
                    if cert.get('all_domains'):
                        all_domains = json.loads(cert['all_domains']) if isinstance(cert['all_domains'], str) else cert['all_domains']
                except (json.JSONDecodeError, TypeError):
                    all_domains = [cert['domain']] if cert['domain'] else []
                
                # Debug expiry information
                logger.info(f"📅 SSL {cert['name']}: expiry_date={cert['expiry_date']}, status={cert.get('status')}, days_until_expiry={cert.get('days_until_expiry')}")
                
                cert_dict = {
                    'id': cert['id'],
                    'name': cert['name'],
                    'domain': cert['domain'],
                    'all_domains': all_domains,
                    'expiry_date': cert['expiry_date'].isoformat().replace('+00:00', 'Z') if cert['expiry_date'] else None,
                    'issuer': cert.get('issuer'),
                    'fingerprint': cert.get('fingerprint'),
                    'status': cert.get('status', 'valid'),
                    'days_until_expiry': cert.get('days_until_expiry', 0),
                    'cluster_id': cert['cluster_id'],
                    'usage_type': cert.get('usage_type', 'frontend'),
                    'ssl_type': cert.get('ssl_type', 'Global' if cert['cluster_id'] is None else 'Cluster-specific'),
                    'cluster_names': cert.get('cluster_names', []),
                    'created_at': cert['created_at'].isoformat().replace('+00:00', 'Z') if cert['created_at'] else None,
                    'updated_at': cert['updated_at'].isoformat().replace('+00:00', 'Z') if cert['updated_at'] else None,
                    'last_config_status': cert.get('last_config_status'),
                    'has_pending_config': cert.get('has_pending_config', False)
                }
                result.append(cert_dict)
            
            return result
            
        except Exception as table_error:
            logger.warning(f"Error checking/querying SSL certificates table: {table_error}")
            await close_database_connection(conn)
            return []  # Return empty list if table doesn't exist or has issues
        
    except Exception as e:
        logger.error(f"Error fetching SSL certificates: {e}")
        try:
            await close_database_connection(conn)
        except:
            pass
        # Return empty list instead of error to prevent frontend crashes
        return []

@router.post("/certificates")
async def create_ssl_certificate(certificate: SSLCertificateCreate, request: Request, authorization: str = Header(None)):
    """Create new SSL certificate with automatic domain and expiry parsing"""
    try:
        # Get current user for activity logging
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for SSL create
        has_permission = await check_user_permission(current_user["id"], "ssl", "create")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: ssl.create required"
            )
        
        conn = await get_database_connection()
        
        # Validate cluster access for multi-cluster security
        if certificate.cluster_ids:
            for cluster_id in certificate.cluster_ids:
                await validate_user_cluster_access(current_user['id'], cluster_id, conn)
        
        # Parse SSL certificate to extract domain and expiry information
        logger.info(f"SSL CREATE: Parsing certificate content for '{certificate.name}'")
        try:
            cert_info = parse_ssl_certificate(certificate.certificate_content)
            
            if cert_info.get("error"):
                await close_database_connection(conn)
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid SSL certificate: {cert_info['error']}"
                )
        except Exception as parse_error:
            logger.error(f"SSL parsing failed: {parse_error}")
            await close_database_connection(conn)
            raise HTTPException(
                status_code=400, 
                detail=f"SSL certificate parsing error: {str(parse_error)}"
            )
        
        # Validate private key (only if provided - server SSL may not have private key)
        if certificate.private_key_content and not validate_private_key(certificate.private_key_content):
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Invalid private key format")
        
        # Validate certificate chain (if provided)
        if certificate.chain_content and not validate_certificate_chain(certificate.chain_content):
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail="Invalid certificate chain format")
        
        # Check if certificate name already exists (including soft-deleted ones)
        # SSL names must be globally unique to prevent conflicts
        if certificate.is_global:
            # For global certificates, check if name already exists globally (including soft-deleted)
            existing = await conn.fetchrow("""
                SELECT id, is_active FROM ssl_certificates 
                WHERE name = $1 AND cluster_id IS NULL
            """, certificate.name)
        else:
            # For cluster-specific certificates, check if name already exists in any of the target clusters
            existing = None
            if certificate.cluster_ids:
                for cluster_id in certificate.cluster_ids:
                    cluster_existing = await conn.fetchrow("""
                        SELECT s.id, s.is_active FROM ssl_certificates s
                        LEFT JOIN ssl_certificate_clusters scc ON s.id = scc.ssl_certificate_id
                        WHERE s.name = $1 AND (s.cluster_id = $2 OR scc.cluster_id = $2)
                    """, certificate.name, cluster_id)
                    if cluster_existing:
                        existing = cluster_existing
                        break
        if existing:
            if existing['is_active']:
                # Active certificate with same name exists
                await close_database_connection(conn)
                raise HTTPException(
                    status_code=400, 
                    detail=f"SSL certificate with name '{certificate.name}' already exists. Please choose a different name or delete the existing certificate first."
                )
            else:
                # Soft-deleted certificate exists - reactivate it instead of creating new one
                logger.info(f"SSL REACTIVATE: Found soft-deleted SSL '{certificate.name}', reactivating instead of creating new")
                
                # Update the existing soft-deleted certificate with new content
                await conn.execute("""
                    UPDATE ssl_certificates 
                    SET is_active = TRUE, 
                        last_config_status = 'PENDING',
                        certificate_content = $2,
                        private_key_content = $3,
                        chain_content = $4,
                        primary_domain = $5,
                        all_domains = $6,
                        expiry_date = $7,
                        usage_type = $8,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $1
                """, existing['id'], certificate.certificate_content, certificate.private_key_content,
                    certificate.chain_content, primary_domain, all_domains, expiry_date, certificate.usage_type)
                
                cert_id = existing['id']
                logger.info(f"SSL REACTIVATED: SSL certificate '{certificate.name}' (ID: {cert_id}) reactivated successfully")
                
                # Continue with the rest of the creation logic (cluster associations, config versions, etc.)
                # Skip the INSERT part since we're reusing existing certificate
        
        # Extract parsed information
        primary_domain = cert_info["primary_domain"]
        all_domains = cert_info["all_domains"]
        expiry_date = cert_info["expiry_date"]
        
        # Ensure expiry_date is timezone-aware for database insertion
        if expiry_date:
            try:
                if expiry_date.tzinfo is None:
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                    logger.info(f"SSL CREATE: Fixed timezone for expiry_date: {expiry_date}")
                else:
                    # Convert to UTC if it has different timezone
                    expiry_date = expiry_date.astimezone(timezone.utc)
                    logger.info(f"SSL CREATE: Converted expiry_date to UTC: {expiry_date}")
            except Exception as tz_error:
                logger.error(f"Timezone conversion failed: {tz_error}")
                # Fallback: set to None if timezone conversion fails
                expiry_date = None
                logger.warning("🚨 SSL CREATE: Using NULL expiry_date due to timezone error")
        
        issuer = cert_info["issuer"]
        status = cert_info["status"]
        fingerprint = cert_info["fingerprint"]
        
        # Recalculate days_until_expiry safely in SSL router
        if expiry_date:
            try:
                now = datetime.now(timezone.utc)
                days_until_expiry = (expiry_date - now).days
                
                # Recalculate status based on days
                if days_until_expiry < 0:
                    status = "expired"
                elif days_until_expiry < 30:
                    status = "expiring_soon"
                else:
                    status = "valid"
                    
                logger.info(f"SSL CREATE: Recalculated days_until_expiry={days_until_expiry}, status={status}")
            except Exception as calc_error:
                logger.error(f"Days calculation failed: {calc_error}")
                days_until_expiry = cert_info.get("days_until_expiry", 0)
        else:
            days_until_expiry = cert_info.get("days_until_expiry", 0)
        
        # Convert timezone-aware datetime to timezone-naive UTC for database insertion
        if expiry_date and hasattr(expiry_date, 'tzinfo') and expiry_date.tzinfo is not None:
            # Convert timezone-aware datetime to UTC and then make it naive
            expiry_date_utc = expiry_date.astimezone(timezone.utc).replace(tzinfo=None)
            logger.info(f"SSL CREATE: Converted timezone-aware {expiry_date} to timezone-naive UTC {expiry_date_utc}")
            expiry_date = expiry_date_utc
        
        # Debug all values before database insertion
        # Only insert if not reactivating existing certificate
        if not existing or existing['is_active']:
            logger.info(f"SSL CREATE: About to insert - expiry_date={expiry_date}, type={type(expiry_date)}")
            logger.info(f"SSL CREATE: About to insert - days_until_expiry={days_until_expiry}, status={status}")
            
            # Insert new SSL certificate with parsed information
            cert_id = await conn.fetchval("""
                INSERT INTO ssl_certificates 
                (name, primary_domain, certificate_content, private_key_content, chain_content, 
                 expiry_date, issuer, fingerprint, status, days_until_expiry, all_domains,
                 is_active, cluster_id, last_config_status, usage_type)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                RETURNING id
            """, certificate.name, primary_domain, certificate.certificate_content, 
                certificate.private_key_content, certificate.chain_content, expiry_date,
                issuer, fingerprint, status, days_until_expiry, json.dumps(all_domains),
                True, None, 'PENDING', certificate.usage_type)  # Always NULL for cluster_id, use junction table
        
        # If not global, insert cluster associations in junction table
        if not certificate.is_global and certificate.cluster_ids:
            for cluster_id in certificate.cluster_ids:
                await conn.execute("""
                    INSERT INTO ssl_certificate_clusters (ssl_certificate_id, cluster_id)
                    VALUES ($1, $2)
                """, cert_id, cluster_id)
        
        # Create config versions for affected clusters
        sync_results = []
        
        if certificate.is_global:
            # For global SSL certificates, create PENDING versions for ALL active clusters
            affected_clusters = await conn.fetch("SELECT id FROM haproxy_clusters WHERE is_active = TRUE")
            affected_clusters = [cluster['id'] for cluster in affected_clusters]
            logger.info(f"GLOBAL SSL: Creating PENDING versions for {len(affected_clusters)} clusters")
        else:
            # For cluster-specific SSL certificates
            affected_clusters = certificate.cluster_ids or []
            logger.info(f"CLUSTER SSL: Creating PENDING versions for specific clusters: {affected_clusters}")
        
        for cluster_id in affected_clusters:
            try:
                # Generate new HAProxy config
                config_content = await generate_haproxy_config_for_cluster(cluster_id)
                logger.info(f"SSL CONFIG DEBUG: Generated config for cluster {cluster_id}, length: {len(config_content)} chars")
                logger.info(f"SSL CONFIG DEBUG: First 500 chars: {config_content[:500]}")
                
                # Check if SSL is actually used in any frontends for this cluster
                ssl_frontends = await conn.fetch("""
                    SELECT name, ssl_enabled, ssl_certificate_id 
                    FROM frontends 
                    WHERE cluster_id = $1 AND is_active = TRUE AND ssl_enabled = TRUE
                """, cluster_id)
                
                logger.info(f"SSL CONFIG DEBUG: Found {len(ssl_frontends)} SSL-enabled frontends in cluster {cluster_id}")
                for fe in ssl_frontends:
                    logger.info(f"SSL CONFIG DEBUG: Frontend '{fe['name']}' - ssl_enabled: {fe['ssl_enabled']}, ssl_certificate_id: {fe['ssl_certificate_id']}")
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"ssl-{cert_id}-create-{int(time.time())}"
                logger.info(f"SSL CONFIG DEBUG: Creating version '{version_name}' with hash {config_hash[:8]}...")
                
                # Also log if this SSL certificate will be used
                ssl_usage = await conn.fetch("""
                    SELECT f.name as frontend_name, f.ssl_enabled, f.ssl_certificate_id
                    FROM frontends f
                    WHERE f.cluster_id = $1 AND f.is_active = TRUE 
                    AND (f.ssl_certificate_id = $2 OR ($3 = TRUE))
                """, cluster_id, cert_id, certificate.is_global)
                
                logger.info(f"SSL CONFIG DEBUG: This SSL certificate will be used by {len(ssl_usage)} frontends:")
                for usage in ssl_usage:
                    logger.info(f"SSL CONFIG DEBUG: - Frontend '{usage['frontend_name']}' (ssl_enabled: {usage['ssl_enabled']}, cert_id: {usage['ssl_certificate_id']})")
                
                # Get system admin user ID for created_by
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Try with status field first, fallback to old behavior if field doesn't exist
                try:
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                        VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                        RETURNING id
                    """, cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {cluster_id}")
                    
                    # Don't notify agents yet - wait for manual Apply
                    sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'SSL certificate created. Click Apply to activate.'}]
                    
                except Exception as status_error:
                    logger.warning(f"FALLBACK: Status field not available, using old immediate-apply behavior: {status_error}")
                    # Fallback to old behavior without status field
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active)
                        VALUES ($1, $2, $3, $4, $5, TRUE)
                        RETURNING id
                    """, certificate.cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    # Deactivate previous versions for this cluster
                    await conn.execute("""
                        UPDATE config_versions 
                        SET is_active = FALSE 
                        WHERE cluster_id = $1 AND id != $2
                    """, certificate.cluster_id, config_version_id)
                    
                    sync_results = [{'node': f'cluster-{certificate.cluster_id}', 'success': True, 'version': version_name, 'message': 'SSL certificate created immediately (fallback mode)'}]
                    logger.info(f"FALLBACK: Using immediate-apply, agents notified")
                
            except Exception as e:
                logger.error(f"Cluster config update failed for SSL certificate {certificate.name}: {e}")
                # Still return success for database save, but with sync warning
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='create',
                resource_type='ssl_certificate',
                resource_id=str(cert_id),
                details={
                    'certificate_name': certificate.name,
                    'domain': cert_info.get('primary_domain', 'unknown'),
                    'is_global': certificate.is_global,
                    'cluster_ids': certificate.cluster_ids,
                    'sync_results': len(sync_results)
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        return {
            "message": f"SSL certificate '{certificate.name}' created successfully",
            "certificate_id": cert_id,
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating SSL certificate: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/certificates/{cert_id}")
async def get_ssl_certificate(cert_id: int, authorization: str = Header(None)):
    """Get specific SSL certificate details"""
    try:
        # Get current user for authentication
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get certificate details with cluster associations
        certificate = await conn.fetchrow("""
            SELECT s.id, s.name, s.primary_domain as domain, s.all_domains, s.certificate_content, 
                   s.private_key_content, s.chain_content, s.expiry_date, s.issuer, s.status, 
                   s.days_until_expiry, s.fingerprint, s.cluster_id, s.usage_type, s.created_at, s.updated_at,
                   CASE 
                       WHEN NOT EXISTS (SELECT 1 FROM ssl_certificate_clusters WHERE ssl_certificate_id = s.id) THEN TRUE
                       ELSE FALSE
                   END as is_global,
                   COALESCE(
                       array_agg(DISTINCT scc.cluster_id ORDER BY scc.cluster_id) FILTER (WHERE scc.cluster_id IS NOT NULL), 
                       ARRAY[]::int[]
                   ) as cluster_ids
            FROM ssl_certificates s
            LEFT JOIN ssl_certificate_clusters scc ON s.id = scc.ssl_certificate_id
            WHERE s.id = $1
            GROUP BY s.id, s.name, s.primary_domain, s.all_domains, s.certificate_content, 
                     s.private_key_content, s.chain_content, s.expiry_date, s.issuer, s.status, 
                     s.days_until_expiry, s.fingerprint, s.cluster_id, s.usage_type, s.created_at, s.updated_at
        """, cert_id)
        
        if not certificate:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="SSL certificate not found")
        
        # Validate user access to cluster
        if certificate['cluster_id']:
            await validate_user_cluster_access(current_user['id'], certificate['cluster_id'], conn)
        
        # For now, assume no pending changes (SSL config versions need separate implementation)
        pending_versions = 0
        
        await close_database_connection(conn)
        
        # Convert record to dict and handle JSON fields safely
        cert_dict = dict(certificate)
        
        # Parse all_domains JSON safely
        if cert_dict.get('all_domains'):
            try:
                if isinstance(cert_dict['all_domains'], str):
                    cert_dict['all_domains'] = json.loads(cert_dict['all_domains'])
            except (json.JSONDecodeError, TypeError):
                cert_dict['all_domains'] = []
        else:
            cert_dict['all_domains'] = []
        
        cert_dict['has_pending_config'] = pending_versions > 0
        
        return cert_dict
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting SSL certificate: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/certificates/{cert_id}/config-versions")
async def get_ssl_certificate_config_versions(cert_id: int):
    """Get config version history for specific SSL certificate"""
    try:
        conn = await get_database_connection()
        
        # Get certificate info first
        certificate = await conn.fetchrow("SELECT name, cluster_id FROM ssl_certificates WHERE id = $1", cert_id)
        if not certificate:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="SSL certificate not found")
        
        # Get all APPLIED config versions that are related to this SSL certificate
        versions = await conn.fetch("""
            SELECT cv.id, cv.version_name, cv.description, cv.status, cv.is_active,
                   cv.created_at, cv.file_size, cv.checksum,
                   u.username as created_by_username
            FROM config_versions cv
            LEFT JOIN users u ON cv.created_by = u.id
            WHERE cv.cluster_id = $1 AND cv.status = 'APPLIED'
            AND cv.version_name ~ $2
            ORDER BY cv.created_at DESC
        """, certificate['cluster_id'], f"ssl-{cert_id}-")
        
        await close_database_connection(conn)
        
        # Convert to list of dicts
        result = []
        for version in versions:
            version_dict = dict(version)
            version_dict['created_at'] = version['created_at'].isoformat().replace('+00:00', 'Z') if version['created_at'] else None
            result.append(version_dict)
        
        return {
            "certificate_name": certificate['name'],
            "cluster_id": certificate['cluster_id'],
            "versions": result
        }
        
    except Exception as e:
        logger.error(f"Error fetching SSL certificate config versions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/certificates/{cert_id}")
async def update_ssl_certificate(cert_id: int, certificate: SSLCertificateUpdate, request: Request, authorization: str = Header(None)):
    """Update existing SSL certificate with content parsing and multi-cluster support"""
    try:
        # Get current user for activity logging
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for SSL update
        has_permission = await check_user_permission(current_user["id"], "ssl", "update")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: ssl.update required"
            )
        
        conn = await get_database_connection()
        
        # PHASE 2: Get FULL SSL certificate record for snapshot (ALL fields)
        # CRITICAL: Use SELECT * to capture all fields for rollback
        existing = await conn.fetchrow("""
            SELECT * FROM ssl_certificates WHERE id = $1
        """, cert_id)
        
        # Also check if certificate is global (for logging)
        is_global = await conn.fetchval("""
            SELECT NOT EXISTS (SELECT 1 FROM ssl_certificate_clusters WHERE ssl_certificate_id = $1)
        """, cert_id)
        
        if not existing:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="SSL certificate not found")
        
        logger.info(f"SSL UPDATE: Updating certificate '{existing['name']}' (ID: {cert_id}, is_global: {is_global})")
        
        # Validate cluster access for multi-cluster security
        cluster_id = existing['cluster_id'] or certificate.cluster_id
        if cluster_id:
            await validate_user_cluster_access(current_user['id'], cluster_id, conn)
        
        # Track if content is being updated (important for parsing and agent sync)
        content_updated = False
        
        # Parse certificate if content is being updated
        cert_info = None
        if certificate.certificate_content or certificate.private_key_content:
            content_updated = True
            logger.info(f"SSL UPDATE: Content update detected, will parse certificate")
            
            # Use new content if provided, otherwise use existing
            cert_content = certificate.certificate_content or existing['certificate_content']
            key_content = certificate.private_key_content or existing['private_key_content']
            chain_content = certificate.chain_content if certificate.chain_content is not None else existing['chain_content']
            
            # Parse SSL certificate to extract domain and expiry information
            try:
                cert_info = parse_ssl_certificate(cert_content)
                
                if cert_info.get("error"):
                    await close_database_connection(conn)
                    raise HTTPException(
                        status_code=400, 
                        detail=f"Invalid SSL certificate: {cert_info['error']}"
                    )
                
                logger.info(f"SSL UPDATE: Certificate parsed - domain: {cert_info['primary_domain']}, expiry: {cert_info['expiry_date']}")
            except Exception as parse_error:
                logger.error(f"SSL parsing failed: {parse_error}")
                await close_database_connection(conn)
                raise HTTPException(
                    status_code=400, 
                    detail=f"SSL certificate parsing error: {str(parse_error)}"
                )
            
            # Validate private key (only if provided - server SSL may not have private key)
            if key_content and not validate_private_key(key_content):
                await close_database_connection(conn)
                raise HTTPException(status_code=400, detail="Invalid private key format")
            
            # Validate certificate chain (if provided)
            if chain_content and not validate_certificate_chain(chain_content):
                await close_database_connection(conn)
                raise HTTPException(status_code=400, detail="Invalid certificate chain format")
        
        # Build dynamic update query
        update_fields = []
        update_values = []
        param_count = 1
        
        # SECURITY: SSL certificate name is IMMUTABLE after creation
        # Name is used as filesystem path (/etc/ssl/haproxy/{name}.pem)
        # Changing name would break file system references and HAProxy config
        if certificate.name and certificate.name != existing["name"]:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=400, 
                detail="SSL certificate name cannot be changed after creation. The name is used as file path on agent servers. Only certificate content (certificate, private key, chain) can be updated."
            )
        
        # FIXED: Use correct field names from model
        if certificate.certificate_content:
            update_fields.append(f"certificate_content = ${param_count}")
            update_values.append(certificate.certificate_content)
            param_count += 1
        
        if certificate.private_key_content:
            update_fields.append(f"private_key_content = ${param_count}")
            update_values.append(certificate.private_key_content)
            param_count += 1
        
        if certificate.chain_content is not None:
            update_fields.append(f"chain_content = ${param_count}")
            update_values.append(certificate.chain_content)
            param_count += 1
        
        # If content was updated and parsed, update derived fields
        if cert_info:
            # Extract parsed information
            primary_domain = cert_info["primary_domain"]
            all_domains = cert_info["all_domains"]
            expiry_date = cert_info["expiry_date"]
            issuer = cert_info["issuer"]
            status = cert_info["status"]
            fingerprint = cert_info["fingerprint"]
            
            # Ensure expiry_date is timezone-aware and convert to naive UTC
            if expiry_date:
                try:
                    if expiry_date.tzinfo is None:
                        expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                    expiry_date = expiry_date.astimezone(timezone.utc).replace(tzinfo=None)
                except Exception as tz_error:
                    logger.error(f"Timezone conversion failed: {tz_error}")
                    expiry_date = None
            
            # Recalculate days_until_expiry and status
            if expiry_date:
                try:
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    days_until_expiry = (expiry_date - now).days
                    
                    if days_until_expiry < 0:
                        status = "expired"
                    elif days_until_expiry < 30:
                        status = "expiring_soon"
                    else:
                        status = "valid"
                    
                    logger.info(f"SSL UPDATE: Recalculated days_until_expiry={days_until_expiry}, status={status}")
                except Exception as calc_error:
                    logger.error(f"Days calculation failed: {calc_error}")
                    days_until_expiry = 0
            else:
                days_until_expiry = 0
            
            # Add parsed fields to update
            update_fields.append(f"primary_domain = ${param_count}")
            update_values.append(primary_domain)
            param_count += 1
            
            update_fields.append(f"all_domains = ${param_count}")
            update_values.append(json.dumps(all_domains))
            param_count += 1
            
            update_fields.append(f"expiry_date = ${param_count}")
            update_values.append(expiry_date)
            param_count += 1
            
            update_fields.append(f"issuer = ${param_count}")
            update_values.append(issuer)
            param_count += 1
            
            update_fields.append(f"status = ${param_count}")
            update_values.append(status)
            param_count += 1
            
            update_fields.append(f"fingerprint = ${param_count}")
            update_values.append(fingerprint)
            param_count += 1
            
            update_fields.append(f"days_until_expiry = ${param_count}")
            update_values.append(days_until_expiry)
            param_count += 1
        
        if certificate.cluster_id is not None:
            update_fields.append(f"cluster_id = ${param_count}")
            update_values.append(certificate.cluster_id)
            param_count += 1
        
        if certificate.usage_type is not None:
            update_fields.append(f"usage_type = ${param_count}")
            update_values.append(certificate.usage_type)
            param_count += 1
        
        # CRITICAL: If content was updated, set last_config_status to PENDING
        # This signals agents that they need to fetch the updated SSL certificate
        if content_updated:
            update_fields.append(f"last_config_status = ${param_count}")
            update_values.append('PENDING')
            param_count += 1
            logger.info(f"SSL UPDATE: Setting last_config_status to PENDING for agent sync")
        
        # Always update timestamp (critical for agent incremental sync)
        update_fields.append("updated_at = CURRENT_TIMESTAMP")
        
        if update_fields:
            # Update certificate
            update_values.append(cert_id)
            await conn.execute(f"""
                UPDATE ssl_certificates SET {', '.join(update_fields)}
                WHERE id = ${param_count}
            """, *update_values)
            logger.info(f"SSL UPDATE: Database updated for certificate ID {cert_id}")
        
        # Determine affected clusters for config version creation
        affected_clusters = []
        
        if is_global:
            # For global SSL certificates, update ALL active clusters
            clusters = await conn.fetch("SELECT id FROM haproxy_clusters WHERE is_active = TRUE")
            affected_clusters = [cluster['id'] for cluster in clusters]
            logger.info(f"SSL UPDATE (GLOBAL): Will create config versions for {len(affected_clusters)} clusters")
        else:
            # For cluster-specific SSL certificates, get associated clusters
            clusters = await conn.fetch("""
                SELECT cluster_id FROM ssl_certificate_clusters 
                WHERE ssl_certificate_id = $1
            """, cert_id)
            affected_clusters = [cluster['cluster_id'] for cluster in clusters]
            logger.info(f"SSL UPDATE (CLUSTER): Will create config versions for specific clusters: {affected_clusters}")
        
        # Create config versions for affected clusters (only if content was updated)
        sync_results = []
        if content_updated and affected_clusters:
            logger.info(f"SSL UPDATE: Creating config versions for {len(affected_clusters)} affected clusters")
            
            for cluster_id in affected_clusters:
                try:
                    # Get current active config for diff comparison
                    # First try: Most recent APPLIED config
                    old_config = await conn.fetchrow("""
                        SELECT config_content, version_name, status
                        FROM config_versions 
                        WHERE cluster_id = $1 AND status = 'APPLIED' AND config_content IS NOT NULL
                        ORDER BY created_at DESC 
                        LIMIT 1
                    """, cluster_id)
                    
                    # Fallback: If no APPLIED config, get most recent consolidated config (any status)
                    if not old_config:
                        old_config = await conn.fetchrow("""
                            SELECT config_content, version_name, status
                            FROM config_versions 
                            WHERE cluster_id = $1 
                            AND config_content IS NOT NULL
                            AND version_name LIKE 'apply-consolidated-%'
                            ORDER BY created_at DESC 
                            LIMIT 1
                        """, cluster_id)
                        if old_config:
                            logger.info(f"SSL UPDATE DIFF: No APPLIED config, using most recent consolidated: {old_config['version_name']} (status: {old_config['status']})")
                    
                    old_config_content = old_config['config_content'] if old_config else ""
                    
                    if old_config:
                        logger.info(f"SSL UPDATE DIFF: Captured pre-apply snapshot for cluster {cluster_id}, version: {old_config['version_name']}, length: {len(old_config_content)}")
                    else:
                        logger.warning(f"SSL UPDATE DIFF: No previous config found for cluster {cluster_id}! This is likely the first configuration.")
                    
                    # Generate new HAProxy config
                    config_content = await generate_haproxy_config_for_cluster(cluster_id)
                    
                    # PHASE 2: Create entity snapshot for rollback
                    from utils.entity_snapshot import save_entity_snapshot
                    
                    # Prepare new values (all fields being updated)
                    new_values = {
                        "certificate_content": certificate.certificate_content,
                        "private_key_content": certificate.private_key_content,
                        "chain_content": certificate.chain_content,
                    }
                    # Add parsed fields if content was parsed
                    if cert_info:
                        new_values["primary_domain"] = cert_info["primary_domain"]
                        new_values["all_domains"] = cert_info["all_domains"]
                        new_values["expiry_date"] = cert_info["expiry_date"]
                        new_values["issuer"] = cert_info.get("issuer")
                        new_values["fingerprint"] = cert_info.get("fingerprint")
                        new_values["days_until_expiry"] = cert_info.get("days_until_expiry")
                    
                    entity_snapshot_metadata = await save_entity_snapshot(
                        conn=conn,
                        entity_type="ssl_certificate",
                        entity_id=cert_id,
                        old_values=existing,  # Full record from line 703
                        new_values=new_values,
                        operation="UPDATE"
                    )
                    
                    # Create metadata with old config for diff display + entity snapshot for rollback
                    metadata = {
                        'pre_apply_snapshot': old_config_content,  # For diff viewer
                        **entity_snapshot_metadata  # For rollback
                    }
                    
                    # Create new config version
                    config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                    version_name = f"ssl-{cert_id}-update-{int(time.time())}"
                    
                    # Get system admin user ID for created_by
                    admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                    
                    # Try with status field first, fallback to old behavior if field doesn't exist
                    try:
                        config_version_id = await conn.fetchval("""
                            INSERT INTO config_versions 
                            (cluster_id, version_name, config_content, checksum, created_by, is_active, status, metadata)
                            VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING', $6)
                            RETURNING id
                        """, cluster_id, version_name, config_content, config_hash, admin_user_id, json.dumps(metadata))
                        
                        logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {cluster_id}")
                        sync_results.append({
                            'cluster_id': cluster_id,
                            'node': 'pending', 
                            'success': True, 
                            'version': version_name, 
                            'status': 'PENDING', 
                            'message': 'SSL certificate updated. Click Apply to activate.'
                        })
                        
                    except Exception as status_error:
                        logger.warning(f"FALLBACK: Status field not available for cluster {cluster_id}, using old immediate-apply behavior")
                        # Fallback to old behavior without status field (still save metadata for diff)
                        config_version_id = await conn.fetchval("""
                            INSERT INTO config_versions 
                            (cluster_id, version_name, config_content, checksum, created_by, is_active, metadata)
                            VALUES ($1, $2, $3, $4, $5, TRUE, $6)
                            RETURNING id
                        """, cluster_id, version_name, config_content, config_hash, admin_user_id, json.dumps(metadata))
                        
                        # Deactivate previous versions for this cluster
                        await conn.execute("""
                            UPDATE config_versions 
                            SET is_active = FALSE 
                            WHERE cluster_id = $1 AND id != $2
                        """, cluster_id, config_version_id)
                        
                        sync_results.append({
                            'cluster_id': cluster_id,
                            'node': f'cluster-{cluster_id}', 
                            'success': True, 
                            'version': version_name, 
                            'message': 'SSL certificate updated immediately (fallback mode)'
                        })
                        logger.info(f"FALLBACK: Using immediate-apply for cluster {cluster_id}, agents notified")
                    
                except Exception as e:
                    logger.error(f"Cluster {cluster_id} config update failed for SSL certificate update: {e}")
                    sync_results.append({
                        'cluster_id': cluster_id,
                        'node': f'cluster-{cluster_id}', 
                        'success': False, 
                        'error': str(e)
                    })
        elif not content_updated:
            logger.info(f"SSL UPDATE: Only metadata updated (no content change), skipping config version creation")
            sync_results = [{'message': 'SSL metadata updated (no content change, no config version needed)'}]
        else:
            logger.info(f"SSL UPDATE: No affected clusters found")
            sync_results = [{'message': 'SSL updated but no clusters affected'}]
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='update',
                resource_type='ssl_certificate',
                resource_id=str(cert_id),
                details={
                    'certificate_name': certificate.name or existing['name'],
                    'is_global': is_global,
                    'content_updated': content_updated,
                    'affected_clusters': len(affected_clusters) if affected_clusters else 0,
                    'sync_results': len(sync_results)
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        return {
            "message": f"SSL certificate updated successfully",
            "content_updated": content_updated,
            "affected_clusters": len(affected_clusters) if affected_clusters else 0,
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating SSL certificate: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/certificates/{cert_id}")
async def delete_ssl_certificate(cert_id: int, request: Request, authorization: str = Header(None)):
    """Delete SSL certificate"""
    try:
        # Get current user for activity logging
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for SSL delete
        has_permission = await check_user_permission(current_user["id"], "ssl", "delete")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: ssl.delete required"
            )
        
        conn = await get_database_connection()
        
        # Check if certificate exists and get cluster_id
        certificate = await conn.fetchrow("SELECT name, cluster_id FROM ssl_certificates WHERE id = $1", cert_id)
        if not certificate:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="SSL certificate not found")
        
        cluster_id = certificate['cluster_id']
        cert_name = certificate['name']
        logger.info(f"SSL certificate delete: cert_id={cert_id}, name={cert_name}, cluster_id={cluster_id}")
        
        # Delete certificate
        await conn.execute("DELETE FROM ssl_certificates WHERE id = $1", cert_id)
        
        # If cluster_id provided, create new config version for agents
        sync_results = []
        if cluster_id:
            try:
                # Generate new HAProxy config without this certificate
                config_content = await generate_haproxy_config_for_cluster(cluster_id)
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"ssl-{cert_id}-delete-{int(time.time())}"
                
                # Get system admin user ID for created_by
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Try with status field first, fallback to old behavior if field doesn't exist
                try:
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                        VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                        RETURNING id
                    """, cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {cluster_id}")
                    
                    # Don't notify agents yet - wait for manual Apply
                    sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'SSL certificate deletion created. Click Apply to activate.'}]
                    
                except Exception as status_error:
                    logger.warning(f"FALLBACK: Status field not available, using old immediate-apply behavior: {status_error}")
                    # Fallback to old behavior without status field
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active)
                        VALUES ($1, $2, $3, $4, $5, TRUE)
                        RETURNING id
                    """, cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    # Deactivate previous versions for this cluster
                    await conn.execute("""
                        UPDATE config_versions 
                        SET is_active = FALSE 
                        WHERE cluster_id = $1 AND id != $2
                    """, cluster_id, config_version_id)
                    
                    # Use old notification behavior - notify agents immediately
                    from agent_notifications import notify_agents_config_change
                    sync_results = await notify_agents_config_change(cluster_id, version_name)
                    logger.info(f"FALLBACK: Using immediate-apply, agents notified")
                
            except Exception as e:
                logger.error(f"Cluster config update failed after deleting SSL certificate {cert_name}: {e}")
                # Still return success for database save, but with sync warning
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='delete',
                resource_type='ssl_certificate',
                resource_id=str(cert_id),
                details={
                    'certificate_name': cert_name,
                    'cluster_id': cluster_id,
                    'sync_results': len(sync_results)
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        return {
            "message": f"SSL certificate '{cert_name}' deleted successfully",
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 