"""
CSR (Certificate Signing Request) endpoints (v1.9.0).

Generate a private key + CSR in-app, download the CSR PEM, have it signed by
an external CA, then import the signed certificate — which creates a normal
ssl_certificates row that flows through the existing pipeline
(config version → Apply Management → agent pull).

Security posture:
- All endpoints enforce ssl.* permissions explicitly (including the read
  endpoints — deliberately stricter than the legacy cert detail route).
- The private key is NEVER returned by any endpoint here; after import it is
  reachable only via the existing certificate detail route.
- Key generation is offloaded to a thread (RSA-4096 takes seconds; the
  backend runs a single-worker event loop by default) and rate-limited
  per user via the user_activity_logs COUNT pattern (acme_diagnostics
  precedent — slowapi is not registered on the app).
"""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Header

from database.connection import get_database_connection, close_database_connection
from auth_middleware import get_current_user_from_token, check_user_permission
from models.csr import SSLCSRCreate, SSLCSRImport
from services import csr_service, ssl_service
from routers.ssl import _assert_safe_cert_name, validate_user_cluster_access
from utils.activity_log import log_user_activity

router = APIRouter(prefix="/api/ssl/csrs", tags=["SSL CSRs"])
logger = logging.getLogger(__name__)

_RATE_LIMIT_CREATE_PER_MIN = 10

# Columns exposed to the API — private_key_pem is deliberately absent so a
# future `SELECT *` refactor cannot silently start leaking it.
_CSR_LIST_COLUMNS = """
    c.id, c.name, c.common_name, c.subject, c.sans, c.key_algorithm,
    c.status, c.ssl_certificate_id, c.completed_at, c.created_at, c.updated_at,
    s.name AS certificate_name, u.username AS created_by_username
"""

_INT32_MAX = 2_147_483_647


def _client_ip(request: Optional[Request]) -> Optional[str]:
    try:
        return str(request.client.host) if request and request.client else None
    except Exception:
        return None


def _user_agent(request: Optional[Request]) -> Optional[str]:
    try:
        return request.headers.get("user-agent") if request else None
    except Exception:
        return None


async def _require(authorization: Optional[str], action: str):
    """Authenticate + enforce ssl.<action>; returns current_user or raises 401/403."""
    current_user = await get_current_user_from_token(authorization)
    ok = await check_user_permission(current_user["id"], "ssl", action, current_user=current_user)
    if not ok:
        raise HTTPException(status_code=403, detail=f"Insufficient permissions: ssl.{action} required")
    return current_user


def _assert_int32_id(csr_id: int) -> None:
    """ssl_csrs.id is int4 — an out-of-range path param would surface as an
    asyncpg DataError 500 (Bulgu #96 precedent); return a clean 404 instead."""
    if csr_id < 1 or csr_id > _INT32_MAX:
        raise HTTPException(status_code=404, detail="CSR not found")


def _assert_valid_cluster_id(cluster_id: int) -> None:
    """Same int4 guard for body-supplied cluster ids: haproxy_clusters.id is
    SERIAL/int4, so an out-of-range value would raise asyncpg DataError inside
    validate_user_cluster_access and surface as a 500 with the raw driver
    error. Fail with the same clean 404 the cluster lookup itself produces."""
    if not isinstance(cluster_id, int) or cluster_id < 1 or cluster_id > _INT32_MAX:
        raise HTTPException(status_code=404, detail="Cluster not found")


async def _enforce_create_rate_limit(conn, user_id: int) -> None:
    """Per-user per-minute limit on key generation, counted against the
    csr_create audit-log action (acme_diagnostics _enforce_rate_limit pattern,
    backed by the (user_id, action, created_at DESC) composite index)."""
    cnt = await conn.fetchval(
        """
        SELECT COUNT(*)
        FROM user_activity_logs
        WHERE user_id = $1
          AND action = 'csr_create'
          AND created_at >= NOW() - INTERVAL '60 seconds'
        """,
        user_id,
    )
    if cnt is not None and cnt >= _RATE_LIMIT_CREATE_PER_MIN:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit exceeded: at most {_RATE_LIMIT_CREATE_PER_MIN} "
                "CSRs may be created per minute"
            ),
        )


@router.post("")
async def create_csr(payload: SSLCSRCreate, request: Request, authorization: Optional[str] = Header(None)):
    """Generate a private key + CSR. Returns the CSR PEM immediately (so the
    UI can show copy/download in one round trip) — never the private key."""
    current_user = await _require(authorization, "create")
    conn = None
    try:
        # Belt and braces on top of the model validator — same duplication
        # convention as the certificate create route.
        _assert_safe_cert_name(payload.name)

        conn = await get_database_connection()
        await _enforce_create_rate_limit(conn, current_user["id"])

        # Fail fast on a taken name BEFORE burning CPU on key generation;
        # insert_csr_row re-checks and the partial unique index closes the race.
        await csr_service.assert_csr_name_available(conn, payload.name)

        bundle = await asyncio.to_thread(csr_service.generate_csr_bundle, payload)
        csr_id = await csr_service.insert_csr_row(conn, payload, bundle, current_user["id"])

        row = await conn.fetchrow(
            f"""
            SELECT {_CSR_LIST_COLUMNS}, c.csr_pem
            FROM ssl_csrs c
            LEFT JOIN ssl_certificates s ON c.ssl_certificate_id = s.id
            LEFT JOIN users u ON c.created_by = u.id
            WHERE c.id = $1
            """,
            csr_id,
        )

        await log_user_activity(
            user_id=current_user["id"],
            action='csr_create',
            resource_type='ssl_csr',
            resource_id=str(csr_id),
            details={
                'csr_name': payload.name,
                'common_name': payload.common_name,
                'sans': bundle['sans'],
                'key_algorithm': payload.key_algorithm,
            },
            ip_address=_client_ip(request),
            user_agent=_user_agent(request),
        )

        return {
            "message": f"CSR '{payload.name}' created successfully",
            "csr": csr_service.csr_row_to_dict(row, include_pem=True),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating CSR: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            await close_database_connection(conn)


@router.get("")
async def list_csrs(authorization: Optional[str] = Header(None)):
    """List CSRs (no PEM payloads — fetch the detail route for the CSR PEM).
    Cluster-agnostic: a CSR binds to clusters only at import time."""
    await _require(authorization, "read")
    conn = None
    try:
        conn = await get_database_connection()
        rows = await conn.fetch(
            f"""
            SELECT {_CSR_LIST_COLUMNS}
            FROM ssl_csrs c
            LEFT JOIN ssl_certificates s ON c.ssl_certificate_id = s.id
            LEFT JOIN users u ON c.created_by = u.id
            ORDER BY c.created_at DESC
            """
        )
        return [csr_service.csr_row_to_dict(r) for r in rows]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing CSRs: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            await close_database_connection(conn)


@router.get("/{csr_id}")
async def get_csr(csr_id: int, authorization: Optional[str] = Header(None)):
    """CSR detail including the CSR PEM. The private key is never included."""
    await _require(authorization, "read")
    _assert_int32_id(csr_id)
    conn = None
    try:
        conn = await get_database_connection()
        row = await conn.fetchrow(
            f"""
            SELECT {_CSR_LIST_COLUMNS}, c.csr_pem
            FROM ssl_csrs c
            LEFT JOIN ssl_certificates s ON c.ssl_certificate_id = s.id
            LEFT JOIN users u ON c.created_by = u.id
            WHERE c.id = $1
            """,
            csr_id,
        )
        if not row:
            raise HTTPException(status_code=404, detail="CSR not found")
        return csr_service.csr_row_to_dict(row, include_pem=True)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching CSR {csr_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            await close_database_connection(conn)


@router.post("/{csr_id}/import")
async def import_csr_certificate(
    csr_id: int,
    payload: SSLCSRImport,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """Import the CA-signed certificate for a pending CSR. Creates an
    ssl_certificates row (source='csr', PENDING) and stages one config
    version per affected cluster — the operator applies manually."""
    current_user = await _require(authorization, "create")
    _assert_int32_id(csr_id)
    conn = None
    try:
        if payload.name:
            _assert_safe_cert_name(payload.name)

        conn = await get_database_connection()

        if not payload.is_global:
            for cluster_id in payload.cluster_ids or []:
                _assert_valid_cluster_id(cluster_id)
                await validate_user_cluster_access(current_user["id"], cluster_id, conn)

        result = await csr_service.import_signed_certificate(
            conn, csr_id, payload, current_user["id"]
        )
        cert_id = result["certificate_id"]

        if payload.is_global:
            cluster_rows = await conn.fetch(
                "SELECT id FROM haproxy_clusters WHERE is_active = TRUE"
            )
            affected_clusters = [r['id'] for r in cluster_rows]
        else:
            affected_clusters = payload.cluster_ids or []

        # Post-commit staging — a config-generation failure never rolls back
        # the certificate (same semantics as the manual create flow).
        sync_results = await ssl_service.stage_ssl_config_versions(
            conn, cert_id, affected_clusters, action='create',
            created_by=current_user["id"],
        )

        await log_user_activity(
            user_id=current_user["id"],
            action='create',
            resource_type='ssl_certificate',
            resource_id=str(cert_id),
            details={
                'certificate_name': result['certificate_name'],
                'domain': result.get('primary_domain', 'unknown'),
                'via': 'csr',
                'csr_id': csr_id,
                'usage_type': payload.usage_type,
                'is_global': payload.is_global,
                'cluster_ids': payload.cluster_ids,
                'warnings': result['warnings'],
            },
            ip_address=_client_ip(request),
            user_agent=_user_agent(request),
        )
        await log_user_activity(
            user_id=current_user["id"],
            action='csr_import',
            resource_type='ssl_csr',
            resource_id=str(csr_id),
            details={
                'certificate_id': cert_id,
                'certificate_name': result['certificate_name'],
            },
            ip_address=_client_ip(request),
            user_agent=_user_agent(request),
        )

        return {
            "message": (
                f"Certificate '{result['certificate_name']}' imported "
                "successfully. Go to Apply Management to deploy."
            ),
            "certificate_id": cert_id,
            "warnings": result["warnings"],
            "sync_results": sync_results,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error importing signed certificate for CSR {csr_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            await close_database_connection(conn)


@router.delete("/{csr_id}")
async def delete_csr(csr_id: int, request: Request, authorization: Optional[str] = Header(None)):
    """Hard delete. For a pending CSR this permanently destroys the private
    key (any certificate later signed from that CSR becomes unusable); for a
    completed CSR it only removes history — the imported certificate is not
    affected (the FK points csr → cert)."""
    current_user = await _require(authorization, "delete")
    _assert_int32_id(csr_id)
    conn = None
    try:
        conn = await get_database_connection()
        async with conn.transaction():
            # FOR UPDATE serialises against an in-flight import of the same CSR.
            row = await conn.fetchrow(
                "SELECT id, name, status FROM ssl_csrs WHERE id = $1 FOR UPDATE",
                csr_id,
            )
            if not row:
                raise HTTPException(status_code=404, detail="CSR not found")
            await conn.execute("DELETE FROM ssl_csrs WHERE id = $1", csr_id)

        await log_user_activity(
            user_id=current_user["id"],
            action='delete',
            resource_type='ssl_csr',
            resource_id=str(csr_id),
            details={'csr_name': row['name'], 'status': row['status']},
            ip_address=_client_ip(request),
            user_agent=_user_agent(request),
        )

        if row['status'] == 'pending':
            message = (
                f"CSR '{row['name']}' deleted — its private key has been "
                "permanently destroyed."
            )
        else:
            message = (
                f"CSR '{row['name']}' deleted (history only) — the imported "
                "certificate is not affected."
            )
        return {"message": message}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting CSR {csr_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            await close_database_connection(conn)
