from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, List
import json
import logging
import time
from datetime import datetime

from database.connection import get_database_connection, close_database_connection
from services.acme_service import acme_service
from services.haproxy_config import generate_haproxy_config_for_cluster

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/letsencrypt", tags=["Let's Encrypt / ACME"])


class AccountCreate(BaseModel):
    email: str
    directory_url: Optional[str] = None
    tos_agreed: bool = True
    eab_kid: Optional[str] = None
    eab_hmac_key: Optional[str] = None


class CertificateRequest(BaseModel):
    domains: List[str]
    account_id: Optional[int] = None
    cluster_ids: Optional[List[int]] = None
    auto_renew: bool = True


# --- Account management ---

@router.get("/accounts")
async def list_accounts(authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token
    current_user = await get_current_user_from_token(authorization)
    if not current_user.get('is_admin', False):
        raise HTTPException(status_code=403, detail="Admin access required")
    conn = await get_database_connection()
    try:
        rows = await conn.fetch(
            "SELECT id, email, directory_url, account_url, status, tos_agreed, eab_kid, created_at, updated_at FROM letsencrypt_accounts ORDER BY id"
        )
        return [dict(r) for r in rows]
    finally:
        await close_database_connection(conn)


@router.post("/accounts")
async def create_account(body: AccountCreate, authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token
    current_user = await get_current_user_from_token(authorization)
    if not current_user.get('is_admin', False):
        raise HTTPException(status_code=403, detail="Admin access required")
    try:
        settings = await acme_service._get_settings()
        directory_url = body.directory_url or settings.get('directory_url', 'https://acme-v02.api.letsencrypt.org/directory')
        if settings.get('staging_mode'):
            if 'letsencrypt' in directory_url:
                directory_url = 'https://acme-staging-v02.api.letsencrypt.org/directory'

        eab_kid = body.eab_kid or settings.get('eab_kid', '') or None
        eab_hmac_key = body.eab_hmac_key or settings.get('eab_hmac_key', '') or None

        result = await acme_service.register_account(
            email=body.email,
            directory_url=directory_url,
            tos_agreed=body.tos_agreed,
            eab_kid=eab_kid,
            eab_hmac_key=eab_hmac_key,
        )
        return result
    except Exception as e:
        logger.error(f"ACME account registration failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/accounts/{account_id}")
async def deactivate_account(account_id: int, authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token
    current_user = await get_current_user_from_token(authorization)
    if not current_user.get('is_admin', False):
        raise HTTPException(status_code=403, detail="Admin access required")

    conn = await get_database_connection()
    try:
        active_orders = await conn.fetchval("""
            SELECT COUNT(*) FROM letsencrypt_orders
            WHERE account_id = $1 AND status NOT IN ('valid', 'invalid', 'cancelled')
        """, account_id)
        if active_orders > 0:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot deactivate account with {active_orders} active order(s). Cancel them first."
            )
    finally:
        await close_database_connection(conn)

    try:
        result = await acme_service.deactivate_account(account_id)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"ACME account deactivation failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/accounts/{account_id}/permanent")
async def remove_account(account_id: int, authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token
    current_user = await get_current_user_from_token(authorization)
    if not current_user.get('is_admin', False):
        raise HTTPException(status_code=403, detail="Admin access required")

    conn = await get_database_connection()
    try:
        account = await conn.fetchrow(
            "SELECT id, status, email FROM letsencrypt_accounts WHERE id = $1", account_id
        )
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")
        if account['status'] != 'deactivated':
            raise HTTPException(
                status_code=409,
                detail="Only deactivated accounts can be permanently removed. Deactivate first."
            )

        linked_orders = await conn.fetchval(
            "SELECT COUNT(*) FROM letsencrypt_orders WHERE account_id = $1", account_id
        )
        if linked_orders > 0:
            await conn.execute(
                "DELETE FROM letsencrypt_orders WHERE account_id = $1", account_id
            )

        await conn.execute("DELETE FROM letsencrypt_accounts WHERE id = $1", account_id)
        logger.info(f"ACME account {account['email']} (id={account_id}) permanently removed by user {current_user.get('username')}")
        return {"message": f"Account {account['email']} permanently removed", "deleted_orders": linked_orders}
    finally:
        await close_database_connection(conn)


# --- Certificate operations ---

@router.post("/certificates")
async def request_certificate(body: CertificateRequest, authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'create')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.create required")

    if not body.domains:
        raise HTTPException(status_code=400, detail="At least one domain is required")

    try:
        account_id = body.account_id
        if not account_id:
            conn = await get_database_connection()
            try:
                account = await conn.fetchrow(
                    "SELECT id FROM letsencrypt_accounts WHERE status = 'valid' ORDER BY created_at DESC LIMIT 1"
                )
            finally:
                await close_database_connection(conn)
            if not account:
                raise HTTPException(
                    status_code=400,
                    detail="No ACME account found. Please configure one in Settings > ACME first."
                )
            account_id = account['id']

        order = await acme_service.create_order(
            account_id=account_id,
            domains=body.domains,
            cluster_ids=body.cluster_ids,
        )

        challenges = await acme_service.respond_to_challenges(order['order_id'])

        return {
            "order_id": order['order_id'],
            "status": order['status'],
            "domains": body.domains,
            "challenges": challenges,
            "message": "Order created. ACME challenges have been posted. Waiting for CA validation."
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Certificate request failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/orders")
async def list_orders(authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'read')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.read required")
    conn = await get_database_connection()
    try:
        rows = await conn.fetch("""
            SELECT o.id, o.account_id, o.order_url, o.status, o.domains,
                   o.ssl_certificate_id, o.cluster_ids, o.error_detail,
                   o.created_at, o.updated_at, a.email as account_email
            FROM letsencrypt_orders o
            JOIN letsencrypt_accounts a ON o.account_id = a.id
            ORDER BY o.created_at DESC
        """)
        results = []
        for r in rows:
            d = dict(r)
            d['domains'] = json.loads(d['domains']) if isinstance(d['domains'], str) else d['domains']
            d['cluster_ids'] = json.loads(d['cluster_ids']) if isinstance(d['cluster_ids'], str) else d['cluster_ids']
            results.append(d)
        return results
    finally:
        await close_database_connection(conn)


@router.get("/orders/{order_id}")
async def get_order(order_id: int, authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'read')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.read required")
    conn = await get_database_connection()
    try:
        order = await conn.fetchrow("""
            SELECT o.id, o.account_id, o.order_url, o.status, o.domains,
                   o.certificate_url, o.finalize_url, o.expires_at,
                   o.error_detail, o.ssl_certificate_id, o.cluster_ids,
                   o.created_at, o.updated_at, a.email as account_email
            FROM letsencrypt_orders o
            JOIN letsencrypt_accounts a ON o.account_id = a.id
            WHERE o.id = $1
        """, order_id)
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        challenges = await conn.fetch(
            "SELECT id, order_id, domain, token, challenge_url, status, validated_at, created_at FROM acme_challenges WHERE order_id = $1 ORDER BY domain", order_id
        )
        result = dict(order)
        result['domains'] = json.loads(result['domains']) if isinstance(result['domains'], str) else result['domains']
        result['cluster_ids'] = json.loads(result['cluster_ids']) if isinstance(result['cluster_ids'], str) else result['cluster_ids']
        result['challenges'] = [dict(c) for c in challenges]
        return result
    finally:
        await close_database_connection(conn)


@router.post("/orders/{order_id}/retry")
async def retry_order(order_id: int, authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'create')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.create required")
    try:
        status_info = await acme_service.check_order_status(order_id)
        if status_info.get('status') == 'ready':
            result = await acme_service.finalize_order(order_id)
            safe_result = {k: v for k, v in result.items() if k not in ('private_key_pem', 'cert_private_key')}
            return {"message": "Order finalized", **safe_result}
        elif status_info.get('status') == 'valid' and status_info.get('certificate_url'):
            return await _complete_certificate(order_id)
        else:
            challenges = await acme_service.respond_to_challenges(order_id)
            return {"message": "Challenges re-submitted", "status": status_info.get('status'), "challenges": challenges}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/orders/{order_id}/renew")
async def renew_order(order_id: int, authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'create')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.create required")
    conn = await get_database_connection()
    try:
        order = await conn.fetchrow(
            "SELECT account_id, domains, cluster_ids FROM letsencrypt_orders WHERE id = $1", order_id
        )
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
        domains = json.loads(order['domains']) if isinstance(order['domains'], str) else order['domains']
        cluster_ids = json.loads(order['cluster_ids']) if isinstance(order['cluster_ids'], str) else order['cluster_ids']

        new_order = await acme_service.create_order(
            account_id=order['account_id'], domains=domains, cluster_ids=cluster_ids
        )
        challenges = await acme_service.respond_to_challenges(new_order['order_id'])
        return {"message": "Renewal order created", "new_order_id": new_order['order_id'], "challenges": challenges}
    finally:
        await close_database_connection(conn)


@router.delete("/orders/{order_id}")
async def cancel_order(order_id: int, authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'delete')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.delete required")
    conn = await get_database_connection()
    try:
        result = await conn.execute(
            "UPDATE letsencrypt_orders SET status = 'cancelled', updated_at = NOW() WHERE id = $1 AND status NOT IN ('valid', 'invalid', 'cancelled')",
            order_id
        )
        if result == "UPDATE 0":
            existing = await conn.fetchval("SELECT status FROM letsencrypt_orders WHERE id = $1", order_id)
            if not existing:
                raise HTTPException(status_code=404, detail="Order not found")
            raise HTTPException(status_code=409, detail=f"Order cannot be cancelled (current status: {existing})")
        return {"message": "Order cancelled"}
    finally:
        await close_database_connection(conn)


@router.post("/certificates/{cert_id}/revoke")
async def revoke_certificate(cert_id: int, authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'delete')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.delete required")
    conn = await get_database_connection()
    try:
        cert = await conn.fetchrow(
            "SELECT s.*, o.account_id FROM ssl_certificates s LEFT JOIN letsencrypt_orders o ON s.letsencrypt_order_id = o.id WHERE s.id = $1",
            cert_id
        )
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        if cert.get('source') != 'letsencrypt':
            raise HTTPException(status_code=400, detail="Only ACME-managed certificates can be revoked through this endpoint")

        account_id = cert.get('account_id')
        if not account_id:
            account = await conn.fetchrow("SELECT id FROM letsencrypt_accounts ORDER BY created_at DESC LIMIT 1")
            if not account:
                raise HTTPException(status_code=400, detail="No ACME account found for revocation")
            account_id = account['id']

        success = await acme_service.revoke_certificate(
            cert['certificate_content'], account_id
        )
        if success:
            await conn.execute(
                "UPDATE ssl_certificates SET auto_renew = FALSE, updated_at = NOW() WHERE id = $1", cert_id
            )
            return {"message": "Certificate revoked successfully"}
        else:
            raise HTTPException(status_code=500, detail="Revocation failed")
    finally:
        await close_database_connection(conn)


@router.post("/import-ca-chain")
async def import_le_ca_chain(authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'create')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.create required")
    import aiohttp
    ca_urls = [
        ("https://letsencrypt.org/certs/isrgrootx1.pem", "ISRG Root X1"),
        ("https://letsencrypt.org/certs/r10.pem", "R10 Intermediate"),
        ("https://letsencrypt.org/certs/r11.pem", "R11 Intermediate"),
    ]
    chain_parts = []
    async with aiohttp.ClientSession() as session:
        for url, name in ca_urls:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        chain_parts.append(await resp.text())
            except Exception as e:
                logger.warning(f"Failed to download {name}: {e}")

    if not chain_parts:
        raise HTTPException(
            status_code=502,
            detail="Failed to download CA certificates from letsencrypt.org. "
                   "This usually means the server cannot reach external HTTPS endpoints. "
                   "Check network/proxy/firewall settings."
        )

    full_chain = '\n'.join(chain_parts)
    conn = await get_database_connection()
    try:
        existing = await conn.fetchrow(
            "SELECT id FROM ssl_certificates WHERE name = 'letsencrypt-ca-chain'"
        )
        if existing:
            await conn.execute(
                "UPDATE ssl_certificates SET certificate_content = $1, updated_at = NOW() WHERE id = $2",
                full_chain, existing['id']
            )
            return {"message": "LE CA chain updated", "id": existing['id']}
        else:
            row = await conn.fetchrow("""
                INSERT INTO ssl_certificates (name, certificate_content, usage_type, source, is_active)
                VALUES ('letsencrypt-ca-chain', $1, 'server', 'letsencrypt-ca', TRUE)
                RETURNING id
            """, full_chain)
            return {"message": "LE CA chain imported", "id": row['id']}
    finally:
        await close_database_connection(conn)


@router.get("/renewal-schedule")
async def get_renewal_schedule(authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'read')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.read required")
    conn = await get_database_connection()
    try:
        certs = await conn.fetch("""
            SELECT id, name, primary_domain, expiry_date, auto_renew, days_until_expiry
            FROM ssl_certificates
            WHERE source = 'letsencrypt' AND is_active = TRUE
            ORDER BY expiry_date ASC NULLS LAST
        """)
        return [dict(c) for c in certs]
    finally:
        await close_database_connection(conn)


async def _complete_certificate(order_id: int) -> dict:
    """Download certificate and create ssl_certificate entry + config version.

    Both new certificates and renewals follow the same flow as manual SSL edit:
    1. Update/insert cert with last_config_status='PENDING'
    2. Create PENDING config versions for affected clusters
    3. For renewals: programmatically trigger the same Apply mechanism
       (apply_ssl_related_configs + consolidated version + agent notify)
    4. For new certs: remain PENDING for manual Apply
    """
    conn = await get_database_connection()
    try:
        order = await conn.fetchrow("SELECT * FROM letsencrypt_orders WHERE id = $1", order_id)
        if not order:
            raise Exception("Order not found")

        if order.get('ssl_certificate_id'):
            return {
                "message": "Certificate already issued for this order",
                "certificate_id": order['ssl_certificate_id'],
            }

        if order['status'] == 'ready':
            await acme_service.finalize_order(order_id)
            order = await conn.fetchrow("SELECT * FROM letsencrypt_orders WHERE id = $1", order_id)

        cert_data = await acme_service.download_certificate(order_id)
        domains = json.loads(order['domains']) if isinstance(order['domains'], str) else order['domains']
        cluster_ids = json.loads(order['cluster_ids']) if isinstance(order['cluster_ids'], str) else order['cluster_ids']
        primary_domain = domains[0] if domains else 'unknown'

        private_key_pem = order.get('cert_private_key') or ''

        expiry_date = None
        days_until_expiry = 0
        issuer = None
        fingerprint = None
        all_domains = json.dumps(domains)
        try:
            from utils.ssl_parser import parse_ssl_certificate
            cert_info = parse_ssl_certificate(cert_data['certificate_pem'])
            if cert_info and not cert_info.get('error'):
                expiry_date = cert_info.get('expiry_date')
                days_until_expiry = cert_info.get('days_until_expiry', 0)
                issuer = cert_info.get('issuer')
                fingerprint = cert_info.get('fingerprint')
                if cert_info.get('all_domains'):
                    all_domains = json.dumps(cert_info['all_domains'])
        except Exception as parse_err:
            logger.warning(f"Could not parse ACME certificate metadata: {parse_err}")

        existing_cert = await conn.fetchrow("""
            SELECT id FROM ssl_certificates
            WHERE primary_domain = $1 AND source = 'letsencrypt' AND is_active = TRUE
            ORDER BY created_at DESC LIMIT 1
        """, primary_domain)

        is_renewal = existing_cert is not None

        if is_renewal:
            cert_id = existing_cert['id']
            await conn.execute("""
                UPDATE ssl_certificates SET
                    certificate_content = $1, private_key_content = $2, chain_content = $3,
                    all_domains = $4::jsonb, expiry_date = $5, days_until_expiry = $6,
                    issuer = $7, fingerprint = $8, letsencrypt_order_id = $9,
                    auto_renew = TRUE, is_active = TRUE, last_config_status = 'PENDING',
                    updated_at = NOW()
                WHERE id = $10
            """, cert_data['certificate_pem'], private_key_pem,
                cert_data.get('chain_pem', ''), all_domains,
                expiry_date, days_until_expiry, issuer, fingerprint, order_id, cert_id)
            logger.info(f"ACME RENEWAL: Updated certificate {cert_id} for {primary_domain}, status=PENDING")
        else:
            cert_row = await conn.fetchrow("""
                INSERT INTO ssl_certificates
                    (name, certificate_content, private_key_content, chain_content,
                     primary_domain, all_domains, expiry_date, days_until_expiry, issuer, fingerprint,
                     usage_type, source, letsencrypt_order_id, auto_renew, is_active,
                     last_config_status)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10,
                        'frontend', 'letsencrypt', $11, TRUE, TRUE, 'PENDING')
                RETURNING id
            """, f"le-{primary_domain}", cert_data['certificate_pem'], private_key_pem,
                cert_data.get('chain_pem', ''), primary_domain, all_domains,
                expiry_date, days_until_expiry, issuer, fingerprint, order_id)
            cert_id = cert_row['id']

        await conn.execute(
            "UPDATE letsencrypt_orders SET ssl_certificate_id = $1, status = 'valid', updated_at = NOW() WHERE id = $2",
            cert_id, order_id
        )

        if cluster_ids:
            for cid in cluster_ids:
                await conn.execute("""
                    INSERT INTO ssl_certificate_clusters (ssl_certificate_id, cluster_id)
                    VALUES ($1, $2) ON CONFLICT DO NOTHING
                """, cert_id, cid)

        effective_cluster_ids = list(cluster_ids or [])
        if is_renewal and not effective_cluster_ids:
            mapped = await conn.fetch(
                "SELECT cluster_id FROM ssl_certificate_clusters WHERE ssl_certificate_id = $1", cert_id
            )
            if mapped:
                effective_cluster_ids = [r['cluster_id'] for r in mapped]
            else:
                all_clusters = await conn.fetch(
                    "SELECT id FROM haproxy_clusters WHERE is_active = TRUE"
                )
                effective_cluster_ids = [r['id'] for r in all_clusters]
            if effective_cluster_ids:
                logger.info(f"ACME RENEWAL: Resolved {len(effective_cluster_ids)} cluster(s) for global cert {cert_id}")

        admin_uid = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1

        for cid in effective_cluster_ids:
            try:
                config_content = await generate_haproxy_config_for_cluster(cid)
                ts = int(time.time())
                action = 'renew' if is_renewal else 'issue'
                version_name = f"ssl-{cert_id}-letsencrypt-{action}-{ts}"
                await conn.execute("""
                    INSERT INTO config_versions (cluster_id, version_name, config_content, status, created_by)
                    VALUES ($1, $2, $3, 'PENDING', $4)
                """, cid, version_name, config_content, admin_uid)
            except Exception as ve:
                logger.error(f"Failed to create config version for cluster {cid}: {ve}")

        if is_renewal:
            await _auto_apply_renewal(cert_id, effective_cluster_ids)

        msg = "Certificate renewed and applied" if is_renewal else "Certificate issued (pending Apply)"
        return {
            "message": msg,
            "certificate_id": cert_id,
            "domains": domains,
            "auto_applied": is_renewal,
        }
    finally:
        await close_database_connection(conn)


async def _auto_apply_renewal(cert_id: int, cluster_ids: list):
    """Trigger the same Apply mechanism used by manual Apply for SSL renewals.

    Follows the exact same flow as cluster.py apply_pending_changes:
    1. apply_ssl_related_configs (cross-cluster SSL propagation)
    2. Generate consolidated config version (APPLIED, is_active=TRUE)
    3. Mark PENDING SSL versions as APPLIED
    4. Set ssl_certificates.last_config_status = 'APPLIED'
    5. Notify agents via Redis
    """
    import hashlib

    applied_clusters = set()

    for cluster_id in cluster_ids:
        conn = await get_database_connection()
        try:
            pending_versions = await conn.fetch("""
                SELECT id, version_name, config_content, created_at
                FROM config_versions
                WHERE cluster_id = $1 AND status = 'PENDING'
                  AND version_name LIKE $2
                ORDER BY created_at
            """, cluster_id, f"ssl-{cert_id}-%")

            if not pending_versions:
                continue

            async with conn.transaction():
                from routers.cluster import apply_ssl_related_configs
                await apply_ssl_related_configs(conn, cluster_id)

                config_content = await generate_haproxy_config_for_cluster(cluster_id, conn)
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"apply-consolidated-{int(time.time())}"

                admin_user_id = await conn.fetchval(
                    "SELECT id FROM users WHERE username = 'admin' LIMIT 1"
                ) or 1

                pre_apply_config = await conn.fetchval("""
                    SELECT config_content FROM config_versions
                    WHERE cluster_id = $1 AND status = 'APPLIED' AND is_active = TRUE
                      AND config_content IS NOT NULL
                    ORDER BY created_at DESC LIMIT 1
                """, cluster_id)

                metadata = json.dumps({'pre_apply_snapshot': pre_apply_config}) if pre_apply_config else None

                await conn.execute("""
                    UPDATE config_versions SET is_active = FALSE
                    WHERE cluster_id = $1 AND is_active = TRUE
                """, cluster_id)

                await conn.fetchval("""
                    INSERT INTO config_versions
                    (cluster_id, version_name, config_content, checksum, created_by, is_active, status, metadata)
                    VALUES ($1, $2, $3, $4, $5, TRUE, 'APPLIED', $6)
                    RETURNING id
                """, cluster_id, version_name, config_content, config_hash, admin_user_id, metadata)

                await conn.execute("""
                    UPDATE config_versions SET is_active = FALSE, status = 'APPLIED'
                    WHERE id = ANY($1)
                """, [v['id'] for v in pending_versions])

                await conn.execute("""
                    UPDATE ssl_certificates
                    SET last_config_status = 'APPLIED', updated_at = CURRENT_TIMESTAMP
                    WHERE id = $1 AND last_config_status = 'PENDING'
                """, cert_id)

            applied_clusters.add(cluster_id)
            logger.info(f"ACME AUTO-APPLY: Applied renewal for cert {cert_id} on cluster {cluster_id}, version={version_name}")
        except Exception as apply_err:
            logger.error(f"ACME AUTO-APPLY: Failed to apply renewal on cluster {cluster_id}: {apply_err}")
        finally:
            await close_database_connection(conn)

    for cluster_id in applied_clusters:
        try:
            from agent_notifications import notify_agents_config_change
            sync_results = await notify_agents_config_change(cluster_id, f"acme-renewal-{cert_id}")
            logger.info(f"ACME AUTO-APPLY: Notified {len(sync_results)} agents for cluster {cluster_id}")
        except Exception as notify_err:
            logger.error(f"ACME AUTO-APPLY: Agent notification failed for cluster {cluster_id}: {notify_err}")
