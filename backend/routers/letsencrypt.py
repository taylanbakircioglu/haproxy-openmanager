from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, List, Dict
import base64
import json
import logging
import re
import time
from datetime import datetime

from database.connection import get_database_connection, close_database_connection
from services.acme_service import acme_service
from services.haproxy_config import generate_haproxy_config_for_cluster
from services.dns_providers import list_providers, is_supported, get_provider, DnsProviderError
from utils.dns_credentials import encrypt_dns_credentials, decrypt_dns_credentials

# Issue #35: DNS-01 challenge methods.
_CHALLENGE_TYPES = ("http-01", "dns-01")


async def _dns01_enabled() -> bool:
    """Global kill-switch (system_settings acme.dns01_enabled, default False). Read via the ACME
    settings dict so non-admins never need the admin-only /api/settings/acme endpoint."""
    try:
        settings = await acme_service._get_settings()
        val = settings.get('dns01_enabled')
        if isinstance(val, str):
            return val.strip().lower() in ('1', 'true', 'yes', 'on')
        return bool(val)
    except Exception:
        return False


# Per-user sliding-window rate limit for the manual dns-confirm action (soft anti-abuse so a user
# can't spam the CA via the confirm button). Per-process; sufficient for a manual UI action.
_DNS_CONFIRM_RL: Dict[int, list] = {}
_DNS_CONFIRM_LIMIT = 5
_DNS_CONFIRM_WINDOW = 60.0


async def _enforce_dns_confirm_rate_limit(user_id: int) -> None:
    now = time.time()
    bucket = [t for t in _DNS_CONFIRM_RL.get(user_id, []) if now - t < _DNS_CONFIRM_WINDOW]
    if len(bucket) >= _DNS_CONFIRM_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded: dns-confirm allowed 5 requests per minute")
    bucket.append(now)
    _DNS_CONFIRM_RL[user_id] = bucket

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/letsencrypt", tags=["Let's Encrypt / ACME"])

# RFC 1035 / RFC 5890: hostname/domain label rules. Permits wildcards (*).
_DOMAIN_REGEX = re.compile(
    r'^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


class AccountCreate(BaseModel):
    email: str
    directory_url: Optional[str] = None
    tos_agreed: bool = True
    # EAB (External Account Binding) for CAs that require it (ZeroSSL, Google). The KID is opaque
    # (bound only); the HMAC key must be base64url so newAccount's _b64url_decode won't raise a
    # cryptic binascii error (a common copy mistake is standard-base64 '+'/'/' vs urlsafe '-'/'_').
    eab_kid: Optional[str] = Field(default=None, max_length=256)
    eab_hmac_key: Optional[str] = Field(default=None, max_length=512)
    # Issue #35: per-account default challenge method + DNS provider (for dns-01).
    challenge_type: str = "http-01"
    dns_provider: Optional[str] = None

    @field_validator('challenge_type')
    @classmethod
    def _validate_challenge_type(cls, v):
        if v not in _CHALLENGE_TYPES:
            raise ValueError(f"challenge_type must be one of {_CHALLENGE_TYPES}")
        return v

    @field_validator('eab_hmac_key')
    @classmethod
    def _validate_eab_hmac_key(cls, v):
        if not v:
            return v
        try:
            base64.urlsafe_b64decode(v + '=' * (-len(v) % 4))
        except Exception:
            raise ValueError("eab_hmac_key is not valid base64; copy it exactly from your CA account.")
        return v

    @model_validator(mode='after')
    def _require_provider_for_dns01(self):
        if self.challenge_type == 'dns-01' and not (self.dns_provider or '').strip():
            raise ValueError("dns_provider is required when challenge_type is 'dns-01'")
        return self


class DnsCredentialsUpsert(BaseModel):
    dns_provider: str = Field(..., min_length=1, max_length=50)
    credentials: Dict[str, str] = Field(default_factory=dict)

    @field_validator('credentials')
    @classmethod
    def _validate_credentials(cls, v):
        if len(v) > 20:
            raise ValueError("Too many credential fields")
        for key, val in v.items():
            if not isinstance(key, str) or not re.match(r'^[a-zA-Z0-9_]{1,50}$', key):
                raise ValueError(f"Invalid credential field name: {key!r}")
            if not isinstance(val, str) or len(val) > 4000:
                raise ValueError(f"Credential value for {key!r} is missing or too long")
        return v


class CertificateRequest(BaseModel):
    # Audit Tur 5 / Commit 8c-2: harden input validation.
    # min_length=1: reject empty domain list at API boundary.
    # max_length=100: prevent abuse / oversized SAN bundles.
    # Default cluster_ids to [] (not None) to simplify downstream handling.
    domains: List[str] = Field(..., min_length=1, max_length=100)
    account_id: Optional[int] = None
    cluster_ids: List[int] = Field(default_factory=list)
    auto_renew: bool = True
    # Issue #35: optional override; when None the account's default method is used.
    challenge_type: Optional[str] = None

    @field_validator('domains')
    @classmethod
    def validate_domains(cls, v):
        normalized = []
        for d in v:
            if not d or not isinstance(d, str):
                raise ValueError("Domain entries must be non-empty strings")
            d_norm = d.strip().lower()
            if not d_norm or len(d_norm) > 253:
                raise ValueError(f"Invalid domain length: '{d}' (max 253 chars)")
            if '..' in d_norm or d_norm.startswith('.') or d_norm.endswith('.'):
                raise ValueError(f"Invalid domain syntax: '{d}'")
            if not _DOMAIN_REGEX.match(d_norm):
                raise ValueError(f"Invalid domain format: '{d}'")
            normalized.append(d_norm)
        # De-duplicate (case/whitespace variants normalize to the same value) while preserving order,
        # so we don't submit a redundant SAN to the CA or render duplicate-keyed tags in the UI.
        return list(dict.fromkeys(normalized))

    @field_validator('challenge_type')
    @classmethod
    def _validate_challenge_type(cls, v):
        if v is not None and v not in _CHALLENGE_TYPES:
            raise ValueError(f"challenge_type must be one of {_CHALLENGE_TYPES}")
        return v

    @model_validator(mode='after')
    def _wildcard_requires_dns01(self):
        # Static cross-field guard: a wildcard SAN can ONLY be issued via dns-01 (the CA rejects
        # wildcard over http-01). The runtime dns01_enabled gate + provider resolution happen in the
        # endpoint (validators can't do async/DB). When challenge_type is None here, the effective
        # method is resolved from the account in the endpoint, which re-checks this.
        if any((d or '').startswith('*.') for d in (self.domains or [])):
            # Only reject when the caller EXPLICITLY chose a non-dns-01 method. When challenge_type is
            # None, the effective method is resolved from the account in the endpoint, which re-checks
            # wildcard-requires-dns-01 — so account-default dns-01 inheritance still works for wildcards.
            if self.challenge_type is not None and self.challenge_type != 'dns-01':
                raise ValueError("Wildcard certificates require challenge_type 'dns-01'")
        return self


# --- Account management ---

@router.get("/accounts")
async def list_accounts(authorization: str = Header(None)):
    """v1.5.0 R12: list of LE accounts is now READ-ONLY for any
    authenticated user. Account *creation* / deletion remains admin-only.

    The wizard ('New Site' / ACME mode) needs this list so the
    user can pick which LE account to bill against when more than one is
    configured. Previously the wizard silently dropped the selector
    because non-admin users got 403 here (Promise.allSettled swallowed
    the failure).
    """
    from auth_middleware import get_current_user_from_token
    # Authentication still required — get_current_user_from_token raises
    # 401 if the token is missing/invalid.
    await get_current_user_from_token(authorization)
    conn = await get_database_connection()
    try:
        rows = await conn.fetch(
            "SELECT id, email, directory_url, account_url, status, tos_agreed, eab_kid, created_at, updated_at, challenge_type, dns_provider FROM letsencrypt_accounts ORDER BY id"
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
        # Commit 5f: respect staging mode for non-Let's Encrypt CAs as well.
        # If `acme.staging_url_override` is set in system_settings, use it when staging
        # mode is active. Falls back to LE staging for the default LE production URL.
        if settings.get('staging_mode'):
            override = settings.get('staging_url_override') or ''
            if override and override.startswith('http'):
                logger.info(f"ACME: Using staging_url_override: {override}")
                directory_url = override
            elif 'letsencrypt' in directory_url:
                directory_url = 'https://acme-staging-v02.api.letsencrypt.org/directory'

        eab_kid = body.eab_kid or settings.get('eab_kid', '') or None
        eab_hmac_key = body.eab_hmac_key or settings.get('eab_hmac_key', '') or None

        # Issue #35: a dns-01 account must name a supported DNS provider.
        if body.challenge_type == 'dns-01':
            if not await _dns01_enabled():
                raise HTTPException(status_code=409, detail="DNS-01 is disabled by an administrator (enable it in Settings).")
            if not is_supported((body.dns_provider or '').strip()):
                raise HTTPException(status_code=422, detail=f"Unsupported DNS provider: {body.dns_provider}")

        result = await acme_service.register_account(
            email=body.email,
            directory_url=directory_url,
            tos_agreed=body.tos_agreed,
            eab_kid=eab_kid,
            eab_hmac_key=eab_hmac_key,
            challenge_type=body.challenge_type,
            dns_provider=(body.dns_provider or None),
        )
        return result
    except HTTPException:
        # Preserve deliberate status codes (e.g. 409 DNS-01 disabled, 422 unsupported provider) —
        # the broad except below would otherwise downgrade them all to 400.
        raise
    except Exception as e:
        logger.error(f"ACME account registration failed: {e}")
        # Humanize the common EAB-required failure (ZeroSSL/Google). The ACME error propagates as a
        # string ("Account registration failed: {<dict>}"), so match the URN substring in str(e).
        if 'externalaccountrequired' in str(e).lower():
            raise HTTPException(status_code=400, detail=(
                "This CA requires External Account Binding (EAB). Enter the EAB Key ID and HMAC Key "
                "from your ZeroSSL/Google account and retry."
            ))
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


# --- Issue #35: DNS-01 providers + per-account DNS credentials ---

@router.get("/dns-providers")
async def get_dns_providers(authorization: str = Header(None)):
    """List supported DNS providers + their credential-field schema (for the UI). Also returns the
    global dns01_enabled gate so a non-admin cert UI can read it without the admin-only settings API.
    Authenticated (any user); not admin-only."""
    from auth_middleware import get_current_user_from_token
    await get_current_user_from_token(authorization)
    return {"dns01_enabled": await _dns01_enabled(), "providers": list_providers()}


@router.get("/accounts/{account_id}/dns-credentials")
async def get_dns_credentials(account_id: int, authorization: str = Header(None)):
    """Masked metadata only — provider + which credential fields are set + updated_at. NEVER returns
    the ciphertext or any plaintext token. Read-only for any authenticated user (matches list_accounts)."""
    from auth_middleware import get_current_user_from_token
    await get_current_user_from_token(authorization)
    conn = await get_database_connection()
    try:
        row = await conn.fetchrow(
            "SELECT dns_provider, credentials_encrypted, updated_at FROM letsencrypt_account_dns_credentials WHERE account_id = $1",
            account_id,
        )
        if not row:
            return {"configured": False, "dns_provider": None, "credential_fields_present": [], "updated_at": None}
        present = []
        decrypted = decrypt_dns_credentials(row["credentials_encrypted"])
        if isinstance(decrypted, dict):
            present = sorted(decrypted.keys())
        return {
            "configured": True,
            "dns_provider": row["dns_provider"],
            "credential_fields_present": present,
            "updated_at": row["updated_at"],
        }
    finally:
        await close_database_connection(conn)


@router.put("/accounts/{account_id}/dns-credentials")
async def upsert_dns_credentials(account_id: int, body: DnsCredentialsUpsert, authorization: str = Header(None)):
    """Store (encrypted) DNS provider credentials for an account. Admin-only. Verifies the
    credentials against the provider BEFORE persisting; returns a sanitized result (never the token)."""
    from auth_middleware import get_current_user_from_token
    current_user = await get_current_user_from_token(authorization)
    if not current_user.get('is_admin', False):
        raise HTTPException(status_code=403, detail="Admin access required")
    provider_name = body.dns_provider.strip()
    if not is_supported(provider_name):
        raise HTTPException(status_code=422, detail=f"Unsupported DNS provider: {provider_name}")

    conn = await get_database_connection()
    try:
        exists = await conn.fetchval("SELECT 1 FROM letsencrypt_accounts WHERE id = $1", account_id)
        if not exists:
            raise HTTPException(status_code=404, detail="ACME account not found")

        # Verify credentials synchronously; only persist on success. The detail is user-safe.
        try:
            provider = get_provider(provider_name, dict(body.credentials))
            verify = await provider.verify_credentials()
        except DnsProviderError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        except HTTPException:
            raise
        except Exception:
            # Defensive: never let a provider-internal exception string (which could echo creds in a
            # future provider) reach the client. Always a sanitized 422.
            raise HTTPException(status_code=422, detail="DNS provider credential verification failed")
        if not verify.get("ok"):
            raise HTTPException(status_code=422, detail=verify.get("detail") or "DNS provider credential verification failed")

        token = encrypt_dns_credentials(dict(body.credentials))
        await conn.execute(
            """INSERT INTO letsencrypt_account_dns_credentials (account_id, dns_provider, credentials_encrypted, updated_at)
               VALUES ($1, $2, $3, NOW())
               ON CONFLICT (account_id) DO UPDATE SET
                   dns_provider = EXCLUDED.dns_provider,
                   credentials_encrypted = EXCLUDED.credentials_encrypted,
                   updated_at = NOW()""",
            account_id, provider_name, token,
        )
        # Keep the account's provider selection in sync.
        await conn.execute(
            "UPDATE letsencrypt_accounts SET dns_provider = $1, updated_at = NOW() WHERE id = $2",
            provider_name, account_id,
        )
        return {"ok": True, "dns_provider": provider_name, "detail": verify.get("detail", "Credentials stored.")}
    finally:
        await close_database_connection(conn)


@router.delete("/accounts/{account_id}/dns-credentials")
async def delete_dns_credentials(account_id: int, authorization: str = Header(None)):
    """Remove an account's stored DNS credentials. Admin-only."""
    from auth_middleware import get_current_user_from_token
    current_user = await get_current_user_from_token(authorization)
    if not current_user.get('is_admin', False):
        raise HTTPException(status_code=403, detail="Admin access required")
    conn = await get_database_connection()
    try:
        await conn.execute("DELETE FROM letsencrypt_account_dns_credentials WHERE account_id = $1", account_id)
        return {"ok": True}
    finally:
        await close_database_connection(conn)


@router.post("/orders/{order_id}/dns-confirm")
async def confirm_dns_order(order_id: int, authorization: str = Header(None)):
    """Manual DNS-01 only: the user asserts the TXT record is published; tell the CA to validate.
    Requires ssl.create + a per-user rate limit; acts only on a dns-01 + manual + pending order."""
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'create')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.create required")
    await _enforce_dns_confirm_rate_limit(current_user['id'])

    conn = await get_database_connection()
    try:
        order = await conn.fetchrow(
            """SELECT o.id, o.status, o.challenge_type, a.dns_provider
               FROM letsencrypt_orders o JOIN letsencrypt_accounts a ON o.account_id = a.id
               WHERE o.id = $1""",
            order_id,
        )
    finally:
        await close_database_connection(conn)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order['challenge_type'] != 'dns-01' or (order['dns_provider'] or 'manual') != 'manual':
        raise HTTPException(status_code=409, detail="This order is not a manual DNS-01 order")
    if order['status'] not in ('pending', 'processing'):
        raise HTTPException(status_code=409, detail=f"Order is '{order['status']}' and cannot be confirmed")

    from services.dns01_orchestrator import confirm_manual_dns01
    await confirm_manual_dns01(order_id)
    return {"ok": True, "message": "DNS-01 confirmation submitted; the CA will validate shortly."}


# --- Certificate operations ---

@router.post("/certificates")
async def request_certificate(body: CertificateRequest, authorization: str = Header(None)):
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'create')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.create required")

    # Pydantic enforces min_length=1 — this is a defensive double-check.
    if not body.domains:
        raise HTTPException(status_code=400, detail="At least one domain is required")

    logger.info(f"ACME: Certificate request initiated for domains={body.domains}, account_id={body.account_id}, cluster_ids={body.cluster_ids}")

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

        logger.info(f"ACME: Using account_id={account_id} for certificate request")

        warnings = []

        # Issue #35: resolve the effective challenge method (request override, else account default).
        conn_acct = await get_database_connection()
        try:
            acct = await conn_acct.fetchrow(
                "SELECT challenge_type, dns_provider FROM letsencrypt_accounts WHERE id = $1", account_id
            )
        finally:
            await close_database_connection(conn_acct)
        effective_challenge = (body.challenge_type or (acct['challenge_type'] if acct else None) or 'http-01')
        dns_provider = (acct['dns_provider'] if acct else None)
        is_dns01 = (effective_challenge == 'dns-01')
        has_wildcard = any(d.startswith('*.') for d in body.domains)

        if is_dns01:
            if not await _dns01_enabled():
                raise HTTPException(status_code=409, detail="DNS-01 is disabled by an administrator (enable it in Settings).")
            if not is_supported((dns_provider or '').strip()):
                raise HTTPException(status_code=422, detail="The selected ACME account has no DNS provider configured for DNS-01.")
            if (dns_provider or 'manual') == 'manual':
                # Manual DNS-01 cannot be renewed unattended; auto-renew is forced off on the issued
                # certificate (see _complete_certificate). Tell the requester so it isn't a surprise.
                warnings.append(
                    "Manual DNS-01 certificates cannot auto-renew unattended. Auto-renew will be disabled; "
                    "re-publish the TXT record and request renewal before expiry."
                )
        elif has_wildcard:
            raise HTTPException(status_code=422, detail="Wildcard certificates require a DNS-01 account.")

        # Empty cluster_ids = "global certificate". For DNS-01 no ACME Challenge Routing / port 80 is
        # needed, so resolve to ALL active clusters; http-01 still requires acme_enabled clusters.
        if not body.cluster_ids:
            conn_resolve = await get_database_connection()
            try:
                if is_dns01:
                    resolved = await conn_resolve.fetch("SELECT id FROM haproxy_clusters WHERE is_active = TRUE")
                else:
                    resolved = await conn_resolve.fetch("SELECT id FROM haproxy_clusters WHERE acme_enabled = TRUE AND is_active = TRUE")
            finally:
                await close_database_connection(conn_resolve)
            if not resolved:
                if is_dns01:
                    raise HTTPException(status_code=422, detail="Cannot issue certificate: no active clusters configured.")
                raise HTTPException(
                    status_code=422,
                    detail="Cannot issue certificate: no ACME-enabled clusters configured. "
                           "Enable ACME Challenge Routing on at least one cluster in Cluster Management, "
                           "Apply the configuration change, then retry."
                )
            body.cluster_ids = [c['id'] for c in resolved]
            warnings.append(
                f"No clusters specified — applied to all {'active' if is_dns01 else 'ACME-enabled'} cluster(s) ({len(body.cluster_ids)})"
            )
        elif not is_dns01:
            # http-01 only: warn if no cluster has ACME Challenge Routing enabled.
            try:
                conn_warn = await get_database_connection()
                try:
                    acme_clusters = await conn_warn.fetchval(
                        "SELECT COUNT(*) FROM haproxy_clusters WHERE acme_enabled = TRUE AND is_active = TRUE"
                    )
                    if acme_clusters == 0:
                        warnings.append(
                            "No clusters have ACME Challenge Routing enabled. "
                            "Certificate validation will fail. Enable it in Cluster Management and Apply Changes first."
                        )
                finally:
                    await close_database_connection(conn_warn)
            except Exception:
                pass

        order = await acme_service.create_order(
            account_id=account_id,
            domains=body.domains,
            cluster_ids=body.cluster_ids,
            challenge_type=effective_challenge,
            created_by=current_user['id'],
        )

        # Audit trail: record who requested the certificate + the method (esp. for DNS-01/wildcard,
        # which has a wider blast radius than http-01). Never raises into the request path.
        try:
            from utils.activity_log import record_event
            await record_event(
                order['order_id'], "acme.order.requested",
                message=f"Certificate requested ({effective_challenge}) by user {current_user['id']}",
                details={"user_id": current_user['id'], "challenge_type": effective_challenge,
                         "dns_provider": dns_provider, "domains": body.domains},
            )
        except Exception:
            pass

        # http-01 posts the challenge response immediately (token served continuously). dns-01 is
        # driven by the orchestrator AFTER the TXT is published (manual waits for dns-confirm), so we
        # must NOT respond here.
        challenges = []
        if not is_dns01:
            challenges = await acme_service.respond_to_challenges(order['order_id'])

        conn_status = await get_database_connection()
        try:
            fresh_status = await conn_status.fetchval(
                "SELECT status FROM letsencrypt_orders WHERE id = $1",
                order['order_id']
            )
        finally:
            await close_database_connection(conn_status)
        effective_status = fresh_status or order['status']

        if is_dns01:
            msg = ("Order created. Publish the DNS TXT record shown for each domain, then confirm."
                   if dns_provider == 'manual'
                   else "Order created. The DNS TXT record(s) will be published automatically; waiting for CA validation.")
        else:
            msg = "Order created. ACME challenges have been posted. Waiting for CA validation."

        logger.info(f"ACME: Order {order['order_id']} created ({effective_challenge}), status={effective_status}")

        return {
            "order_id": order['order_id'],
            "status": effective_status,
            "domains": body.domains,
            "challenge_type": effective_challenge,
            "dns_provider": dns_provider,
            "challenges": challenges,
            "message": msg,
            "warnings": warnings,
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
                   o.created_at, o.updated_at, o.challenge_type, a.email as account_email,
                   a.dns_provider
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
                   o.created_at, o.updated_at, o.challenge_type, a.email as account_email,
                   a.dns_provider
            FROM letsencrypt_orders o
            JOIN letsencrypt_accounts a ON o.account_id = a.id
            WHERE o.id = $1
        """, order_id)
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")

        # Issue #35: include challenge_type + dns_txt_value (PUBLIC DNS data — NOT key_authorization,
        # NOT the API token) so the UI can render manual DNS-01 instructions. Explicit column list.
        challenges = await conn.fetch(
            "SELECT id, order_id, domain, token, challenge_url, status, validated_at, created_at, "
            "challenge_type, dns_txt_value FROM acme_challenges WHERE order_id = $1 ORDER BY domain", order_id
        )
        result = dict(order)
        result['domains'] = json.loads(result['domains']) if isinstance(result['domains'], str) else result['domains']
        result['cluster_ids'] = json.loads(result['cluster_ids']) if isinstance(result['cluster_ids'], str) else result['cluster_ids']
        ch_list = []
        for c in challenges:
            cd = dict(c)
            if cd.get('challenge_type') == 'dns-01':
                # Server computes the record name (wildcard *.-stripping lives server-side).
                cd['dns_record_name'] = acme_service._challenge_dns_name(cd['domain'])
            ch_list.append(cd)
        result['challenges'] = ch_list
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
        # Idempotency + concurrency guard. Two checks in one round-trip:
        #   1. ssl_certificate_id NOT NULL   -> already done, return success
        #   2. updated_at touched in last 30s -> auto-completion task is actively
        #      processing this order. Returning a 202-style hint avoids a
        #      simultaneous duplicate _complete_certificate() race that would
        #      hit the ssl_certificates UNIQUE(name) constraint and cost an
        #      extra CA download.
        conn = await get_database_connection()
        try:
            row = await conn.fetchrow(
                """SELECT ssl_certificate_id,
                          (updated_at IS NOT NULL AND updated_at > NOW() - INTERVAL '30 seconds')
                              AS recently_touched
                   FROM letsencrypt_orders WHERE id = $1""",
                order_id
            )
        finally:
            await close_database_connection(conn)
        if not row:
            raise HTTPException(status_code=404, detail="Order not found")
        if row['ssl_certificate_id']:
            return {
                "message": "Certificate already issued for this order",
                "order_id": order_id,
                "certificate_id": row['ssl_certificate_id'],
            }
        if row['recently_touched']:
            return {
                "message": "Order is currently being processed by the auto-completion task. "
                           "Please wait ~60 seconds and refresh.",
                "order_id": order_id,
                "in_progress": True,
            }

        status_info = await acme_service.check_order_status(order_id)
        current_status = status_info.get('status')

        if current_status == 'invalid':
            raise HTTPException(
                status_code=409,
                detail="This order is invalid and cannot be retried. "
                       "Please cancel it and create a new certificate request."
            )
        if current_status == 'cancelled':
            raise HTTPException(
                status_code=409,
                detail="This order has been cancelled. Please create a new certificate request."
            )

        if current_status == 'ready':
            result = await acme_service.finalize_order(order_id)
            safe_result = {k: v for k, v in result.items() if k not in ('private_key_pem', 'cert_private_key')}
            return {"message": "Order finalized", **safe_result}
        elif current_status == 'valid':
            # Issue #12 / Commit 3b: handle valid-without-certificate-url edge case.
            # CA marked the order valid but our DB has no certificate_url yet
            # (race between finalize and check_order_status). Trigger finalize
            # if not yet done, then drive completion.
            if not status_info.get('certificate_url'):
                logger.info(f"ACME RETRY: Order {order_id} valid without certificate_url, attempting finalize")
                try:
                    await acme_service.finalize_order(order_id)
                except Exception as fin_err:
                    # Order may already be finalized server-side; re-poll status
                    logger.warning(f"ACME RETRY: finalize_order returned {fin_err}, re-polling status")
                status_info = await acme_service.check_order_status(order_id)
                current_status = status_info.get('status')
            
            if current_status == 'valid' and status_info.get('certificate_url'):
                return await _complete_certificate(order_id)
            else:
                return {
                    "message": f"Order is valid but certificate URL not yet available (status={current_status}). "
                               f"Auto-completion task will retry within 60 seconds.",
                    "order_id": order_id,
                    "status": current_status,
                }
        else:
            # pending / processing — re-submit challenges
            challenges = await acme_service.respond_to_challenges(order_id)
            return {"message": "Challenges re-submitted", "status": current_status, "challenges": challenges}
    except HTTPException:
        raise
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
            "SELECT account_id, domains, cluster_ids, challenge_type FROM letsencrypt_orders WHERE id = $1", order_id
        )
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
        domains = json.loads(order['domains']) if isinstance(order['domains'], str) else order['domains']
        cluster_ids = json.loads(order['cluster_ids']) if isinstance(order['cluster_ids'], str) else order['cluster_ids']
        challenge_type = order['challenge_type'] or 'http-01'

        new_order = await acme_service.create_order(
            account_id=order['account_id'], domains=domains, cluster_ids=cluster_ids,
            challenge_type=challenge_type, created_by=current_user['id'],
        )
        # dns-01 is driven by the orchestrator after the TXT is published; only http-01 responds here.
        challenges = []
        if challenge_type != 'dns-01':
            challenges = await acme_service.respond_to_challenges(new_order['order_id'])
        return {"message": "Renewal order created", "new_order_id": new_order['order_id'], "challenge_type": challenge_type, "challenges": challenges}
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
            "UPDATE letsencrypt_orders SET status = 'cancelled', updated_at = NOW() WHERE id = $1 AND status NOT IN ('valid', 'cancelled')",
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
        # Issue #35: expose the challenge method/provider (via the originating order/account) so the
        # UI can distinguish manual DNS-01 certs, which cannot auto-renew unattended. LEFT JOINs keep
        # legacy certs (no order link / pre-DNS-01 columns) rendering as http-01.
        certs = await conn.fetch("""
            SELECT c.id, c.name, c.primary_domain, c.expiry_date, c.auto_renew, c.days_until_expiry,
                   o.challenge_type, a.dns_provider
            FROM ssl_certificates c
            LEFT JOIN letsencrypt_orders o ON o.id = c.letsencrypt_order_id
            LEFT JOIN letsencrypt_accounts a ON a.id = o.account_id
            WHERE c.source = 'letsencrypt' AND c.is_active = TRUE
            ORDER BY c.expiry_date ASC NULLS LAST
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
    # Concurrency guard: PostgreSQL session-level advisory lock keyed on order_id.
    # Serializes concurrent _complete_certificate(order_id) calls across this
    # process and across replicas (user-clicks-Complete + auto-completion task,
    # or two simultaneous user clicks). A second caller blocks here until the
    # first finishes, then re-reads ssl_certificate_id below and exits via the
    # idempotency guard. Released in the outer finally before connection close.
    # Namespace 0x41434D45 ('ACME' ASCII) XOR'd with order_id to avoid collision.
    ADVISORY_NS = 0x41434D45
    await conn.execute("SELECT pg_advisory_lock($1, $2)", ADVISORY_NS, order_id)
    lock_held = True
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

        # Issue #35: a manual DNS-01 certificate cannot be auto-renewed unattended (the renewal task
        # skips it — see main.py), so persist auto_renew=FALSE rather than storing a misleading
        # "Enabled" that the user trusts while the cert silently expires. http-01 and automated
        # DNS-01 (e.g. Cloudflare) keep auto_renew=TRUE, preserving existing behaviour.
        auto_renew_value = True
        if order.get('challenge_type') == 'dns-01':
            acct_provider = await conn.fetchval(
                "SELECT dns_provider FROM letsencrypt_accounts WHERE id = $1", order['account_id']
            )
            if (acct_provider or 'manual') == 'manual':
                auto_renew_value = False

        # Commit 5g: guard against empty cert_private_key.
        # Inserting an SSL certificate row with an empty private_key would silently
        # produce an unusable certificate (HAProxy would fail to load on Apply, or
        # SSL handshakes would fail at runtime). Fail-fast with a clear diagnostic
        # so the user can re-finalize the order.
        private_key_pem = order.get('cert_private_key') or ''
        if not private_key_pem.strip() or '-----BEGIN' not in private_key_pem:
            error_payload = json.dumps({
                "stage": "_complete_certificate",
                "reason": "missing_or_invalid_cert_private_key",
                "private_key_present": bool(private_key_pem),
                "timestamp": datetime.utcnow().isoformat(),
            })
            try:
                await conn.execute(
                    "UPDATE letsencrypt_orders SET status = 'invalid', error_detail = $1, updated_at = NOW() WHERE id = $2",
                    error_payload, order_id
                )
            except Exception:
                pass
            raise Exception(
                f"Cannot complete order {order_id}: cert_private_key is missing or invalid. "
                f"This indicates finalize_order() did not persist the key correctly. "
                f"Cancel this order and create a new certificate request."
            )

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
                # Issue #10: ssl_certificates.expiry_date column is TIMESTAMP (timezone-naive).
                # parse_ssl_certificate always returns timezone-aware UTC datetime.
                # Without normalization asyncpg silently fails the INSERT/UPDATE for tz-aware
                # values, leaving expiry_date NULL and breaking auto-renewal.
                if expiry_date is not None and getattr(expiry_date, 'tzinfo', None) is not None:
                    from datetime import timezone
                    expiry_date = expiry_date.astimezone(timezone.utc).replace(tzinfo=None)
                days_until_expiry = cert_info.get('days_until_expiry', 0)
                issuer = cert_info.get('issuer')
                fingerprint = cert_info.get('fingerprint')
                if cert_info.get('all_domains'):
                    all_domains = json.dumps(cert_info['all_domains'])
        except Exception as parse_err:
            logger.warning(f"Could not parse ACME certificate metadata: {parse_err}")

        # v1.5.0 (Bulgu #4 fix): a wizard-staged order ALWAYS expects a fresh
        # cert + post-completion actions to fire. If `post_completion_actions`
        # is non-empty we must NOT match against a manually-issued cert that
        # happens to share the same primary_domain — that would silently
        # swallow the HTTPS frontend creation and leave the wizard host
        # broken.
        pca_raw_for_match = order.get("post_completion_actions")
        try:
            _pca_check = (
                json.loads(pca_raw_for_match)
                if isinstance(pca_raw_for_match, str) and pca_raw_for_match.strip()
                else (pca_raw_for_match or [])
            )
        except Exception:
            _pca_check = []
        is_wizard_order = bool(_pca_check)

        if is_wizard_order:
            existing_cert = None
        else:
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
                    auto_renew = $11, is_active = TRUE, last_config_status = 'PENDING',
                    updated_at = NOW()
                WHERE id = $10
            """, cert_data['certificate_pem'], private_key_pem,
                cert_data.get('chain_pem', ''), all_domains,
                expiry_date, days_until_expiry, issuer, fingerprint, order_id, cert_id,
                auto_renew_value)
            logger.info(f"ACME RENEWAL: Updated certificate {cert_id} for {primary_domain}, status=PENDING")
        else:
            cert_row = await conn.fetchrow("""
                INSERT INTO ssl_certificates
                    (name, certificate_content, private_key_content, chain_content,
                     primary_domain, all_domains, expiry_date, days_until_expiry, issuer, fingerprint,
                     usage_type, source, letsencrypt_order_id, auto_renew, is_active,
                     last_config_status)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10,
                        'frontend', 'letsencrypt', $11, $12, TRUE, 'PENDING')
                RETURNING id
            """, f"le-{primary_domain}", cert_data['certificate_pem'], private_key_pem,
                cert_data.get('chain_pem', ''), primary_domain, all_domains,
                expiry_date, days_until_expiry, issuer, fingerprint, order_id,
                auto_renew_value)
            cert_id = cert_row['id']

        await conn.execute(
            "UPDATE letsencrypt_orders SET ssl_certificate_id = $1, status = 'valid', updated_at = NOW() WHERE id = $2",
            cert_id, order_id
        )

        # Issue #12 / Commit 3c: idempotent ssl_certificate_clusters reconcile.
        # On renewal, the order may carry a different cluster_ids list than the
        # original cert's junction (user added new clusters between issue and renewal).
        # We INSERT new entries (additive, ON CONFLICT DO NOTHING) but never DELETE
        # existing junction rows — manually-added cluster assignments are preserved.
        if cluster_ids:
            existing_cluster_set = set()
            if is_renewal:
                existing_rows = await conn.fetch(
                    "SELECT cluster_id FROM ssl_certificate_clusters WHERE ssl_certificate_id = $1",
                    cert_id
                )
                existing_cluster_set = {r['cluster_id'] for r in existing_rows}
                new_clusters = [cid for cid in cluster_ids if cid not in existing_cluster_set]
                if new_clusters:
                    logger.info(
                        f"ACME RENEWAL: Adding {len(new_clusters)} new cluster(s) to cert {cert_id}: {new_clusters}"
                    )
                # WARN if order mentioned clusters that were manually removed from junction
                missing_in_order = existing_cluster_set - set(cluster_ids)
                if missing_in_order:
                    logger.warning(
                        f"ACME RENEWAL: cert {cert_id} has manual junction entries not in order.cluster_ids: "
                        f"{sorted(missing_in_order)}. Preserving manual assignments."
                    )
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
                # Audit Tur 6 / Commit 5j: http-01 only falls back to ACME-enabled clusters.
                # Issue #35: a dns-01 cert needs NO challenge routing / port 80, so it can renew on
                # any active cluster — resolve to all active clusters for dns-01.
                ch_type = await conn.fetchval(
                    "SELECT challenge_type FROM letsencrypt_orders WHERE id = $1", order_id
                )
                if ch_type == 'dns-01':
                    all_clusters = await conn.fetch("SELECT id FROM haproxy_clusters WHERE is_active = TRUE")
                else:
                    all_clusters = await conn.fetch(
                        "SELECT id FROM haproxy_clusters WHERE is_active = TRUE AND acme_enabled = TRUE"
                    )
                effective_cluster_ids = [r['id'] for r in all_clusters]
            if effective_cluster_ids:
                logger.info(f"ACME RENEWAL: Resolved {len(effective_cluster_ids)} cluster(s) for global cert {cert_id}")

        admin_uid = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1

        # Issue #12 / Commit 4d: per-cluster error tracking + observability.
        cluster_errors = []  # [{cluster_id, error}]
        clusters_succeeded = []

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
                clusters_succeeded.append(cid)
            except Exception as ve:
                # Was logger.error swallowing details; now surface to API caller.
                logger.error(
                    f"[ACME] Failed to create config version for cluster {cid} "
                    f"(cert {cert_id}, action {action}): {ve}",
                    exc_info=True
                )
                cluster_errors.append({"cluster_id": cid, "error": str(ve)})

        if is_renewal and clusters_succeeded:
            await _auto_apply_renewal(cert_id, clusters_succeeded)

        # ====================================================================
        # v1.5.0 Feature B (Issue #14): post_completion_actions JSONB support.
        #
        # The wizard staged this order with a deferred HTTPS-frontend create
        # request. Now that the cert is downloaded we execute it.
        #
        # M2 guard: NEVER run on renewal — renewing a wizard-issued cert
        # must not re-create the HTTPS frontend.
        # M3 cancellation race: re-fetch the order's status before exec.
        # M21/R35 collision re-check: re-validate bind_port collision.
        # M24 conn reuse: pass our existing transaction conn into record_event.
        # M26/R42 atomicity: wrap each action in its own conn.transaction().
        # ====================================================================
        post_completion_outcomes: list = []
        if not is_renewal:
            try:
                pca_raw = order.get("post_completion_actions")
                if isinstance(pca_raw, str) and pca_raw.strip():
                    pca = json.loads(pca_raw)
                elif isinstance(pca_raw, list):
                    pca = pca_raw
                else:
                    pca = []
            except Exception:
                pca = []

            if pca:
                # M3: re-check status to detect a cancellation race
                fresh = await conn.fetchrow(
                    "SELECT status FROM letsencrypt_orders WHERE id = $1", order_id
                )
                if fresh and fresh["status"] == "valid":
                    post_completion_outcomes = await _execute_post_completion_actions(
                        conn, order_id, pca, cert_id
                    )
                else:
                    logger.info(
                        f"[ACME] Skipping post_completion_actions for order {order_id}: "
                        f"status changed to {fresh and fresh['status']}"
                    )

        msg = "Certificate renewed and applied" if is_renewal else "Certificate issued (pending Apply)"
        if cluster_errors:
            msg += f" ({len(cluster_errors)} cluster(s) failed: see cluster_errors)"
        return {
            "message": msg,
            "certificate_id": cert_id,
            "domains": domains,
            "auto_applied": is_renewal,
            "clusters_succeeded": clusters_succeeded,
            "cluster_errors": cluster_errors,
            "post_completion_outcomes": post_completion_outcomes,
        }
    finally:
        if lock_held:
            try:
                await conn.execute("SELECT pg_advisory_unlock($1, $2)", ADVISORY_NS, order_id)
            except Exception as unlock_err:
                logger.warning(f"ACME: failed to release advisory lock for order {order_id}: {unlock_err}")
        await close_database_connection(conn)


async def _execute_post_completion_actions(
    conn,
    order_id: int,
    actions: list,
    cert_id: int,
) -> list:
    """v1.5.0 Feature B: execute the deferred actions stored on a wizard
    ACME order's post_completion_actions JSONB.

    Each action is independently wrapped in conn.transaction() (R42/M26),
    has its own try/except (per-action errors do NOT block other actions),
    and an executed_at idempotency flag.

    Auto-apply is triggered if any executed action set _auto_apply=true on
    its frontend_config.
    """
    from utils.activity_log import record_event
    from services.frontend_service import (
        check_bind_port_collision,
        create_frontend_row,
    )

    outcomes = []
    auto_apply_user_ids: set = set()
    auto_apply_cluster_ids: set = set()

    for idx, action in enumerate(actions):
        if not isinstance(action, dict):
            outcomes.append({"index": idx, "status": "skipped", "reason": "not a dict"})
            continue

        if action.get("executed_at"):
            outcomes.append({"index": idx, "status": "skipped", "reason": "already executed"})
            continue

        action_type = action.get("type")
        try:
            async with conn.transaction():
                if action_type == "create_frontend":
                    fe_cfg = action.get("frontend_config") or {}
                    cluster_id = fe_cfg.get("cluster_id")
                    bind_address = fe_cfg.get("bind_address", "*")
                    bind_port = fe_cfg.get("bind_port", 443)
                    fe_name = fe_cfg.get("name") or f"fe-{order_id}-https"

                    if not cluster_id:
                        raise ValueError("frontend_config.cluster_id required")

                    # Bulgu #52 (round-18 audit) — verify the cluster still
                    # exists before any further work.
                    #
                    # `letsencrypt_orders.cluster_ids` is JSONB (not an FK),
                    # so an operator can delete a cluster between
                    # `wizard_staged` and post-completion. With the previous
                    # code path:
                    #
                    #   - check_bind_port_collision would find no frontends
                    #     for the missing cluster (returns None — no
                    #     collision)
                    #   - the backend-existence check would correctly flag
                    #     `backend_missing` IF a default_backend was set,
                    #     but actions without `default_backend` (legacy
                    #     payloads, TCP-mode wizard runs) would proceed to
                    #     create_frontend_row pointing at a dead
                    #     cluster_id, then fail with a FK violation that
                    #     surfaces only in the logs.
                    #
                    # Catch this upfront with the same shape as the
                    # `backend_missing` outcome so the operator sees a
                    # clear "cluster removed — re-run the wizard" message
                    # in the order's activity log instead of a generic
                    # FK error.
                    cluster_row = await conn.fetchrow(
                        "SELECT id FROM haproxy_clusters "
                        "WHERE id = $1 AND is_active = TRUE",
                        cluster_id,
                    )
                    if cluster_row is None:
                        action["error"] = "cluster_missing"
                        action["error_detail"] = (
                            f"Cluster id={cluster_id} no longer exists "
                            "(or was deactivated) — the wizard's target "
                            "cluster was removed after the ACME order "
                            "was staged. Cert was issued but no HTTPS "
                            "frontend was created. Re-run the wizard "
                            "against an active cluster, or assign the "
                            "issued cert to a frontend manually."
                        )
                        await record_event(
                            order_id,
                            "post_completion_action_skipped",
                            severity="ERROR",
                            message=action["error_detail"],
                            details={
                                "action_index": idx,
                                "type": action_type,
                                "missing_cluster_id": cluster_id,
                            },
                            conn=conn,
                        )
                        outcomes.append({
                            "index": idx, "status": "error",
                            "reason": "cluster_missing",
                            "detail": action["error_detail"],
                        })
                        continue

                    # M21/R35: re-check port collision pre-INSERT
                    collision = await check_bind_port_collision(
                        conn, cluster_id, bind_address, bind_port
                    )
                    if collision:
                        action["error"] = "port_collision"
                        action["error_detail"] = (
                            f"bind {bind_address}:{bind_port} already used by frontend id={collision}"
                        )
                        await record_event(
                            order_id,
                            "post_completion_action_skipped",
                            severity="ERROR",
                            message=action["error_detail"],
                            details={"action_index": idx, "type": action_type},
                            conn=conn,
                        )
                        outcomes.append({
                            "index": idx, "status": "error",
                            "reason": "port_collision",
                            "detail": action["error_detail"],
                        })
                        continue

                    # Bulgu #31 (round-13 audit) — referenced default_backend
                    # MUST still exist before we insert the deferred HTTPS
                    # frontend. The wizard's HTTP frontend + backend are
                    # created at submit time and become part of the
                    # `bulk-site-create-<ts>` config version's snapshot. If
                    # the operator REJECTS that version between apply and
                    # post-completion, the snapshot rollback deletes the
                    # backend rows. `create_frontend_row` would still
                    # happily INSERT this HTTPS frontend with
                    # `default_backend='be_xxx'` — and HAProxy then refuses
                    # to load the config at the next apply with:
                    #
                    #     [ALERT] : Proxy 'fe_xxx-https' references unknown
                    #               backend 'be_xxx'.
                    #
                    # Operator sees an unrecoverable "config parse error"
                    # AFTER the cert was already issued and the order
                    # marked 'valid' — leaving an orphan cert and a
                    # locked-up apply queue. Bail early with a clear
                    # message so the operator can re-run the wizard or
                    # create the HTTPS frontend manually pointing at a
                    # different backend.
                    default_be_name = fe_cfg.get("default_backend")
                    if default_be_name:
                        be_row = await conn.fetchrow(
                            "SELECT id FROM backends "
                            "WHERE cluster_id = $1 AND name = $2",
                            cluster_id,
                            default_be_name,
                        )
                        if be_row is None:
                            action["error"] = "backend_missing"
                            action["error_detail"] = (
                                f"default_backend='{default_be_name}' no "
                                f"longer exists in cluster {cluster_id} "
                                "— the wizard's bulk-site-create version "
                                "was likely rejected after issuance. "
                                "Cert was issued but no HTTPS frontend "
                                "was created. Re-run the wizard or "
                                "create the HTTPS frontend manually."
                            )
                            await record_event(
                                order_id,
                                "post_completion_action_skipped",
                                severity="ERROR",
                                message=action["error_detail"],
                                details={
                                    "action_index": idx,
                                    "type": action_type,
                                    "missing_backend": default_be_name,
                                },
                                conn=conn,
                            )
                            outcomes.append({
                                "index": idx, "status": "error",
                                "reason": "backend_missing",
                                "detail": action["error_detail"],
                            })
                            continue

                    # v1.5.0 R12 — Pydantic-light shim with FULL field
                    # surface. create_frontend_row reads every attribute
                    # via getattr(payload, X, None), so we MUST forward
                    # every advanced TLS / HSTS / header field the wizard
                    # may have stored on frontend_config. Earlier versions
                    # of this shim only listed a handful of fields, which
                    # silently dropped HSTS / ALPN / TLS-version /
                    # compression preferences for ACME-issued HTTPS
                    # frontends — visible to the user as "I enabled HSTS
                    # but the frontend doesn't have it" after the LE order
                    # completed.
                    from types import SimpleNamespace
                    fe_payload = SimpleNamespace(
                        # core
                        name=fe_name,
                        bind_address=bind_address,
                        bind_port=bind_port,
                        default_backend=fe_cfg.get("default_backend"),
                        mode=fe_cfg.get("mode", "http"),
                        ssl_enabled=True,
                        # routing rules
                        acl_rules=fe_cfg.get("acl_rules", []),
                        redirect_rules=fe_cfg.get("redirect_rules", []),
                        use_backend_rules=fe_cfg.get("use_backend_rules", []),
                        # tcp-mode
                        tcp_request_rules=fe_cfg.get("tcp_request_rules"),
                        # timeouts + capacity
                        timeout_client=fe_cfg.get("timeout_client"),
                        timeout_http_request=fe_cfg.get("timeout_http_request"),
                        maxconn=fe_cfg.get("maxconn"),
                        rate_limit=fe_cfg.get("rate_limit"),
                        # observability + traffic shaping
                        compression=fe_cfg.get("compression"),
                        log_separate=fe_cfg.get("log_separate"),
                        monitor_uri=fe_cfg.get("monitor_uri"),
                        # header injection (HSTS lands here)
                        request_headers=fe_cfg.get("request_headers"),
                        response_headers=fe_cfg.get("response_headers"),
                        # raw HAProxy options (free-form lines)
                        options=fe_cfg.get("options"),
                        # advanced TLS — HAProxy 2.4+ bind directives
                        ssl_alpn=fe_cfg.get("ssl_alpn"),
                        ssl_npn=fe_cfg.get("ssl_npn"),
                        ssl_ciphers=fe_cfg.get("ssl_ciphers"),
                        ssl_ciphersuites=fe_cfg.get("ssl_ciphersuites"),
                        ssl_min_ver=fe_cfg.get("ssl_min_ver"),
                        ssl_max_ver=fe_cfg.get("ssl_max_ver"),
                        ssl_strict_sni=fe_cfg.get("ssl_strict_sni"),
                        # R17 minimum-parity: ssl_verify (mTLS client auth)
                        # was already in the SimpleNamespace forwarding list
                        # but the wizard's SSLChoice now actually populates
                        # it. No code change here, but call out the contract:
                        # SimpleNamespace.ssl_verify must reach
                        # create_frontend_row's HAProxy bind generation.
                        ssl_verify=fe_cfg.get("ssl_verify"),
                        ssl_port=fe_cfg.get("ssl_port"),
                        ssl_cert_path=fe_cfg.get("ssl_cert_path"),
                        ssl_cert=fe_cfg.get("ssl_cert"),
                    )
                    new_fe_id = await create_frontend_row(
                        conn,
                        fe_payload,
                        cluster_id,
                        ssl_certificate_id=cert_id,
                        ssl_enabled=True,
                        mark_pending=True,
                    )

                    action["executed_at"] = datetime.utcnow().isoformat() + "Z"
                    action["created_frontend_id"] = new_fe_id

                    # Persist the executed_at flag back to the order (idempotency)
                    await conn.execute(
                        """
                        UPDATE letsencrypt_orders
                        SET post_completion_actions = $1::jsonb, updated_at = NOW()
                        WHERE id = $2
                        """,
                        json.dumps(actions),
                        order_id,
                    )

                    # Generate a fresh PENDING config_version so the new
                    # HTTPS frontend can be applied.
                    try:
                        # R18c audit fix (round 1 #4 — KRITIK): pass
                        # the active transaction connection into the
                        # config generator. Pre-fix the call obtained
                        # a SECOND pooled connection, which under
                        # PostgreSQL READ COMMITTED cannot see the
                        # uncommitted INSERT that just created the
                        # HTTPS frontend in this same transaction.
                        # Result: the new HTTPS frontend was silently
                        # OMITTED from the post-completion
                        # config_versions snapshot, so when the
                        # operator (or auto-apply) deployed the
                        # ACME-completed config, HAProxy reloaded
                        # WITHOUT the HTTPS bind for the freshly-
                        # issued cert. Operator saw "ACME success"
                        # but the cert never went live until the
                        # next manual config consolidation.
                        from services.haproxy_config import generate_haproxy_config_for_cluster
                        cfg = await generate_haproxy_config_for_cluster(cluster_id, conn)
                        import hashlib
                        cfg_hash = hashlib.sha256(cfg.encode()).hexdigest()
                        ts = int(time.time())
                        version_name = f"acme-post-https-{cert_id}-{ts}"
                        await conn.execute(
                            """
                            INSERT INTO config_versions (
                                cluster_id, version_name, config_content, checksum,
                                is_active, status, description
                            ) VALUES ($1, $2, $3, $4, FALSE, 'PENDING', $5)
                            """,
                            cluster_id,
                            version_name,
                            cfg,
                            cfg_hash,
                            f"ACME post-completion: HTTPS frontend for cert {cert_id}",
                        )
                    except Exception as cfg_err:
                        logger.warning(
                            f"[ACME] post_completion config_version creation failed: {cfg_err}"
                        )

                    if fe_cfg.get("_auto_apply"):
                        auto_apply_cluster_ids.add(cluster_id)
                        if fe_cfg.get("_user_id"):
                            auto_apply_user_ids.add(fe_cfg["_user_id"])

                    await record_event(
                        order_id,
                        "post_completion_action_executed",
                        severity="INFO",
                        message=f"Created HTTPS frontend '{fe_name}' from post_completion_actions",
                        details={"action_index": idx, "frontend_id": new_fe_id},
                        conn=conn,
                    )
                    outcomes.append({
                        "index": idx, "status": "ok",
                        "frontend_id": new_fe_id,
                        "type": action_type,
                    })
                else:
                    outcomes.append({
                        "index": idx, "status": "skipped",
                        "reason": f"unknown action type: {action_type}",
                    })
        except Exception as action_err:
            logger.error(f"[ACME] post_completion action {idx} failed: {action_err}", exc_info=True)
            outcomes.append({"index": idx, "status": "error", "reason": str(action_err)})
            try:
                await record_event(
                    order_id,
                    "post_completion_action_failed",
                    severity="ERROR",
                    message=str(action_err)[:500],
                    details={"action_index": idx, "type": action_type},
                    conn=conn,
                )
            except Exception:
                pass

    # Auto-apply if requested
    if auto_apply_cluster_ids:
        try:
            from services.apply_service import apply_cluster_pending
            for cid in auto_apply_cluster_ids:
                # Order's created_by lookup with admin fallback (M23/M46)
                user_for_apply = None
                if auto_apply_user_ids:
                    user_for_apply = next(iter(auto_apply_user_ids))
                if user_for_apply is None:
                    order_row = await conn.fetchrow(
                        "SELECT created_by FROM letsencrypt_orders WHERE id = $1",
                        order_id,
                    )
                    if order_row:
                        user_for_apply = order_row["created_by"]
                # apply_service handles None via is_admin fallback
                try:
                    apply_res = await apply_cluster_pending(cid, user_id=user_for_apply)
                    await record_event(
                        order_id,
                        "post_completion_auto_apply",
                        severity="INFO",
                        message=f"Auto-applied cluster {cid} after post_completion_actions",
                        details={"latest_version": apply_res.get("latest_version")},
                        conn=conn,
                    )
                except Exception as apply_err:
                    logger.error(
                        f"[ACME] post_completion auto-apply for cluster {cid} failed: {apply_err}"
                    )
                    await record_event(
                        order_id,
                        "post_completion_auto_apply_failed",
                        severity="ERROR",
                        message=str(apply_err)[:500],
                        details={"cluster_id": cid},
                        conn=conn,
                    )
        except Exception as outer_apply_err:
            logger.error(f"[ACME] post_completion auto-apply outer failure: {outer_apply_err}")

    return outcomes


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


@router.get("/prerequisites")
async def check_prerequisites(authorization: str = Header(None)):
    """Check ACME prerequisites and return step-by-step setup status with navigation hints."""
    from auth_middleware import get_current_user_from_token, check_user_permission
    current_user = await get_current_user_from_token(authorization)
    has_perm = await check_user_permission(current_user['id'], 'ssl', 'read')
    if not has_perm:
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.read required")

    conn = await get_database_connection()
    try:
        steps = []

        # Step 1: ACME Settings configured
        dir_url = await conn.fetchval(
            "SELECT value FROM system_settings WHERE key = 'acme.directory_url'"
        )
        dir_url_str = ""
        if dir_url:
            try:
                parsed = json.loads(dir_url) if isinstance(dir_url, str) else dir_url
                dir_url_str = str(parsed) if not isinstance(parsed, str) else parsed
            except (json.JSONDecodeError, TypeError, ValueError):
                dir_url_str = str(dir_url)

        provider_row = await conn.fetchval(
            "SELECT value FROM system_settings WHERE key = 'acme.provider'"
        )
        provider = ""
        if provider_row:
            try:
                parsed = json.loads(provider_row) if isinstance(provider_row, str) else provider_row
                provider = str(parsed) if not isinstance(parsed, str) else parsed
            except (json.JSONDecodeError, TypeError, ValueError):
                provider = str(provider_row)

        settings_ok = bool(dir_url_str and dir_url_str.startswith("http"))
        settings_detail = f"Provider: {provider or 'Not set'}, Directory URL configured" if settings_ok else "ACME provider and directory URL not configured"
        steps.append({
            "key": "acme_settings",
            "title": "Configure ACME Settings",
            "ok": settings_ok,
            "detail": settings_detail,
            "navigate": "/settings?tab=acme",
        })

        # Step 2: ACME Account registered
        account = await conn.fetchrow(
            "SELECT id, email FROM letsencrypt_accounts WHERE status = 'valid' ORDER BY created_at DESC LIMIT 1"
        )
        account_ok = account is not None
        account_detail = f"Active account: {account['email']}" if account else "No active ACME account registered"
        steps.append({
            "key": "acme_account",
            "title": "Register ACME Account",
            "ok": account_ok,
            "detail": account_detail,
            "action": "register_account",
        })

        # Pre-fetch ACME-related pending versions (used by both Step 3 and Step 4)
        pending_rows = await conn.fetch("""
            SELECT c.id AS cluster_id, c.name AS cluster_name, COUNT(*) AS cnt
            FROM config_versions cv
            JOIN haproxy_clusters c ON c.id = cv.cluster_id
            WHERE cv.status = 'PENDING'
              AND c.is_active = TRUE
              AND (c.acme_enabled = TRUE OR cv.version_name LIKE 'cluster-%-acme-%')
            GROUP BY c.id, c.name
        """)
        pending_count = sum(r['cnt'] for r in pending_rows)
        pending_clusters = [{"id": r['cluster_id'], "name": r['cluster_name'], "count": r['cnt']} for r in pending_rows]
        pending_enable_cluster_ids = set()
        pe_rows = await conn.fetch("""
            SELECT DISTINCT cv.cluster_id
            FROM config_versions cv
            JOIN haproxy_clusters c ON c.id = cv.cluster_id
            WHERE cv.status = 'PENDING'
              AND c.is_active = TRUE
              AND cv.version_name LIKE 'cluster-%-acme-enable-%'
        """)
        for r in pe_rows:
            pending_enable_cluster_ids.add(r['cluster_id'])

        # Step 3: Cluster ACME enabled
        acme_clusters_rows = await conn.fetch(
            "SELECT id, name FROM haproxy_clusters WHERE acme_enabled = TRUE AND is_active = TRUE"
        )
        has_enabled = len(acme_clusters_rows) > 0
        any_pending_enable = has_enabled and any(r['id'] in pending_enable_cluster_ids for r in acme_clusters_rows)
        if has_enabled:
            name_parts = []
            for r in acme_clusters_rows:
                if r['id'] in pending_enable_cluster_ids:
                    name_parts.append(f"{r['name']} (pending apply)")
                else:
                    name_parts.append(r['name'])
            if any_pending_enable:
                cluster_ok = "pending"
                cluster_detail = f"Enabled on: {', '.join(name_parts)} — go to Apply Management to activate"
                cluster_navigate = "/apply-management"
                step3_pending_clusters = [{"id": r['cluster_id'], "name": r['cluster_name'], "count": r['cnt']} for r in pending_rows if r['cluster_id'] in pending_enable_cluster_ids]
            else:
                cluster_ok = True
                cluster_detail = f"Enabled on: {', '.join(name_parts)}"
                cluster_navigate = "/clusters"
                step3_pending_clusters = []
        else:
            cluster_ok = False
            cluster_detail = "No clusters have ACME Challenge Routing enabled"
            cluster_navigate = "/clusters"
            step3_pending_clusters = []
        steps.append({
            "key": "cluster_acme_enabled",
            "title": "Enable ACME on Cluster",
            "ok": cluster_ok,
            "detail": cluster_detail,
            "navigate": cluster_navigate,
            "pending_clusters": step3_pending_clusters,
        })

        # Step 4: Configuration applied
        if has_enabled:
            config_ok = pending_count == 0
            if config_ok:
                config_detail = "All ACME cluster configurations are applied"
            else:
                names = ', '.join(r['cluster_name'] for r in pending_rows)
                config_detail = f"{pending_count} pending configuration change(s) on cluster: {names}"
        elif pending_count > 0:
            config_ok = False
            names = ', '.join(r['cluster_name'] for r in pending_rows)
            config_detail = f"{pending_count} pending configuration change(s) on cluster: {names}"
        else:
            config_ok = None
            config_detail = "Enable ACME on a cluster first, then apply changes"
            pending_clusters = []
        steps.append({
            "key": "config_applied",
            "title": "Apply Configuration Changes",
            "ok": config_ok,
            "detail": config_detail,
            "navigate": "/apply-management",
            "pending_clusters": pending_clusters,
        })

        # Step 5: Stuck order detection (Issue #12 / Commit 4c).
        # An order in "valid" state but without ssl_certificate_id is stuck. The
        # auto-completion task should resolve it within 60s, but surface visibility
        # so users notice if Pebble/CA is unreachable.
        stuck_orders = await conn.fetch("""
            SELECT id, domains, created_at FROM letsencrypt_orders
            WHERE status = 'valid' AND ssl_certificate_id IS NULL
            AND created_at > NOW() - INTERVAL '7 days'
            ORDER BY created_at DESC
            LIMIT 10
        """)
        if stuck_orders:
            stuck_ids = [r['id'] for r in stuck_orders]
            steps.append({
                "key": "stuck_orders",
                "title": "Resolve Stuck Orders",
                "ok": False,
                "detail": f"{len(stuck_orders)} order(s) validated by CA but certificate not yet downloaded. "
                          f"Auto-completion runs every 60s. Order IDs: {stuck_ids}. "
                          f"If this persists, check ACME backend connectivity.",
                "navigate": "/ssl-certificates?tab=acme",
                "stuck_order_ids": stuck_ids,
            })

        # Step 6: DNS & Network (informational only)
        steps.append({
            "key": "network_dns",
            "title": "Verify DNS and Network",
            "ok": None,
            "detail": "Domain DNS must point to HAProxy IP, Port 80 must be open from internet",
            "navigate": None,
        })

        ready = all(step["ok"] is True for step in steps if step["ok"] is not None)

        return {"ready": ready, "steps": steps}
    finally:
        await close_database_connection(conn)
