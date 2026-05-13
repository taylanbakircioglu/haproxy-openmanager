"""
ssl_service: extracted helpers for SSL certificate row creation + cluster junction.

Used by:
- routers/site_wizard.py wizard (mode=upload | existing)
- (future) other SSL flows

Design (Section 4.3 of v1.5.0 plan):
- R38 schema: ssl_certificates.cluster_id always NULL — junction table
  ssl_certificate_clusters is the single source of truth for cluster binding.
- M11 idempotent junction insertion via ON CONFLICT DO NOTHING.
- last_config_status='PENDING' set explicitly at INSERT time (matches ssl.py:467-477).

Phase K Phase D follow-up (Bulgu #9) — parity with SSL Management page.

Before the follow-up, the wizard's PEM upload path persisted a sparse
row: primary_domain/all_domains came from the operator-entered
FRONTEND domains (not the cert SAN); expiry_date/issuer/fingerprint
were NULL; status was hard-coded `'valid'`; days_until_expiry was
`0`; private_key / chain went un-validated; name uniqueness was
not enforced (would 500 on the DB unique constraint instead of
returning a friendly 400); soft-deleted rows could not be
reactivated. SSL Management's `/api/ssl/certificates` POST does
all of this. The wizard-created cert appeared on the SSL
Management page with empty expiry/issuer columns and a permanent
"valid" status — confusing UX and inconsistent with the dedicated
flow.

`create_cert_row` now:
- parses the certificate via `utils.ssl_parser.parse_ssl_certificate`,
- validates private_key + chain via the same helpers SSL Management uses,
- enforces name uniqueness within the target cluster (mirrors
  ssl.py:392-411 but scoped to the wizard's single cluster),
- reactivates soft-deleted certs with the same name (mirrors
  ssl.py:470-500), preserving the row id so existing references
  do not break,
- recomputes status / days_until_expiry / timezone-normalises
  expiry_date the same way ssl.py:432-460 does,
- raises `HTTPException(400)` on every parse/validation failure
  (callers translate to wizard step-jumpback toasts).
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import HTTPException

from utils.ssl_parser import (
    parse_ssl_certificate,
    validate_certificate_chain,
    validate_private_key,
)

logger = logging.getLogger(__name__)


def _normalise_expiry_to_naive_utc(expiry: Optional[datetime]) -> Optional[datetime]:
    """Mirror ssl.py:418-460 timezone handling — DB column is
    timezone-naive UTC; pre-normalisation drift caused inconsistent
    `expires_in_days` math between rows created via the two flows."""
    if not expiry:
        return None
    try:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        else:
            expiry = expiry.astimezone(timezone.utc)
        return expiry.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception as tz_error:
        logger.warning(
            "ssl_service._normalise_expiry_to_naive_utc: timezone "
            f"conversion failed ({tz_error}); persisting NULL"
        )
        return None


def _recompute_status_from_expiry(
    cert_info_status: str,
    expiry_date: Optional[datetime],
    cert_info_days: int,
) -> tuple[str, int]:
    """Mirror ssl.py:436-454 — recompute status + days_until_expiry
    from the normalised expiry date so two SSL rows created on the
    same cert have identical lifecycle fields regardless of the
    creation flow.

    Returns (status, days_until_expiry).
    """
    if not expiry_date:
        return cert_info_status or "valid", cert_info_days or 0
    try:
        now_utc = datetime.utcnow()
        days_left = (expiry_date - now_utc).days
        if days_left < 0:
            return "expired", days_left
        if days_left < 30:
            return "expiring_soon", days_left
        return "valid", days_left
    except Exception as calc_error:
        logger.warning(
            "ssl_service._recompute_status_from_expiry: failed "
            f"({calc_error}); falling back to parser-provided values"
        )
        return cert_info_status or "valid", cert_info_days or 0


async def create_cert_row(
    conn,
    payload: Any,
    cluster_id: int,
) -> int:
    """Insert a row into ssl_certificates (always cluster_id=NULL) + junction
    binding to the given cluster_id. Returns new ssl_certificate_id.

    payload is expected to expose:
      name, certificate_content, private_key_content, chain_content,
      usage_type (optional, default 'frontend').

    All cert metadata (primary_domain, all_domains, expiry_date,
    issuer, fingerprint, status, days_until_expiry) is now parsed
    FROM the PEM content via `parse_ssl_certificate` — operator-
    supplied values on the payload are accepted as a graceful
    fallback only when parsing fails (which itself raises 400).
    """
    cert_content = getattr(payload, "certificate_content", None) or ""
    if not cert_content.strip():
        raise HTTPException(
            status_code=400,
            detail="ssl.certificate_content is empty — paste the PEM-encoded certificate.",
        )

    cert_info = parse_ssl_certificate(cert_content)
    if cert_info.get("error"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid SSL certificate: {cert_info['error']}",
        )

    private_key_content = getattr(payload, "private_key_content", None)
    if private_key_content and not validate_private_key(private_key_content):
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid private key format — paste the PEM-encoded private "
                "key. If the key is encrypted with a passphrase, decrypt it "
                "first (`openssl rsa -in encrypted.key -out plain.key`) — "
                "HAProxy cannot read passphrase-protected keys."
            ),
        )

    # Bulgu #23 (round-12 audit): cert and key MUST share the same
    # public key. Pre-fix the upload paths validated cert and key
    # independently, so mixing PEMs from different sites surfaced
    # only at the agent's `haproxy -c` with an opaque
    # "X509_check_private_key: key values mismatch" alert — by which
    # point entities + PENDING version were already created.
    if private_key_content:
        from utils.ssl_parser import verify_certificate_key_match
        match_result = verify_certificate_key_match(cert_content, private_key_content)
        if match_result.get("match") is False:
            raise HTTPException(
                status_code=400,
                detail=(
                    "SSL certificate and private key do not match — the "
                    "cert's public key differs from the private key's public "
                    "key. The pair likely belongs to two different sites or "
                    "a stale key was pasted. Re-export both PEM files from "
                    "the same issuance and try again."
                ),
            )

    chain_content = getattr(payload, "chain_content", None)
    if chain_content and not validate_certificate_chain(chain_content):
        raise HTTPException(
            status_code=400,
            detail="Invalid certificate chain format — paste the PEM-encoded chain.",
        )

    # Bulgu #24 (round-12 audit): refuse to create a row for an already
    # EXPIRED certificate. Pre-fix the wizard / direct upload accepted
    # certs with `status='expired'` from parse_ssl_certificate, the
    # row was inserted, the wizard built an HTTPS frontend bound to
    # it, and the agent deployed a cert that EVERY browser rejects
    # at the TLS handshake. Recovery required noticing the broken
    # site, rejecting the version, and re-uploading a valid cert.
    # Hard-reject here so the operator sees a clear 400 at upload
    # time instead of a runtime user-facing TLS failure.
    if cert_info.get("status") == "expired":
        days_past = cert_info.get("days_until_expiry", 0)
        raise HTTPException(
            status_code=400,
            detail=(
                f"SSL certificate is already expired ({-int(days_past) if isinstance(days_past, (int, float)) else 'unknown'} "
                "days past notAfter). HAProxy will load it but every browser "
                "TLS handshake will fail with NET::ERR_CERT_DATE_INVALID. "
                "Replace with a non-expired certificate before deploying."
            ),
        )

    expiry_date = _normalise_expiry_to_naive_utc(cert_info.get("expiry_date"))
    primary_domain = cert_info.get("primary_domain") or getattr(payload, "primary_domain", None)
    all_domains = cert_info.get("all_domains") or getattr(payload, "all_domains", None) or (
        [primary_domain] if primary_domain else []
    )
    issuer = cert_info.get("issuer") or getattr(payload, "issuer", None)
    fingerprint = cert_info.get("fingerprint") or getattr(payload, "fingerprint", None)
    status, days_until_expiry = _recompute_status_from_expiry(
        cert_info.get("status", "valid"),
        expiry_date,
        cert_info.get("days_until_expiry", 0),
    )
    usage_type = getattr(payload, "usage_type", "frontend") or "frontend"

    existing = await conn.fetchrow(
        """
        SELECT s.id, s.is_active
        FROM ssl_certificates s
        LEFT JOIN ssl_certificate_clusters scc ON s.id = scc.ssl_certificate_id
        WHERE s.name = $1
          AND (
                NOT EXISTS (
                    SELECT 1 FROM ssl_certificate_clusters
                    WHERE ssl_certificate_id = s.id
                )
                OR scc.cluster_id = $2
              )
        LIMIT 1
        """,
        payload.name,
        cluster_id,
    )
    if existing and existing["is_active"]:
        raise HTTPException(
            status_code=400,
            detail=(
                f"SSL certificate with name '{payload.name}' already exists in this cluster. "
                "Choose a different name or remove the existing one from SSL Management first."
            ),
        )

    if existing and not existing["is_active"]:
        await conn.execute(
            """
            DELETE FROM ssl_certificate_clusters WHERE ssl_certificate_id = $1
            """,
            existing["id"],
        )
        await conn.execute(
            """
            UPDATE ssl_certificates
            SET is_active = TRUE,
                last_config_status = 'PENDING',
                certificate_content = $2,
                private_key_content = $3,
                chain_content = $4,
                primary_domain = $5,
                all_domains = $6::jsonb,
                expiry_date = $7,
                usage_type = $8,
                issuer = $9,
                fingerprint = $10,
                status = $11,
                days_until_expiry = $12,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
            """,
            existing["id"],
            cert_content,
            private_key_content,
            chain_content,
            primary_domain,
            json.dumps(all_domains),
            expiry_date,
            usage_type,
            issuer,
            fingerprint,
            status,
            days_until_expiry,
        )
        cert_id = existing["id"]
        logger.info(
            "ssl_service.create_cert_row: reactivated soft-deleted "
            f"cert '{payload.name}' (id={cert_id}) via wizard parity path"
        )
    else:
        cert_id = await conn.fetchval(
            """
            INSERT INTO ssl_certificates (
                name, primary_domain, certificate_content, private_key_content, chain_content,
                expiry_date, issuer, fingerprint, status, days_until_expiry, all_domains,
                is_active, cluster_id, last_config_status, usage_type
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb,
                TRUE, NULL, 'PENDING', $12
            )
            RETURNING id
            """,
            payload.name,
            primary_domain,
            cert_content,
            private_key_content,
            chain_content,
            expiry_date,
            issuer,
            fingerprint,
            status,
            days_until_expiry,
            json.dumps(all_domains),
            usage_type,
        )

    await ensure_cluster_junction(conn, cert_id, cluster_id)
    return cert_id


async def ensure_cluster_junction(conn, ssl_certificate_id: int, cluster_id: int) -> None:
    """Idempotent insert into ssl_certificate_clusters (M11)."""
    await conn.execute(
        """
        INSERT INTO ssl_certificate_clusters (ssl_certificate_id, cluster_id)
        VALUES ($1, $2)
        ON CONFLICT (ssl_certificate_id, cluster_id) DO NOTHING
        """,
        ssl_certificate_id,
        cluster_id,
    )


async def select_existing_cert(conn, ssl_certificate_id: int, cluster_id: int) -> Optional[int]:
    """Validate that the cert exists AND is eligible for the given
    cluster, then ensure cluster junction. Returns the cert id when
    valid, else None.

    R18b audit fix (round 4 #C — cert RBAC bypass): pre-fix this
    helper only checked `is_active=TRUE` and then UNCONDITIONALLY
    attached the cluster junction row. That meant an authenticated
    operator with access to cluster B could reference any
    cluster-A-bound cert id (or any global-but-not-junctioned cert)
    and the wizard would silently bind it to cluster B. The
    `GET /api/ssl/certificates` listing already enforces the correct
    eligibility predicate ("global cert OR junction already includes
    this cluster"); this helper now mirrors that predicate so the
    wizard cannot grant access the listing forbids.

    Eligibility rule (matches ssl.py listing):
      - cert is "global" (no rows in ssl_certificate_clusters), OR
      - cert is already bound to `cluster_id`.
    """
    row = await conn.fetchrow(
        """
        SELECT sc.id
        FROM ssl_certificates sc
        WHERE sc.id = $1
          AND sc.is_active = TRUE
          AND (
                NOT EXISTS (
                    SELECT 1 FROM ssl_certificate_clusters
                    WHERE ssl_certificate_id = sc.id
                )
                OR EXISTS (
                    SELECT 1 FROM ssl_certificate_clusters
                    WHERE ssl_certificate_id = sc.id AND cluster_id = $2
                )
              )
        """,
        ssl_certificate_id,
        cluster_id,
    )
    if not row:
        return None
    await ensure_cluster_junction(conn, ssl_certificate_id, cluster_id)
    return row["id"]


async def validate_server_ca_bundle_eligibility(
    conn, ssl_certificate_id: int, cluster_id: int
) -> bool:
    """R18b audit fix (round 4 #C): per-server `ssl_certificate_id`
    (HAProxy `ca-file` for upstream verification) skipped any cluster
    eligibility check pre-R18b — only DB FK integrity. That allowed
    the same cross-cluster reference primitive as `select_existing_cert`.
    The wizard now calls this validator before persisting the row.

    Returns True iff the cert is active AND visible to the cluster
    using the same eligibility rule as `select_existing_cert`.
    """
    row = await conn.fetchrow(
        """
        SELECT 1
        FROM ssl_certificates sc
        WHERE sc.id = $1
          AND sc.is_active = TRUE
          AND (
                NOT EXISTS (
                    SELECT 1 FROM ssl_certificate_clusters
                    WHERE ssl_certificate_id = sc.id
                )
                OR EXISTS (
                    SELECT 1 FROM ssl_certificate_clusters
                    WHERE ssl_certificate_id = sc.id AND cluster_id = $2
                )
              )
        LIMIT 1
        """,
        ssl_certificate_id,
        cluster_id,
    )
    return row is not None
