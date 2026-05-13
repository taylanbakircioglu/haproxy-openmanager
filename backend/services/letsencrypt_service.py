"""
letsencrypt_service: thin extraction layer for ACME order creation paths.

Two flavors needed by v1.5.0 wizard (Section 4.4):

1) create_order_staged(conn, ...) — INSERTs a letsencrypt_orders row with
   status='wizard_staged', NO LE API call yet. The background task
   complete_pending_acme_orders will later detect agent confirmation and
   transition this to a real ACME order via create_order_via_api.

2) create_order_via_api(conn, ...) — thin wrapper around the existing
   acme_service.AcmeService.create_order() routine, used both by the
   /api/letsencrypt/orders endpoint and the staged-promotion flow. Caller
   may pass `expected_account_id` so we can update existing letsencrypt_orders
   row in place (UPDATE order_url + status='pending') instead of inserting a
   new one.

Notes:
- Staged orders have order_url IS NULL — the wizard's create flow never
  contacts the CA, so failure modes here are purely DB-bound. R58/M37
  (`order_url IS NULL` idempotency check) lives in main.py background task.
- post_completion_actions JSONB carries the *deferred* HTTPS frontend create
  request that fires once the certificate is downloaded — see
  letsencrypt.py _complete_certificate.
"""

import json
import logging
from typing import Any, List, Optional

logger = logging.getLogger(__name__)


async def create_order_staged(
    conn,
    *,
    account_id: int,
    domains: List[str],
    cluster_ids: List[int],
    post_completion_actions: List[dict],
    pending_apply_version_name: Optional[str] = None,
    created_by: Optional[int] = None,
) -> int:
    """Insert a wizard-staged ACME order row with status='wizard_staged'.

    No LE API call. Returns new order id.

    The background task complete_pending_acme_orders will later detect agent
    confirmation (via pending_apply_version_name match) and call
    create_order_via_api to promote to status='pending'.
    """
    order_id = await conn.fetchval(
        """
        INSERT INTO letsencrypt_orders (
            account_id, order_url, status, domains, finalize_url, expires_at,
            cluster_ids, post_completion_actions, pending_apply_version_name,
            created_by, wizard_staged_until
        ) VALUES (
            $1, NULL, 'wizard_staged', $2::jsonb, '', NULL,
            $3::jsonb, $4::jsonb, $5,
            $6, NOW() + INTERVAL '24 hours'
        )
        RETURNING id
        """,
        account_id,
        json.dumps(domains),
        json.dumps(cluster_ids),
        json.dumps(post_completion_actions or []),
        pending_apply_version_name,
        created_by,
    )
    logger.info(
        "ACME WIZARD: staged order id=%s domains=%s pending_apply_version_name=%s",
        order_id,
        domains,
        pending_apply_version_name,
    )
    return order_id


async def promote_staged_order_to_pending(
    conn,
    *,
    order_id: int,
    order_url: str,
    finalize_url: str,
    status: str = "pending",
    expires_at: Any = None,
) -> None:
    """In-place update of a wizard_staged order row after the LE newOrder call
    has succeeded. status -> 'pending' (or whatever LE returned).
    """
    await conn.execute(
        """
        UPDATE letsencrypt_orders
        SET order_url = $2,
            finalize_url = $3,
            status = $4,
            expires_at = $5,
            updated_at = NOW()
        WHERE id = $1
        """,
        order_id,
        order_url,
        finalize_url,
        status,
        expires_at,
    )


async def create_order_via_api(
    acme_service_instance,
    *,
    account_id: int,
    domains: List[str],
    cluster_ids: Optional[List[int]] = None,
) -> dict:
    """Thin wrapper around AcmeService.create_order() — used by both the public
    POST /api/letsencrypt/orders endpoint and the staged promotion path.

    Returns the same dict the upstream method returns (id, order_url,
    status, domains, ...).
    """
    return await acme_service_instance.create_order(
        account_id=account_id,
        domains=domains,
        cluster_ids=cluster_ids,
    )
