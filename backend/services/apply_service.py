"""
apply_service: programmatic invocation of the cluster apply pipeline.

Used by:
- routers/site_wizard.py (atomic create flow with apply_immediately=true)
- routers/letsencrypt.py _complete_certificate (post-completion auto-apply)

Design (Section 4.5 of v1.5.0 plan):
- Reuses the existing /api/clusters/{id}/apply-changes route handler so that
  the response shape (`latest_version`, `consolidated_version_id`,
  `sync_results`, `applied_count`, `agents_notified`) and transaction
  boundary are byte-identical to UI-driven applies.
- M23/M46 (R65): when user_id is None (e.g. ACME completion auto-apply with
  legacy created_by NULL), falls back to a short-lived JWT minted for the
  first active admin user (`is_admin=TRUE AND is_active=TRUE`).
- This file deliberately delegates rather than duplicating the ~800 LOC apply
  pipeline; that keeps drift impossible. The wrapper only injects auth.
"""

import logging
from datetime import timedelta
from typing import Any, Dict, Optional

from database.connection import close_database_connection, get_database_connection
from utils.auth import create_access_token

logger = logging.getLogger(__name__)


async def _resolve_user_id(user_id: Optional[int]) -> Optional[int]:
    """If user_id is provided AND still valid (active), return it; else
    return the first active admin user's id. Returns None if no admin user
    exists (extreme edge case).

    M46/R65: schema accuracy — `users.is_super_admin` does NOT exist; the
    correct columns are `is_admin` (BOOLEAN) and `is_active` (BOOLEAN).

    Bulgu #27 fix: when a wizard-staged ACME order's `created_by` user has
    been deleted/deactivated by the time the post-completion auto-apply
    fires (could be 24h+ later), do NOT mint a JWT for that ghost user —
    we'd just produce a 401 from get_current_user_from_token. Fall through
    to the admin fallback instead.
    """
    conn = await get_database_connection()
    try:
        if user_id is not None:
            valid = await conn.fetchval(
                "SELECT id FROM users WHERE id = $1 AND is_active = TRUE",
                user_id,
            )
            if valid:
                return valid
            logger.warning(
                "apply_service: requested user_id=%s no longer exists or is inactive — "
                "falling back to admin", user_id,
            )

        admin_id = await conn.fetchval(
            """
            SELECT id FROM users
            WHERE is_admin = TRUE AND is_active = TRUE
            ORDER BY id ASC LIMIT 1
            """
        )
        if not admin_id:
            logger.error(
                "apply_service: no active admin user found (is_admin=TRUE AND is_active=TRUE)"
            )
        return admin_id
    finally:
        await close_database_connection(conn)


def _mint_internal_jwt(user_id: int) -> str:
    """Mint a short-lived JWT for an internal apply call. Token uses the
    standard claim shape (`sub`/`user_id`) accepted by
    auth_middleware.get_current_user_from_token.
    """
    return create_access_token(
        {"sub": str(user_id), "user_id": user_id},
        expires_delta=timedelta(minutes=5),
    )


async def apply_cluster_pending(
    cluster_id: int,
    *,
    user_id: Optional[int] = None,
    apply_request: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Programmatic equivalent of POST /api/clusters/{cluster_id}/apply-changes.

    Returns the same response dict the HTTP endpoint returns:
        {
            "message": str,
            "applied_count": int,
            "latest_version": str,
            "consolidated_version_id": int,
            "sync_results": list,
            "agents_notified": int,
            ...optionally global_ssl_applied...
        }
    """
    # Local import to avoid cluster.py <-> apply_service circular import at
    # module load (cluster.py uses apply_service indirectly via routers/__init__).
    from routers.cluster import apply_pending_changes  # noqa: WPS433 (intentional)

    resolved = await _resolve_user_id(user_id)
    if resolved is None:
        raise RuntimeError(
            "apply_service.apply_cluster_pending: no admin user available for system context apply"
        )

    auth_header = f"Bearer {_mint_internal_jwt(resolved)}"
    return await apply_pending_changes(
        cluster_id=cluster_id,
        apply_request=apply_request or {},
        authorization=auth_header,
    )
