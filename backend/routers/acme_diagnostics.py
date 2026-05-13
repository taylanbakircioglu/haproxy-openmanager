"""
ACME diagnostics router (Feature A — Issue #13).

Endpoints:
- POST /api/letsencrypt/orders/{order_id}/diagnostics
    Run the full pre-flight + post-failure check suite for an order.
- POST /api/letsencrypt/orders/{order_id}/diagnostics/{check_id}/rerun
    Re-run a single check (DNS/port80/routing/account/agents).
- GET  /api/letsencrypt/orders/{order_id}/events
    Return the merged event timeline (acme_order_events + correlated
    user_activity_logs).

RBAC: ssl.read for run, ssl.read for events read.
Per-user 5/min rate-limit via user_activity_logs SQL count (M18 / R50).
"""

import json
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException

from auth_middleware import check_user_permission, get_current_user_from_token
from database.connection import close_database_connection, get_database_connection
from services.acme_diagnostics import CHECK_IDS, humanize_error_detail, run_checks

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/letsencrypt", tags=["Let's Encrypt / ACME"])


_RATE_LIMIT_PER_MIN = 5


async def _enforce_rate_limit(conn, user_id: int, action: str) -> None:
    """Per-user, per-minute COUNT(*) rate limit against user_activity_logs.

    Backed by the (user_id, action, created_at DESC) composite index added in
    v1.5.0 (M33/R50).
    """
    cnt = await conn.fetchval(
        """
        SELECT COUNT(*)
        FROM user_activity_logs
        WHERE user_id = $1
          AND action = $2
          AND created_at >= NOW() - INTERVAL '60 seconds'
        """,
        user_id,
        action,
    )
    if cnt is not None and cnt >= _RATE_LIMIT_PER_MIN:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {action} allowed {_RATE_LIMIT_PER_MIN} requests per minute",
        )


async def _load_order(conn, order_id: int) -> dict:
    row = await conn.fetchrow(
        """
        SELECT id, account_id, status, domains, cluster_ids, error_detail,
               post_completion_actions, pending_apply_version_name,
               wizard_staged_until, created_by
        FROM letsencrypt_orders
        WHERE id = $1
        """,
        order_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail=f"Order {order_id} not found")
    return dict(row)


def _parse_jsonb_list(raw, default):
    if raw is None:
        return default
    if isinstance(raw, (list, dict)):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return default
    return default


@router.post("/orders/{order_id}/diagnostics")
async def run_diagnostics(order_id: int, authorization: str = Header(None)):
    """Run the full pre-flight + post-failure diagnostic suite."""
    current_user = await get_current_user_from_token(authorization)
    if not await check_user_permission(current_user["id"], "ssl", "read"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.read required")

    conn = await get_database_connection()
    try:
        await _enforce_rate_limit(conn, current_user["id"], "acme_diagnostics_run")
        order = await _load_order(conn, order_id)

        domains = _parse_jsonb_list(order["domains"], [])
        cluster_ids = _parse_jsonb_list(order["cluster_ids"], [])

        results = await run_checks(
            conn,
            domains=domains,
            cluster_ids=cluster_ids,
            account_id=order["account_id"],
        )

        humanized_error = humanize_error_detail(order["error_detail"])

        return {
            "order_id": order_id,
            "status": order["status"],
            "checks": results,
            "humanized_error": humanized_error,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
    finally:
        await close_database_connection(conn)


@router.post("/orders/{order_id}/diagnostics/{check_id}/rerun")
async def rerun_diagnostic_check(
    order_id: int,
    check_id: str,
    authorization: str = Header(None),
):
    """Re-run a single check (DNS / port80 / routing / account / agents)."""
    current_user = await get_current_user_from_token(authorization)
    if not await check_user_permission(current_user["id"], "ssl", "read"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.read required")

    if check_id not in CHECK_IDS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown check_id '{check_id}'. Valid: {', '.join(CHECK_IDS)}",
        )

    conn = await get_database_connection()
    try:
        await _enforce_rate_limit(conn, current_user["id"], "acme_diagnostic_check_rerun")
        order = await _load_order(conn, order_id)

        domains = _parse_jsonb_list(order["domains"], [])
        cluster_ids = _parse_jsonb_list(order["cluster_ids"], [])

        results = await run_checks(
            conn,
            domains=domains,
            cluster_ids=cluster_ids,
            account_id=order["account_id"],
            only=[check_id],
        )

        return {
            "order_id": order_id,
            "check": results[0] if results else None,
        }
    finally:
        await close_database_connection(conn)


@router.get("/orders/{order_id}/events")
async def get_order_events(
    order_id: int,
    limit: int = 100,
    authorization: str = Header(None),
):
    """Return the merged event timeline for an order:
    - acme_order_events rows (typed events)
    - correlated user_activity_logs entries (resource='letsencrypt_order' AND
      resource_id=order_id) for context.

    Sorted by created_at ASC (oldest first) so the timeline reads naturally.
    """
    current_user = await get_current_user_from_token(authorization)
    if not await check_user_permission(current_user["id"], "ssl", "read"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.read required")

    if limit <= 0 or limit > 500:
        limit = 100

    conn = await get_database_connection()
    try:
        # Existence check
        await _load_order(conn, order_id)

        # Detect whether acme_order_events exists (zero-impact for envs that
        # have not yet run the v1.5.0 migration). Returns empty event_log when
        # not yet present rather than 500-ing.
        events_table_exists = await conn.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables WHERE table_name = 'acme_order_events'
            )
            """
        )

        events: List[dict] = []
        if events_table_exists:
            event_rows = await conn.fetch(
                """
                SELECT id, event_type, severity, message, details, correlation_id, created_at
                FROM acme_order_events
                WHERE order_id = $1
                ORDER BY created_at ASC, id ASC
                LIMIT $2
                """,
                order_id,
                limit,
            )
            for r in event_rows:
                # R18c round 8 (Bulgu A): asyncpg returns JSONB columns as
                # raw JSON strings (no codec on the pool). For the FE
                # contract the `details` field MUST be either a dict or
                # null — otherwise the React renderer ends up trying to
                # access `details.foo` on a plain string and silently
                # gets undefined.
                _det = r["details"]
                if isinstance(_det, str):
                    try:
                        _det = json.loads(_det)
                    except Exception:
                        _det = {}
                if not isinstance(_det, (dict, list)):
                    _det = {} if _det is None else {"raw": str(_det)}
                events.append({
                    "source": "acme_order_event",
                    "id": r["id"],
                    "event_type": r["event_type"],
                    "severity": r["severity"],
                    "message": r["message"],
                    "details": _det,
                    "correlation_id": r["correlation_id"],
                    "created_at": r["created_at"].isoformat().replace("+00:00", "Z")
                        if r["created_at"] else None,
                })

        # User activity rows correlated by resource — schema is permissive
        # (`resource_type`/`resource_id` may not always be populated for older
        # rows) so this query stays best-effort.
        ua_rows = await conn.fetch(
            """
            SELECT id, action, resource_type, resource_id, status, details, created_at, user_id
            FROM user_activity_logs
            WHERE resource_type = 'letsencrypt_order' AND resource_id = $1
            ORDER BY created_at ASC, id ASC
            LIMIT $2
            """,
            str(order_id),
            limit,
        ) if await conn.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'user_activity_logs' AND column_name = 'resource_id'
            )
            """
        ) else []

        for r in ua_rows:
            events.append({
                "source": "user_activity_log",
                "id": r["id"],
                "event_type": r["action"],
                "severity": "info" if (r["status"] or "").lower() in ("success", "ok", "") else "warn",
                "message": (r["details"] or "")[:500] if isinstance(r["details"], str) else "",
                "details": r["details"] if not isinstance(r["details"], (str, type(None))) else {},
                "correlation_id": None,
                "created_at": r["created_at"].isoformat().replace("+00:00", "Z")
                    if r["created_at"] else None,
            })

        events.sort(key=lambda e: (e["created_at"] or "", e.get("id") or 0))

        return {
            "order_id": order_id,
            "events": events,
            "count": len(events),
        }
    finally:
        await close_database_connection(conn)
