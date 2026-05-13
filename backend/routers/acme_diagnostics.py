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
import uuid
from datetime import datetime
from typing import List, Optional

import asyncpg
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
    """Fetch the order row, or raise a clean 404.

    Bulgu #96 (prod-canary audit): `letsencrypt_orders.id` is a Postgres
    int4 column. A path-param `order_id` outside the int4 range
    (e.g. > 2_147_483_647) used to bubble up as
    `asyncpg.exceptions.DataError: invalid input for query argument $1:
    ... (value out of int32 range)` — which the diagnostics endpoint
    then surfaced in a `diagnostics_unavailable` envelope, leaking the
    raw Postgres / asyncpg error string ("query argument $1",
    "int32 range") into the operator-visible response body.
    Semantically an out-of-range ID can never reference a real order,
    so we treat it identically to "row not found" and return a clean
    404 — same shape as the not-found path, no SQL detail leakage.
    """
    try:
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
    except asyncpg.exceptions.DataError as exc:
        logger.info(
            "ACME order lookup rejected by Postgres (out-of-range / "
            "uncastable id): order_id=%s exc=%s",
            order_id,
            exc,
        )
        raise HTTPException(status_code=404, detail=f"Order {order_id} not found")
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


def _diagnostic_failure_envelope(
    order_id: int,
    correlation_id: str,
    exc: Exception,
    *,
    stage: str,
) -> dict:
    """Build a structured response when the diagnostic suite itself
    cannot run. Bulgu #94 (Round-25): we return HTTP 200 with this
    envelope rather than 500 so the UI can still SHOW the operator
    what happened — the panel's whole purpose is to surface failure
    causes, and the panel itself silently 500-ing is the worst-case
    UX. The server-side log carries the full traceback keyed by
    correlation_id for operator follow-up.
    """
    return {
        "order_id": order_id,
        "status": "diagnostics_unavailable",
        "checks": [
            {
                "id": "diagnostics_runner",
                "label": "Diagnostic runner",
                "status": "fail",
                "severity": "error",
                "message": (
                    f"Diagnostics could not run ({stage}): "
                    f"{exc.__class__.__name__}: {exc}"
                ),
                "details": {
                    "stage": stage,
                    "exception_type": exc.__class__.__name__,
                    "exception_message": str(exc),
                    "correlation_id": correlation_id,
                    "hint": (
                        "Check the backend log for correlation_id "
                        f"{correlation_id} for the full traceback."
                    ),
                },
                "duration_ms": None,
            }
        ],
        "humanized_error": {
            "title": "Diagnostic panel could not run",
            "message": (
                "The diagnostic runner itself crashed before any check "
                "could complete. This is independent of whether the ACME "
                "provider is reachable from this cluster."
            ),
            "hint": (
                "Share the correlation_id below with the platform team; "
                "they can grep the API log for the full traceback."
            ),
            "correlation_id": correlation_id,
        },
        "meta": {
            "correlation_id": correlation_id,
            "error_stage": stage,
            "error_type": exc.__class__.__name__,
            "error_message": str(exc),
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/orders/{order_id}/diagnostics")
async def run_diagnostics(order_id: int, authorization: str = Header(None)):
    """Run the full pre-flight + post-failure diagnostic suite.

    Bulgu #94 (Round-25 audit): this endpoint must NEVER return HTTP 500
    for an in-suite failure. The diagnostic panel exists precisely to
    explain what is broken; producing an opaque 500 defeats the entire
    feature. Authentication / authorisation / rate-limit / not-found
    errors still raise the appropriate 4xx, but any unexpected
    exception from check execution is converted to a 200 response with
    a structured failure envelope so the UI can display the cause.
    """
    current_user = await get_current_user_from_token(authorization)
    if not await check_user_permission(current_user["id"], "ssl", "read"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.read required")

    correlation_id = uuid.uuid4().hex[:12]
    conn = await get_database_connection()
    try:
        await _enforce_rate_limit(conn, current_user["id"], "acme_diagnostics_run")
        order = await _load_order(conn, order_id)
    except HTTPException:
        await close_database_connection(conn)
        raise
    except Exception as exc:  # noqa: BLE001 — diagnostic boundary
        logger.exception(
            "ACME diagnostics setup failed for order=%s correlation_id=%s",
            order_id,
            correlation_id,
        )
        try:
            return _diagnostic_failure_envelope(order_id, correlation_id, exc, stage="load_order")
        finally:
            await close_database_connection(conn)

    try:
        domains = _parse_jsonb_list(order["domains"], [])
        cluster_ids = _parse_jsonb_list(order["cluster_ids"], [])

        try:
            results = await run_checks(
                conn,
                domains=domains,
                cluster_ids=cluster_ids,
                account_id=order["account_id"],
            )
        except Exception as exc:  # noqa: BLE001 — diagnostic boundary
            # run_checks now wraps individual checks, but a top-level
            # crash (e.g. lost DB connection) still needs to be visible.
            logger.exception(
                "ACME diagnostics top-level failure for order=%s correlation_id=%s",
                order_id,
                correlation_id,
            )
            return _diagnostic_failure_envelope(order_id, correlation_id, exc, stage="run_checks")

        try:
            humanized_error = humanize_error_detail(order["error_detail"])
        except Exception as exc:  # noqa: BLE001 — defensive
            logger.warning(
                "humanize_error_detail failed for order=%s correlation_id=%s: %s",
                order_id,
                correlation_id,
                exc,
            )
            humanized_error = {
                "title": "ACME error (raw)",
                "message": str(order["error_detail"]) if order["error_detail"] else "",
                "hint": "",
                "parse_error": exc.__class__.__name__,
            }

        return {
            "order_id": order_id,
            "status": order["status"],
            "checks": results,
            "humanized_error": humanized_error,
            "meta": {
                "correlation_id": correlation_id,
                "checks_total": len(results),
                "checks_failed": sum(1 for r in results if r.get("status") == "fail"),
                "checks_warn": sum(1 for r in results if r.get("status") == "warn"),
            },
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
    """Re-run a single check (DNS / port80 / routing / account / agents).

    Bulgu #94 follow-up (Round-25 audit): the rerun path is just as
    sensitive to opaque 500s as the full-suite POST. If
    `_enforce_rate_limit` / `_load_order` / `run_checks` raises an
    unexpected exception, we surface a structured `fail` row in the
    same shape the table already renders — so the operator clicking
    "Re-run" never sees an opaque toast and the row updates in place.
    """
    current_user = await get_current_user_from_token(authorization)
    if not await check_user_permission(current_user["id"], "ssl", "read"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.read required")

    if check_id not in CHECK_IDS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown check_id '{check_id}'. Valid: {', '.join(CHECK_IDS)}",
        )

    correlation_id = uuid.uuid4().hex[:12]
    conn = await get_database_connection()
    try:
        try:
            await _enforce_rate_limit(conn, current_user["id"], "acme_diagnostic_check_rerun")
            order = await _load_order(conn, order_id)
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001 — diagnostic boundary
            logger.exception(
                "ACME rerun setup failed for order=%s check=%s correlation_id=%s",
                order_id,
                check_id,
                correlation_id,
            )
            return {
                "order_id": order_id,
                "check": {
                    "id": check_id,
                    "label": check_id,
                    "status": "fail",
                    "severity": "error",
                    "message": (
                        f"Re-run setup failed: "
                        f"{exc.__class__.__name__}: {exc}"
                    ),
                    "details": {
                        "stage": "setup",
                        "exception_type": exc.__class__.__name__,
                        "exception_message": str(exc),
                        "correlation_id": correlation_id,
                    },
                    "duration_ms": None,
                },
                "meta": {"correlation_id": correlation_id, "error_stage": "setup"},
            }

        try:
            domains = _parse_jsonb_list(order["domains"], [])
            cluster_ids = _parse_jsonb_list(order["cluster_ids"], [])
            results = await run_checks(
                conn,
                domains=domains,
                cluster_ids=cluster_ids,
                account_id=order["account_id"],
                only=[check_id],
            )
        except Exception as exc:  # noqa: BLE001 — diagnostic boundary
            logger.exception(
                "ACME rerun run_checks failed for order=%s check=%s correlation_id=%s",
                order_id,
                check_id,
                correlation_id,
            )
            return {
                "order_id": order_id,
                "check": {
                    "id": check_id,
                    "label": check_id,
                    "status": "fail",
                    "severity": "error",
                    "message": (
                        f"Re-run crashed: "
                        f"{exc.__class__.__name__}: {exc}"
                    ),
                    "details": {
                        "stage": "run_checks",
                        "exception_type": exc.__class__.__name__,
                        "exception_message": str(exc),
                        "correlation_id": correlation_id,
                    },
                    "duration_ms": None,
                },
                "meta": {"correlation_id": correlation_id, "error_stage": "run_checks"},
            }

        return {
            "order_id": order_id,
            "check": results[0] if results else None,
            "meta": {"correlation_id": correlation_id},
        }
    finally:
        await close_database_connection(conn)


async def _user_activity_columns(conn) -> set:
    """Return the set of column names actually present on user_activity_logs.

    Bulgu #95 (Round-25 audit) — the canonical migration for
    `user_activity_logs` defines `id, user_id, action, resource_type,
    resource_id, details, ip_address, user_agent, created_at, timestamp`.
    There is NO `status` column. The original `/events` SELECT pulled
    `status` directly, so every diagnostic-panel open against an order
    that had any user-activity-log correlation raised
    `UndefinedColumnError: column "status" does not exist` and the API
    returned HTTP 500. We now introspect the schema and only project
    the columns that exist, so deployments at any migration level keep
    rendering the diagnostic panel.
    """
    try:
        rows = await conn.fetch(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'user_activity_logs'
            """
        )
        return {r["column_name"] for r in rows}
    except Exception as exc:  # noqa: BLE001 — schema introspection is best-effort
        logger.warning("user_activity_logs schema introspection failed: %s", exc)
        return set()


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

    Bulgu #94/#95 (Round-25 audit): every sub-query is wrapped so that a
    partial failure (missing column, missing table, malformed JSONB) is
    surfaced via `meta.errors[]` rather than collapsing the whole panel
    to HTTP 500. The diagnostic UI is a debugging surface — it must not
    itself become opaque when one of its data sources is degraded.
    """
    current_user = await get_current_user_from_token(authorization)
    if not await check_user_permission(current_user["id"], "ssl", "read"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.read required")

    if limit <= 0 or limit > 500:
        limit = 100

    correlation_id = uuid.uuid4().hex[:12]
    conn = await get_database_connection()
    section_errors: List[dict] = []
    try:
        try:
            await _load_order(conn, order_id)
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001 — surface, don't 500
            logger.exception(
                "ACME events load_order failed order=%s correlation_id=%s",
                order_id,
                correlation_id,
            )
            return {
                "order_id": order_id,
                "events": [],
                "count": 0,
                "meta": {
                    "correlation_id": correlation_id,
                    "errors": [
                        {
                            "section": "load_order",
                            "exception_type": exc.__class__.__name__,
                            "message": str(exc),
                        }
                    ],
                },
            }

        events: List[dict] = []

        # --- Section 1: acme_order_events ---
        try:
            events_table_exists = await conn.fetchval(
                """
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = 'acme_order_events'
                )
                """
            )
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
        except Exception as exc:  # noqa: BLE001 — surface and continue
            logger.exception(
                "ACME events acme_order_events query failed order=%s correlation_id=%s",
                order_id,
                correlation_id,
            )
            section_errors.append({
                "section": "acme_order_events",
                "exception_type": exc.__class__.__name__,
                "message": str(exc),
            })

        # --- Section 2: user_activity_logs (best-effort, schema-aware) ---
        try:
            ua_columns = await _user_activity_columns(conn)
            if "resource_id" in ua_columns and "resource_type" in ua_columns:
                # Project only columns we know exist. `status` is NOT in
                # the canonical schema and was the original 500 cause.
                projection_candidates = [
                    "id", "action", "resource_type", "resource_id",
                    "details", "created_at", "user_id", "status",
                ]
                projection = [c for c in projection_candidates if c in ua_columns]
                if "id" not in projection or "created_at" not in projection:
                    raise RuntimeError(
                        "user_activity_logs is missing required columns "
                        "(id / created_at) — skipping correlation"
                    )
                sql = (
                    f"SELECT {', '.join(projection)} "
                    "FROM user_activity_logs "
                    "WHERE resource_type = 'letsencrypt_order' AND resource_id = $1 "
                    "ORDER BY created_at ASC, id ASC LIMIT $2"
                )
                ua_rows = await conn.fetch(sql, str(order_id), limit)
                for r in ua_rows:
                    rd = dict(r)
                    raw_details = rd.get("details")
                    if isinstance(raw_details, str):
                        msg = raw_details[:500]
                        details_obj = {}
                        try:
                            parsed = json.loads(raw_details)
                            if isinstance(parsed, (dict, list)):
                                details_obj = parsed
                        except Exception:
                            details_obj = {}
                    elif isinstance(raw_details, (dict, list)):
                        msg = ""
                        details_obj = raw_details
                    else:
                        msg = ""
                        details_obj = {}
                    raw_status = rd.get("status") or ""
                    severity = "info" if str(raw_status).lower() in ("success", "ok", "") else "warn"
                    events.append({
                        "source": "user_activity_log",
                        "id": rd.get("id"),
                        "event_type": rd.get("action"),
                        "severity": severity,
                        "message": msg,
                        "details": details_obj,
                        "correlation_id": None,
                        "created_at": rd["created_at"].isoformat().replace("+00:00", "Z")
                            if rd.get("created_at") else None,
                    })
            else:
                section_errors.append({
                    "section": "user_activity_logs",
                    "exception_type": "SchemaMissing",
                    "message": "user_activity_logs lacks resource_type/resource_id columns",
                })
        except Exception as exc:  # noqa: BLE001 — surface and continue
            logger.exception(
                "ACME events user_activity_logs query failed order=%s correlation_id=%s",
                order_id,
                correlation_id,
            )
            section_errors.append({
                "section": "user_activity_logs",
                "exception_type": exc.__class__.__name__,
                "message": str(exc),
            })

        events.sort(key=lambda e: (e["created_at"] or "", e.get("id") or 0))

        return {
            "order_id": order_id,
            "events": events,
            "count": len(events),
            "meta": {
                "correlation_id": correlation_id,
                "errors": section_errors,
            },
        }
    finally:
        await close_database_connection(conn)
