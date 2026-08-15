"""v1.11.0 — the read/administration API for the unified request/response log.

Endpoints (declaration order matters — see below):

    GET    /api/request-logs/settings   requestlog.manage
    PUT    /api/request-logs/settings   requestlog.manage
    GET    /api/request-logs/stats      requestlog.read
    POST   /api/request-logs/purge      requestlog.manage
    GET    /api/request-logs            requestlog.read
    GET    /api/request-logs/{log_id}   requestlog.read

`/{log_id}` is a single-segment path, so FastAPI — which matches in declaration
order — would shadow `/settings`, `/stats` and `/purge` if it came first. The
literals are therefore declared before it. (This is the mirror image of the
trap in routers/settings.py, where `GET /{category}` sits at the top of the
file and swallows every literal route added after it.)

Settings are stored in `system_settings` under the `requestlog` category, so
`GET /api/settings/requestlog` still reads them, but writes go through THIS
router: the generic `PUT /api/settings/{category}` stringifies values with
`str(value)`, which turns `True` into `'True'` — not valid JSON, and the
`::jsonb` cast then fails.
"""
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from auth_middleware import check_user_permission, get_current_user_from_token
from database.connection import get_database_connection, close_database_connection
from utils.request_log_settings import (
    DEFAULT_CONFIG,
    DEFAULT_EXCLUDE_PATHS,
    MAX_EXCLUDE_PATHS,
    MAX_EXCLUDE_PATH_LENGTH,
    SETTINGS_CATEGORY,
    config_from_mapping,
    get_config,
    load_settings_rows,
    refresh_config,
    set_config,
)
from utils.request_log_sink import TARGET_INBOUND_AGENT, request_log_sink

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/request-logs", tags=["Request Logs"])

# Columns returned by the list endpoint. Bodies and headers are detail-only:
# a 200-row page carrying two 8 KB JSONB blobs per row is a 3 MB response.
_LIST_COLUMNS = """
    id, request_id, direction, target, method, url, path, status_code,
    status_class, duration_ms, user_id, username, host(client_ip) AS client_ip,
    error, request_body_bytes, response_body_bytes, truncated, created_at
"""

_JSONB_COLUMNS = ("query_params", "request_headers", "request_body",
                  "response_headers", "response_body")


class RequestLogSettings(BaseModel):
    """Operator-tunable capture + retention policy."""

    enabled: bool = True
    capture_inbound: bool = True
    capture_outbound: bool = True
    capture_bodies: bool = True
    capture_get: bool = True
    capture_agent_success: bool = False
    max_body_bytes: int = Field(8192, ge=0, le=262144)
    sample_rate: float = Field(1.0, ge=0.0, le=1.0)
    exclude_paths: List[str] = Field(
        default_factory=lambda: list(DEFAULT_EXCLUDE_PATHS),
        max_length=MAX_EXCLUDE_PATHS,
    )
    success_retention_days: int = Field(7, ge=1, le=365)
    error_retention_days: int = Field(30, ge=1, le=365)
    max_rows: int = Field(500000, ge=1000, le=50_000_000)
    prune_interval_minutes: int = Field(60, ge=5, le=1440)

    @field_validator("exclude_paths")
    @classmethod
    def _validate_paths(cls, value: List[str]) -> List[str]:
        for entry in value:
            if not entry.startswith("/"):
                raise ValueError("exclude_paths entries must start with '/'")
            if len(entry) > MAX_EXCLUDE_PATH_LENGTH:
                raise ValueError(
                    f"exclude_paths entries must be <= {MAX_EXCLUDE_PATH_LENGTH} characters"
                )
        return value


async def _require(authorization: Optional[str], action: str) -> Dict[str, Any]:
    """Authenticate, then enforce `requestlog.<action>`.

    `current_user=` is passed through so the admin bypass in
    check_user_permission short-circuits without a second DB round-trip.
    """
    current_user = await get_current_user_from_token(authorization)
    allowed = await check_user_permission(
        current_user["id"], "requestlog", action, current_user=current_user
    )
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Insufficient permissions: requestlog.{action} required",
        )
    return current_user


async def _can_manage(current_user: Dict[str, Any]) -> bool:
    return await check_user_permission(
        current_user["id"], "requestlog", "manage", current_user=current_user
    )


def _parse_jsonb(value: Any) -> Any:
    """asyncpg has no JSONB codec on this pool, so JSONB comes back as raw
    text. This router is a new contract, so it parses server-side and returns
    real JSON rather than pushing a JSON.parse() into the UI."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return value
    return value


def _row_to_dict(row) -> Dict[str, Any]:
    out = dict(row)
    for key in _JSONB_COLUMNS:
        if key in out:
            out[key] = _parse_jsonb(out[key])
    created = out.get("created_at")
    if isinstance(created, datetime):
        out["created_at"] = created.isoformat()
    return out


# ---------------------------------------------------------------------------
# Literal paths FIRST — see the module docstring.
# ---------------------------------------------------------------------------


@router.get("/settings")
async def get_request_log_settings(authorization: Optional[str] = Header(None)):
    """Current capture + retention policy, plus the shipped defaults so the UI
    can offer a 'reset' without hardcoding them."""
    await _require(authorization, "manage")

    conn = None
    try:
        conn = await get_database_connection()
        values = await load_settings_rows(conn)
        config = config_from_mapping(values) if values else DEFAULT_CONFIG
        return {
            "settings": config.as_dict(),
            "defaults": DEFAULT_CONFIG.as_dict(),
            "category": SETTINGS_CATEGORY,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching request log settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch request log settings")
    finally:
        if conn is not None:
            await close_database_connection(conn)


@router.put("/settings")
async def update_request_log_settings(
    body: RequestLogSettings,
    authorization: Optional[str] = Header(None),
):
    """Persist the policy and apply it immediately.

    `refresh_config()` at the end is what makes an operator's change take
    effect on the very next request instead of up to 30 seconds later, when
    the writer loop would otherwise pick it up.
    """
    current_user = await _require(authorization, "manage")

    conn = None
    try:
        conn = await get_database_connection()
        updated = []
        for suffix, value in body.model_dump().items():
            await conn.execute(
                """
                INSERT INTO system_settings (key, value, category, updated_at, updated_by)
                VALUES ($1, $2::jsonb, $3, $4, $5)
                ON CONFLICT (key) DO UPDATE SET
                    value = EXCLUDED.value,
                    updated_at = EXCLUDED.updated_at,
                    updated_by = EXCLUDED.updated_by
                """,
                f"{SETTINGS_CATEGORY}.{suffix}",
                json.dumps(value),
                SETTINGS_CATEGORY,
                datetime.utcnow(),
                current_user.get("id"),
            )
            updated.append(suffix)

        # Apply in-process right away, then re-read so this worker's snapshot
        # is exactly what is on disk.
        set_config(config_from_mapping(body.model_dump()))
        await refresh_config()

        logger.info(
            f"Request log settings updated by {current_user.get('username')}: {len(updated)} keys"
        )
        return {"message": f"Updated {len(updated)} settings", "settings": get_config().as_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating request log settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to update request log settings")
    finally:
        if conn is not None:
            await close_database_connection(conn)


@router.get("/stats")
async def get_request_log_stats(
    authorization: Optional[str] = Header(None),
    hours: int = Query(24, ge=1, le=720),
):
    """Volume and error breakdown over a window, plus table-level totals and
    this worker's sink counters (so a saturated queue is visible)."""
    await _require(authorization, "read")

    conn = None
    try:
        conn = await get_database_connection()

        by_direction = await conn.fetch(
            """
            SELECT direction,
                   COUNT(*)                                                    AS total,
                   COUNT(*) FILTER (WHERE status_class = 0 OR status_class >= 4) AS errors,
                   COALESCE(ROUND(AVG(duration_ms))::int, 0)                   AS avg_duration_ms,
                   COALESCE(MAX(duration_ms), 0)                               AS max_duration_ms
            FROM request_logs
            WHERE created_at > NOW() - ($1 || ' hours')::INTERVAL
            GROUP BY direction
            """,
            str(hours),
        )

        by_status = await conn.fetch(
            """
            SELECT status_class, COUNT(*) AS total
            FROM request_logs
            WHERE created_at > NOW() - ($1 || ' hours')::INTERVAL
            GROUP BY status_class
            ORDER BY status_class
            """,
            str(hours),
        )

        by_target = await conn.fetch(
            """
            SELECT target,
                   COUNT(*)                                                    AS total,
                   COUNT(*) FILTER (WHERE status_class = 0 OR status_class >= 4) AS errors
            FROM request_logs
            WHERE target IS NOT NULL
              AND created_at > NOW() - ($1 || ' hours')::INTERVAL
            GROUP BY target
            ORDER BY total DESC
            LIMIT 20
            """,
            str(hours),
        )

        totals = await conn.fetchrow(
            "SELECT COUNT(*) AS total_rows, MIN(created_at) AS oldest_at, "
            "MAX(created_at) AS newest_at FROM request_logs"
        )

        return {
            "window_hours": hours,
            "by_direction": [dict(r) for r in by_direction],
            "by_status_class": [dict(r) for r in by_status],
            "by_target": [dict(r) for r in by_target],
            "total_rows": (totals or {}).get("total_rows", 0),
            "oldest_at": totals["oldest_at"].isoformat() if totals and totals["oldest_at"] else None,
            "newest_at": totals["newest_at"].isoformat() if totals and totals["newest_at"] else None,
            # THIS WORKER only. The sink is a module global, so with
            # UVICORN_WORKERS > 1 each process keeps its own queue and its own
            # counters, and whichever worker happens to serve this request is
            # the one being reported. Labelled rather than aggregated: there is
            # no cross-process channel here, and a number that looks fleet-wide
            # but is not would understate drops by exactly the worker count.
            "sink": {**request_log_sink.stats, "scope": "this worker only"},
            "retention": {
                "success_retention_days": get_config().success_retention_days,
                "error_retention_days": get_config().error_retention_days,
                "max_rows": get_config().max_rows,
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching request log stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch request log stats")
    finally:
        if conn is not None:
            await close_database_connection(conn)


@router.post("/purge")
async def purge_request_logs(authorization: Optional[str] = Header(None)):
    """Run a retention pass now, ignoring the watermark.

    This applies the CONFIGURED retention — it is not a 'delete everything'
    button. It exists so an operator who has just lowered the retention does
    not have to wait for the next scheduled pass to reclaim the space.
    """
    current_user = await _require(authorization, "manage")
    from utils.request_log_prune import prune_request_logs_if_due

    counts = await prune_request_logs_if_due(force=True)
    logger.info(f"Manual request log purge by {current_user.get('username')}: {counts}")
    return {
        "message": "Retention pass completed",
        "removed": {
            "success": counts.get("success", 0),
            "error": counts.get("error", 0),
            "overflow": counts.get("overflow", 0),
        },
        "ran": bool(counts.get("ran")),
    }


# ---------------------------------------------------------------------------
# List, then the catch-all detail route LAST.
# ---------------------------------------------------------------------------


@router.get("")
async def list_request_logs(
    authorization: Optional[str] = Header(None),
    direction: Optional[str] = Query(None, pattern="^(inbound|outbound)$"),
    status_class: Optional[int] = Query(None, ge=0, le=5),
    method: Optional[str] = Query(None, max_length=10),
    target: Optional[str] = Query(None, max_length=32),
    user_id: Optional[int] = Query(None, ge=1),
    path_prefix: Optional[str] = Query(None, max_length=200),
    q: Optional[str] = Query(None, max_length=200),
    request_id: Optional[str] = Query(None, max_length=64),
    errors_only: bool = Query(False),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    min_duration_ms: Optional[int] = Query(None, ge=0),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Filtered, server-paginated list. Bodies are not included — use the
    detail endpoint for those."""
    current_user = await _require(authorization, "read")
    can_manage = await _can_manage(current_user)

    where: List[str] = []
    params: List[Any] = []

    def add(clause_template: str, value: Any) -> None:
        params.append(value)
        where.append(clause_template.format(n=len(params)))

    if direction:
        add("direction = ${n}", direction)
    if status_class is not None:
        add("status_class = ${n}", status_class)
    if method:
        add("method = ${n}", method.upper())
    if target:
        add("target = ${n}", target)
    if user_id is not None:
        add("user_id = ${n}", user_id)
    if path_prefix:
        add("path LIKE ${n} || '%'", path_prefix)
    if q:
        # Substring search has no index to lean on; it is the deliberately slow
        # filter and should be combined with a time window.
        add("url ILIKE '%' || ${n} || '%'", q)
    if request_id:
        add("request_id = ${n}", request_id)
    if errors_only:
        where.append("(status_class = 0 OR status_class >= 4)")
    if since:
        add("created_at >= ${n}", since)
    if until:
        add("created_at <= ${n}", until)
    if min_duration_ms is not None:
        add("duration_ms >= ${n}", min_duration_ms)

    # Self-scoping. Captured bodies are a broader disclosure surface than the
    # existing activity log, so a caller holding only `requestlog.read` sees
    # their OWN inbound requests, plus the fleet's. `requestlog.manage` (and the
    # is_admin bypass inside it) lifts the restriction.
    #
    # The agent clause is not a widening for its own sake, it is what makes the
    # `operator` grant do what the migration says it is for: "operators debug
    # failing applies and ACME orders, so they get read access to the request
    # log". An apply fails on the NODE, and the node reports that back over its
    # own API key - so the row carrying the diagnosis is an agent row with
    # `user_id IS NULL`, which own-rows-only scoping hid from exactly the role
    # the grant was written for. Scoped on `target`, not on `user_id IS NULL`:
    # anonymous inbound traffic (failed logins and their usernames, unauthorised
    # probes) is NOT agent traffic and stays admin-only.
    if not can_manage:
        params.append(current_user["id"])
        own = f"user_id = ${len(params)}"
        params.append(TARGET_INBOUND_AGENT)
        where.append(
            f"(direction = 'inbound' AND ({own} OR target = ${len(params)}))"
        )

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    conn = None
    try:
        conn = await get_database_connection()

        rows = await conn.fetch(
            f"SELECT {_LIST_COLUMNS} FROM request_logs{where_sql} "
            f"ORDER BY id DESC LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}",
            *params, limit, offset,
        )

        # Bounded count: an unfiltered COUNT(*) over a multi-million-row table
        # is a sequential scan on every page change. Cap it and tell the client
        # the number is a floor.
        count_cap = 10001
        counted = await conn.fetchval(
            f"SELECT COUNT(*) FROM (SELECT 1 FROM request_logs{where_sql} LIMIT {count_cap}) t",
            *params,
        )
        total = int(counted or 0)

        return {
            "logs": [_row_to_dict(r) for r in rows],
            "total": total,
            "total_is_estimate": total >= count_cap,
            "limit": limit,
            "offset": offset,
            "scoped_to_self": not can_manage,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing request logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to list request logs")
    finally:
        if conn is not None:
            await close_database_connection(conn)


@router.get("/{log_id}")
async def get_request_log(log_id: int, authorization: Optional[str] = Header(None)):
    """One exchange in full, plus every other row sharing its `request_id`.

    That `related` list is the point of the feature: one inbound API call and
    the ACME / DNS / agent calls it triggered read as a single trace.
    """
    current_user = await _require(authorization, "read")
    can_manage = await _can_manage(current_user)

    conn = None
    try:
        conn = await get_database_connection()
        row = await conn.fetchrow(
            "SELECT *, host(client_ip) AS client_ip_text FROM request_logs WHERE id = $1",
            log_id,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Request log entry not found")

        record = _row_to_dict(row)
        record["client_ip"] = record.pop("client_ip_text", None)

        if not can_manage and not (
            record.get("direction") == "inbound"
            and (
                record.get("user_id") == current_user["id"]
                or record.get("target") == TARGET_INBOUND_AGENT
            )
        ):
            # Same self-scoping rule as the list endpoint. 404 rather than 403
            # so the endpoint does not confirm that a given id exists.
            raise HTTPException(status_code=404, detail="Request log entry not found")

        related = await conn.fetch(
            f"SELECT {_LIST_COLUMNS} FROM request_logs "
            "WHERE request_id = $1 AND id <> $2 ORDER BY id ASC LIMIT 100",
            record["request_id"], log_id,
        )

        return {"log": record, "related": [_row_to_dict(r) for r in related]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching request log {log_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch request log entry")
    finally:
        if conn is not None:
            await close_database_connection(conn)
