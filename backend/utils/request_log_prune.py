"""v1.11.0 — retention prune for `request_logs`.

Three independent limits, applied in order:

  1. successful rows (`status_class` 1..3) older than `success_retention_days`
  2. errored rows (`status_class` 0, 4, 5 — 0 meaning "no HTTP response at
     all") older than `error_retention_days`
  3. a hard row cap: anything below the `max_rows`-th newest id

Splitting success from error is the point of the design: a busy install can
keep a week of ordinary traffic while still holding three months of failures
for forensics, without paying for both.

Deliberately NOT folded into `utils/activity_log.prune_acme_events_and_drafts_if_due`:
that function is driven by tests with fixed `execute.side_effect` lists and an
exact return dict, and it is gated behind a `letsencrypt_orders`-exists check
that would silently disable this prune on an ACME-free install.

Three safety properties, all of which matter at scale:

  * **Batched deletes.** The pool sets `command_timeout=60`; an unbounded
    DELETE over a multi-million-row table raises `asyncpg.TimeoutError` and
    then nothing is ever pruned.
  * **Advisory lock.** `pg_try_advisory_lock` (try, never block) so N replicas
    × M uvicorn workers do not all scan at once.
  * **Watermark stamped only after a complete pass.** A pass that times out
    mid-way is retried at the next tick instead of being recorded as done.
"""
import json
import logging
from datetime import datetime
from typing import Dict, Optional

from database.connection import get_database_connection, close_database_connection
from utils.request_log_settings import get_config

logger = logging.getLogger("haproxy_openmanager.request_log")

# Fresh namespace. Already taken in this codebase: 18181818 (draft cap),
# 18181819 (wizard create), 18181820 (apply), 0x41434D45 (per-ACME-order),
# 1836016242 (migration lock).
PRUNE_LOCK_KEY = 18181821

WATERMARK_KEY = "requestlog.last_pruned_at"

BATCH_SIZE = 5000
MAX_BATCHES = 40  # ceiling of 200k rows removed per pass

# Retention days ALWAYS travel as a bind parameter. They are operator-supplied,
# so interpolating them into the SQL string would be an injection point.
_SQL_TTL_SUCCESS = """
DELETE FROM request_logs
WHERE ctid IN (
    SELECT ctid FROM request_logs
    WHERE status_class BETWEEN 1 AND 3
      AND created_at < NOW() - ($1 || ' days')::INTERVAL
    LIMIT $2
)
"""

_SQL_TTL_ERROR = """
DELETE FROM request_logs
WHERE ctid IN (
    SELECT ctid FROM request_logs
    WHERE (status_class = 0 OR status_class >= 4)
      AND created_at < NOW() - ($1 || ' days')::INTERVAL
    LIMIT $2
)
"""

_SQL_CAP_CUTOFF = "SELECT id FROM request_logs ORDER BY id DESC OFFSET $1 LIMIT 1"

_SQL_CAP_DELETE = """
DELETE FROM request_logs
WHERE ctid IN (
    SELECT ctid FROM request_logs WHERE id <= $1 LIMIT $2
)
"""


def _deleted_count(result) -> int:
    """asyncpg returns the command tag ('DELETE 42') from execute()."""
    if isinstance(result, str) and result.startswith("DELETE "):
        try:
            return int(result.split()[-1])
        except (ValueError, IndexError):
            return 0
    return 0


async def _batched_delete(conn, sql: str, first_param) -> int:
    """Run `sql` repeatedly until a short batch comes back or the ceiling hits."""
    total = 0
    for _ in range(MAX_BATCHES):
        result = await conn.execute(sql, first_param, BATCH_SIZE)
        count = _deleted_count(result)
        total += count
        if count < BATCH_SIZE:
            break
    else:
        logger.info(
            f"request_logs prune hit the {MAX_BATCHES}-batch ceiling "
            f"({total} rows this pass); the remainder is removed on the next run"
        )
    return total


async def _is_due(conn, key: str, min_interval_seconds: int) -> bool:
    """Watermark gate. Unlike the hardcoded 24h in utils/activity_log.py the
    interval here is operator-configurable."""
    row = await conn.fetchrow("SELECT value FROM system_settings WHERE key = $1", key)
    if not row or row["value"] is None:
        return True
    raw = row["value"]
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return True
    if not isinstance(raw, str):
        return True
    try:
        last = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return True
    age = (datetime.utcnow() - last.replace(tzinfo=None)).total_seconds()
    return age >= min_interval_seconds


async def _stamp(conn, key: str) -> None:
    await conn.execute(
        """
        INSERT INTO system_settings (key, value, category, description)
        VALUES ($1, $2::jsonb, 'requestlog', 'Internal: last request_logs prune timestamp')
        ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP
        """,
        key,
        json.dumps(datetime.utcnow().isoformat() + "Z"),
    )


async def _prune_row_cap(conn, max_rows: int) -> int:
    """Delete everything below the `max_rows`-th newest id."""
    cutoff: Optional[int] = await conn.fetchval(_SQL_CAP_CUTOFF, max_rows)
    if cutoff is None:
        return 0  # fewer rows than the cap — nothing to do
    return await _batched_delete(conn, _SQL_CAP_DELETE, cutoff)


async def prune_request_logs_if_due(force: bool = False) -> Dict[str, int]:
    """Run one retention pass if the watermark says it is due.

    Never raises: a prune failure must not take down the loop that calls it.
    `force=True` skips the watermark gate (used by the manual purge endpoint).
    """
    counts = {"success": 0, "error": 0, "overflow": 0, "ran": 0}
    cfg = get_config()

    conn = None
    locked = False
    try:
        conn = await get_database_connection()

        # One replica only. try-lock: never block a pod waiting on another's pass.
        locked = await conn.fetchval("SELECT pg_try_advisory_lock($1)", PRUNE_LOCK_KEY)
        if not locked:
            return counts

        if not force and not await _is_due(conn, WATERMARK_KEY, cfg.prune_interval_minutes * 60):
            return counts

        counts["success"] = await _batched_delete(conn, _SQL_TTL_SUCCESS, str(cfg.success_retention_days))
        counts["error"] = await _batched_delete(conn, _SQL_TTL_ERROR, str(cfg.error_retention_days))
        counts["overflow"] = await _prune_row_cap(conn, cfg.max_rows)
        counts["ran"] = 1

        # Only after all three steps completed — a partial pass must be retried,
        # not recorded as done.
        await _stamp(conn, WATERMARK_KEY)

        if counts["success"] or counts["error"] or counts["overflow"]:
            logger.info(
                f"request_logs prune: {counts['success']} successful, {counts['error']} errored, "
                f"{counts['overflow']} over-cap row(s) removed"
            )
        return counts
    except Exception as exc:
        logger.warning(f"prune_request_logs_if_due: {exc}")
        return counts
    finally:
        if conn is not None:
            if locked:
                try:
                    await conn.execute("SELECT pg_advisory_unlock($1)", PRUNE_LOCK_KEY)
                except Exception:
                    pass
            try:
                await close_database_connection(conn)
            except Exception:
                pass
