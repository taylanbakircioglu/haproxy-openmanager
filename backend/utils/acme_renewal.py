"""Issue #79: ACME auto-renewal settings and renewal-task events.

The hourly renewal task (main.check_letsencrypt_renewals) and the Renewal Schedule endpoint
read the same two settings through these helpers, so the UI shows exactly what the task does.

The task also records an event on a certificate's ACME order when it cannot start a renewal.
Before this, those failures only reached the backend log.
"""

import json
import logging
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Optional, Tuple

from database.connection import get_database_connection, close_database_connection

logger = logging.getLogger(__name__)

DEFAULT_RENEW_BEFORE_DAYS = 30

RENEWAL_EVENT_FAILED = "acme.renewal.failed"
RENEWAL_EVENT_SKIPPED = "acme.renewal.skipped"
RENEWAL_EVENT_TYPES = (RENEWAL_EVENT_FAILED, RENEWAL_EVENT_SKIPPED)

# The task runs hourly; the same reason is recorded at most once per order in this window.
RENEWAL_EVENT_THROTTLE_HOURS = 24
# How long the Renewal Schedule keeps showing the last recorded reason. Longer than the
# throttle so a reason that keeps recurring stays visible between two records.
RENEWAL_ISSUE_VISIBLE_HOURS = 48
# pg_advisory_xact_lock(ns, order_id) around check-then-insert: every uvicorn worker and replica
# runs its own renewal task. Distinct from the other (ns, id) spaces: 18181818-18181821,
# 18181873 and 0x41434D45 (held by _complete_certificate for the same order ids).
RENEWAL_EVENT_LOCK_NS = 18181879


def parse_auto_renew_enabled(raw: Any) -> bool:
    """Value of system_settings `acme.auto_renew_enabled` as the renewal task reads it."""
    if not raw:
        return False
    try:
        val = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError):
        return False
    return val in (True, 'true', 'True')


def parse_renew_before_days(raw: Any) -> int:
    """Value of system_settings `acme.renew_before_days` as the renewal task reads it."""
    if not raw:
        return DEFAULT_RENEW_BEFORE_DAYS
    try:
        return int(json.loads(raw) if isinstance(raw, str) else raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        return DEFAULT_RENEW_BEFORE_DAYS


def renewal_due_date(expiry: Any, renew_before_days: Optional[int]) -> Optional[date]:
    """First day on which the renewal task picks the certificate up.

    The task selects `expiry_date <= CURRENT_DATE + renew_before_days days`, so this is the
    smallest date D with D 00:00 + N days >= expiry: one day after expiry - N when expiry is
    not at midnight. ssl_certificates.expiry_date is TIMESTAMP or, on some older installs, DATE.
    """
    if expiry is None or renew_before_days is None:
        return None
    if isinstance(expiry, datetime):
        if expiry.tzinfo is not None:
            expiry = expiry.astimezone(timezone.utc).replace(tzinfo=None)
        threshold = expiry - timedelta(days=renew_before_days)
        due = threshold.date()
        return due if threshold.time() == time.min else due + timedelta(days=1)
    if isinstance(expiry, date):
        return expiry - timedelta(days=renew_before_days)
    return None


async def load_renewal_settings(conn) -> Tuple[bool, int]:
    enabled_raw = await conn.fetchval(
        "SELECT value FROM system_settings WHERE key = 'acme.auto_renew_enabled'"
    )
    days_raw = await conn.fetchval(
        "SELECT value FROM system_settings WHERE key = 'acme.renew_before_days'"
    )
    return parse_auto_renew_enabled(enabled_raw), parse_renew_before_days(days_raw)


async def record_renewal_issue(
    order_id: int,
    event_type: str,
    message: str,
    *,
    severity: str = "WARNING",
    details: Optional[dict] = None,
) -> bool:
    """Record why the renewal task could not renew the certificate issued by `order_id`.

    Skipped when the same event type was already recorded on that order within
    RENEWAL_EVENT_THROTTLE_HOURS. Returns True when a row was written. Never raises.
    """
    from utils.activity_log import record_event

    conn = None
    try:
        conn = await get_database_connection()
        async with conn.transaction():
            await conn.execute(
                "SELECT pg_advisory_xact_lock($1, $2)", RENEWAL_EVENT_LOCK_NS, order_id
            )
            recent = await conn.fetchval(
                """
                SELECT 1 FROM acme_order_events
                WHERE order_id = $1 AND event_type = $2
                  AND created_at > NOW() - ($3 || ' hours')::INTERVAL
                LIMIT 1
                """,
                order_id, event_type, str(RENEWAL_EVENT_THROTTLE_HOURS),
            )
            if recent:
                return False
            row_id = await record_event(
                order_id, event_type,
                severity=severity,
                message=(message or "")[:500],
                details=details,
                conn=conn,
            )
            return row_id is not None
    except Exception as exc:
        logger.debug(f"record_renewal_issue skipped (order_id={order_id}): {exc}")
        return False
    finally:
        if conn is not None:
            try:
                await close_database_connection(conn)
            except Exception:
                pass


async def fetch_latest_renewal_issues(conn, order_ids) -> dict:
    """Latest renewal-task event per order, within RENEWAL_ISSUE_VISIBLE_HOURS.

    Returns {order_id: {event_type, severity, message, created_at}}. Returns {} on any
    failure, so the caller's own response never depends on the event table.
    """
    ids = sorted({int(i) for i in order_ids if i})
    if not ids:
        return {}
    try:
        rows = await conn.fetch(
            """
            SELECT DISTINCT ON (order_id) order_id, event_type, severity, message, created_at
            FROM acme_order_events
            WHERE order_id = ANY($1::int[])
              AND event_type = ANY($2::text[])
              AND created_at > NOW() - ($3 || ' hours')::INTERVAL
            ORDER BY order_id, created_at DESC
            """,
            ids, list(RENEWAL_EVENT_TYPES), str(RENEWAL_ISSUE_VISIBLE_HOURS),
        )
    except Exception as exc:
        logger.debug(f"fetch_latest_renewal_issues skipped: {exc}")
        return {}
    return {
        r["order_id"]: {
            "event_type": r["event_type"],
            "severity": r["severity"],
            "message": r["message"],
            "created_at": r["created_at"],
        }
        for r in rows
    }
