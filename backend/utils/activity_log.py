import asyncio
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from database.connection import get_database_connection, close_database_connection

logger = logging.getLogger(__name__)

async def log_user_activity(
    user_id: int,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
):
    """Log user activity to the database"""
    try:
        conn = await get_database_connection()
        
        # Serialize details to JSON if it's a dict
        details_json = json.dumps(details) if details and isinstance(details, dict) else details
        
        # Try with created_at column first, then fallback
        try:
            await conn.execute("""
                INSERT INTO user_activity_logs 
                (user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """, user_id, action, resource_type, resource_id, 
                details_json, ip_address, user_agent, datetime.utcnow())
        except Exception as column_error:
            logger.warning(f"created_at column not found, trying fallback: {column_error}")
            # Fallback without created_at column
            await conn.execute("""
                INSERT INTO user_activity_logs 
                (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            """, user_id, action, resource_type, resource_id, 
                details_json, ip_address, user_agent)
        
        await close_database_connection(conn)
        
    except Exception as e:
        logger.error(f"Failed to log user activity: {e}")
        # Don't raise exception - activity logging should not break the main flow

async def get_user_activity_logs(
    user_id: Optional[int] = None,
    limit: int = 100,
    offset: int = 0
) -> list:
    """Get user activity logs"""
    try:
        conn = await get_database_connection()
        
        # Schema-safe activity log queries
        try:
            if user_id:
                logs = await conn.fetch("""
                    SELECT ual.*, u.username
                    FROM user_activity_logs ual
                    LEFT JOIN users u ON ual.user_id = u.id
                    WHERE ual.user_id = $1
                    ORDER BY ual.created_at DESC
                    LIMIT $2 OFFSET $3
                """, user_id, limit, offset)
            else:
                logs = await conn.fetch("""
                    SELECT ual.*, u.username
                    FROM user_activity_logs ual
                    LEFT JOIN users u ON ual.user_id = u.id
                    ORDER BY ual.created_at DESC
                    LIMIT $1 OFFSET $2
                """, limit, offset)
        except Exception as schema_error:
            logger.warning(f"Schema error in activity logs, using fallback: {schema_error}")
            # Fallback without ORDER BY created_at
            if user_id:
                logs = await conn.fetch("""
                    SELECT ual.*, u.username
                    FROM user_activity_logs ual
                    LEFT JOIN users u ON ual.user_id = u.id
                    WHERE ual.user_id = $1
                    LIMIT $2 OFFSET $3
                """, user_id, limit, offset)
            else:
                logs = await conn.fetch("""
                    SELECT ual.*, u.username
                    FROM user_activity_logs ual
                    LEFT JOIN users u ON ual.user_id = u.id
                    LIMIT $1 OFFSET $2
                """, limit, offset)
        
        await close_database_connection(conn)
        return logs
        
    except Exception as e:
        logger.error(f"Failed to get user activity logs: {e}")
        return []


# ----------------------------------------------------------------------------
# v1.5.0 Feature A (Issue #13): typed ACME order event log helper
# ----------------------------------------------------------------------------


async def record_event(
    order_id: int,
    event_type: str,
    *,
    severity: str = "INFO",
    message: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None,
    conn=None,
) -> Optional[int]:
    """Insert a typed event row into acme_order_events.

    Wrapped in try/except so that an event-log DB failure NEVER breaks the
    main ACME flow (Section 5.2 of the v1.5.0 plan).

    M24: when `conn` is passed in (e.g. inside the
    complete_pending_acme_orders pool-pressure-sensitive task), reuse the
    existing connection instead of acquiring a new one from the pool.

    Returns the inserted row id, or None on failure.
    """
    own_conn = False
    try:
        if conn is None:
            conn = await get_database_connection()
            own_conn = True

        details_json = json.dumps(details or {}) if not isinstance(details, str) else details
        try:
            row_id = await conn.fetchval(
                """
                INSERT INTO acme_order_events (
                    order_id, event_type, severity, message, details, correlation_id
                ) VALUES ($1, $2, $3, $4, $5::jsonb, $6)
                RETURNING id
                """,
                order_id,
                event_type,
                severity.upper() if severity else "INFO",
                message,
                details_json,
                correlation_id,
            )
            return row_id
        except Exception as e:
            # Most likely cause: acme_order_events table missing in older
            # deployments (migration not yet run). NEVER raise.
            logger.debug(
                f"record_event: insert failed (order_id={order_id}, "
                f"event_type={event_type}): {e}"
            )
            return None
    except Exception as e:
        logger.debug(f"record_event: outer failure (order_id={order_id}): {e}")
        return None
    finally:
        if own_conn and conn is not None:
            try:
                await close_database_connection(conn)
            except Exception:
                pass


async def prune_acme_events_and_drafts_if_due() -> Dict[str, int]:
    """Daily-watermarked TTL prune (M30 / Section 5.3 of v1.5.0 plan).

    - acme_order_events: 90d retention.
    - wizard_drafts: 30d retention (also pruned by expires_at < NOW() since
      that column exists explicitly).

    Watermarking via system_settings (dot-notation keys —
    `acme.events_last_pruned_at` / `wizard.drafts_last_pruned_at`)
    ensures multi-replica deployments only run the prune once per day.

    Always returns a dict with the (possibly zero) prune counts. Never raises.
    """
    counts = {"acme_events": 0, "wizard_drafts": 0}
    conn = None
    try:
        conn = await get_database_connection()

        async def _maybe_run(setting_key: str, ttl_query: str) -> int:
            """Returns # rows pruned, or 0 if not yet due."""
            try:
                row = await conn.fetchrow(
                    "SELECT value FROM system_settings WHERE key = $1",
                    setting_key,
                )
                last_at: Optional[datetime] = None
                if row and row["value"] is not None:
                    raw = row["value"]
                    if isinstance(raw, str):
                        try:
                            raw = json.loads(raw)
                        except json.JSONDecodeError:
                            raw = None
                    if isinstance(raw, str):
                        try:
                            last_at = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                        except ValueError:
                            last_at = None

                if last_at is not None:
                    age_seconds = (datetime.utcnow() - last_at.replace(tzinfo=None)).total_seconds()
                    if age_seconds < 24 * 3600:
                        return 0

                result = await conn.execute(ttl_query)
                count = 0
                if isinstance(result, str) and result.startswith("DELETE "):
                    try:
                        count = int(result.split()[-1])
                    except (ValueError, IndexError):
                        count = 0

                ts_value = json.dumps(datetime.utcnow().isoformat() + "Z")
                await conn.execute(
                    """
                    INSERT INTO system_settings (key, value, category, description)
                    VALUES ($1, $2::jsonb, $3, $4)
                    ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP
                    """,
                    setting_key,
                    ts_value,
                    "acme" if setting_key.startswith("acme.") else "wizard",
                    "Internal: last daily prune timestamp (v1.5.0)",
                )
                return count
            except Exception as inner:
                logger.debug(f"prune watermark step failed for {setting_key}: {inner}")
                return 0

        # acme_order_events 90d
        counts["acme_events"] = await _maybe_run(
            "acme.events_last_pruned_at",
            "DELETE FROM acme_order_events WHERE created_at < NOW() - INTERVAL '90 days'",
        )
        # wizard_drafts 30d (also catches expires_at-passed rows)
        counts["wizard_drafts"] = await _maybe_run(
            "wizard.drafts_last_pruned_at",
            """
            DELETE FROM wizard_drafts
            WHERE created_at < NOW() - INTERVAL '30 days'
               OR expires_at < NOW()
            """,
        )

        if counts["acme_events"] or counts["wizard_drafts"]:
            logger.info(
                f"v1.5.0 daily prune: acme_events={counts['acme_events']} "
                f"wizard_drafts={counts['wizard_drafts']}"
            )
        return counts
    except Exception as e:
        logger.debug(f"prune_acme_events_and_drafts_if_due: {e}")
        return counts
    finally:
        if conn is not None:
            try:
                await close_database_connection(conn)
            except Exception:
                pass
