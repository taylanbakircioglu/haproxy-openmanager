"""v1.11.0 — operator-tunable settings for the request/response log.

The middleware runs on EVERY request, so the hot path must not touch the
database. `get_config()` returns a module-global immutable snapshot with no
`await`; `refresh_config()` reloads it from `system_settings` and is called

  * once at startup, right after migrations,
  * every `_TTL_SECONDS` from the sink's writer loop (off the request path),
  * synchronously at the end of `PUT /api/request-logs/settings`, so an
    operator's change takes effect immediately instead of up to 30s later.

asyncpg has no JSONB codec registered on this pool (see
database/connection.py), so every value comes back as a raw JSON *string* and
needs the `isinstance(v, str)` + `json.loads` guard used elsewhere in this
codebase (services/acme_service.py, utils/activity_log.py).
"""
import json
import logging
import time
from dataclasses import dataclass, replace
from typing import Any, Dict, Optional, Tuple

from database.connection import get_database_connection, close_database_connection

logger = logging.getLogger("haproxy_openmanager.request_log")

SETTINGS_CATEGORY = "requestlog"

# Kept in sync with the seed in database/migrations.ensure_request_log_settings().
# backend/tests/test_request_log_settings.py asserts the two agree, so a change
# here without a change there fails the suite rather than drifting silently.
DEFAULT_EXCLUDE_PATHS = (
    "/api/request-logs",
    "/api/health",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/.well-known/acme-challenge",
    "/api/agents/heartbeat",
    "/static",
    "/favicon.ico",
)


@dataclass(frozen=True)
class RequestLogConfig:
    enabled: bool = True
    capture_inbound: bool = True
    capture_outbound: bool = True
    capture_bodies: bool = True
    capture_get: bool = True
    # SUCCESSFUL agent polls only. Off by default because the row rate of this
    # table is otherwise a linear function of fleet size, not of operator
    # activity: each agent runs a 30s cycle that issues three logged calls
    # (config, pending-requests, upgrade-status; the heartbeat is already
    # excluded) plus two more every fifth cycle. Measured, that is ~9 800 rows
    # per day PER AGENT, so a 200-node fleet writes ~2M rows/day and reaches the
    # 500 000 max_rows cap in about six hours - at which point the shipped
    # "7 days of successes, 30 days of failures" is not 7 and 30, it is 0.25.
    # FAILED agent calls are always kept regardless of this flag: they are the
    # half an operator actually needs, and they are rare.
    capture_agent_success: bool = False
    max_body_bytes: int = 8192
    sample_rate: float = 1.0
    exclude_paths: Tuple[str, ...] = DEFAULT_EXCLUDE_PATHS
    success_retention_days: int = 7
    error_retention_days: int = 30
    max_rows: int = 500000
    prune_interval_minutes: int = 60

    def as_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "capture_inbound": self.capture_inbound,
            "capture_outbound": self.capture_outbound,
            "capture_bodies": self.capture_bodies,
            "capture_get": self.capture_get,
            "capture_agent_success": self.capture_agent_success,
            "max_body_bytes": self.max_body_bytes,
            "sample_rate": self.sample_rate,
            "exclude_paths": list(self.exclude_paths),
            "success_retention_days": self.success_retention_days,
            "error_retention_days": self.error_retention_days,
            "max_rows": self.max_rows,
            "prune_interval_minutes": self.prune_interval_minutes,
        }


DEFAULT_CONFIG = RequestLogConfig()

_CACHE: RequestLogConfig = DEFAULT_CONFIG
_CACHE_AT: float = 0.0
_TTL_SECONDS: float = 30.0

# Bounds, mirrored by the Pydantic model in routers/request_logs.py. Kept here
# too because refresh_config() reads whatever is in the table, which may have
# been written by an older build or by hand.
_BOUNDS = {
    "max_body_bytes": (0, 262144),
    "success_retention_days": (1, 365),
    "error_retention_days": (1, 365),
    "max_rows": (1000, 50_000_000),
    "prune_interval_minutes": (5, 1440),
}

MAX_EXCLUDE_PATHS = 64
MAX_EXCLUDE_PATH_LENGTH = 200


def get_config() -> RequestLogConfig:
    """Hot-path read: no await, no DB, no lock. Returns the last snapshot."""
    return _CACHE


def set_config(config: RequestLogConfig) -> None:
    """Replace the snapshot directly. Used by the settings PUT handler (which
    already has the validated values) and by tests."""
    global _CACHE, _CACHE_AT
    _CACHE = config
    _CACHE_AT = time.monotonic()


def _clamp_int(raw: Any, field: str, fallback: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return fallback
    low, high = _BOUNDS[field]
    return max(low, min(high, value))


def _clamp_float(raw: Any, fallback: float, low: float, high: float) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return fallback
    return max(low, min(high, value))


def _as_bool(raw: Any, fallback: bool) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    if isinstance(raw, str):
        lowered = raw.strip().lower()
        if lowered in ("true", "1", "yes", "on"):
            return True
        if lowered in ("false", "0", "no", "off"):
            return False
    return fallback


def normalize_exclude_paths(raw: Any, fallback: Tuple[str, ...]) -> Tuple[str, ...]:
    """Coerce whatever is stored into a bounded tuple of path prefixes."""
    if not isinstance(raw, (list, tuple)):
        return fallback
    out = []
    for item in raw:
        if not isinstance(item, str):
            continue
        candidate = item.strip()
        if not candidate.startswith("/") or len(candidate) > MAX_EXCLUDE_PATH_LENGTH:
            continue
        out.append(candidate)
        if len(out) >= MAX_EXCLUDE_PATHS:
            break
    return tuple(out) if out else fallback


def config_from_mapping(values: Dict[str, Any], base: Optional[RequestLogConfig] = None) -> RequestLogConfig:
    """Build a config from a plain suffix→value mapping, clamping every field.

    Unknown keys are ignored and missing keys keep the value from `base`
    (default: the shipped defaults), so a partially-seeded table still yields a
    complete, usable config.
    """
    base = base or DEFAULT_CONFIG
    return replace(
        base,
        enabled=_as_bool(values.get("enabled", base.enabled), base.enabled),
        capture_inbound=_as_bool(values.get("capture_inbound", base.capture_inbound), base.capture_inbound),
        capture_outbound=_as_bool(values.get("capture_outbound", base.capture_outbound), base.capture_outbound),
        capture_bodies=_as_bool(values.get("capture_bodies", base.capture_bodies), base.capture_bodies),
        capture_get=_as_bool(values.get("capture_get", base.capture_get), base.capture_get),
        capture_agent_success=_as_bool(
            values.get("capture_agent_success", base.capture_agent_success),
            base.capture_agent_success,
        ),
        max_body_bytes=_clamp_int(values.get("max_body_bytes", base.max_body_bytes), "max_body_bytes", base.max_body_bytes),
        sample_rate=_clamp_float(values.get("sample_rate", base.sample_rate), base.sample_rate, 0.0, 1.0),
        exclude_paths=normalize_exclude_paths(values.get("exclude_paths"), base.exclude_paths),
        success_retention_days=_clamp_int(
            values.get("success_retention_days", base.success_retention_days),
            "success_retention_days", base.success_retention_days,
        ),
        error_retention_days=_clamp_int(
            values.get("error_retention_days", base.error_retention_days),
            "error_retention_days", base.error_retention_days,
        ),
        max_rows=_clamp_int(values.get("max_rows", base.max_rows), "max_rows", base.max_rows),
        prune_interval_minutes=_clamp_int(
            values.get("prune_interval_minutes", base.prune_interval_minutes),
            "prune_interval_minutes", base.prune_interval_minutes,
        ),
    )


def _decode_setting_value(raw: Any) -> Any:
    """JSONB comes back as a raw string on this pool — parse it, but keep the
    original text if it is not valid JSON (an operator may have hand-written
    `7` or `seven`)."""
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return raw
    return raw


async def load_settings_rows(conn) -> Dict[str, Any]:
    """Read the `requestlog.*` rows into a suffix→value mapping."""
    rows = await conn.fetch(
        "SELECT key, value FROM system_settings WHERE category = $1",
        SETTINGS_CATEGORY,
    )
    values: Dict[str, Any] = {}
    for row in rows:
        key = row["key"]
        suffix = key.split(".", 1)[1] if "." in key else key
        values[suffix] = _decode_setting_value(row["value"])
    return values


async def refresh_config(force: bool = True) -> RequestLogConfig:
    """Reload the snapshot from the database.

    Never raises and never leaves a half-built config behind: on any failure
    the previous snapshot is kept, so a transient DB blip cannot silently turn
    logging off (or on).
    """
    global _CACHE_AT
    if not force and (time.monotonic() - _CACHE_AT) < _TTL_SECONDS:
        return _CACHE

    conn = None
    try:
        conn = await get_database_connection()
        values = await load_settings_rows(conn)
        if values:
            set_config(config_from_mapping(values))
        else:
            # Table not seeded yet (fresh install mid-migration) — keep the
            # in-code defaults but stamp the timestamp so we don't re-query
            # every tick.
            _CACHE_AT = time.monotonic()
        return _CACHE
    except Exception as exc:
        logger.debug(f"refresh_config: keeping previous snapshot ({exc})")
        _CACHE_AT = time.monotonic()
        return _CACHE
    finally:
        if conn is not None:
            try:
                await close_database_connection(conn)
            except Exception:
                pass


async def maybe_refresh_config() -> RequestLogConfig:
    """TTL-gated refresh, called from the sink's writer loop."""
    return await refresh_config(force=False)
