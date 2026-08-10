import os
from typing import Optional

# Database connection settings
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://haproxy_user:haproxy_password@postgres:5432/haproxy_openmanager")

# Redis connection
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# CORS settings
# Configurable via CORS_ORIGINS env var (comma-separated), e.g. "http://localhost:3000,http://server:8080"
# Default allows common development and Docker Compose origins
_cors_env = os.getenv("CORS_ORIGINS", "")
CORS_ORIGINS = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else [
    "http://localhost:3000",
    "http://localhost:8080",
    "http://localhost:8000",
]

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
JWT_SECRET_KEY = SECRET_KEY  # Alias for JWT middleware
ALGORITHM = "HS256"
JWT_ALGORITHM = ALGORITHM  # Alias for JWT middleware
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Logging level
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Public URL configuration (for agent installation scripts)
PUBLIC_URL = os.getenv("PUBLIC_URL", "http://localhost:8000")
MANAGEMENT_BASE_URL = os.getenv("MANAGEMENT_BASE_URL", PUBLIC_URL)  # Backward compatibility

# Agent settings
AGENT_HEARTBEAT_TIMEOUT_SECONDS = 15
AGENT_CONFIG_SYNC_INTERVAL_SECONDS = 30

# Entity snapshot enabled by default (rollback functionality)
# Set to "false" only if you need to disable snapshot temporarily
ENTITY_SNAPSHOT_ENABLED = os.getenv("ENTITY_SNAPSHOT_ENABLED", "true").lower() == "true"


# ---------------------------------------------------------------------------
# v1.11.0 — unified request/response log
# ---------------------------------------------------------------------------
# These four are deliberately ENV-only (not database settings): they decide
# whether the middleware is even registered and how much memory the writer
# queue may hold, so they must be resolvable before the DB pool exists.
# Everything the operator tunes at runtime (retention, body capture, sampling,
# excluded paths) lives in `system_settings` under the `requestlog.` category
# and is editable from Settings → Request Log.

def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off", "")


def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    """Read an int env var, clamped. A malformed value falls back to the
    default rather than crashing the process at import time."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


# Hard kill-switch. When false the logging middleware is never added to the
# ASGI stack and neither the writer nor the prune task is started — literally
# zero overhead, not even a settings lookup.
REQUEST_LOG_ENABLED = _bool_env("REQUEST_LOG_ENABLED", True)
# Per-worker in-process queue depth. When full, rows are DROPPED (counted, and
# reported through GET /api/request-logs/stats) — the request path never blocks
# on the database.
REQUEST_LOG_QUEUE_MAX = _int_env("REQUEST_LOG_QUEUE_MAX", 2000, 100, 100000)
# Rows per batched INSERT: one pool acquire per batch, not per request.
REQUEST_LOG_BATCH_SIZE = _int_env("REQUEST_LOG_BATCH_SIZE", 100, 1, 1000)
# Max wait before a partial batch is flushed (milliseconds).
REQUEST_LOG_FLUSH_MS = _int_env("REQUEST_LOG_FLUSH_MS", 500, 50, 10000) 