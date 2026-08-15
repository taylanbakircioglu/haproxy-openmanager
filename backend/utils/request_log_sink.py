"""v1.11.0 — batching writer for the unified request/response log.

One row per API call is the highest write volume in this system, and the
asyncpg pool (min=10/max=50, see database/connection.py) is shared with every
request handler and four background loops. Acquiring a connection per logged
request would exhaust it under any real load, so instead:

    hot path  ──offer(row)──▶  bounded asyncio.Queue  ──▶  single writer task
                                (drops when full)          (executemany batches)

The hot path never awaits I/O and never raises. When the queue is full rows are
counted as dropped and reported through `GET /api/request-logs/stats`, so a
saturated logger is visible rather than silent.

Redaction deliberately happens HERE, on the writer task, not in the middleware:
the recursive walk is the most expensive part of building a row and it has no
business running inside the request coroutine.
"""
import asyncio
import json
import logging
import random
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from config import REQUEST_LOG_BATCH_SIZE, REQUEST_LOG_FLUSH_MS, REQUEST_LOG_QUEUE_MAX
from database.connection import get_database_connection, close_database_connection
from utils.request_log_redaction import decode_body, redact_headers
from utils.request_log_settings import get_config, maybe_refresh_config

logger = logging.getLogger("haproxy_openmanager.request_log")

# Set by the inbound middleware; read by outbound_span so an outbound call
# inherits the id of the inbound request that caused it. That is what turns
# "operator clicked Issue Certificate" and "we POSTed to Let's Encrypt" into
# one readable trace.
request_id_context: ContextVar[Optional[str]] = ContextVar(
    "request_log_request_id", default=None
)

_INSERT_SQL = """
INSERT INTO request_logs (
    request_id, direction, target, method, url, path, query_params,
    status_code, status_class, duration_ms, user_id, username, client_ip,
    user_agent, request_headers, request_body, request_body_bytes,
    response_headers, response_body, response_body_bytes, error, truncated,
    created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7::jsonb,
    $8, $9, $10, $11, $12, $13::inet,
    $14, $15::jsonb, $16::jsonb, $17,
    $18::jsonb, $19::jsonb, $20, $21, $22,
    $23
)
"""


def _jsonb(value: Any) -> Optional[str]:
    """asyncpg has no JSONB codec on this pool, so JSONB params travel as text
    and are cast in SQL — the house idiom (utils/activity_log.py)."""
    if value is None:
        return None
    try:
        return json.dumps(value, default=str)
    except Exception:
        return json.dumps({"_serialize_error": True})


@dataclass
class RequestLogRow:
    """One captured exchange, still holding RAW body bytes.

    Decoding and redaction run in `to_params()` on the writer task.
    """

    request_id: str
    direction: str
    method: str
    url: str
    target: Optional[str] = None
    path: Optional[str] = None
    query_string: Optional[str] = None
    query_params: Optional[Dict[str, Any]] = None
    status_code: Optional[int] = None
    duration_ms: int = 0
    user_id: Optional[int] = None
    username: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    request_headers: Optional[Dict[str, str]] = None
    response_headers: Optional[Dict[str, str]] = None
    request_body_raw: Optional[bytes] = None
    request_body_bytes: int = 0
    request_content_type: Optional[str] = None
    response_body_raw: Optional[bytes] = None
    response_body_bytes: int = 0
    response_content_type: Optional[str] = None
    # Pre-decoded body override, used by outbound spans that hold a dict/str
    # rather than wire bytes (e.g. the synthetic JWS summary).
    request_body_value: Optional[Any] = None
    response_body_value: Optional[Any] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def status_class(self) -> int:
        """`status_code // 100`, or 0 when there was no HTTP response at all
        (transport error / unhandled exception). 0 is what the error-retention
        prune treats as an error alongside >= 4."""
        if not self.status_code:
            return 0
        return int(self.status_code) // 100

    def to_params(self) -> List[Any]:
        req_body, req_truncated = (self.request_body_value, False)
        if req_body is None:
            req_body, req_truncated = decode_body(
                self.request_body_raw, self.request_content_type, self.request_body_bytes
            )

        res_body, res_truncated = (self.response_body_value, False)
        if res_body is None:
            res_body, res_truncated = decode_body(
                self.response_body_raw, self.response_content_type, self.response_body_bytes
            )

        return [
            self.request_id[:64],
            self.direction,
            self.target[:32] if self.target else None,
            (self.method or "")[:10],
            self.url or "",
            self.path[:512] if self.path else None,
            _jsonb(self.query_params),
            self.status_code,
            self.status_class,
            max(0, int(self.duration_ms)),
            self.user_id,
            self.username[:50] if self.username else None,
            self.client_ip,
            self.user_agent[:1024] if self.user_agent else None,
            _jsonb(redact_headers(self.request_headers)),
            _jsonb(req_body),
            max(0, int(self.request_body_bytes)),
            _jsonb(redact_headers(self.response_headers)),
            _jsonb(res_body),
            max(0, int(self.response_body_bytes)),
            self.error[:4000] if self.error else None,
            bool(req_truncated or res_truncated),
            self.created_at,
        ]


class RequestLogSink:
    """Bounded queue + single batching writer task (one per uvicorn worker)."""

    def __init__(self, maxsize: int, batch_size: int, flush_ms: int):
        self._maxsize = maxsize
        self._batch_size = batch_size
        self._flush_seconds = flush_ms / 1000.0
        self._queue: Optional[asyncio.Queue] = None
        self._dropped = 0
        self._written = 0
        self._failed = 0
        self._running = False

    # -- lifecycle ---------------------------------------------------------

    def _ensure_queue(self) -> asyncio.Queue:
        # Created lazily so importing this module never needs a running loop
        # (matters for the test suite, which imports main.py without one).
        if self._queue is None:
            self._queue = asyncio.Queue(maxsize=self._maxsize)
        return self._queue

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "queued": self._queue.qsize() if self._queue is not None else 0,
            "queue_capacity": self._maxsize,
            "written": self._written,
            "dropped": self._dropped,
            "failed_batches": self._failed,
            "running": 1 if self._running else 0,
        }

    # -- producer side (hot path) -----------------------------------------

    def offer(self, row: RequestLogRow) -> None:
        """Enqueue a row. NEVER blocks, NEVER raises.

        Sampling is applied here rather than in the middleware so both
        directions go through one policy: successful *inbound* traffic can be
        sampled down, errors never are.
        """
        try:
            cfg = get_config()
            if not cfg.enabled:
                return
            if row.direction == "inbound" and not cfg.capture_inbound:
                return
            if row.direction == "outbound" and not cfg.capture_outbound:
                return
            if (
                row.direction == "inbound"
                and cfg.sample_rate < 1.0
                and row.status_class in (1, 2, 3)
                and random.random() > cfg.sample_rate
            ):
                return
            if not cfg.capture_bodies:
                row.request_body_raw = None
                row.response_body_raw = None
                row.request_body_value = None
                row.response_body_value = None

            self._ensure_queue().put_nowait(row)
        except asyncio.QueueFull:
            self._dropped += 1
            if self._dropped % 500 == 1:
                logger.warning(
                    f"request_log: queue full, {self._dropped} row(s) dropped so far "
                    f"(capacity {self._maxsize}; raise REQUEST_LOG_QUEUE_MAX or lower "
                    f"requestlog.sample_rate)"
                )
        except Exception as exc:
            # Instrumentation must never break the thing it instruments.
            logger.debug(f"request_log: offer() failed: {exc}")

    # -- consumer side (writer task) --------------------------------------

    async def _collect(self) -> List[RequestLogRow]:
        """Wait for at least one row, then drain up to batch_size or flush_ms."""
        queue = self._ensure_queue()
        first = await queue.get()
        batch = [first]
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._flush_seconds
        while len(batch) < self._batch_size:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                batch.append(await asyncio.wait_for(queue.get(), timeout=remaining))
            except asyncio.TimeoutError:
                break
        return batch

    async def _write(self, batch: List[RequestLogRow]) -> None:
        if not batch:
            return
        params = []
        for row in batch:
            try:
                params.append(row.to_params())
            except Exception as exc:
                logger.debug(f"request_log: row serialization failed, skipped: {exc}")
        if not params:
            return

        conn = None
        try:
            conn = await get_database_connection()
            await conn.executemany(_INSERT_SQL, params)
            self._written += len(params)
        except Exception as exc:
            self._failed += 1
            # A missing table (pre-migration) or a transient pool error must not
            # take the writer loop down — drop the batch and carry on.
            logger.warning(f"request_log: batch write failed ({len(params)} rows): {exc}")
        finally:
            if conn is not None:
                try:
                    await close_database_connection(conn)
                except Exception:
                    pass

    async def run(self) -> None:
        """Writer loop. Started once per worker from startup_event()."""
        self._running = True
        logger.info(
            f"request_log sink started (queue={self._maxsize}, batch={self._batch_size}, "
            f"flush={int(self._flush_seconds * 1000)}ms)"
        )
        try:
            while True:
                try:
                    batch = await self._collect()
                    await self._write(batch)
                    await maybe_refresh_config()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # pragma: no cover - defensive
                    logger.error(f"request_log sink loop error: {exc}")
                    await asyncio.sleep(1)
        finally:
            self._running = False

    async def flush(self, timeout: float = 3.0) -> int:
        """Drain and persist whatever is queued. Called on shutdown."""
        queue = self._queue
        if queue is None or queue.empty():
            return 0
        written = 0
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while not queue.empty() and loop.time() < deadline:
            batch: List[RequestLogRow] = []
            while not queue.empty() and len(batch) < self._batch_size:
                batch.append(queue.get_nowait())
            await self._write(batch)
            written += len(batch)
        return written


request_log_sink = RequestLogSink(
    REQUEST_LOG_QUEUE_MAX, REQUEST_LOG_BATCH_SIZE, REQUEST_LOG_FLUSH_MS
)
