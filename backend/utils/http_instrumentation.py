"""v1.11.0 — outbound half of the unified request/response log.

This is deliberately NOT a session or connector factory. Three incompatible
connector policies coexist in this codebase:

  * `utils.ssrf_guard.safe_connector()` — IPv4-pinned, TLS verification on;
    returns a NEW connector per call because `ClientSession` closes the one it
    owns, so a shared long-lived connector would raise "Connector is closed".
  * `services/acme_diagnostics.py` — IPv4-pinned with `ssl=False` for the
    plain-HTTP port-80 probe.
  * the DNS providers and the CA-chain import — the default dual-stack
    connector.

On top of that, `backend/tests/test_acme_diagnostics.py` monkeypatches
`aiohttp.ClientSession` globally with fakes that implement only
`__aenter__/__aexit__/head(...)`. Centralising session construction would break
all of it. So this module wraps the CALL, never the session.

Two hard rules, both load-bearing:

1.  `outbound_span` NEVER raises. Both DNS provider funnels end in
    `except Exception: raise DnsProviderError("Unexpected ... failure")`, and in
    GoDaddy's publish path that reverts `dns_record_published` and stalls the
    ACME order — an instrumentation bug must not masquerade as a provider
    outage.
2.  `outbound_span` NEVER swallows. An exception raised inside the block is
    recorded (status_class 0) and re-raised unchanged.
"""
import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from utils.request_log_redaction import safe_error_text, scrub_query_string, scrub_url
from utils.request_log_settings import get_config
from utils.request_log_sink import RequestLogRow, request_id_context, request_log_sink

logger = logging.getLogger("haproxy_openmanager.request_log")

# Stable identifiers for the `request_logs.target` column — this is the
# "kime gitti" (who did we call) axis of the log.
TARGET_ACME = "acme"
TARGET_ACME_DIAG = "acme_diag"
TARGET_LETSENCRYPT_CA = "letsencrypt_ca"
TARGET_DNS_CLOUDFLARE = "dns_cloudflare"
TARGET_DNS_GODADDY = "dns_godaddy"
TARGET_AGENT = "agent"
TARGET_HAPROXY_STATS = "haproxy_stats"
TARGET_SETTINGS_PROBE = "settings_probe"


def begin_background_trace(label: str) -> str:
    """Open a fresh correlation id for ONE iteration of a background loop.

    Without this, background outbound rows fell back to `bg:<asyncio task
    name>`. Nothing in main.py passes `name=` to `create_task`, so a loop is
    `Task-5` for its entire life and EVERY call it ever makes carries the same
    `request_id` — measured: fifteen ACME calls across five renewal ticks came
    out as one id. `GET /api/request-logs/{id}` then answers with up to 100 rows
    under `related`, presented as "the calls this request made", which in a
    forensics tool is worse than having no trace: an operator reading a failed
    renewal is shown a hundred unrelated calls spanning days. Task numbers are
    also reused across restarts, so `bg:Task-5` can mean a different loop after
    a redeploy.

    Called at the top of each iteration; the loop task is dedicated, so the next
    iteration simply overwrites it and there is nothing to reset.
    """
    trace_id = f"bg:{label}:{uuid.uuid4().hex[:12]}"[:64]
    request_id_context.set(trace_id)
    return trace_id


def _correlation_id() -> str:
    """Inherit the inbound request's id when there is one, so an API call and
    the CA/DNS calls it triggered share a trace. Background work gets the id
    opened by begin_background_trace() for the current iteration."""
    existing = request_id_context.get()
    if existing:
        return existing
    # No inbound request and no iteration trace: background code that has not
    # been wrapped. Mint a unique id rather than falling back to the task name,
    # which would silently re-collapse every such call into one row group.
    try:
        task = asyncio.current_task()
        name = task.get_name() if task else "unknown"
    except Exception:
        name = "unknown"
    return f"bg:{name}:{uuid.uuid4().hex[:12]}"[:64]


class OutboundSpan:
    """Handle passed to the `async with` body so the call site can attach the
    response it just read."""

    __slots__ = (
        "target", "method", "url", "capture_request_body", "capture_response_body",
        "safe_error_only",
        "_status", "_response_headers", "_response_body", "_response_bytes",
        "_response_content_type", "_request_body", "_request_headers", "_error",
    )

    def __init__(
        self,
        *,
        target: str,
        method: str,
        url: str,
        capture_request_body: bool,
        capture_response_body: bool,
        safe_error_only: bool,
        request_body: Any = None,
        request_headers: Optional[Dict[str, str]] = None,
    ):
        self.target = target
        self.method = (method or "GET").upper()
        self.url = url
        # Two independent switches on purpose: the ACME JWS request body is a
        # replayable credential and must never be stored, but the CA's RESPONSE
        # (problem JSON, order state) is exactly what an operator needs to see.
        self.capture_request_body = capture_request_body
        self.capture_response_body = capture_response_body
        self.safe_error_only = safe_error_only
        self._request_body = request_body
        self._request_headers = request_headers
        self._status: Optional[int] = None
        self._response_headers: Optional[Dict[str, str]] = None
        self._response_body: Any = None
        self._response_bytes: int = 0
        self._response_content_type: Optional[str] = None
        self._error: Optional[str] = None

    def set_response(
        self,
        status: Optional[int],
        headers: Optional[Dict[str, str]] = None,
        body: Any = None,
    ) -> None:
        """Record what came back. Safe to call with a partially-read response;
        never raises, so a call site can hand us whatever it happens to have."""
        try:
            self._status = int(status) if status is not None else None
        except (TypeError, ValueError):
            self._status = None
        try:
            if headers:
                self._response_headers = {str(k).lower(): str(v) for k, v in dict(headers).items()}
                self._response_content_type = self._response_headers.get("content-type")
        except Exception:
            self._response_headers = None

        if body is None or not self.capture_response_body:
            return
        try:
            if isinstance(body, (bytes, bytearray)):
                self._response_bytes = len(body)
                cap = get_config().max_body_bytes
                self._response_body = bytes(body[:cap]) if cap else None
            elif isinstance(body, str):
                encoded = body.encode("utf-8", "replace")
                self._response_bytes = len(encoded)
                cap = get_config().max_body_bytes
                self._response_body = encoded[:cap] if cap else None
            else:
                # Already-decoded JSON (the common case: `await resp.json()`).
                self._response_body = body
        except Exception:
            self._response_body = None

    def set_error(self, exc: BaseException, *, type_only: Optional[bool] = None) -> None:
        try:
            only = self.safe_error_only if type_only is None else type_only
            self._error = safe_error_text(exc, type_only=only)
        except Exception:
            self._error = "UnknownError"

    def to_row(self, duration_ms: int) -> RequestLogRow:
        scrubbed = scrub_url(self.url)
        path = None
        query_params = None
        try:
            import urllib.parse

            parts = urllib.parse.urlsplit(self.url)
            path = parts.path or "/"
            _, query_params = scrub_query_string(parts.query)
        except Exception:
            pass

        row = RequestLogRow(
            request_id=_correlation_id(),
            direction="outbound",
            target=self.target,
            method=self.method,
            url=scrubbed,
            path=path,
            query_params=query_params,
            status_code=self._status,
            duration_ms=duration_ms,
            request_headers=self._request_headers,
            response_headers=self._response_headers,
            error=self._error,
        )

        if self._request_body is not None:
            if not self.capture_request_body:
                # The call site handed us a synthetic SUMMARY instead of the real
                # payload (the ACME JWS case) — store the summary as-is.
                row.request_body_value = _redacted_value(self._request_body)
            elif isinstance(self._request_body, (bytes, bytearray)):
                row.request_body_bytes = len(self._request_body)
                cap = get_config().max_body_bytes
                row.request_body_raw = bytes(self._request_body[:cap]) if cap else None
            else:
                row.request_body_value = _redacted_value(self._request_body)

        if isinstance(self._response_body, (bytes, bytearray)):
            row.response_body_raw = bytes(self._response_body)
            row.response_body_bytes = self._response_bytes or len(self._response_body)
            row.response_content_type = self._response_content_type
        elif self._response_body is not None:
            row.response_body_value = _redacted_value(self._response_body)

        return row


def _redacted_value(value: Any) -> Any:
    from utils.request_log_redaction import redact

    return redact(value)


@asynccontextmanager
async def outbound_span(
    *,
    target: str,
    method: str,
    url: str,
    request_body: Any = None,
    request_headers: Optional[Dict[str, str]] = None,
    capture_body: bool = True,
    capture_response_body: bool = True,
    safe_error_only: bool = False,
):
    """Time an outbound HTTP call and record one `direction='outbound'` row.

    `capture_body=False` applies to the REQUEST body only, for payloads that
    are themselves credentials — the ACME JWS body is a replayable, signed
    capability for the lifetime of its nonce, so the call site passes a
    description of it instead. The CA's response is still captured, because
    that is the half an operator actually needs when an order fails.

    `safe_error_only=True` reduces a recorded exception to its type name, for
    the DNS providers whose own error handling already refuses to surface
    `str(exc)` (it can carry the request URL and, through it, zone identifiers).
    """
    span: Optional[OutboundSpan] = None
    started = time.perf_counter()
    try:
        cfg = get_config()
        if cfg.enabled and cfg.capture_outbound:
            span = OutboundSpan(
                target=target,
                method=method,
                url=url,
                capture_request_body=capture_body and cfg.capture_bodies,
                capture_response_body=capture_response_body and cfg.capture_bodies,
                safe_error_only=safe_error_only,
                request_body=request_body,
                request_headers=request_headers,
            )
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"outbound_span: could not start span for {target}: {exc}")
        span = None

    if span is None:
        # Logging is off (or failed to initialise) — yield a throwaway span so
        # the call site's `span.set_response(...)` still works.
        span = OutboundSpan(
            target=target, method=method, url=url,
            capture_request_body=False, capture_response_body=False,
            safe_error_only=safe_error_only,
        )
        try:
            yield span
        finally:
            pass
        return

    try:
        yield span
    except BaseException as exc:
        try:
            span.set_error(exc)
        except Exception:
            pass
        raise
    finally:
        try:
            duration_ms = int((time.perf_counter() - started) * 1000)
            request_log_sink.offer(span.to_row(duration_ms))
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug(f"outbound_span: failed to record row for {target}: {exc}")


async def instrumented_request(session, method: str, url: str, *, target: str,
                               safe_error_only: bool = True, capture_body: bool = True,
                               **kwargs):
    """Convenience wrapper for the call sites that already funnel through
    `session.request(...)` (the two DNS providers).

    Returns `(status, headers, text)` and leaves error handling entirely to the
    caller — this helper only adds the log row.
    """
    async with outbound_span(
        target=target,
        method=method,
        url=url,
        request_body=kwargs.get("json"),
        capture_body=capture_body,
        safe_error_only=safe_error_only,
    ) as span:
        async with session.request(method, url, **kwargs) as resp:
            text = await resp.text()
            span.set_response(resp.status, dict(resp.headers), text)
            return resp.status, dict(resp.headers), text
