"""v1.11.0 — inbound half of the unified request/response log.

Pure ASGI on purpose, NOT BaseHTTPMiddleware:

  * `BaseHTTPMiddleware` hands the response back as a
    `starlette.middleware.base._StreamingResponse`, which has no `.body` to
    read, and
  * `await request.body()` inside a `dispatch()` DRAINS the receive channel.
    `POST /api/agents/heartbeat` (routers/agent.py) reads the raw stream
    itself, as does the validation-error body preview in
    middleware/error_handler.py — draining it here would break both.

So we never consume anything: we TEE. `receive` and `send` are wrapped, every
message is forwarded verbatim, and a size-capped copy is kept for the log row.
Cost per in-flight request is therefore bounded at ~2 × max_body_bytes (8 KB
by default), not the size of the upload.

Registration: this MUST be the LAST `app.add_middleware(...)` call, because
Starlette inserts at index 0 — the last registration is the OUTERMOST
middleware. Outermost is what we want: we then see the exact status and body
the client receives (including the JSONResponse that RequestLoggingMiddleware
fabricates out of a swallowed exception), and we can seed
`correlation_id_context` before anything downstream reads it.
"""
import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from starlette.types import ASGIApp, Receive, Scope, Send

from utils.logging_config import correlation_id_context
from utils.request_log_redaction import is_capturable_content_type, scrub_query_string
from utils.request_log_settings import get_config
from utils.request_log_sink import RequestLogRow, request_id_context, request_log_sink

logger = logging.getLogger("haproxy_openmanager.request_log")

# Hard floor, NOT settable away through `requestlog.exclude_paths`. Without it
# an operator who clears the exclude list turns the log viewer into a machine
# that logs itself reading its own logs.
_ALWAYS_EXCLUDED: Tuple[str, ...] = ("/api/request-logs",)


def _header(scope: Scope, name: bytes) -> Optional[str]:
    for key, value in scope.get("headers") or ():
        if key == name:
            try:
                return value.decode("latin-1")
            except Exception:
                return None
    return None


def _identify(scope: Scope) -> Tuple[Optional[int], Optional[str]]:
    """Resolve the caller from the JWT locally — NO database round-trip.

    `log_activity_middleware` already pays a `SELECT ... FROM users` per
    non-GET request; this middleware runs on every request including GETs, so a
    second lookup per call is not acceptable. The token issued at
    routers/auth.py carries both `user_id` and `username`, which is everything
    the log row needs.

    A token that fails to decode simply yields (None, None): this is a logging
    path, not an authorization path — the real auth check still runs
    downstream.
    """
    raw = _header(scope, b"authorization")
    if not raw:
        return None, None
    token = raw[7:].strip() if raw.lower().startswith("bearer ") else raw.strip()
    if not token or token in ("null", "undefined") or token.count(".") != 2:
        return None, None
    try:
        from jose import jwt
        from config import JWT_SECRET_KEY, JWT_ALGORITHM

        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None, None

    raw_uid = payload.get("user_id") or payload.get("sub")
    try:
        user_id = int(raw_uid) if raw_uid is not None else None
    except (TypeError, ValueError):
        user_id = None
    username = payload.get("username")
    return user_id, (str(username) if username else None)


def _client_ip(scope: Scope) -> Optional[str]:
    """The peer address only.

    `request_logs.client_ip` is an INET column, so a comma-joined
    X-Forwarded-For string would raise on INSERT (the same trap as
    `user_activity_logs.ip_address`). The XFF header is still captured — it is
    on the header allowlist — so the original client is not lost behind a proxy.
    """
    client = scope.get("client")
    if not client:
        return None
    try:
        return str(client[0])
    except Exception:
        return None


class RequestResponseLogMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        cfg = get_config()
        path = scope.get("path", "") or ""
        method = scope.get("method", "") or ""

        if (
            not cfg.enabled
            or not cfg.capture_inbound
            # OPTIONS never reaches a handler — CORSMiddleware short-circuits
            # it below us — and a preflight carries no information worth a row.
            or method == "OPTIONS"
            or (method == "GET" and not cfg.capture_get)
            or any(path.startswith(prefix) for prefix in _ALWAYS_EXCLUDED)
            or any(path.startswith(prefix) for prefix in cfg.exclude_paths)
        ):
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex
        # Seed the id BEFORE the downstream app runs so error_handler's
        # get_correlation_id() adopts ours instead of minting a second one; the
        # X-Correlation-ID header then matches request_logs.request_id.
        cid_token = correlation_id_context.set(request_id[:8])
        rid_token = request_id_context.set(request_id)

        cap = cfg.max_body_bytes if cfg.capture_bodies else 0
        req_ctype = _header(scope, b"content-type")
        req_capturable = is_capturable_content_type(req_ctype)

        req_buf = bytearray()
        res_buf = bytearray()
        state = {
            "req_bytes": 0,
            "res_bytes": 0,
            "status": None,
            "res_headers": {},
            "res_ctype": None,
            "res_capturable": True,
        }

        async def tee_receive() -> Dict[str, Any]:
            message = await receive()
            try:
                if message.get("type") == "http.request":
                    chunk = message.get("body", b"") or b""
                    state["req_bytes"] += len(chunk)
                    if cap and req_capturable and len(req_buf) < cap:
                        req_buf.extend(chunk[: cap - len(req_buf)])
            except Exception:
                pass
            return message  # forwarded verbatim, always

        async def tee_send(message: Dict[str, Any]) -> None:
            try:
                mtype = message.get("type")
                if mtype == "http.response.start":
                    state["status"] = message.get("status")
                    raw_headers: List[Tuple[bytes, bytes]] = message.get("headers") or []
                    headers = {}
                    for key, value in raw_headers:
                        try:
                            headers[key.decode("latin-1").lower()] = value.decode("latin-1")
                        except Exception:
                            continue
                    state["res_headers"] = headers
                    state["res_ctype"] = headers.get("content-type")
                    state["res_capturable"] = is_capturable_content_type(state["res_ctype"])
                    # Hand the id to the client so a user reporting a problem can
                    # quote it and an operator can find the exact row.
                    if isinstance(raw_headers, list):
                        raw_headers.append((b"x-request-id", request_id.encode("latin-1")))
                elif mtype == "http.response.body":
                    chunk = message.get("body", b"") or b""
                    state["res_bytes"] += len(chunk)
                    if cap and state["res_capturable"] and len(res_buf) < cap:
                        res_buf.extend(chunk[: cap - len(res_buf)])
            except Exception:
                pass
            await send(message)  # forwarded verbatim, always

        started = time.perf_counter()
        error_text: Optional[str] = None
        try:
            await self.app(scope, tee_receive, tee_send)
        except Exception as exc:
            # Almost never taken: RequestLoggingMiddleware sits below us and
            # converts exceptions into a JSONResponse first. It IS taken for
            # paths on that middleware's own exclude list, so the row still has
            # to be recorded before the exception continues upward.
            error_text = f"{type(exc).__name__}: {exc}"[:2000]
            raise
        finally:
            duration_ms = int((time.perf_counter() - started) * 1000)
            try:
                self._record(
                    scope=scope,
                    request_id=request_id,
                    method=method,
                    path=path,
                    duration_ms=duration_ms,
                    status=state["status"],
                    req_buf=bytes(req_buf),
                    req_bytes=state["req_bytes"],
                    req_ctype=req_ctype,
                    res_buf=bytes(res_buf),
                    res_bytes=state["res_bytes"],
                    res_ctype=state["res_ctype"],
                    res_headers=state["res_headers"],
                    error_text=error_text,
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug(f"request_log: failed to record inbound row: {exc}")
            try:
                correlation_id_context.reset(cid_token)
                request_id_context.reset(rid_token)
            except Exception:
                pass

    @staticmethod
    def _record(
        *,
        scope: Scope,
        request_id: str,
        method: str,
        path: str,
        duration_ms: int,
        status: Optional[int],
        req_buf: bytes,
        req_bytes: int,
        req_ctype: Optional[str],
        res_buf: bytes,
        res_bytes: int,
        res_ctype: Optional[str],
        res_headers: Dict[str, str],
        error_text: Optional[str],
    ) -> None:
        raw_query = scope.get("query_string") or b""
        try:
            query = raw_query.decode("latin-1")
        except Exception:
            query = ""
        scrubbed_query, query_params = scrub_query_string(query)

        user_id, username = _identify(scope)

        req_headers = {}
        for key, value in scope.get("headers") or ():
            try:
                req_headers[key.decode("latin-1").lower()] = value.decode("latin-1")
            except Exception:
                continue

        request_log_sink.offer(
            RequestLogRow(
                request_id=request_id,
                direction="inbound",
                method=method,
                url=path + (("?" + scrubbed_query) if scrubbed_query else ""),
                path=path,
                query_string=scrubbed_query or None,
                query_params=query_params,
                status_code=status,
                duration_ms=duration_ms,
                user_id=user_id,
                username=username,
                client_ip=_client_ip(scope),
                user_agent=req_headers.get("user-agent"),
                request_headers=req_headers or None,
                response_headers=res_headers or None,
                request_body_raw=req_buf or None,
                request_body_bytes=req_bytes,
                request_content_type=req_ctype,
                response_body_raw=res_buf or None,
                response_body_bytes=res_bytes,
                response_content_type=res_ctype,
                error=error_text,
            )
        )
