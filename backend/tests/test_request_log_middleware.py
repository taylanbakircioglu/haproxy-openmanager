"""v1.11.0: the request/response logger must be invisible to everything below it.

This is the highest-risk piece of the feature. A logging middleware that reads
the request body the naive way DRAINS the ASGI receive channel, and the handler
underneath then sees an empty body — `POST /api/agents/heartbeat` reads the raw
stream itself, so every agent in the fleet would start failing its heartbeat
because someone wanted nicer logs.

The implementation therefore TEES rather than consumes. These tests drive the
middleware over a stub ASGI app and assert that property directly: the
downstream app sees the full body, the client sees the full response, and only
a capped copy is kept.
"""
import asyncio
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dataclasses import replace  # noqa: E402

from middleware.request_logger import RequestResponseLogMiddleware  # noqa: E402
from utils.logging_config import correlation_id_context  # noqa: E402
from utils import request_log_settings  # noqa: E402
from utils.request_log_settings import DEFAULT_CONFIG  # noqa: E402
from utils import request_log_sink as sink_module  # noqa: E402


_MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py")


@pytest.fixture
def captured(monkeypatch):
    """Collect the rows the middleware hands to the sink, instead of writing them."""
    rows = []
    monkeypatch.setattr(sink_module.request_log_sink, "offer", rows.append)
    # The middleware imports `request_log_sink` by value, so patch there too.
    import middleware.request_logger as rl
    monkeypatch.setattr(rl.request_log_sink, "offer", rows.append)
    return rows


@pytest.fixture(autouse=True)
def default_config(monkeypatch):
    """Every test starts from the shipped defaults, with a small body cap so the
    truncation paths are exercised without megabyte fixtures."""
    cfg = replace(DEFAULT_CONFIG, max_body_bytes=1024)
    monkeypatch.setattr(request_log_settings, "_CACHE", cfg)
    import middleware.request_logger as rl
    monkeypatch.setattr(rl, "get_config", lambda: request_log_settings._CACHE)
    return cfg


def set_config(monkeypatch, **overrides):
    cfg = replace(request_log_settings._CACHE, **overrides)
    monkeypatch.setattr(request_log_settings, "_CACHE", cfg)
    return cfg


# --------------------------------------------------------------------------
# A minimal ASGI harness — no TestClient, no HTTP stack, just the protocol.
# --------------------------------------------------------------------------

async def drive(app, *, method="POST", path="/api/backends", body=b"", query=b"",
                headers=None, content_type="application/json"):
    """Run one request through `app` and return (status, headers, body)."""
    raw_headers = [(b"host", b"testserver")]
    if content_type:
        raw_headers.append((b"content-type", content_type.encode()))
    for k, v in (headers or {}).items():
        raw_headers.append((k.encode().lower(), v.encode()))

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query,
        "root_path": "",
        "headers": raw_headers,
        "client": ("10.1.2.3", 51234),
        "server": ("testserver", 80),
    }

    # Deliver the body in three chunks so the tee is exercised across messages.
    chunks = [body[i:i + max(1, len(body) // 3 or 1)] for i in range(0, len(body), max(1, len(body) // 3 or 1))] or [b""]
    pending = list(chunks)

    async def receive():
        if pending:
            chunk = pending.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(pending)}
        return {"type": "http.request", "body": b"", "more_body": False}

    sent = {"status": None, "headers": [], "body": b""}

    async def send(message):
        if message["type"] == "http.response.start":
            sent["status"] = message["status"]
            sent["headers"] = message.get("headers", [])
        elif message["type"] == "http.response.body":
            sent["body"] += message.get("body", b"") or b""

    await app(scope, receive, send)
    return sent


def echo_length_app(status=200, content_type=b"application/json"):
    """Stub app that CONSUMES the whole request body and reports its length.

    This is the regression shape: if the middleware drained the stream, the app
    below it would see 0 bytes.
    """
    async def app(scope, receive, send):
        total = 0
        while True:
            message = await receive()
            total += len(message.get("body", b"") or b"")
            if not message.get("more_body"):
                break
        payload = json.dumps({"received_bytes": total}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", content_type)]})
        await send({"type": "http.response.body", "body": payload})
    return app


def chunked_app(chunks, content_type=b"application/json"):
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", content_type)]})
        for i, chunk in enumerate(chunks):
            await send({"type": "http.response.body", "body": chunk,
                        "more_body": i < len(chunks) - 1})
    return app


# --------------------------------------------------------------------------
# The transparency guarantees
# --------------------------------------------------------------------------

def test_request_body_reaches_downstream_intact(captured):
    """THE regression guard: draining the receive channel would break the raw-body
    agent heartbeat handler."""
    body = b"x" * 100_000
    app = RequestResponseLogMiddleware(echo_length_app())

    sent = asyncio.run(drive(app, body=body))

    assert json.loads(sent["body"])["received_bytes"] == 100_000, (
        "the handler below the logger saw a different body length than the client sent — "
        "the middleware consumed the receive channel instead of teeing it"
    )


def test_response_body_reaches_client_intact(captured):
    chunks = [b'{"part":', b'"one",', b'"n":2}']
    app = RequestResponseLogMiddleware(chunked_app(chunks))

    sent = asyncio.run(drive(app, method="GET", body=b""))

    assert sent["body"] == b"".join(chunks), "a response chunk was swallowed by the logger"
    assert sent["status"] == 200


def test_only_the_capped_prefix_is_captured(captured):
    body = b"y" * 100_000
    app = RequestResponseLogMiddleware(echo_length_app())

    asyncio.run(drive(app, body=body))

    row = captured[0]
    assert row.request_body_bytes == 100_000, "the on-the-wire size must be recorded in full"
    assert len(row.request_body_raw) <= 1024, (
        "the middleware buffered more than max_body_bytes — memory is unbounded per request"
    )


def test_non_capturable_content_type_is_counted_but_not_buffered(captured):
    app = RequestResponseLogMiddleware(chunked_app([b"\x00\x01\x02" * 500],
                                                   content_type=b"application/octet-stream"))

    asyncio.run(drive(app, method="GET", content_type=None))

    row = captured[0]
    assert row.response_body_bytes == 1500
    assert row.response_body_raw is None, (
        "a binary response body was buffered — this is what keeps streaming/file "
        "responses safe"
    )


# --------------------------------------------------------------------------
# What gets logged, and what does not
# --------------------------------------------------------------------------

def test_basic_row_fields(captured):
    app = RequestResponseLogMiddleware(echo_length_app())

    asyncio.run(drive(app, method="POST", path="/api/backends",
                      body=b'{"name":"web"}', query=b"cluster_id=2&token=secret"))

    row = captured[0]
    assert row.direction == "inbound"
    assert row.method == "POST"
    assert row.path == "/api/backends"
    assert row.status_code == 200
    assert row.status_class == 2
    assert row.client_ip == "10.1.2.3"
    assert row.duration_ms >= 0
    # The query string is scrubbed before it is stored, in the URL and the dict.
    assert "secret" not in row.url
    assert row.query_params["token"] == "***REDACTED***"
    assert row.query_params["cluster_id"] == "2"


@pytest.mark.parametrize("path", [
    "/api/health",
    "/api/health/deep",
    "/api/docs",
    "/api/openapi.json",
    "/.well-known/acme-challenge/abc123",
    "/api/agents/heartbeat",
    "/favicon.ico",
])
def test_excluded_paths_produce_no_row(captured, path):
    app = RequestResponseLogMiddleware(echo_length_app())
    asyncio.run(drive(app, method="GET", path=path))
    assert captured == [], f"{path} must not be logged by default"


def test_log_viewer_path_cannot_be_un_excluded(captured, monkeypatch):
    """`exclude_paths` is operator-editable, so the viewer's own endpoints have a
    hard floor — otherwise reading the log generates log entries about reading
    the log."""
    set_config(monkeypatch, exclude_paths=())

    app = RequestResponseLogMiddleware(echo_length_app())
    asyncio.run(drive(app, method="GET", path="/api/request-logs?limit=50"))

    assert captured == [], (
        "clearing exclude_paths re-enabled logging of the log viewer itself"
    )


def test_options_preflight_is_skipped(captured):
    app = RequestResponseLogMiddleware(echo_length_app())
    asyncio.run(drive(app, method="OPTIONS", path="/api/backends"))
    assert captured == []


def test_get_can_be_turned_off(captured, monkeypatch):
    set_config(monkeypatch, capture_get=False)
    app = RequestResponseLogMiddleware(echo_length_app())

    asyncio.run(drive(app, method="GET", path="/api/backends"))
    assert captured == []

    asyncio.run(drive(app, method="POST", path="/api/backends", body=b"{}"))
    assert len(captured) == 1, "turning GETs off must not silence writes"


def test_disabled_config_short_circuits_but_still_serves(captured, monkeypatch):
    set_config(monkeypatch, enabled=False)
    app = RequestResponseLogMiddleware(echo_length_app())

    sent = asyncio.run(drive(app, body=b"hello"))

    assert captured == []
    assert sent["status"] == 200, "the kill-switch must not break request serving"


def test_capture_bodies_off_keeps_sizes_but_drops_content(captured, monkeypatch):
    set_config(monkeypatch, capture_bodies=False)
    app = RequestResponseLogMiddleware(echo_length_app())

    asyncio.run(drive(app, body=b'{"secret":"x"}'))

    row = captured[0]
    assert row.request_body_raw is None
    assert row.request_body_bytes == 14, "size accounting must survive with bodies off"


# --------------------------------------------------------------------------
# Errors and correlation
# --------------------------------------------------------------------------

def test_exception_is_recorded_as_status_class_zero_and_reraised(captured):
    async def boom(scope, receive, send):
        raise RuntimeError("handler exploded")

    app = RequestResponseLogMiddleware(boom)

    with pytest.raises(RuntimeError):
        asyncio.run(drive(app, method="GET"))

    row = captured[0]
    assert row.status_code is None
    assert row.status_class == 0, (
        "a request that produced no HTTP response must be status_class 0 — that is the "
        "sentinel the error-retention prune keys off"
    )
    assert row.error.startswith("RuntimeError")


def test_correlation_id_is_seeded_before_downstream_and_reset_after(captured):
    seen = {}

    async def app(scope, receive, send):
        seen["cid"] = correlation_id_context.get()
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    wrapped = RequestResponseLogMiddleware(app)
    asyncio.run(drive(wrapped, method="GET"))

    row = captured[0]
    assert seen["cid"] == row.request_id[:8], (
        "the downstream error handler would mint its own id, so X-Correlation-ID would "
        "not match request_logs.request_id"
    )
    assert correlation_id_context.get() is None, (
        "the ContextVar token was not reset — the next request on this task would inherit "
        "a stale correlation id"
    )


def test_x_request_id_header_is_returned_to_the_client(captured):
    app = RequestResponseLogMiddleware(echo_length_app())
    sent = asyncio.run(drive(app, method="GET"))

    names = {k.decode().lower() for k, _ in sent["headers"]}
    assert "x-request-id" in names, (
        "without this header a user reporting a problem has no id to quote"
    )


def test_error_responses_are_logged_with_their_status(captured):
    app = RequestResponseLogMiddleware(echo_length_app(status=422))
    asyncio.run(drive(app, body=b'{"bad":true}'))

    row = captured[0]
    assert row.status_code == 422
    assert row.status_class == 4, "4xx must be classed as an error for retention purposes"


def test_jwt_identity_is_resolved_without_a_database(captured):
    """The middleware runs on every request; a DB lookup per call is not
    acceptable, so the user is read straight out of the token claims."""
    from datetime import datetime, timedelta

    from jose import jwt
    from config import JWT_ALGORITHM, JWT_SECRET_KEY

    token = jwt.encode(
        {"user_id": 42, "username": "ops", "exp": datetime.utcnow() + timedelta(minutes=10)},
        JWT_SECRET_KEY, algorithm=JWT_ALGORITHM,
    )

    app = RequestResponseLogMiddleware(echo_length_app())
    asyncio.run(drive(app, body=b"{}", headers={"authorization": f"Bearer {token}"}))

    row = captured[0]
    assert row.user_id == 42
    assert row.username == "ops"


def test_malformed_token_yields_an_anonymous_row(captured):
    app = RequestResponseLogMiddleware(echo_length_app())
    asyncio.run(drive(app, body=b"{}", headers={"authorization": "Bearer not.a.jwt"}))

    row = captured[0]
    assert row.user_id is None
    assert row.username is None
    # Logging is not an auth path — a bad token must not turn into an exception.


def test_authorization_header_is_never_stored_verbatim(captured):
    app = RequestResponseLogMiddleware(echo_length_app())
    asyncio.run(drive(app, body=b"{}", headers={"authorization": "Bearer super-secret"}))

    params = captured[0].to_params()
    assert "super-secret" not in json.dumps(params, default=str)


# --------------------------------------------------------------------------
# Registration order in main.py
# --------------------------------------------------------------------------

def test_middleware_is_registered_last_so_it_is_outermost():
    with open(_MAIN, encoding="utf-8") as f:
        src = f.read()

    log_at = src.index("app.add_middleware(RequestResponseLogMiddleware)")
    cors_at = src.index("    CORSMiddleware,")

    assert log_at > cors_at, (
        "Starlette's add_middleware inserts at index 0, so the LAST registration is the "
        "OUTERMOST middleware. Registering the request logger before CORS would put it "
        "inside the stack, where it can no longer see the final client-visible response "
        "and can no longer seed the correlation id before the error handler reads it."
    )


def test_env_kill_switch_guards_the_registration():
    with open(_MAIN, encoding="utf-8") as f:
        src = f.read()

    assert re.search(
        r"if REQUEST_LOG_ENABLED:\s*\n\s*app\.add_middleware\(RequestResponseLogMiddleware\)",
        src,
    ), (
        "REQUEST_LOG_ENABLED must gate the add_middleware call itself, not a branch inside "
        "the middleware — the whole point is that a disabled log costs nothing"
    )


def test_cors_exposes_the_request_id_header():
    with open(_MAIN, encoding="utf-8") as f:
        src = f.read()

    assert "expose_headers=" in src and "X-Request-ID" in src, (
        "without expose_headers the browser cannot read X-Request-ID on a cross-origin "
        "deployment, so the id is unusable from the app"
    )
