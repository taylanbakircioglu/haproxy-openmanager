"""v1.11.0: the request log API is gated, and its routes resolve.

Two distinct failure modes are pinned here.

**Auth.** The table holds redacted-but-real request and response bodies for
every user, so an unauthenticated or under-privileged caller must never get a
row. There is no database in this suite, so the behavioural checks assert only
that an anonymous call is rejected before any DB work — which is exactly the
property that matters — and a source scan covers the per-endpoint permission.

**Route order.** `/{log_id}` is a single-segment path and FastAPI matches in
declaration order, so declaring it before `/settings`, `/stats` or `/purge`
makes those three unreachable (they parse as a log id and 422). This is the
mirror image of the shadowing trap already present in routers/settings.py.
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROUTER = os.path.join(_BACKEND, "routers", "request_logs.py")
_MAIN = os.path.join(_BACKEND, "main.py")

REJECT = (401, 403, 422)


@pytest.fixture(scope="module")
def src():
    with open(_ROUTER, encoding="utf-8") as f:
        return f.read()


# --------------------------------------------------------------------------
# Behavioural: nothing is readable without credentials
# --------------------------------------------------------------------------

@pytest.mark.parametrize("method,path", [
    ("get", "/api/request-logs"),
    ("get", "/api/request-logs/1"),
    ("get", "/api/request-logs/stats"),
    ("get", "/api/request-logs/settings"),
    ("put", "/api/request-logs/settings"),
    ("post", "/api/request-logs/purge"),
])
def test_anonymous_access_is_rejected(client, method, path):
    res = getattr(client, method)(path) if method != "put" else client.put(path, json={})
    assert res.status_code in REJECT, (
        f"{method.upper()} {path} returned {res.status_code} without an Authorization "
        f"header — the request log contains captured bodies for every user"
    )


def test_a_garbage_token_is_rejected(client):
    res = client.get("/api/request-logs", headers={"authorization": "Bearer not-a-token"})
    assert res.status_code in REJECT


# --------------------------------------------------------------------------
# Source scan: per-endpoint permission
# --------------------------------------------------------------------------

def _handler_body(src, decorator):
    start = src.index(decorator)
    rest = src[start + len(decorator):]
    end = rest.find("\n@router.")
    return rest if end == -1 else rest[:end]


@pytest.mark.parametrize("decorator,action", [
    ('@router.get("/settings")', "manage"),
    ('@router.put("/settings")', "manage"),
    ('@router.get("/stats")', "read"),
    ('@router.post("/purge")', "manage"),
    ('@router.get("")', "read"),
    ('@router.get("/{log_id}")', "read"),
])
def test_every_endpoint_enforces_its_permission(src, decorator, action):
    body = _handler_body(src, decorator)
    assert f'_require(authorization, "{action}")' in body, (
        f"{decorator} does not enforce requestlog.{action}"
    )


def test_require_helper_raises_403_not_a_silent_pass(src):
    helper = src.split("async def _require", 1)[1].split("\nasync def ", 1)[0]
    assert "check_user_permission" in helper
    assert "status_code=403" in helper
    assert "current_user=current_user" in helper, (
        "the admin bypass is skipped, so every call pays an extra SELECT on users"
    )


# --------------------------------------------------------------------------
# Route declaration order
# --------------------------------------------------------------------------

@pytest.mark.parametrize("literal", ['@router.get("/settings")', '@router.put("/settings")',
                                     '@router.get("/stats")', '@router.post("/purge")'])
def test_literal_routes_are_declared_before_the_catch_all(src, literal):
    catch_all = src.index('@router.get("/{log_id}")')
    assert src.index(literal) < catch_all, (
        f"{literal} is declared after GET /{{log_id}}. FastAPI matches in declaration "
        f"order and /{{log_id}} is a single-segment path, so it would swallow this route "
        f"and the request would fail parsing 'settings' as an int."
    )


def test_list_route_is_declared_before_the_catch_all(src):
    assert src.index('@router.get("")') < src.index('@router.get("/{log_id}")')


# --------------------------------------------------------------------------
# Query construction
# --------------------------------------------------------------------------

def test_filters_are_bound_never_interpolated(src):
    """User-supplied filters reach the WHERE clause; they must arrive as $n
    parameters."""
    body = _handler_body(src, '@router.get("")')
    # The only f-string interpolation allowed into SQL is the placeholder index
    # and the assembled clause list, never a raw value.
    for match in re.findall(r'add\("([^"]+)"', body):
        assert "{n}" in match, f"filter clause {match!r} does not use a bound placeholder"


def test_list_endpoint_scopes_non_privileged_callers(src):
    """A caller with only `requestlog.read` sees their own rows plus the fleet's.

    Widened from own-rows-only during review, deliberately. The `operator` role
    is granted requestlog.read to "debug failing applies and ACME orders", but
    an apply fails on the NODE and the node reports it over its own API key, so
    the row carrying the diagnosis has `user_id IS NULL` — own-rows-only hid it
    from exactly the role the grant was written for.

    What must NOT widen is the part this test was written to protect: another
    USER's captured bodies. Both halves are asserted below.
    """
    # Comments explain what the clause deliberately does NOT do, so match on
    # code only — otherwise the prose describing the rule fails the test for it.
    body = "\n".join(
        line for line in _handler_body(src, '@router.get("")').splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "if not can_manage:" in body
    assert "direction = 'inbound'" in body, (
        "outbound rows are not scoped at all, so a caller with only "
        "requestlog.read would see every CA and DNS call the backend ever made"
    )
    assert "user_id = $" in body, (
        "a caller with only requestlog.read can see every other user's captured "
        "request bodies"
    )
    assert "TARGET_INBOUND_AGENT" in body, (
        "agent rows are hidden from requestlog.read, which is the one thing the "
        "operator grant exists for"
    )
    assert "user_id IS NULL" not in body, (
        "scoping on NULL rather than on target would also expose anonymous "
        "traffic — failed logins and the usernames they carry, unauthenticated "
        "probes — to any requestlog.read holder"
    )


def test_detail_endpoint_applies_the_same_scoping(src):
    body = _handler_body(src, '@router.get("/{log_id}")')
    assert "can_manage" in body
    assert "404" in body, (
        "the detail endpoint should 404 rather than 403 for a row the caller may not see, "
        "so it does not confirm which ids exist"
    )


def test_list_response_omits_bodies(src):
    """A 200-row page carrying two 8 KB JSONB blobs per row is a multi-megabyte
    response; bodies belong to the detail endpoint."""
    columns = src.split("_LIST_COLUMNS = ", 1)[1].split('"""', 2)[1]
    assert "request_body," not in columns
    assert "response_body," not in columns
    assert "request_body_bytes" in columns, "the size is still useful in the list"


def test_count_is_bounded(src):
    body = _handler_body(src, '@router.get("")')
    assert "LIMIT {count_cap}" in body or "count_cap" in body, (
        "an unbounded COUNT(*) over request_logs is a sequential scan on every page change"
    )
    assert "total_is_estimate" in body


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------

def test_router_is_registered_in_main():
    with open(_MAIN, encoding="utf-8") as f:
        main_src = f.read()

    assert "from routers.request_logs import router as request_logs_router" in main_src
    assert "app.include_router(request_logs_router)" in main_src, (
        "the router is imported but never mounted, so every endpoint 404s"
    )
