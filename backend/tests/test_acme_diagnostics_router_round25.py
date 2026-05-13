"""Router-level tests for the ACME diagnostic endpoints (Round-25 audit).

These tests pin the contract introduced by Bulgu #94 / #95:

* ``POST /api/letsencrypt/orders/{order_id}/diagnostics`` must NEVER return
  HTTP 500 for an in-suite failure. Authentication / authorisation /
  rate-limit / not-found errors still raise the appropriate 4xx, but any
  unexpected exception during check execution is converted to HTTP 200
  with a structured failure envelope so the UI can render the cause.

* ``GET /api/letsencrypt/orders/{order_id}/events`` must NEVER return
  HTTP 500 because of schema drift in ``user_activity_logs`` (the
  original 500 cause: SELECTing a non-existent ``status`` column). A
  partial failure is reported via ``meta.errors[]``.

The tests use AsyncMock-based fake connections rather than spinning up a
real Postgres so they run hermetically inside CI.
"""
from unittest.mock import AsyncMock, patch

import pytest

from routers import acme_diagnostics as router_mod


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------


class _FakeUser(dict):
    pass


def _patch_auth_and_db(monkeypatch, conn, user_id=1):
    """Patch the auth / db helpers used by both endpoints so the tests
    don't have to construct a real FastAPI request stack."""
    async def _fake_user(_auth):
        return _FakeUser(id=user_id, username="t", email="t@x")

    async def _fake_perm(_uid, *_a, **_k):
        return True

    async def _fake_get_conn():
        return conn

    async def _fake_close_conn(_c):
        return None

    async def _fake_rate_limit(*_a, **_kw):
        return None

    monkeypatch.setattr(router_mod, "get_current_user_from_token", _fake_user)
    monkeypatch.setattr(router_mod, "check_user_permission", _fake_perm)
    monkeypatch.setattr(router_mod, "get_database_connection", _fake_get_conn)
    monkeypatch.setattr(router_mod, "close_database_connection", _fake_close_conn)
    monkeypatch.setattr(router_mod, "_enforce_rate_limit", _fake_rate_limit)


# ----------------------------------------------------------------------------
# /diagnostics endpoint
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulgu94_diagnostics_load_order_crash_returns_envelope_not_500(monkeypatch):
    """A DB crash during load_order must surface a 200 envelope, not 500.

    Pre-fix, any RuntimeError between auth and run_checks bubbled out of
    the bare ``try/finally`` block and FastAPI returned an opaque HTTP 500.
    The Round-25 fix wraps load_order so the operator sees the cause
    inside the diagnostic panel.
    """
    conn = AsyncMock()
    conn.fetchrow.side_effect = RuntimeError("simulated DB connectivity loss")
    _patch_auth_and_db(monkeypatch, conn)

    out = await router_mod.run_diagnostics(order_id=42, authorization="Bearer x")

    assert out["order_id"] == 42
    assert out["status"] == "diagnostics_unavailable"
    assert out["checks"][0]["status"] == "fail"
    assert out["checks"][0]["id"] == "diagnostics_runner"
    assert "simulated DB connectivity loss" in out["checks"][0]["message"]
    assert out["meta"]["correlation_id"]
    assert out["meta"]["error_stage"] == "load_order"
    assert "humanized_error" in out


@pytest.mark.asyncio
async def test_bulgu94_diagnostics_run_checks_crash_returns_envelope(monkeypatch):
    """A crash inside run_checks (after order is loaded) must also stay 200."""
    conn = AsyncMock()
    conn.fetchrow.return_value = {
        "id": 5,
        "account_id": 1,
        "status": "invalid",
        "domains": '["a.example.com"]',
        "cluster_ids": "[1]",
        "error_detail": None,
        "post_completion_actions": None,
        "pending_apply_version_name": None,
        "wizard_staged_until": None,
        "created_by": 1,
    }
    _patch_auth_and_db(monkeypatch, conn)

    async def _boom(*_a, **_kw):
        raise RuntimeError("simulated check orchestrator crash")

    monkeypatch.setattr(router_mod, "run_checks", _boom)

    out = await router_mod.run_diagnostics(order_id=5, authorization="Bearer x")

    assert out["order_id"] == 5
    assert out["status"] == "diagnostics_unavailable"
    assert out["meta"]["error_stage"] == "run_checks"
    assert out["meta"]["error_type"] == "RuntimeError"
    assert "simulated check orchestrator crash" in out["meta"]["error_message"]


@pytest.mark.asyncio
async def test_bulgu94_diagnostics_returns_meta_summary_on_success(monkeypatch):
    """Successful diagnostics responses carry a meta summary the UI uses
    to surface 'N checks failed, M warnings' without recomputing."""
    conn = AsyncMock()
    conn.fetchrow.return_value = {
        "id": 5,
        "account_id": 1,
        "status": "invalid",
        "domains": '["a.example.com"]',
        "cluster_ids": "[1]",
        "error_detail": None,
        "post_completion_actions": None,
        "pending_apply_version_name": None,
        "wizard_staged_until": None,
        "created_by": 1,
    }
    _patch_auth_and_db(monkeypatch, conn)

    async def _fake_checks(*_a, **_kw):
        return [
            {"id": "dns", "label": "DNS", "status": "ok", "severity": "info", "message": "", "details": {}, "duration_ms": 1},
            {"id": "routing", "label": "Routing", "status": "fail", "severity": "error", "message": "", "details": {}, "duration_ms": 1},
            {"id": "port80", "label": "Port 80", "status": "warn", "severity": "warn", "message": "", "details": {}, "duration_ms": 1},
        ]

    monkeypatch.setattr(router_mod, "run_checks", _fake_checks)

    out = await router_mod.run_diagnostics(order_id=5, authorization="Bearer x")

    assert out["meta"]["checks_total"] == 3
    assert out["meta"]["checks_failed"] == 1
    assert out["meta"]["checks_warn"] == 1
    assert out["meta"]["correlation_id"]


# ----------------------------------------------------------------------------
# /events endpoint
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulgu95_events_missing_status_column_returns_partial_envelope(monkeypatch):
    """Bulgu #95 — user_activity_logs lacks a `status` column.

    Pre-fix, the SELECT pulled `status` directly and the endpoint
    returned HTTP 500 for every order that had any correlated
    user-activity rows. The Round-25 fix introspects the schema; here
    we simulate a deployment with no `status` column AND a JOIN /
    query that would otherwise crash — the endpoint must stay 200,
    return whatever it could collect from acme_order_events, and
    record the user_activity_logs section as degraded but recoverable.
    """
    conn = AsyncMock()

    # _load_order
    order_row = {
        "id": 5,
        "account_id": 1,
        "status": "invalid",
        "domains": '["a.example.com"]',
        "cluster_ids": "[1]",
        "error_detail": None,
        "post_completion_actions": None,
        "pending_apply_version_name": None,
        "wizard_staged_until": None,
        "created_by": 1,
    }

    fetchval_calls = {"n": 0}

    async def _fetchval(sql, *args):
        fetchval_calls["n"] += 1
        # First call: existence check for acme_order_events table
        if "acme_order_events" in sql:
            return True
        return False

    async def _fetchrow(sql, *args):
        return order_row

    columns_no_status = [
        {"column_name": "id"},
        {"column_name": "user_id"},
        {"column_name": "action"},
        {"column_name": "resource_type"},
        {"column_name": "resource_id"},
        {"column_name": "details"},
        {"column_name": "created_at"},
        # NOTE: no "status" column — this is the canonical schema.
    ]

    async def _fetch(sql, *args):
        if "information_schema.columns" in sql and "user_activity_logs" in sql:
            return columns_no_status
        if "FROM acme_order_events" in sql:
            return []  # empty timeline is fine for this test
        if "FROM user_activity_logs" in sql:
            # If the projection includes `status` we will fail loudly.
            assert "status" not in sql, (
                "SELECT must not include `status` when the column is absent; "
                f"SQL was: {sql!r}"
            )
            return []
        return []

    conn.fetchval = _fetchval
    conn.fetchrow = _fetchrow
    conn.fetch = _fetch

    _patch_auth_and_db(monkeypatch, conn)

    out = await router_mod.get_order_events(order_id=5, authorization="Bearer x")

    assert out["order_id"] == 5
    assert out["count"] == 0
    assert out["meta"]["correlation_id"]
    # No section errors expected — schema-aware projection silently
    # adapted, the panel just got an empty event list.
    assert out["meta"]["errors"] == []


@pytest.mark.asyncio
async def test_bulgu95_events_acme_order_events_query_crash_returns_partial(monkeypatch):
    """A crash in the acme_order_events sub-query must NOT kill the
    whole endpoint — the user_activity_logs section should still run
    and the failure must appear in meta.errors."""
    conn = AsyncMock()
    order_row = {
        "id": 5,
        "account_id": 1,
        "status": "invalid",
        "domains": '["a.example.com"]',
        "cluster_ids": "[1]",
        "error_detail": None,
        "post_completion_actions": None,
        "pending_apply_version_name": None,
        "wizard_staged_until": None,
        "created_by": 1,
    }

    async def _fetchval(sql, *args):
        if "acme_order_events" in sql:
            return True
        return False

    async def _fetchrow(sql, *args):
        return order_row

    async def _fetch(sql, *args):
        if "information_schema.columns" in sql:
            return [
                {"column_name": "id"}, {"column_name": "action"},
                {"column_name": "resource_type"}, {"column_name": "resource_id"},
                {"column_name": "details"}, {"column_name": "created_at"},
            ]
        if "FROM acme_order_events" in sql:
            raise RuntimeError("simulated acme_order_events index corruption")
        if "FROM user_activity_logs" in sql:
            return []
        return []

    conn.fetchval = _fetchval
    conn.fetchrow = _fetchrow
    conn.fetch = _fetch
    _patch_auth_and_db(monkeypatch, conn)

    out = await router_mod.get_order_events(order_id=5, authorization="Bearer x")

    assert out["count"] == 0
    error_sections = [e["section"] for e in out["meta"]["errors"]]
    assert "acme_order_events" in error_sections


@pytest.mark.asyncio
async def test_bulgu95_events_load_order_404_still_raises(monkeypatch):
    """The 404 HTTPException raised by `_load_order` for an unknown order
    must remain a 404 — the Round-25 envelope is only for *unexpected*
    failures, not for client-supplied invalid order IDs."""
    from fastapi import HTTPException

    conn = AsyncMock()
    conn.fetchrow.return_value = None  # no order found
    _patch_auth_and_db(monkeypatch, conn)

    with pytest.raises(HTTPException) as exc_info:
        await router_mod.get_order_events(order_id=9999, authorization="Bearer x")
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_bulgu94_rerun_setup_crash_returns_check_envelope(monkeypatch):
    """The single-check re-run path must also envelope, never 500.

    Pre-fix the rerun handler used the same bare ``try/finally`` shape
    as the suite POST. If `_load_order` / `_enforce_rate_limit` raised,
    the operator clicking the row's "Re-run" button got an opaque
    toast and the row never updated. Now the rerun handler returns a
    `fail` check shaped the same way the table already renders, so
    the row updates in place with the cause + correlation_id.
    """
    conn = AsyncMock()
    conn.fetchrow.side_effect = RuntimeError("simulated DB drop during rerun")
    _patch_auth_and_db(monkeypatch, conn)

    out = await router_mod.rerun_diagnostic_check(
        order_id=5, check_id="dns", authorization="Bearer x",
    )
    assert out["order_id"] == 5
    assert out["check"]["status"] == "fail"
    assert out["check"]["id"] == "dns"
    assert "simulated DB drop during rerun" in out["check"]["message"]
    assert out["meta"]["error_stage"] == "setup"
    assert out["meta"]["correlation_id"]


@pytest.mark.asyncio
async def test_bulgu94_rerun_run_checks_crash_returns_check_envelope(monkeypatch):
    """A crash inside run_checks during a re-run also stays 200."""
    conn = AsyncMock()
    conn.fetchrow.return_value = {
        "id": 5, "account_id": 1, "status": "invalid",
        "domains": '["a.example.com"]', "cluster_ids": "[1]",
        "error_detail": None, "post_completion_actions": None,
        "pending_apply_version_name": None, "wizard_staged_until": None,
        "created_by": 1,
    }
    _patch_auth_and_db(monkeypatch, conn)

    async def _boom(*_a, **_kw):
        raise RuntimeError("simulated run_checks failure")

    monkeypatch.setattr(router_mod, "run_checks", _boom)

    out = await router_mod.rerun_diagnostic_check(
        order_id=5, check_id="agents", authorization="Bearer x",
    )
    assert out["check"]["id"] == "agents"
    assert out["check"]["status"] == "fail"
    assert "simulated run_checks failure" in out["check"]["message"]
    assert out["meta"]["error_stage"] == "run_checks"


@pytest.mark.asyncio
async def test_bulgu94_rerun_invalid_check_id_still_400(monkeypatch):
    """An unknown check_id must remain a 400, not an envelope. The
    envelope is only for *unexpected* server-side failures, not for
    client-supplied invalid identifiers."""
    from fastapi import HTTPException

    conn = AsyncMock()
    _patch_auth_and_db(monkeypatch, conn)

    with pytest.raises(HTTPException) as exc_info:
        await router_mod.rerun_diagnostic_check(
            order_id=5, check_id="bogus", authorization="Bearer x",
        )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_bulgu95_events_status_column_is_used_when_present(monkeypatch):
    """If a deployment DID add a `status` column (e.g. via a private
    schema extension), the projection picks it up and the resulting
    severity reflects it."""
    conn = AsyncMock()
    order_row = {
        "id": 5, "account_id": 1, "status": "invalid",
        "domains": '["a.example.com"]', "cluster_ids": "[1]",
        "error_detail": None, "post_completion_actions": None,
        "pending_apply_version_name": None, "wizard_staged_until": None,
        "created_by": 1,
    }

    async def _fetchval(sql, *args):
        if "acme_order_events" in sql:
            return True
        return False

    async def _fetchrow(sql, *args):
        return order_row

    captured_sql = {"ua": None}
    from datetime import datetime, timezone

    async def _fetch(sql, *args):
        if "information_schema.columns" in sql:
            return [
                {"column_name": "id"}, {"column_name": "action"},
                {"column_name": "resource_type"}, {"column_name": "resource_id"},
                {"column_name": "details"}, {"column_name": "created_at"},
                {"column_name": "status"},
            ]
        if "FROM acme_order_events" in sql:
            return []
        if "FROM user_activity_logs" in sql:
            captured_sql["ua"] = sql
            return [{
                "id": 100,
                "action": "letsencrypt.order.create",
                "resource_type": "letsencrypt_order",
                "resource_id": "5",
                "details": '{"foo":"bar"}',
                "created_at": datetime(2026, 5, 13, 19, 0, 0, tzinfo=timezone.utc),
                "user_id": 7,
                "status": "failure",
            }]
        return []

    conn.fetchval = _fetchval
    conn.fetchrow = _fetchrow
    conn.fetch = _fetch
    _patch_auth_and_db(monkeypatch, conn)

    out = await router_mod.get_order_events(order_id=5, authorization="Bearer x")

    assert "status" in captured_sql["ua"]
    assert out["count"] == 1
    ev = out["events"][0]
    assert ev["source"] == "user_activity_log"
    assert ev["severity"] == "warn"  # status="failure" → warn
    assert ev["details"] == {"foo": "bar"}


# ----------------------------------------------------------------------------
# Bulgu #96 (prod-canary follow-up): int4 overflow on order_id must NOT
# leak the asyncpg DataError message ("invalid input for query argument
# $1: ... value out of int32 range") into the operator-facing response
# body. Same shape as the "row not found" path: clean HTTPException(404).
# ----------------------------------------------------------------------------


import asyncpg as _asyncpg  # noqa: E402 — late import so the test module
# can still be collected even if asyncpg has changed its exception module.


def _data_error(msg: str) -> _asyncpg.exceptions.DataError:
    """Construct an asyncpg DataError that mirrors what Postgres returns
    when a path-param order_id overflows int4. We can't easily build the
    real instance from the binary protocol, so we synthesize one with the
    same class so the router's `except asyncpg.exceptions.DataError`
    branch is exercised."""
    return _asyncpg.exceptions.DataError(msg)


@pytest.mark.asyncio
async def test_bulgu96_diagnostics_int4_overflow_returns_clean_404(monkeypatch):
    """``order_id`` outside the int4 range must surface as a clean 404,
    NOT as a `diagnostics_unavailable` envelope leaking the asyncpg
    DataError message ("query argument $1", "int32 range").
    """
    conn = AsyncMock()
    conn.fetchrow.side_effect = _data_error(
        "invalid input for query argument $1: 2147483648 (value out of int32 range)"
    )
    _patch_auth_and_db(monkeypatch, conn)

    with pytest.raises(router_mod.HTTPException) as excinfo:
        await router_mod.run_diagnostics(
            order_id=2_147_483_648,
            authorization="Bearer x",
        )

    assert excinfo.value.status_code == 404
    # The operator must see the canonical "not found" detail, NOT the
    # raw asyncpg error message.
    assert "not found" in str(excinfo.value.detail).lower()
    assert "int32" not in str(excinfo.value.detail).lower()
    assert "query argument" not in str(excinfo.value.detail).lower()


@pytest.mark.asyncio
async def test_bulgu96_events_int4_overflow_returns_clean_404(monkeypatch):
    """Same contract on the events endpoint — out-of-range order_id is a
    clean 404, not a `meta.errors[]` envelope leaking SQL detail."""
    conn = AsyncMock()
    conn.fetchrow.side_effect = _data_error(
        "invalid input for query argument $1: 9999999999 (value out of int32 range)"
    )
    _patch_auth_and_db(monkeypatch, conn)

    with pytest.raises(router_mod.HTTPException) as excinfo:
        await router_mod.get_order_events(
            order_id=9_999_999_999,
            authorization="Bearer x",
        )

    assert excinfo.value.status_code == 404
    assert "not found" in str(excinfo.value.detail).lower()
    assert "int32" not in str(excinfo.value.detail).lower()


@pytest.mark.asyncio
async def test_bulgu96_rerun_int4_overflow_returns_clean_404(monkeypatch):
    """Same contract on the per-check rerun endpoint — out-of-range
    order_id is a clean 404, not a structured ``check.fail`` envelope
    leaking the asyncpg DataError message."""
    conn = AsyncMock()
    conn.fetchrow.side_effect = _data_error(
        "invalid input for query argument $1: 5000000000 (value out of int32 range)"
    )
    _patch_auth_and_db(monkeypatch, conn)

    with pytest.raises(router_mod.HTTPException) as excinfo:
        await router_mod.rerun_diagnostic_check(
            order_id=5_000_000_000,
            check_id="dns",
            authorization="Bearer x",
        )

    assert excinfo.value.status_code == 404
    assert "not found" in str(excinfo.value.detail).lower()
    assert "int32" not in str(excinfo.value.detail).lower()


@pytest.mark.asyncio
async def test_bulgu96_load_order_dataerror_does_not_leak_correlation_envelope(monkeypatch):
    """Belt-and-braces: even when the DataError carries other kinds of
    invalid-input strings (e.g. type coercion failure on an int4
    column), `_load_order` must still answer with the canonical 404
    envelope and NOT route it through `_diagnostic_failure_envelope`
    (which would surface the raw SQL detail to the UI)."""
    conn = AsyncMock()
    conn.fetchrow.side_effect = _data_error("invalid integer literal: 'NaN'")
    _patch_auth_and_db(monkeypatch, conn)

    with pytest.raises(router_mod.HTTPException) as excinfo:
        await router_mod.run_diagnostics(order_id=123, authorization="Bearer x")

    assert excinfo.value.status_code == 404
    # No SQL detail leak
    assert "invalid integer literal" not in str(excinfo.value.detail).lower()
    assert "NaN" not in str(excinfo.value.detail)
