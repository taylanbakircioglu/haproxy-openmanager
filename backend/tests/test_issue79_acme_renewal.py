"""Issue #79: editing an ACME wildcard certificate and seeing why it was not auto-renewed.

  * The Edit form must not re-validate the locked name: ACME names a wildcard certificate
    le-*.<domain>, which the create-time pattern rejects.
  * The renewal task is gated by the global acme.auto_renew_enabled setting (default false)
    before a certificate's own auto_renew. The Renewal Schedule now carries that setting, and
    the task records an event when it cannot renew a certificate.
"""
import json
import os
import re
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from utils import acme_renewal
from utils.acme_renewal import (
    parse_auto_renew_enabled,
    parse_renew_before_days,
    load_renewal_settings,
    record_renewal_issue,
    fetch_latest_renewal_issues,
    renewal_due_date,
    RENEWAL_EVENT_FAILED,
    RENEWAL_EVENT_LOCK_NS,
    RENEWAL_EVENT_SKIPPED,
)

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_DIR = os.path.dirname(BACKEND_DIR)


def _read_backend(*parts):
    with open(os.path.join(BACKEND_DIR, *parts), encoding="utf-8") as fh:
        return fh.read()


def _read_frontend(*parts):
    path = os.path.join(REPO_DIR, "frontend", *parts)
    if not os.path.exists(path):
        pytest.skip(f"frontend not present at {path}; backend-only container")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# Settings parsing: identical to the inline code the renewal task used before v1.12.2
# ---------------------------------------------------------------------------

def _legacy_auto_renew_enabled(auto_renew_setting):
    auto_renew_enabled = False
    if auto_renew_setting:
        try:
            val = json.loads(auto_renew_setting) if isinstance(auto_renew_setting, str) else auto_renew_setting
            auto_renew_enabled = val in (True, 'true', 'True')
        except (json.JSONDecodeError, TypeError):
            pass
    return auto_renew_enabled


def _legacy_renew_days(renew_days_raw):
    renew_days = 30
    if renew_days_raw:
        try:
            renew_days = int(json.loads(renew_days_raw) if isinstance(renew_days_raw, str) else renew_days_raw)
        except (ValueError, TypeError, json.JSONDecodeError):
            pass
    return renew_days


AUTO_RENEW_INPUTS = [
    None, '', 'true', 'false', '"true"', '"True"', '"false"', 'True', 'yes', '1', '0',
    'null', '{}', '[]', '[true]', True, False, 1, 0,
]
RENEW_DAYS_INPUTS = [
    None, '', '30', '7', '0', '"14"', '"abc"', 'abc', 'null', '{}', '[]', '45.0', 45, 0, '90',
]


@pytest.mark.parametrize("raw", AUTO_RENEW_INPUTS)
def test_parse_auto_renew_enabled_matches_legacy(raw):
    assert parse_auto_renew_enabled(raw) == _legacy_auto_renew_enabled(raw)


@pytest.mark.parametrize("raw", RENEW_DAYS_INPUTS)
def test_parse_renew_before_days_matches_legacy(raw):
    assert parse_renew_before_days(raw) == _legacy_renew_days(raw)


def test_settings_ui_values_round_trip():
    # Settings.js sends JSON.stringify(value); the column is jsonb and asyncpg returns its text.
    assert parse_auto_renew_enabled('true') is True
    assert parse_auto_renew_enabled('false') is False
    assert parse_renew_before_days('30') == 30


@pytest.mark.asyncio
async def test_load_renewal_settings_reads_both_keys():
    conn = AsyncMock()
    conn.fetchval.side_effect = ['true', '21']
    assert await load_renewal_settings(conn) == (True, 21)
    sqls = [c.args[0] for c in conn.fetchval.call_args_list]
    assert "acme.auto_renew_enabled" in sqls[0]
    assert "acme.renew_before_days" in sqls[1]


@pytest.mark.asyncio
async def test_load_renewal_settings_defaults_when_rows_missing():
    conn = AsyncMock()
    conn.fetchval.side_effect = [None, None]
    assert await load_renewal_settings(conn) == (False, 30)


def _task_selects(expiry, today, days):
    """Python form of the task's `expiry_date <= CURRENT_DATE + (days || ' days')::INTERVAL`."""
    from datetime import date as _date, datetime as _dt, timedelta as _td
    threshold = _dt.combine(today, _dt.min.time()) + _td(days=days)
    if isinstance(expiry, _dt):
        return expiry <= threshold
    return _dt.combine(expiry, _dt.min.time()) <= threshold


@pytest.mark.parametrize("expiry", [
    datetime(2026, 12, 7, 10, 19, 4),   # typical ACME expiry with a time of day
    datetime(2026, 12, 7, 0, 0, 0),     # exactly midnight
    datetime(2026, 12, 7, 23, 59, 59),
    datetime(2027, 3, 1, 0, 0, 1),      # across a month end
    datetime(2028, 3, 1, 12, 0, 0),     # across a leap day
])
@pytest.mark.parametrize("days", [1, 7, 30, 90])
def test_renewal_due_date_is_the_first_day_the_task_selects(expiry, days):
    from datetime import timedelta as _td
    due = renewal_due_date(expiry, days)
    assert _task_selects(expiry, due, days), "the task must select the certificate on the due date"
    assert not _task_selects(expiry, due - _td(days=1), days), "and not the day before"


def test_renewal_due_date_date_column_and_missing_values():
    from datetime import date as _date, timezone as _tz
    # Older installs created ssl_certificates.expiry_date as DATE.
    assert renewal_due_date(_date(2026, 12, 7), 30) == _date(2026, 11, 7)
    assert renewal_due_date(None, 30) is None
    assert renewal_due_date(datetime(2026, 12, 7), None) is None
    aware = datetime(2026, 12, 7, 10, 0, tzinfo=_tz.utc)
    assert renewal_due_date(aware, 30) == _date(2026, 11, 8)


def test_renewal_event_lock_namespace_is_its_own():
    # (ns, id) advisory spaces already in use; 0x41434D45 is held per order id by
    # _complete_certificate, so sharing it would block certificate completion.
    assert RENEWAL_EVENT_LOCK_NS not in (18181818, 18181819, 18181820, 18181821, 18181873, 0x41434D45, 1836016242)


def test_renewal_task_uses_shared_settings_and_gates_before_query():
    src = _read_backend("main.py")
    start = src.index("async def check_letsencrypt_renewals")
    end = src.index("async def ", start + 10)
    body = src[start:end]
    assert "load_renewal_settings(conn)" in body
    assert "val in (True, 'true', 'True')" not in body, "inline parsing must not come back next to the helper"
    gate = body.index("if not auto_renew_enabled:")
    query = body.index("expiring_certs = await conn.fetch")
    assert gate < query, "the global switch must still be checked before any certificate is looked at"


# ---------------------------------------------------------------------------
# record_renewal_issue
# ---------------------------------------------------------------------------

def _tx_conn():
    """AsyncMock connection whose transaction() works as `async with`."""
    conn = AsyncMock()
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=tx)
    return conn


@pytest.mark.asyncio
async def test_record_renewal_issue_writes_event_when_not_recent():
    conn = _tx_conn()
    conn.fetchval.return_value = None
    with patch.object(acme_renewal, "get_database_connection", AsyncMock(return_value=conn)), \
         patch.object(acme_renewal, "close_database_connection", AsyncMock()) as close_mock, \
         patch("utils.activity_log.record_event", AsyncMock(return_value=5)) as rec:
        ok = await record_renewal_issue(42, RENEWAL_EVENT_FAILED, "x" * 900, severity="ERROR",
                                        details={"certificate_id": 7})
    assert ok is True
    rec.assert_awaited_once()
    args, kwargs = rec.call_args
    assert args == (42, RENEWAL_EVENT_FAILED)
    assert kwargs["severity"] == "ERROR"
    assert len(kwargs["message"]) == 500
    assert kwargs["details"] == {"certificate_id": 7}
    assert kwargs["conn"] is conn
    conn.transaction.assert_called_once()
    lock_sql, lock_ns, lock_id = conn.execute.call_args.args
    assert "pg_advisory_xact_lock" in lock_sql
    assert lock_ns == RENEWAL_EVENT_LOCK_NS and lock_id == 42
    throttle_sql, order_id, event_type, hours = conn.fetchval.call_args.args
    assert "acme_order_events" in throttle_sql
    assert (order_id, event_type, hours) == (42, RENEWAL_EVENT_FAILED, "24")
    close_mock.assert_awaited_once_with(conn)


@pytest.mark.asyncio
async def test_record_renewal_issue_throttled_within_window():
    conn = _tx_conn()
    conn.fetchval.return_value = 1
    with patch.object(acme_renewal, "get_database_connection", AsyncMock(return_value=conn)), \
         patch.object(acme_renewal, "close_database_connection", AsyncMock()), \
         patch("utils.activity_log.record_event", AsyncMock(return_value=5)) as rec:
        ok = await record_renewal_issue(42, RENEWAL_EVENT_SKIPPED, "again")
    assert ok is False
    rec.assert_not_awaited()


@pytest.mark.asyncio
async def test_record_renewal_issue_never_raises():
    with patch.object(acme_renewal, "get_database_connection", AsyncMock(side_effect=RuntimeError("pool down"))):
        assert await record_renewal_issue(1, RENEWAL_EVENT_FAILED, "m") is False

    conn = _tx_conn()
    conn.fetchval.side_effect = RuntimeError('relation "acme_order_events" does not exist')
    with patch.object(acme_renewal, "get_database_connection", AsyncMock(return_value=conn)), \
         patch.object(acme_renewal, "close_database_connection", AsyncMock()) as close_mock:
        assert await record_renewal_issue(1, RENEWAL_EVENT_FAILED, "m") is False
    close_mock.assert_awaited_once_with(conn)


# ---------------------------------------------------------------------------
# fetch_latest_renewal_issues
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_latest_renewal_issues_no_ids_no_query():
    conn = AsyncMock()
    assert await fetch_latest_renewal_issues(conn, [None, None]) == {}
    conn.fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_fetch_latest_renewal_issues_maps_rows():
    ts = datetime(2026, 11, 17, 10, 0, 0)
    conn = AsyncMock()
    conn.fetch.return_value = [
        {"order_id": 3, "event_type": RENEWAL_EVENT_FAILED, "severity": "ERROR", "message": "boom", "created_at": ts},
    ]
    out = await fetch_latest_renewal_issues(conn, [3, 3, None, 9])
    assert out == {3: {"event_type": RENEWAL_EVENT_FAILED, "severity": "ERROR", "message": "boom", "created_at": ts}}
    sql, ids, types, hours = conn.fetch.call_args.args
    assert ids == [3, 9]
    assert set(types) == {RENEWAL_EVENT_FAILED, RENEWAL_EVENT_SKIPPED}
    assert hours == "48"


@pytest.mark.asyncio
async def test_fetch_latest_renewal_issues_swallows_errors():
    conn = AsyncMock()
    conn.fetch.side_effect = RuntimeError("no table")
    assert await fetch_latest_renewal_issues(conn, [1]) == {}


# ---------------------------------------------------------------------------
# GET /api/letsencrypt/renewal-schedule
# ---------------------------------------------------------------------------

def _cert_row(**over):
    row = {
        "id": 11, "name": "le-*.example.com", "primary_domain": "*.example.com",
        "expiry_date": datetime(2026, 12, 1), "auto_renew": True, "days_until_expiry": 14,
        "challenge_type": "dns-01", "dns_provider": "cloudflare",
        "letsencrypt_order_id": 5, "order_domains": json.dumps(["*.example.com", "example.com"]),
        "account_status": "valid",
    }
    row.update(over)
    return row


async def _call_schedule(conn):
    from routers import letsencrypt
    with patch("auth_middleware.get_current_user_from_token", AsyncMock(return_value={"id": 1})), \
         patch("auth_middleware.check_user_permission", AsyncMock(return_value=True)), \
         patch.object(letsencrypt, "get_database_connection", AsyncMock(return_value=conn)), \
         patch.object(letsencrypt, "close_database_connection", AsyncMock()):
        return await letsencrypt.get_renewal_schedule(authorization="Bearer t")


LEGACY_KEYS = {"id", "name", "primary_domain", "expiry_date", "auto_renew", "days_until_expiry",
               "challenge_type", "dns_provider"}


@pytest.mark.asyncio
async def test_renewal_schedule_keeps_legacy_fields_and_adds_new_ones():
    issue_ts = datetime(2026, 11, 17, 9, 0, 0)
    conn = AsyncMock()
    conn.fetch.side_effect = [
        [_cert_row(), _cert_row(id=12, letsencrypt_order_id=None, order_domains=None, account_status=None,
                                challenge_type=None, dns_provider=None)],
        [{"order_id": 5, "event_type": RENEWAL_EVENT_FAILED, "severity": "ERROR", "message": "CA said no",
          "created_at": issue_ts}],
    ]
    conn.fetchval.side_effect = ['false', '30']
    result = await _call_schedule(conn)

    assert isinstance(result, list) and len(result) == 2
    first, second = result
    assert LEGACY_KEYS <= set(first)
    assert first["name"] == "le-*.example.com"
    assert first["global_auto_renew_enabled"] is False
    assert first["renew_before_days"] == 30
    from datetime import date as _date
    assert first["renewal_due_date"] == _date(2026, 11, 1)  # expiry 2026-12-01 00:00 - 30 days
    assert first["order_domains"] == ["*.example.com", "example.com"]
    assert first["account_status"] == "valid"
    assert first["last_renewal_issue"]["message"] == "CA said no"
    assert second["letsencrypt_order_id"] is None
    assert second["renewal_due_date"] is None  # the task skips certificates without an order
    assert second["order_domains"] is None
    assert second["last_renewal_issue"] is None
    cert_sql = conn.fetch.call_args_list[0].args[0]
    assert "c.source = 'letsencrypt' AND c.is_active = TRUE" in cert_sql


@pytest.mark.asyncio
@pytest.mark.parametrize("over,expected", [
    ({}, "date"),
    ({"auto_renew": False}, None),
    ({"letsencrypt_order_id": None}, None),
    ({"challenge_type": "dns-01", "dns_provider": "manual"}, None),
    ({"challenge_type": "dns-01", "dns_provider": None}, None),   # account without a provider = manual
    ({"challenge_type": "http-01", "dns_provider": None}, "date"),
    ({"challenge_type": None, "dns_provider": None}, "date"),     # legacy order without the column
])
async def test_renewal_due_date_only_for_certificates_the_task_renews(over, expected):
    conn = AsyncMock()
    conn.fetch.side_effect = [[_cert_row(**over)], []]
    conn.fetchval.side_effect = ['true', '30']
    (row,) = await _call_schedule(conn)
    if expected is None:
        assert row["renewal_due_date"] is None
    else:
        from datetime import date as _date
        assert row["renewal_due_date"] == _date(2026, 11, 1)


@pytest.mark.asyncio
async def test_renewal_schedule_survives_settings_and_event_failures():
    conn = AsyncMock()
    conn.fetch.side_effect = [[_cert_row()], RuntimeError("no acme_order_events")]
    conn.fetchval.side_effect = RuntimeError("system_settings unavailable")
    result = await _call_schedule(conn)
    assert len(result) == 1
    assert result[0]["global_auto_renew_enabled"] is None
    assert result[0]["renew_before_days"] is None
    assert result[0]["renewal_due_date"] is None
    assert result[0]["last_renewal_issue"] is None


@pytest.mark.asyncio
async def test_renewal_schedule_still_requires_ssl_read():
    from routers import letsencrypt
    with patch("auth_middleware.get_current_user_from_token", AsyncMock(return_value={"id": 1})), \
         patch("auth_middleware.check_user_permission", AsyncMock(return_value=False)):
        with pytest.raises(HTTPException) as exc:
            await letsencrypt.get_renewal_schedule(authorization="Bearer t")
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/letsencrypt/orders/{id}/renew (used by Renew Now)
# ---------------------------------------------------------------------------

async def _call_renew(conn, create_order):
    from routers import letsencrypt
    with patch("auth_middleware.get_current_user_from_token", AsyncMock(return_value={"id": 1})), \
         patch("auth_middleware.check_user_permission", AsyncMock(return_value=True)), \
         patch.object(letsencrypt, "get_database_connection", AsyncMock(return_value=conn)), \
         patch.object(letsencrypt, "close_database_connection", AsyncMock()), \
         patch.object(letsencrypt.acme_service, "create_order", create_order), \
         patch.object(letsencrypt.acme_service, "respond_to_challenges", AsyncMock(return_value=[])):
        return await letsencrypt.renew_order(5, authorization="Bearer t")


@pytest.mark.asyncio
async def test_renew_order_success_shape_unchanged():
    conn = AsyncMock()
    conn.fetchrow.return_value = {"account_id": 1, "domains": json.dumps(["*.example.com"]),
                                  "cluster_ids": json.dumps([2]), "challenge_type": "dns-01"}
    res = await _call_renew(conn, AsyncMock(return_value={"order_id": 77}))
    assert res == {"message": "Renewal order created", "new_order_id": 77, "challenge_type": "dns-01", "challenges": []}


@pytest.mark.asyncio
async def test_renew_order_failure_reports_reason_with_same_status():
    conn = AsyncMock()
    conn.fetchrow.return_value = {"account_id": 1, "domains": json.dumps(["a.example.com"]),
                                  "cluster_ids": json.dumps([]), "challenge_type": "http-01"}
    with pytest.raises(HTTPException) as exc:
        await _call_renew(conn, AsyncMock(side_effect=Exception("Order creation failed: account deactivated")))
    assert exc.value.status_code == 500
    assert "account deactivated" in exc.value.detail


@pytest.mark.asyncio
async def test_renew_order_keeps_http_exception_status():
    conn = AsyncMock()
    conn.fetchrow.return_value = {"account_id": 1, "domains": json.dumps(["a.example.com"]),
                                  "cluster_ids": json.dumps([]), "challenge_type": "http-01"}
    with pytest.raises(HTTPException) as exc:
        await _call_renew(conn, AsyncMock(side_effect=HTTPException(status_code=409, detail="busy")))
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_renew_order_missing_order_is_404():
    conn = AsyncMock()
    conn.fetchrow.return_value = None
    with pytest.raises(HTTPException) as exc:
        await _call_renew(conn, AsyncMock())
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# Renewal task: events, and nothing happens while the global switch is off
# ---------------------------------------------------------------------------

class _StopLoop(BaseException):
    """Not an Exception, so the task's own `except Exception` does not swallow it."""


async def _run_one_renewal_pass(main_conns, create_order, record_issue):
    """Run check_letsencrypt_renewals for exactly one pass (initial sleep, then stop)."""
    import main

    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) > 1:
            raise _StopLoop()

    with patch.object(main.asyncio, "sleep", fake_sleep), \
         patch.object(main, "get_database_connection", AsyncMock(side_effect=main_conns)), \
         patch.object(main, "close_database_connection", AsyncMock()), \
         patch("services.acme_service.acme_service.create_order", create_order), \
         patch("services.acme_service.acme_service.respond_to_challenges", AsyncMock(return_value=[])), \
         patch.object(acme_renewal, "record_renewal_issue", record_issue):
        with pytest.raises(_StopLoop):
            await main.check_letsencrypt_renewals()
    return sleeps


@pytest.mark.asyncio
async def test_renewal_task_does_nothing_while_global_switch_off():
    conn = AsyncMock()
    conn.fetchval.side_effect = [True, 'false', '30']
    create_order = AsyncMock()
    record_issue = AsyncMock()
    sleeps = await _run_one_renewal_pass([conn], create_order, record_issue)
    assert sleeps == [120, 3600]
    conn.fetch.assert_not_awaited()
    create_order.assert_not_awaited()
    record_issue.assert_not_awaited()


@pytest.mark.asyncio
async def test_renewal_task_records_event_when_order_creation_fails():
    conn = AsyncMock()
    conn.fetchval.side_effect = [True, 'true', '30']
    conn.fetch.return_value = [{"id": 11, "name": "le-*.example.com", "primary_domain": "*.example.com",
                                "letsencrypt_order_id": 5}]
    conn2 = AsyncMock()
    conn2.fetchrow.side_effect = [
        {"account_id": 1, "domains": json.dumps(["*.example.com"]), "cluster_ids": json.dumps([2]),
         "challenge_type": "dns-01", "dns_provider": "cloudflare"},
        None,  # no renewal order in progress
        None,  # no exhausted DNS-01 retry chain
    ]
    conn3 = AsyncMock()
    conn3.fetch.return_value = []
    create_order = AsyncMock(side_effect=Exception("Order creation failed: {'type': 'urn:ietf:params:acme:error:unauthorized'}"))
    record_issue = AsyncMock(return_value=True)

    await _run_one_renewal_pass([conn, conn2, conn3], create_order, record_issue)

    create_order.assert_awaited_once()
    record_issue.assert_awaited_once()
    args, kwargs = record_issue.call_args
    assert args[0] == 5 and args[1] == RENEWAL_EVENT_FAILED
    assert "unauthorized" in args[2]
    assert kwargs["severity"] == "ERROR"


@pytest.mark.asyncio
async def test_renewal_task_records_skip_when_dns01_retries_exhausted():
    conn = AsyncMock()
    conn.fetchval.side_effect = [True, 'true', '30']
    conn.fetch.return_value = [{"id": 11, "name": "le-*.example.com", "primary_domain": "*.example.com",
                                "letsencrypt_order_id": 5}]
    conn2 = AsyncMock()
    conn2.fetchrow.side_effect = [
        {"account_id": 1, "domains": json.dumps(["*.example.com"]), "cluster_ids": json.dumps([2]),
         "challenge_type": "dns-01", "dns_provider": "cloudflare"},
        None,
        {"id": 90},
    ]
    conn3 = AsyncMock()
    conn3.fetch.return_value = []
    create_order = AsyncMock()
    record_issue = AsyncMock(return_value=True)

    await _run_one_renewal_pass([conn, conn2, conn3], create_order, record_issue)

    create_order.assert_not_awaited()
    args, _ = record_issue.call_args
    assert args[0] == 5 and args[1] == RENEWAL_EVENT_SKIPPED
    assert "90" in args[2]


@pytest.mark.asyncio
async def test_renewal_task_success_records_nothing():
    conn = AsyncMock()
    conn.fetchval.side_effect = [True, 'true', '30']
    conn.fetch.return_value = [{"id": 11, "name": "le-a.example.com", "primary_domain": "a.example.com",
                                "letsencrypt_order_id": 5}]
    conn2 = AsyncMock()
    conn2.fetchrow.side_effect = [
        {"account_id": 1, "domains": json.dumps(["a.example.com"]), "cluster_ids": json.dumps([]),
         "challenge_type": "http-01", "dns_provider": None},
        None,
    ]
    conn3 = AsyncMock()
    conn3.fetch.return_value = []
    create_order = AsyncMock(return_value={"order_id": 99})
    record_issue = AsyncMock()

    await _run_one_renewal_pass([conn, conn2, conn3], create_order, record_issue)

    create_order.assert_awaited_once_with(1, ["a.example.com"], [], challenge_type="http-01")
    record_issue.assert_not_awaited()


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

def test_ssl_edit_skips_name_pattern_but_create_keeps_it():
    src = _read_frontend("src", "components", "SSLManagement.js")
    block = src[src.index('name="name"'):src.index('placeholder="e.g., my-domain-cert"')]
    assert re.search(
        r"selectedCertificate && selectedCertificate\.id\s*\?\s*\[\]\s*:\s*\[\{ pattern: /\^\[a-zA-Z0-9_\.-\]\+\$/",
        block,
    ), "the name pattern must apply to new certificates only"


def test_ssl_edit_locks_scope_fields():
    src = _read_frontend("src", "components", "SSLManagement.js")
    scope = src[src.index('name="ssl_type"'):src.index('<Select.Option value="global">')]
    assert "disabled={selectedCertificate && selectedCertificate.id ? true : false}" in scope
    clusters = src[src.index('name="cluster_ids"'):src.index("{(clusters || []).map(cluster =>")]
    assert "disabled={sslType === 'global' || !!(selectedCertificate && selectedCertificate.id)}" in clusters


def test_ssl_update_model_still_ignores_scope():
    # The Edit form locks scope because PUT has never applied it; if PUT starts handling
    # scope, the lock in SSLManagement.js has to be revisited together with this test.
    from models.ssl import SSLCertificateUpdate
    fields = set(SSLCertificateUpdate.model_fields)
    assert "is_global" not in fields and "cluster_ids" not in fields


def test_acme_ui_treats_missing_fields_as_legacy():
    src = _read_frontend("src", "components", "ACMEAutomation.js")
    assert "c.global_auto_renew_enabled === false" in src
    assert "record.global_auto_renew_enabled === false" in src
    assert "record.global_auto_renew_enabled === true && (!record.letsencrypt_order_id || !record.expiry_date)" in src
    assert "record.renewal_due_date || ''" in src


def test_acme_ui_renew_now_uses_renew_endpoint_and_guards_duplicates():
    src = _read_frontend("src", "components", "ACMEAutomation.js")
    assert "axios.post(`/api/letsencrypt/orders/${cert.letsencrypt_order_id}/renew`)" in src
    assert "findRenewalInProgress(record)" in src
    assert "record.challenge_type === 'dns-01' && dns01Known && !dns01Enabled" in src
    assert "['valid', 'invalid', 'cancelled'].includes(o.status)" in src
