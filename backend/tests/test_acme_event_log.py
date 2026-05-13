"""
v1.5.0 Feature A — record_event() and prune_acme_events_and_drafts_if_due() unit tests.

These tests validate:
  * happy-path INSERT shape against acme_order_events,
  * silent failure when the underlying table is missing (older deployments),
  * conn-reuse path doesn't open/close a pool connection,
  * daily-watermark logic correctly skips reruns within 24h.
"""
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from utils.activity_log import (
    record_event,
    prune_acme_events_and_drafts_if_due,
)


# ----------------------------------------------------------------------------
# record_event happy path
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_event_happy_path_with_provided_conn():
    conn = AsyncMock()
    conn.fetchval.return_value = 42

    row_id = await record_event(
        order_id=100,
        event_type="acme.order.created",
        severity="info",
        message="Test event",
        details={"foo": "bar"},
        correlation_id="corr-123",
        conn=conn,
    )

    assert row_id == 42
    conn.fetchval.assert_awaited_once()
    args = conn.fetchval.call_args.args
    sql = args[0]
    assert "INSERT INTO acme_order_events" in sql
    # Positional args after the SQL template
    assert args[1] == 100                          # order_id
    assert args[2] == "acme.order.created"         # event_type
    assert args[3] == "INFO"                       # severity normalized upper
    assert args[4] == "Test event"                 # message
    parsed_details = json.loads(args[5])
    assert parsed_details == {"foo": "bar"}
    assert args[6] == "corr-123"


@pytest.mark.asyncio
async def test_record_event_severity_uppercased_default_info():
    conn = AsyncMock()
    conn.fetchval.return_value = 1

    await record_event(order_id=1, event_type="x", conn=conn)
    args = conn.fetchval.call_args.args
    assert args[3] == "INFO"


@pytest.mark.asyncio
async def test_record_event_dict_details_serialized_to_json():
    conn = AsyncMock()
    conn.fetchval.return_value = 7

    await record_event(
        order_id=1,
        event_type="x",
        details={"k": [1, 2, 3], "nested": {"a": True}},
        conn=conn,
    )
    args = conn.fetchval.call_args.args
    parsed = json.loads(args[5])
    assert parsed == {"k": [1, 2, 3], "nested": {"a": True}}


@pytest.mark.asyncio
async def test_record_event_none_details_serialized_to_empty_object():
    conn = AsyncMock()
    conn.fetchval.return_value = 1

    await record_event(order_id=1, event_type="x", details=None, conn=conn)
    args = conn.fetchval.call_args.args
    parsed = json.loads(args[5])
    assert parsed == {}


# ----------------------------------------------------------------------------
# record_event resilience
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_record_event_swallows_db_error_returns_none():
    """If the table doesn't exist or the DB rejects the insert, NEVER raise."""
    conn = AsyncMock()
    conn.fetchval.side_effect = Exception(
        'relation "acme_order_events" does not exist'
    )

    row_id = await record_event(order_id=1, event_type="x", conn=conn)
    assert row_id is None


@pytest.mark.asyncio
async def test_record_event_swallows_outer_failure_when_pool_unavailable():
    """If get_database_connection itself raises (pool exhausted), still return None."""
    with patch(
        "utils.activity_log.get_database_connection",
        side_effect=Exception("pool exhausted"),
    ):
        row_id = await record_event(order_id=1, event_type="x")
        assert row_id is None


@pytest.mark.asyncio
async def test_record_event_acquires_and_releases_own_conn():
    """When no conn is supplied we must open one and release it."""
    fake_conn = AsyncMock()
    fake_conn.fetchval.return_value = 99

    with patch(
        "utils.activity_log.get_database_connection",
        AsyncMock(return_value=fake_conn),
    ) as mocked_get, patch(
        "utils.activity_log.close_database_connection",
        AsyncMock(),
    ) as mocked_close:
        row_id = await record_event(order_id=1, event_type="x")

    assert row_id == 99
    mocked_get.assert_awaited_once()
    mocked_close.assert_awaited_once_with(fake_conn)


@pytest.mark.asyncio
async def test_record_event_does_not_close_caller_provided_conn():
    """When conn is passed in, we must NOT close it."""
    conn = AsyncMock()
    conn.fetchval.return_value = 1

    with patch(
        "utils.activity_log.close_database_connection",
        AsyncMock(),
    ) as mocked_close:
        await record_event(order_id=1, event_type="x", conn=conn)

    mocked_close.assert_not_awaited()


# ----------------------------------------------------------------------------
# prune_acme_events_and_drafts_if_due — daily watermark
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prune_skips_when_last_run_is_recent():
    """If acme.events_last_pruned_at is < 24h old, skip the DELETE."""
    fake_conn = AsyncMock()
    recent = (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z"
    fake_conn.fetchrow.return_value = {"value": json.dumps(recent)}

    with patch(
        "utils.activity_log.get_database_connection",
        AsyncMock(return_value=fake_conn),
    ), patch(
        "utils.activity_log.close_database_connection",
        AsyncMock(),
    ):
        out = await prune_acme_events_and_drafts_if_due()

    assert out == {"acme_events": 0, "wizard_drafts": 0}
    # Assert NO DELETE was issued: every conn.execute call was for INSERT or never called.
    delete_calls = [
        c for c in fake_conn.execute.call_args_list
        if c.args and "DELETE" in c.args[0]
    ]
    assert delete_calls == []


@pytest.mark.asyncio
async def test_prune_runs_when_last_run_is_stale():
    """If watermark is > 24h old, prune executes and watermark updates."""
    fake_conn = AsyncMock()

    stale = (datetime.utcnow() - timedelta(hours=48)).isoformat() + "Z"
    # First fetchrow is for acme key, second for wizard key.
    fake_conn.fetchrow.side_effect = [
        {"value": json.dumps(stale)},
        {"value": json.dumps(stale)},
    ]

    # asyncpg returns "DELETE <n>" string for DELETE statements.
    fake_conn.execute.side_effect = [
        "DELETE 5",   # acme_order_events delete
        "INSERT 0 1", # watermark upsert for acme
        "DELETE 2",   # wizard_drafts delete
        "INSERT 0 1", # watermark upsert for wizard
    ]

    with patch(
        "utils.activity_log.get_database_connection",
        AsyncMock(return_value=fake_conn),
    ), patch(
        "utils.activity_log.close_database_connection",
        AsyncMock(),
    ):
        out = await prune_acme_events_and_drafts_if_due()

    assert out == {"acme_events": 5, "wizard_drafts": 2}
    # Verify both DELETE queries were issued.
    delete_sqls = [
        c.args[0] for c in fake_conn.execute.call_args_list
        if c.args and "DELETE" in c.args[0]
    ]
    assert any("acme_order_events" in s for s in delete_sqls)
    assert any("wizard_drafts" in s for s in delete_sqls)


@pytest.mark.asyncio
async def test_prune_runs_on_first_run_when_watermark_missing():
    """Missing watermark row should NOT block first-run prune."""
    fake_conn = AsyncMock()
    fake_conn.fetchrow.return_value = None
    fake_conn.execute.side_effect = [
        "DELETE 0", "INSERT 0 1",
        "DELETE 0", "INSERT 0 1",
    ]

    with patch(
        "utils.activity_log.get_database_connection",
        AsyncMock(return_value=fake_conn),
    ), patch(
        "utils.activity_log.close_database_connection",
        AsyncMock(),
    ):
        out = await prune_acme_events_and_drafts_if_due()

    assert out == {"acme_events": 0, "wizard_drafts": 0}


@pytest.mark.asyncio
async def test_prune_swallows_top_level_db_failure():
    """If the connection itself fails, return zeros, never raise."""
    with patch(
        "utils.activity_log.get_database_connection",
        side_effect=Exception("db down"),
    ):
        out = await prune_acme_events_and_drafts_if_due()
    assert out == {"acme_events": 0, "wizard_drafts": 0}
