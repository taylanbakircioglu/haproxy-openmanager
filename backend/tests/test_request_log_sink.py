"""v1.11.0: the batching writer must never slow down or break a request.

One row per API call is the highest write volume in the system and the asyncpg
pool (min=10/max=50) is shared with every handler and four background loops. So
the hot path enqueues and returns; a single writer task batches and inserts.
The properties pinned here:

  * `offer()` never blocks and never raises — a full queue drops and counts;
  * the parameter list stays aligned with the INSERT placeholders (a column
    added to one and not the other would fail every write at runtime, in
    production, with the migration already applied);
  * a failed batch is dropped with a warning rather than killing the loop.
"""
import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dataclasses import replace  # noqa: E402

from utils import request_log_settings  # noqa: E402
from utils import request_log_sink as sink_module  # noqa: E402
from utils.request_log_sink import (  # noqa: E402
    RequestLogRow,
    RequestLogSink,
    _INSERT_SQL,
)
from utils.request_log_settings import DEFAULT_CONFIG  # noqa: E402


def _row(**overrides):
    base = dict(
        request_id="abc123",
        direction="inbound",
        method="POST",
        url="/api/backends",
        path="/api/backends",
        status_code=200,
        duration_ms=12,
        created_at=datetime(2026, 8, 11, 9, 0, tzinfo=timezone.utc),
    )
    base.update(overrides)
    return RequestLogRow(**base)


@pytest.fixture(autouse=True)
def defaults(monkeypatch):
    monkeypatch.setattr(request_log_settings, "_CACHE", DEFAULT_CONFIG)
    monkeypatch.setattr(sink_module, "get_config", lambda: request_log_settings._CACHE)


def _set(monkeypatch, **overrides):
    monkeypatch.setattr(request_log_settings, "_CACHE", replace(DEFAULT_CONFIG, **overrides))


# --------------------------------------------------------------------------
# SQL / parameter alignment
# --------------------------------------------------------------------------

def test_insert_placeholders_match_the_column_list():
    columns = _INSERT_SQL.split("(", 1)[1].split(")", 1)[0]
    n_columns = len([c for c in columns.split(",") if c.strip()])
    n_placeholders = len(set(re.findall(r"\$(\d+)", _INSERT_SQL)))

    assert n_columns == n_placeholders, (
        f"the INSERT names {n_columns} columns but binds {n_placeholders} placeholders — "
        f"every write would fail at runtime, on a database where the migration has "
        f"already succeeded"
    )


def test_row_produces_exactly_as_many_params_as_the_insert_binds():
    n_placeholders = len(set(re.findall(r"\$(\d+)", _INSERT_SQL)))
    assert len(_row().to_params()) == n_placeholders, (
        "RequestLogRow.to_params() drifted from _INSERT_SQL"
    )


def test_jsonb_params_are_serialized_strings_not_dicts():
    """No JSONB codec is registered on this pool, so JSONB values travel as text
    and are cast in SQL — handing asyncpg a dict raises."""
    row = _row(
        query_params={"page": "2"},
        request_headers={"content-type": "application/json"},
        request_body_value={"name": "web"},
    )
    params = row.to_params()

    for value in params:
        assert not isinstance(value, (dict, list)), (
            f"{value!r} was passed as a Python container; asyncpg cannot bind it to a "
            f"jsonb parameter"
        )

    assert json.loads(params[6]) == {"page": "2"}


def test_client_ip_is_never_a_placeholder_string():
    """client_ip is an INET column: 'unknown' or a comma-joined X-Forwarded-For
    raises on INSERT."""
    params = _row(client_ip=None).to_params()
    assert params[12] is None


def test_status_class_is_zero_when_there_was_no_response():
    assert _row(status_code=None).status_class == 0
    assert _row(status_code=204).status_class == 2
    assert _row(status_code=503).status_class == 5


# --------------------------------------------------------------------------
# offer(): the hot path
# --------------------------------------------------------------------------

def test_offer_drops_and_counts_when_the_queue_is_full():
    sink = RequestLogSink(maxsize=3, batch_size=10, flush_ms=10)

    async def run():
        for _ in range(10):
            sink.offer(_row())

    asyncio.run(run())

    assert sink.stats["queued"] == 3
    assert sink.stats["dropped"] == 7, (
        "a full queue must drop and count, never block the request or raise"
    )


def test_offer_never_raises_on_a_broken_row():
    sink = RequestLogSink(maxsize=10, batch_size=10, flush_ms=10)

    async def run():
        sink.offer(None)  # not a RequestLogRow at all

    asyncio.run(run())  # must not raise


def test_offer_respects_the_kill_switch(monkeypatch):
    _set(monkeypatch, enabled=False)
    sink = RequestLogSink(maxsize=10, batch_size=10, flush_ms=10)

    asyncio.run(_offer(sink, _row()))
    assert sink.stats["queued"] == 0


def test_offer_respects_the_per_direction_switches(monkeypatch):
    _set(monkeypatch, capture_outbound=False)
    sink = RequestLogSink(maxsize=10, batch_size=10, flush_ms=10)

    async def run():
        sink.offer(_row(direction="outbound", target="acme"))
        sink.offer(_row(direction="inbound"))

    asyncio.run(run())
    assert sink.stats["queued"] == 1


def test_sampling_never_drops_errors(monkeypatch):
    """A sample rate of zero must still capture every failure — that is the whole
    point of sampling successes only."""
    _set(monkeypatch, sample_rate=0.0)
    sink = RequestLogSink(maxsize=100, batch_size=10, flush_ms=10)

    async def run():
        for _ in range(20):
            sink.offer(_row(status_code=200))
        for _ in range(5):
            sink.offer(_row(status_code=500))
        for _ in range(5):
            sink.offer(_row(status_code=None))

    asyncio.run(run())
    assert sink.stats["queued"] == 10, (
        "sampling removed error rows; only 1xx/2xx/3xx inbound traffic may be sampled out"
    )


def test_sampling_does_not_touch_outbound_rows(monkeypatch):
    _set(monkeypatch, sample_rate=0.0)
    sink = RequestLogSink(maxsize=100, batch_size=10, flush_ms=10)

    async def run():
        for _ in range(5):
            sink.offer(_row(direction="outbound", target="acme", status_code=200))

    asyncio.run(run())
    assert sink.stats["queued"] == 5, (
        "outbound calls are low-volume and high-value; sampling them away hides which CA "
        "or DNS call was made"
    )


def test_capture_bodies_off_strips_the_payload_before_queueing(monkeypatch):
    _set(monkeypatch, capture_bodies=False)
    sink = RequestLogSink(maxsize=10, batch_size=10, flush_ms=10)
    row = _row(request_body_raw=b'{"a":1}', request_body_bytes=7)

    asyncio.run(_offer(sink, row))

    assert row.request_body_raw is None
    assert row.request_body_bytes == 7, "the size must survive so growth is still measurable"


async def _offer(sink, row):
    sink.offer(row)


# --------------------------------------------------------------------------
# The writer
# --------------------------------------------------------------------------

def test_a_batch_is_written_with_one_executemany():
    conn = AsyncMock()
    sink = RequestLogSink(maxsize=100, batch_size=10, flush_ms=10)

    async def run():
        for _ in range(5):
            sink.offer(_row())
        with patch.object(sink_module, "get_database_connection", AsyncMock(return_value=conn)), \
             patch.object(sink_module, "close_database_connection", AsyncMock()):
            return await sink.flush(timeout=1.0)

    written = asyncio.run(run())

    assert written == 5
    assert conn.executemany.await_count == 1, (
        "rows were inserted one at a time; that is one pool acquire per API call and the "
        "pool has 50 connections"
    )
    sql, params = conn.executemany.await_args.args
    assert "INSERT INTO request_logs" in sql
    assert len(params) == 5


def test_a_failed_batch_does_not_kill_the_writer():
    conn = AsyncMock()
    conn.executemany = AsyncMock(side_effect=RuntimeError("relation does not exist"))
    sink = RequestLogSink(maxsize=100, batch_size=10, flush_ms=10)

    async def run():
        sink.offer(_row())
        with patch.object(sink_module, "get_database_connection", AsyncMock(return_value=conn)), \
             patch.object(sink_module, "close_database_connection", AsyncMock()):
            await sink.flush(timeout=1.0)

    asyncio.run(run())  # must not raise
    assert sink.stats["failed_batches"] == 1


def test_the_connection_is_released_even_when_the_write_fails():
    conn = AsyncMock()
    conn.executemany = AsyncMock(side_effect=RuntimeError("boom"))
    release = AsyncMock()
    sink = RequestLogSink(maxsize=100, batch_size=10, flush_ms=10)

    async def run():
        sink.offer(_row())
        with patch.object(sink_module, "get_database_connection", AsyncMock(return_value=conn)), \
             patch.object(sink_module, "close_database_connection", release):
            await sink.flush(timeout=1.0)

    asyncio.run(run())
    assert release.await_count == 1, "a failed batch leaked a pooled connection"


def test_flush_on_an_empty_queue_is_a_noop():
    sink = RequestLogSink(maxsize=10, batch_size=10, flush_ms=10)
    assert asyncio.run(sink.flush(timeout=0.1)) == 0
