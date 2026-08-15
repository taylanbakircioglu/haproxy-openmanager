"""v1.11.0: retention actually reclaims space, and cannot be turned into an
injection point or a 60-second lock.

`request_logs` is the highest-volume table in the system, so the prune has
three properties that are easy to get wrong and expensive to get wrong:

  * the operator-supplied retention day counts are BIND PARAMETERS, never
    string-interpolated into the SQL;
  * deletes are BATCHED, because the pool's command_timeout is 60s and an
    unbounded DELETE over millions of rows raises and then nothing is ever
    pruned;
  * the watermark is stamped only after a COMPLETE pass, so a pass that dies
    half-way is retried instead of being recorded as done.

The fake connection dispatches on the SQL text rather than on call order — an
ordered side_effect list silently passes tests for the wrong reason as soon as
the number of statements changes.
"""
import asyncio
import json
import os
import sys
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dataclasses import replace  # noqa: E402

from utils import request_log_prune  # noqa: E402
from utils.request_log_prune import (  # noqa: E402
    BATCH_SIZE,
    MAX_BATCHES,
    PRUNE_LOCK_KEY,
    prune_request_logs_if_due,
)
from utils.request_log_settings import DEFAULT_CONFIG  # noqa: E402

_SUCCESS_MARKER = "status_class BETWEEN 1 AND 3"
_ERROR_MARKER = "status_class = 0 OR status_class >= 4"
_CAP_MARKER = "id <= $1"


def _conn(*, lock=True, watermark_age_minutes=None, cutoff_id=None,
          success_batches=None, error_batches=None, cap_batches=None,
          fail_on=None):
    """A fake asyncpg connection that answers by SQL shape."""
    conn = AsyncMock()

    def fetchval(sql, *args):
        text = str(sql)
        if "pg_try_advisory_lock" in text:
            return lock
        if "ORDER BY id DESC OFFSET" in text:
            return cutoff_id
        return None

    conn.fetchval = AsyncMock(side_effect=fetchval)

    if watermark_age_minutes is None:
        conn.fetchrow = AsyncMock(return_value=None)
    else:
        stamp = (datetime.utcnow() - timedelta(minutes=watermark_age_minutes)).isoformat() + "Z"
        conn.fetchrow = AsyncMock(return_value={"value": json.dumps(stamp)})

    queues = {
        _SUCCESS_MARKER: list(success_batches or ["DELETE 0"]),
        _ERROR_MARKER: list(error_batches or ["DELETE 0"]),
        _CAP_MARKER: list(cap_batches or ["DELETE 0"]),
    }

    def execute(sql, *args):
        text = str(sql)
        if fail_on and fail_on in text:
            raise RuntimeError("statement timeout")
        for marker, queue in queues.items():
            if marker in text:
                return queue.pop(0) if queue else "DELETE 0"
        return ""

    conn.execute = AsyncMock(side_effect=execute)
    return conn


def _run(conn, *, force=False, **cfg_overrides):
    cfg = replace(DEFAULT_CONFIG, **cfg_overrides)
    with patch.object(request_log_prune, "get_config", lambda: cfg), \
         patch.object(request_log_prune, "get_database_connection", AsyncMock(return_value=conn)), \
         patch.object(request_log_prune, "close_database_connection", AsyncMock()):
        return asyncio.run(prune_request_logs_if_due(force=force))


def _delete_sql(conn):
    return [str(c.args[0]) for c in conn.execute.call_args_list
            if "DELETE FROM request_logs" in str(c.args[0])]


def test_skips_entirely_when_another_replica_holds_the_lock():
    conn = _conn(lock=False)
    counts = _run(conn)

    assert counts == {"success": 0, "error": 0, "overflow": 0, "ran": 0}
    assert _delete_sql(conn) == [], (
        "a second replica ran the prune concurrently — pg_try_advisory_lock is what keeps "
        "N pods from all scanning the same table at once"
    )


def test_skips_when_the_watermark_is_still_fresh():
    conn = _conn(watermark_age_minutes=10)
    counts = _run(conn, prune_interval_minutes=60)

    assert counts["ran"] == 0
    assert _delete_sql(conn) == []


def test_runs_all_three_limits_when_due():
    conn = _conn(
        watermark_age_minutes=120, cutoff_id=999,
        success_batches=["DELETE 3"], error_batches=["DELETE 4"], cap_batches=["DELETE 5"],
    )
    counts = _run(conn, prune_interval_minutes=60, success_retention_days=7,
                  error_retention_days=30, max_rows=500000)

    sqls = _delete_sql(conn)
    assert len(sqls) == 3, f"expected success TTL + error TTL + row cap, got {len(sqls)}"
    assert _SUCCESS_MARKER in sqls[0]
    assert _ERROR_MARKER in sqls[1]
    assert _CAP_MARKER in sqls[2]

    assert counts["success"] == 3
    assert counts["error"] == 4
    assert counts["overflow"] == 5
    assert counts["ran"] == 1


def test_retention_days_travel_as_bind_parameters():
    """Injection guard: the day counts come straight from an operator-editable
    setting, so they must never be formatted into the SQL text."""
    conn = _conn(watermark_age_minutes=120)
    _run(conn, prune_interval_minutes=60, success_retention_days=7, error_retention_days=30)

    ttl_calls = [c for c in conn.execute.call_args_list
                 if "created_at < NOW()" in str(c.args[0])]
    assert len(ttl_calls) == 2

    for call in ttl_calls:
        assert "($1 || ' days')::INTERVAL" in str(call.args[0]), (
            "the retention window is interpolated into the SQL string instead of bound — "
            "an operator-supplied value reaching the parser is an injection point"
        )

    assert ttl_calls[0].args[1] == "7"
    assert ttl_calls[1].args[1] == "30"
    assert ttl_calls[0].args[2] == BATCH_SIZE


def test_deletes_are_batched_until_a_short_batch():
    conn = _conn(
        watermark_age_minutes=120,
        success_batches=[f"DELETE {BATCH_SIZE}", f"DELETE {BATCH_SIZE}", "DELETE 12"],
    )
    counts = _run(conn, prune_interval_minutes=60)

    assert counts["success"] == BATCH_SIZE * 2 + 12, (
        "the batch loop stopped early or double-counted"
    )
    success_calls = [s for s in _delete_sql(conn) if _SUCCESS_MARKER in s]
    assert len(success_calls) == 3, "the loop must stop on the first short batch"


def test_batch_loop_respects_the_ceiling():
    """A table so far behind that every batch comes back full must still hand the
    connection back rather than looping forever."""
    conn = _conn(
        watermark_age_minutes=120,
        success_batches=[f"DELETE {BATCH_SIZE}"] * (MAX_BATCHES * 3),
    )
    counts = _run(conn, prune_interval_minutes=60)

    assert counts["success"] == BATCH_SIZE * MAX_BATCHES
    success_calls = [s for s in _delete_sql(conn) if _SUCCESS_MARKER in s]
    assert len(success_calls) == MAX_BATCHES


def test_watermark_is_not_stamped_when_a_step_fails():
    conn = _conn(watermark_age_minutes=120, cutoff_id=42, fail_on=_CAP_MARKER)
    counts = _run(conn, prune_interval_minutes=60)

    stamps = [c for c in conn.execute.call_args_list
              if "INSERT INTO system_settings" in str(c.args[0])]
    assert stamps == [], (
        "a partially-completed pass stamped the watermark, so the remainder would not be "
        "retried until the next interval"
    )
    assert counts["ran"] == 0


def test_watermark_is_stamped_after_a_complete_pass():
    conn = _conn(watermark_age_minutes=120, cutoff_id=None)
    counts = _run(conn, prune_interval_minutes=60)

    stamps = [c for c in conn.execute.call_args_list
              if "INSERT INTO system_settings" in str(c.args[0])]
    assert len(stamps) == 1
    # args = (sql, key, json_value)
    assert stamps[0].args[1] == "requestlog.last_pruned_at"
    assert stamps[0].args[2].startswith('"'), (
        "the watermark must be stored as a JSON string — the ::jsonb cast rejects a bare "
        "timestamp, and the reader json.loads() it back"
    )
    assert counts["ran"] == 1


def test_advisory_lock_is_released_even_on_failure():
    conn = _conn(watermark_age_minutes=120, fail_on=_SUCCESS_MARKER)
    _run(conn, prune_interval_minutes=60)

    unlocks = [c for c in conn.execute.call_args_list if "pg_advisory_unlock" in str(c.args[0])]
    assert unlocks, "the advisory lock was leaked — every later pass on any replica would skip"
    assert unlocks[0].args[1] == PRUNE_LOCK_KEY


def test_never_raises_when_the_pool_is_exhausted():
    with patch.object(request_log_prune, "get_database_connection",
                      AsyncMock(side_effect=RuntimeError("pool exhausted"))), \
         patch.object(request_log_prune, "close_database_connection", AsyncMock()):
        counts = asyncio.run(prune_request_logs_if_due())

    assert counts == {"success": 0, "error": 0, "overflow": 0, "ran": 0}


def test_row_cap_is_a_noop_when_the_table_is_smaller_than_the_cap():
    conn = _conn(watermark_age_minutes=120, cutoff_id=None, cap_batches=["DELETE 77"])
    counts = _run(conn, prune_interval_minutes=60)

    assert counts["overflow"] == 0, (
        "the cap deleted rows even though OFFSET max_rows found no cutoff — that would "
        "truncate a table that is under the limit"
    )
    assert not any(_CAP_MARKER in s for s in _delete_sql(conn))


def test_force_bypasses_the_watermark():
    """The manual purge button must not be a no-op just because the scheduled
    pass ran a minute ago."""
    conn = _conn(watermark_age_minutes=1, cutoff_id=None,
                 success_batches=["DELETE 1"], error_batches=["DELETE 2"])
    counts = _run(conn, force=True, prune_interval_minutes=1440)

    assert counts["ran"] == 1
    assert counts["success"] == 1
    assert counts["error"] == 2


def test_lock_key_does_not_collide_with_the_existing_ones():
    # 18181818 drafts cap, 18181819 wizard create, 18181820 apply,
    # 0x41434D45 per-ACME-order, 1836016242 migration.
    assert PRUNE_LOCK_KEY not in (18181818, 18181819, 18181820, 0x41434D45, 1836016242)
