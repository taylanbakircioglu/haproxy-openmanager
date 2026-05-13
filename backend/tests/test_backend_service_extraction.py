"""
v1.5.0 service extraction parity — backend_service.

Asserts that create_backend_row + create_server_row pass the SAME column-set
and ordering that POST /api/backends and POST /api/backends/{id}/servers
already use. This protects us from a subtle field-drift regression that
would only surface as silent NULL columns in the wizard's bulk-create.

Notes:
- We don't run the actual SQL, we capture the SQL+args via a mock conn and
  assert on the column names + argument count.
- M13 helper extension: mark_pending=True must follow the INSERT with a
  UPDATE last_config_status='PENDING' (matching the existing endpoint).
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services.backend_service import (
    _filter_httpchk_from_options,
    create_backend_row,
    create_server_row,
)


# ----------------------------------------------------------------------------
# _filter_httpchk_from_options
# ----------------------------------------------------------------------------


def test_filter_httpchk_strips_only_httpchk_lines():
    raw = "option httpchk GET /healthz\noption http-server-close\nbalance roundrobin"
    out = _filter_httpchk_from_options(raw)
    assert "httpchk" not in out
    assert "http-server-close" in out
    assert "balance roundrobin" in out


def test_filter_httpchk_handles_empty_input():
    assert _filter_httpchk_from_options(None) is None
    assert _filter_httpchk_from_options("") == ""


def test_filter_httpchk_handles_only_httpchk_returns_none():
    assert _filter_httpchk_from_options("option httpchk GET /") is None


# ----------------------------------------------------------------------------
# create_backend_row column parity
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_backend_row_inserts_all_expected_columns():
    conn = AsyncMock()
    conn.fetchval.return_value = 7

    payload = SimpleNamespace(
        name="be_test",
        balance_method="leastconn",
        mode="http",
        health_check_uri="/healthz",
        health_check_interval=2000,
        health_check_expected_status=200,
        timeout_connect=10000,
        timeout_server=60000,
        timeout_queue=60000,
        options=None,
    )

    new_id = await create_backend_row(conn, payload, cluster_id=1)
    assert new_id == 7

    # Verify INSERT shape
    sql, *args = conn.fetchval.call_args.args
    assert "INSERT INTO backends" in sql
    # 19 placeholders => 19 args
    assert len(args) == 19
    assert args[0] == "be_test"
    assert args[1] == "leastconn"
    assert args[18] == 1  # cluster_id last positional

    # mark_pending=True default → UPDATE last_config_status='PENDING'
    update_calls = [c for c in conn.execute.call_args_list
                    if c.args and "UPDATE backends" in c.args[0]]
    assert len(update_calls) == 1
    assert "last_config_status='PENDING'" in update_calls[0].args[0]


@pytest.mark.asyncio
async def test_create_backend_row_mark_pending_false_skips_update():
    conn = AsyncMock()
    conn.fetchval.return_value = 5
    payload = SimpleNamespace(
        name="be_x", balance_method="roundrobin", mode="http",
    )
    await create_backend_row(conn, payload, cluster_id=1, mark_pending=False)

    update_calls = [c for c in conn.execute.call_args_list
                    if c.args and "UPDATE backends" in c.args[0]]
    assert update_calls == []


@pytest.mark.asyncio
async def test_create_backend_row_filters_httpchk_from_options():
    conn = AsyncMock()
    conn.fetchval.return_value = 1
    payload = SimpleNamespace(
        name="be_x",
        balance_method="roundrobin",
        mode="http",
        options="option httpchk GET /\nbalance roundrobin",
    )
    await create_backend_row(conn, payload, cluster_id=1)
    sql, *args = conn.fetchval.call_args.args
    options_arg = args[14]  # 15th positional (1-indexed $15)
    assert "httpchk" not in (options_arg or "")
    assert "balance roundrobin" in (options_arg or "")


# ----------------------------------------------------------------------------
# create_server_row column parity
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_server_row_inserts_all_expected_columns():
    conn = AsyncMock()
    conn.fetchval.return_value = 11

    server = SimpleNamespace(
        server_name="srv1",
        server_address="10.0.0.1",
        server_port=8080,
        weight=100,
        check_enabled=True,
        backup_server=False,
        ssl_enabled=False,
    )
    new_id = await create_server_row(
        conn, backend_id=7, backend_name="be_test", cluster_id=1, server=server,
    )
    assert new_id == 11

    sql, *args = conn.fetchval.call_args.args
    assert "INSERT INTO backend_servers" in sql
    assert len(args) == 22
    assert args[0] == 7         # backend_id
    assert args[1] == "be_test" # backend_name
    assert args[2] == "srv1"
    assert args[3] == "10.0.0.1"
    assert args[4] == 8080
    assert args[21] == 1        # cluster_id last positional

    # mark_pending=True default → UPDATE
    update_calls = [c for c in conn.execute.call_args_list
                    if c.args and "UPDATE backend_servers" in c.args[0]]
    assert len(update_calls) == 1


@pytest.mark.asyncio
async def test_create_server_row_uses_server_address_not_host():
    """Schema accuracy R38: column is server_address NOT host or ip."""
    conn = AsyncMock()
    conn.fetchval.return_value = 1
    server = SimpleNamespace(
        server_name="s", server_address="10.1.1.1", server_port=80,
        weight=100, check_enabled=True, backup_server=False, ssl_enabled=False,
    )
    await create_server_row(conn, 1, "be", 1, server)
    sql, *_ = conn.fetchval.call_args.args
    # Verify the column list explicitly mentions server_address, server_port, server_name
    assert "server_address" in sql
    assert "server_port" in sql
    assert "server_name" in sql
