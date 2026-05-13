"""
v1.5.0 service extraction parity — frontend_service.

Asserts:
- create_frontend_row writes BOTH ssl_certificate_id (INT col) AND
  ssl_certificate_ids (JSONB col) consistently (M13).
- check_bind_port_collision honours exclude_frontend_id (M21/R35).
- mark_pending toggles the follow-up UPDATE.
"""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services.frontend_service import (
    check_bind_port_collision,
    create_frontend_row,
)


# ----------------------------------------------------------------------------
# create_frontend_row
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_frontend_row_writes_both_ssl_columns_when_cert_present():
    """M13: ssl_certificate_id (INT) and ssl_certificate_ids (JSONB) both set."""
    conn = AsyncMock()
    conn.fetchval.return_value = 99

    payload = SimpleNamespace(
        name="fe_https",
        bind_address="0.0.0.0",
        bind_port=443,
        default_backend="be",
        mode="http",
        ssl_enabled=True,
    )
    new_id = await create_frontend_row(
        conn, payload, cluster_id=1,
        ssl_certificate_id=42, ssl_enabled=True,
    )
    assert new_id == 99

    sql, *args = conn.fetchval.call_args.args
    assert "INSERT INTO frontends" in sql
    # ssl_certificate_id position $7 → index 6
    assert args[6] == 42
    # ssl_certificate_ids position $8 → index 7 (JSONB-encoded)
    assert json.loads(args[7]) == [42]


@pytest.mark.asyncio
async def test_create_frontend_row_emits_empty_ssl_cert_ids_when_no_cert():
    conn = AsyncMock()
    conn.fetchval.return_value = 1
    payload = SimpleNamespace(name="fe", bind_address="*", bind_port=80, mode="http")
    await create_frontend_row(conn, payload, cluster_id=1)
    sql, *args = conn.fetchval.call_args.args
    assert args[6] is None        # ssl_certificate_id NULL
    assert json.loads(args[7]) == []  # ssl_certificate_ids JSONB empty list


@pytest.mark.asyncio
async def test_create_frontend_row_uses_name_override():
    conn = AsyncMock()
    conn.fetchval.return_value = 1
    payload = SimpleNamespace(name="fe_http", bind_address="*", bind_port=80, mode="http")
    await create_frontend_row(conn, payload, cluster_id=1, name_override="fe_http-https")
    sql, *args = conn.fetchval.call_args.args
    assert args[0] == "fe_http-https"


@pytest.mark.asyncio
async def test_create_frontend_row_uses_bind_port_override():
    conn = AsyncMock()
    conn.fetchval.return_value = 1
    payload = SimpleNamespace(name="fe", bind_address="*", bind_port=80, mode="http")
    await create_frontend_row(conn, payload, cluster_id=1, bind_port_override=443)
    sql, *args = conn.fetchval.call_args.args
    assert args[2] == 443  # bind_port position $3


@pytest.mark.asyncio
async def test_create_frontend_row_jsonb_rules_serialized():
    conn = AsyncMock()
    conn.fetchval.return_value = 1
    payload = SimpleNamespace(
        name="fe", bind_address="*", bind_port=80, mode="http",
        acl_rules=[{"name": "a"}],
        redirect_rules=[{"type": "redirect"}],
        use_backend_rules=[{"backend": "be"}],
    )
    await create_frontend_row(conn, payload, cluster_id=1)
    sql, *args = conn.fetchval.call_args.args
    # acl_rules ($20 idx 19), redirect_rules ($21 idx 20), use_backend_rules ($22 idx 21)
    assert json.loads(args[19]) == [{"name": "a"}]
    assert json.loads(args[20]) == [{"type": "redirect"}]
    assert json.loads(args[21]) == [{"backend": "be"}]


@pytest.mark.asyncio
async def test_create_frontend_row_mark_pending_default_true():
    conn = AsyncMock()
    conn.fetchval.return_value = 1
    payload = SimpleNamespace(name="fe", bind_address="*", bind_port=80, mode="http")
    await create_frontend_row(conn, payload, cluster_id=1)
    update_calls = [c for c in conn.execute.call_args_list
                    if c.args and "UPDATE frontends" in c.args[0]]
    assert len(update_calls) == 1


@pytest.mark.asyncio
async def test_create_frontend_row_mark_pending_false_skips_update():
    conn = AsyncMock()
    conn.fetchval.return_value = 1
    payload = SimpleNamespace(name="fe", bind_address="*", bind_port=80, mode="http")
    await create_frontend_row(conn, payload, cluster_id=1, mark_pending=False)
    update_calls = [c for c in conn.execute.call_args_list
                    if c.args and "UPDATE frontends" in c.args[0]]
    assert update_calls == []


# ----------------------------------------------------------------------------
# check_bind_port_collision
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_bind_port_collision_returns_id_when_conflict():
    conn = AsyncMock()
    conn.fetchval.return_value = 17
    out = await check_bind_port_collision(conn, 1, "0.0.0.0", 80)
    assert out == 17


@pytest.mark.asyncio
async def test_check_bind_port_collision_no_conflict_returns_none():
    conn = AsyncMock()
    conn.fetchval.return_value = None
    out = await check_bind_port_collision(conn, 1, "0.0.0.0", 80)
    assert out is None


@pytest.mark.asyncio
async def test_check_bind_port_collision_excludes_frontend_id():
    conn = AsyncMock()
    conn.fetchval.return_value = None
    await check_bind_port_collision(conn, 1, "0.0.0.0", 443, exclude_frontend_id=99)
    sql, *args = conn.fetchval.call_args.args
    assert "id <> $4" in sql
    assert args[3] == 99
