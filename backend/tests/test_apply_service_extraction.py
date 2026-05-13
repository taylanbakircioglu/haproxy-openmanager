"""
v1.5.0 service extraction parity — apply_service.

Asserts:
- _resolve_user_id falls back to the first active admin user using the
  CORRECT schema columns (is_admin, is_active) — NOT the non-existent
  is_super_admin (M46/R65).
- _mint_internal_jwt passes user_id under both `sub` and `user_id` claims so
  it round-trips through get_current_user_from_token.
- apply_cluster_pending delegates to routers.cluster.apply_pending_changes
  with a Bearer header (i.e. NEVER duplicates the ~800-line apply pipeline).
"""
from unittest.mock import AsyncMock, patch

import pytest

from services.apply_service import (
    _mint_internal_jwt,
    _resolve_user_id,
    apply_cluster_pending,
)


# ----------------------------------------------------------------------------
# _resolve_user_id
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_user_id_passthrough_when_user_still_valid():
    """Bulgu #27: a still-active user_id is returned as-is after re-validation."""
    fake_conn = AsyncMock()
    # First fetchval validates the requested user, returns its id.
    fake_conn.fetchval.return_value = 42

    with patch(
        "services.apply_service.get_database_connection",
        AsyncMock(return_value=fake_conn),
    ), patch(
        "services.apply_service.close_database_connection",
        AsyncMock(),
    ):
        out = await _resolve_user_id(42)
    assert out == 42


@pytest.mark.asyncio
async def test_resolve_user_id_falls_back_when_requested_user_inactive():
    """Bulgu #27: deleted/deactivated created_by must NOT mint a ghost JWT —
    fall back to the admin user instead."""
    fake_conn = AsyncMock()
    # Validation lookup returns None (user gone/inactive); admin fallback returns 1.
    fake_conn.fetchval.side_effect = [None, 1]

    with patch(
        "services.apply_service.get_database_connection",
        AsyncMock(return_value=fake_conn),
    ), patch(
        "services.apply_service.close_database_connection",
        AsyncMock(),
    ):
        out = await _resolve_user_id(99)

    assert out == 1
    assert fake_conn.fetchval.await_count == 2


@pytest.mark.asyncio
async def test_resolve_user_id_falls_back_to_active_admin():
    fake_conn = AsyncMock()
    fake_conn.fetchval.return_value = 1  # admin id

    with patch(
        "services.apply_service.get_database_connection",
        AsyncMock(return_value=fake_conn),
    ), patch(
        "services.apply_service.close_database_connection",
        AsyncMock(),
    ):
        out = await _resolve_user_id(None)

    assert out == 1
    sql, *_ = fake_conn.fetchval.call_args.args
    # Schema accuracy: is_admin AND is_active (NOT is_super_admin)
    assert "is_admin" in sql
    assert "is_active" in sql
    assert "is_super_admin" not in sql


@pytest.mark.asyncio
async def test_resolve_user_id_returns_none_when_no_admin():
    fake_conn = AsyncMock()
    fake_conn.fetchval.return_value = None
    with patch(
        "services.apply_service.get_database_connection",
        AsyncMock(return_value=fake_conn),
    ), patch(
        "services.apply_service.close_database_connection",
        AsyncMock(),
    ):
        out = await _resolve_user_id(None)
    assert out is None


# ----------------------------------------------------------------------------
# _mint_internal_jwt
# ----------------------------------------------------------------------------


def test_mint_internal_jwt_includes_both_claim_shapes():
    """sub + user_id ensures compat with get_current_user_from_token."""
    captured = {}

    def fake_create(payload, expires_delta=None):
        captured.update(payload)
        captured["__expires"] = expires_delta
        return "fake-jwt-token"

    with patch("services.apply_service.create_access_token", side_effect=fake_create):
        token = _mint_internal_jwt(99)

    assert token == "fake-jwt-token"
    assert captured["sub"] == "99"
    assert captured["user_id"] == 99
    assert captured["__expires"] is not None


# ----------------------------------------------------------------------------
# apply_cluster_pending
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_cluster_pending_raises_when_no_admin_available():
    with patch(
        "services.apply_service._resolve_user_id",
        AsyncMock(return_value=None),
    ):
        with pytest.raises(RuntimeError, match="no admin user available"):
            await apply_cluster_pending(cluster_id=1)


@pytest.mark.asyncio
async def test_apply_cluster_pending_delegates_to_router_with_bearer():
    """Delegate, don't duplicate. We pass through cluster_id, apply_request,
    and a Bearer auth header.
    """
    apply_mock = AsyncMock(return_value={"applied_count": 3})

    # Patch the local-imported symbol via routers.cluster
    with patch(
        "services.apply_service._resolve_user_id",
        AsyncMock(return_value=42),
    ), patch(
        "services.apply_service._mint_internal_jwt",
        return_value="fake.jwt.token",
    ), patch("routers.cluster.apply_pending_changes", apply_mock):
        out = await apply_cluster_pending(
            cluster_id=7,
            apply_request={"force": True},
        )

    assert out == {"applied_count": 3}
    kwargs = apply_mock.call_args.kwargs
    assert kwargs["cluster_id"] == 7
    assert kwargs["apply_request"] == {"force": True}
    assert kwargs["authorization"].startswith("Bearer ")
    assert "fake.jwt.token" in kwargs["authorization"]


@pytest.mark.asyncio
async def test_apply_cluster_pending_default_empty_apply_request():
    apply_mock = AsyncMock(return_value={})
    with patch(
        "services.apply_service._resolve_user_id",
        AsyncMock(return_value=1),
    ), patch(
        "services.apply_service._mint_internal_jwt",
        return_value="t",
    ), patch("routers.cluster.apply_pending_changes", apply_mock):
        await apply_cluster_pending(cluster_id=1)
    kwargs = apply_mock.call_args.kwargs
    assert kwargs["apply_request"] == {}
