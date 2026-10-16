"""Read-only role access: read endpoints work without pool access, private keys stay hidden.

A user on the built-in ``viewer`` role (``ssl.read``, ``waf.read``, no
``ssl.download``) and no ``user_pool_access`` rows used to get 403 on the
cluster-scoped SSL list and SSL detail, while clusters, frontends, backends and
WAF rules were readable. These tests pin the fix:

* ``<resource>.read`` lets the caller read that resource on every cluster;
  without it the pool check still applies.
* the SSL private key is returned only with ``ssl.download`` plus pool access,
  both in the certificate detail and in the Apply Management SSL diff.
"""
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

import auth_middleware
from routers import cluster as cluster_mod
from routers import ssl as ssl_mod
from routers import waf as waf_mod

KEY_PEM = "-----BEGIN PRIVATE KEY-----\nSECRETKEYMATERIAL\n-----END PRIVATE KEY-----"
CERT_PEM = "-----BEGIN CERTIFICATE-----\nPUBLICCERT\n-----END CERTIFICATE-----"
USER = {"id": 7, "username": "readonly", "is_admin": False}


def _no_pool_access():
    async def _validate(_uid, _cid, _conn):
        raise HTTPException(status_code=403, detail="You don't have access to this cluster.")
    return _validate


def _pool_access_ok():
    async def _validate(_uid, _cid, _conn):
        return True
    return _validate


def _patch_common(monkeypatch, module, conn, permissions, pool_validator):
    async def _user(_auth):
        return dict(USER)

    async def _perm(_uid, resource, action, **_kw):
        return f"{resource}.{action}" in permissions

    async def _get_conn():
        return conn

    async def _close(_c):
        return None

    monkeypatch.setattr(auth_middleware, "check_user_permission", _perm)
    monkeypatch.setattr(auth_middleware, "get_current_user_from_token", _user)
    monkeypatch.setattr(module, "get_database_connection", _get_conn)
    monkeypatch.setattr(module, "close_database_connection", _close)
    monkeypatch.setattr(module, "validate_user_cluster_access", pool_validator)
    if hasattr(module, "get_current_user_from_token"):
        monkeypatch.setattr(module, "get_current_user_from_token", _user)


def _cert_row(cluster_id=1):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return {
        "id": 5, "name": "example", "domain": "example.com", "all_domains": '["example.com"]',
        "certificate_content": CERT_PEM, "private_key_content": KEY_PEM, "chain_content": None,
        "expiry_date": now, "issuer": "CA", "status": "valid", "days_until_expiry": 90,
        "fingerprint": "ab", "cluster_id": cluster_id, "usage_type": "frontend", "source": "manual",
        "is_active": True, "created_at": now, "updated_at": now, "is_global": False, "cluster_ids": [1],
    }


def _detail_conn(cluster_id=1):
    conn = AsyncMock()
    conn.fetchrow.return_value = _cert_row(cluster_id)
    conn.fetchval.return_value = cluster_id  # cluster exists
    conn.fetch.return_value = []
    return conn


# ---------------------------------------------------------------- SSL detail


@pytest.mark.asyncio
async def test_viewer_reads_ssl_detail_without_pool_access_but_key_is_hidden(monkeypatch):
    _patch_common(monkeypatch, ssl_mod, _detail_conn(), {"ssl.read"}, _no_pool_access())

    out = await ssl_mod.get_ssl_certificate(5, authorization="Bearer x")

    assert out["certificate_content"] == CERT_PEM
    assert out["private_key_content"] is None
    assert out["private_key_redacted"] is True
    assert "SECRETKEYMATERIAL" not in repr(out)


@pytest.mark.asyncio
async def test_ssl_download_with_pool_access_returns_key(monkeypatch):
    _patch_common(monkeypatch, ssl_mod, _detail_conn(), {"ssl.read", "ssl.download"}, _pool_access_ok())

    out = await ssl_mod.get_ssl_certificate(5, authorization="Bearer x")

    assert out["private_key_content"] == KEY_PEM
    assert out["private_key_redacted"] is False


@pytest.mark.asyncio
async def test_ssl_download_without_pool_access_keeps_key_hidden(monkeypatch):
    _patch_common(monkeypatch, ssl_mod, _detail_conn(), {"ssl.read", "ssl.download"}, _no_pool_access())

    out = await ssl_mod.get_ssl_certificate(5, authorization="Bearer x")

    assert out["private_key_content"] is None
    assert out["private_key_redacted"] is True


@pytest.mark.asyncio
async def test_ssl_detail_without_ssl_read_still_needs_pool_access(monkeypatch):
    _patch_common(monkeypatch, ssl_mod, _detail_conn(), set(), _no_pool_access())

    with pytest.raises(HTTPException) as exc:
        await ssl_mod.get_ssl_certificate(5, authorization="Bearer x")
    assert exc.value.status_code == 403


# ------------------------------------------------------------------ SSL list


@pytest.mark.asyncio
async def test_viewer_lists_cluster_ssl_without_pool_access(monkeypatch):
    conn = AsyncMock()
    conn.fetchval.return_value = 1  # cluster exists / table exists
    conn.fetch.return_value = []
    _patch_common(monkeypatch, ssl_mod, conn, {"ssl.read"}, _no_pool_access())

    out = await ssl_mod.get_ssl_certificates(cluster_id=1, usage_type=None, authorization="Bearer x")

    assert out == []


@pytest.mark.asyncio
async def test_ssl_list_unknown_cluster_is_404_for_read_role(monkeypatch):
    conn = AsyncMock()
    conn.fetchval.return_value = None
    _patch_common(monkeypatch, ssl_mod, conn, {"ssl.read"}, _no_pool_access())

    with pytest.raises(HTTPException) as exc:
        await ssl_mod.get_ssl_certificates(cluster_id=99, usage_type=None, authorization="Bearer x")
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_ssl_list_without_ssl_read_still_needs_pool_access(monkeypatch):
    conn = AsyncMock()
    _patch_common(monkeypatch, ssl_mod, conn, set(), _no_pool_access())

    with pytest.raises(HTTPException) as exc:
        await ssl_mod.get_ssl_certificates(cluster_id=1, usage_type=None, authorization="Bearer x")
    assert exc.value.status_code == 403


# ----------------------------------------------------------------- WAF stats


def _waf_conn():
    conn = AsyncMock()
    conn.fetchval.return_value = 1
    conn.fetch.return_value = []
    return conn


@pytest.mark.asyncio
async def test_viewer_reads_cluster_waf_stats_without_pool_access(monkeypatch):
    _patch_common(monkeypatch, waf_mod, _waf_conn(), {"waf.read"}, _no_pool_access())

    out = await waf_mod.get_waf_stats(cluster_id=1, authorization="Bearer x")

    assert "overview" in out


@pytest.mark.asyncio
async def test_waf_stats_denial_is_403_not_500(monkeypatch):
    _patch_common(monkeypatch, waf_mod, _waf_conn(), set(), _no_pool_access())

    with pytest.raises(HTTPException) as exc:
        await waf_mod.get_waf_stats(cluster_id=1, authorization="Bearer x")
    assert exc.value.status_code == 403


# --------------------------------------------------- Apply Management SSL diff


def _diff_conn():
    conn = AsyncMock()
    version = {
        "id": 11, "version_name": "ssl-5-update-1700000000", "config_content": "",
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc), "metadata": None,
    }
    ssl_cert = {
        "id": 5, "name": "example", "primary_domain": "example.com",
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "certificate_content": CERT_PEM, "private_key_content": KEY_PEM, "chain_content": None,
        "usage_type": "frontend", "ssl_type": "Cluster-specific",
    }
    conn.fetchrow.side_effect = [version, ssl_cert]
    return conn


@pytest.mark.asyncio
async def test_ssl_diff_redacts_private_key_without_ssl_download(monkeypatch):
    _patch_common(monkeypatch, cluster_mod, _diff_conn(), {"apply.read"}, _pool_access_ok())

    out = await cluster_mod.get_config_version_diff(1, 11, authorization="Bearer x")

    lines = [c["line"] for c in out["changes"]]
    assert not any("SECRETKEYMATERIAL" in line for line in lines)
    assert any("redacted" in line for line in lines)
    assert any("PUBLICCERT" in line for line in lines)


@pytest.mark.asyncio
async def test_ssl_diff_shows_private_key_with_ssl_download(monkeypatch):
    _patch_common(monkeypatch, cluster_mod, _diff_conn(), {"ssl.download"}, _pool_access_ok())

    out = await cluster_mod.get_config_version_diff(1, 11, authorization="Bearer x")

    assert any("SECRETKEYMATERIAL" in c["line"] for c in out["changes"])
