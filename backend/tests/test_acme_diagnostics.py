"""
v1.5.0 Feature A — services/acme_diagnostics.py per-check unit tests.

Each check is exercised with a mocked asyncpg connection (or no conn at all
for stdlib-only checks). DNS / port-80 are exercised through monkeypatched
asyncio primitives so the tests run hermetically — no real network.
"""
import asyncio
import json
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.acme_diagnostics import (
    CHECK_IDS,
    _check_result,
    check_account,
    check_agents,
    check_dns,
    check_port80,
    check_routing,
    run_checks,
)


# ----------------------------------------------------------------------------
# _check_result schema invariants
# ----------------------------------------------------------------------------


def test_check_result_default_shape():
    r = _check_result("dns", "DNS resolution", "ok", "all good")
    assert set(r.keys()) >= {"id", "label", "status", "severity", "message", "details", "duration_ms"}
    assert r["id"] == "dns"
    assert r["status"] == "ok"
    assert r["severity"] == "info"
    assert r["details"] == {}
    assert r["duration_ms"] is None


def test_check_ids_constant_order():
    assert CHECK_IDS == ("dns", "port80", "routing", "account", "agents")


# ----------------------------------------------------------------------------
# DNS check
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_dns_all_resolve(monkeypatch):
    def fake_gethostbyname_ex(domain):
        return (domain, [], ["10.0.0.1"])

    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)

    out = await check_dns(["a.example.com", "b.example.com"])
    assert out["status"] == "ok"
    assert out["details"]["resolved"]["a.example.com"] == ["10.0.0.1"]
    assert out["duration_ms"] is not None and out["duration_ms"] >= 0


@pytest.mark.asyncio
async def test_check_dns_failure_marks_fail(monkeypatch):
    def fake_gethostbyname_ex(domain):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)

    out = await check_dns(["nope.example.com"])
    assert out["status"] == "fail"
    assert out["severity"] == "error"
    assert len(out["details"]["failed"]) == 1
    assert out["details"]["failed"][0]["domain"] == "nope.example.com"


@pytest.mark.asyncio
async def test_check_dns_wildcard_skipped(monkeypatch):
    """*.example.com cannot be HTTP-01 validated — must NOT be resolved."""
    called = []

    def fake_gethostbyname_ex(domain):
        called.append(domain)
        return (domain, [], ["10.0.0.1"])

    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)

    out = await check_dns(["*.example.com"])
    assert out["status"] == "ok"
    assert called == []  # wildcard never reached the resolver
    assert out["details"]["resolved"]["*.example.com"] == []


@pytest.mark.asyncio
async def test_check_dns_empty_ips_marks_failure(monkeypatch):
    def fake_gethostbyname_ex(domain):
        return (domain, [], [])

    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)
    out = await check_dns(["a.example.com"])
    assert out["status"] == "fail"
    assert "no A records" in out["details"]["failed"][0]["reason"]


# ----------------------------------------------------------------------------
# Port-80 check (HEAD probe)
# ----------------------------------------------------------------------------


class _FakeHEADResp:
    def __init__(self, status):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    def __init__(self, *, statuses=None, raise_timeout=False, raise_client_error=False):
        self._statuses = list(statuses or [])
        self._raise_timeout = raise_timeout
        self._raise_client_error = raise_client_error

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def head(self, url, allow_redirects=False):
        if self._raise_timeout:
            raise asyncio.TimeoutError()
        if self._raise_client_error:
            import aiohttp
            raise aiohttp.ClientError("connection refused")
        status = self._statuses.pop(0) if self._statuses else 200
        return _FakeHEADResp(status)


def _mock_public_dns(monkeypatch, ip="93.184.216.34"):
    """R18b round 4 #B: check_port80 now refuses to probe domains
    whose A records point at private/loopback/metadata IP space
    (SSRF guard). Tests that exercise the success path must
    monkeypatch DNS to a public-looking IP so the guard allows the
    probe through."""
    def fake_gethostbyname_ex(domain):
        return (domain, [], [ip])
    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)


@pytest.mark.asyncio
async def test_check_port80_ok_on_200(monkeypatch):
    _mock_public_dns(monkeypatch)
    def _ctor(*args, **kwargs):
        return _FakeSession(statuses=[200, 200])

    monkeypatch.setattr("aiohttp.ClientSession", _ctor)

    out = await check_port80(["a.example.com", "b.example.com"])
    assert out["status"] == "ok"
    assert all(t["ok"] for t in out["details"]["targets"])


@pytest.mark.asyncio
async def test_check_port80_ok_on_404(monkeypatch):
    """404 on /.well-known/acme-challenge/* is a valid 'served' signal."""
    _mock_public_dns(monkeypatch)
    def _ctor(*args, **kwargs):
        return _FakeSession(statuses=[404])

    monkeypatch.setattr("aiohttp.ClientSession", _ctor)

    out = await check_port80(["a.example.com"])
    assert out["status"] == "ok"


@pytest.mark.asyncio
async def test_check_port80_warn_on_egress_timeout(monkeypatch):
    """Corporate egress blocks port 80 outbound — warn, don't fail."""
    _mock_public_dns(monkeypatch)
    def _ctor(*args, **kwargs):
        return _FakeSession(raise_timeout=True)

    monkeypatch.setattr("aiohttp.ClientSession", _ctor)

    out = await check_port80(["a.example.com"])
    assert out["status"] == "warn"
    assert out["severity"] == "warn"


@pytest.mark.asyncio
async def test_check_port80_skips_private_ip_for_ssrf_guard(monkeypatch):
    """R18b round 4 #B: SSRF guard. A domain that resolves to a
    private/loopback/metadata IP must NOT trigger an outbound HTTP
    request — the diagnostic must skip it with a warn-level row.
    Pre-fix this was a usable SSRF primitive for any authenticated
    operator."""
    def fake_gethostbyname_ex(domain):
        # AWS / GCP metadata IP — most dangerous SSRF target
        return (domain, [], ["169.254.169.254"])
    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)

    # Track whether ClientSession.head was called — it must not be.
    head_called = []
    class _SpyClientSession:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a, **k):
            return None
        def head(self, url, **kwargs):
            head_called.append(url)
            class _Resp:
                async def __aenter__(self_inner):
                    self_inner.status = 200
                    return self_inner
                async def __aexit__(self_inner, *a, **k):
                    return None
            return _Resp()
    monkeypatch.setattr("aiohttp.ClientSession", _SpyClientSession)

    out = await check_port80(["evil.example.com"])
    assert head_called == [], (
        "SSRF guard regression: check_port80 issued an outbound HEAD "
        "to a private-IP domain"
    )
    targets = out["details"]["targets"]
    assert any("non-public" in (t.get("skip") or "") for t in targets), (
        "SSRF guard regression: skip row missing for non-public IP"
    )


@pytest.mark.asyncio
async def test_check_port80_skips_loopback_ip_for_ssrf_guard(monkeypatch):
    """SSRF guard must also block loopback (127.0.0.1)."""
    def fake_gethostbyname_ex(domain):
        return (domain, [], ["127.0.0.1"])
    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)

    head_called = []
    class _SpyClientSession:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a, **k):
            return None
        def head(self, url, **kwargs):
            head_called.append(url)
            raise RuntimeError("should never be called")
    monkeypatch.setattr("aiohttp.ClientSession", _SpyClientSession)

    out = await check_port80(["loopback.example.com"])
    assert head_called == []
    assert any("non-public" in (t.get("skip") or "") for t in out["details"]["targets"])


@pytest.mark.asyncio
async def test_check_port80_skips_rfc1918_for_ssrf_guard(monkeypatch):
    """SSRF guard must also block RFC1918 (10.0.0.0/8)."""
    def fake_gethostbyname_ex(domain):
        return (domain, [], ["10.0.0.42"])
    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)

    head_called = []
    class _SpyClientSession:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a, **k):
            return None
        def head(self, url, **kwargs):
            head_called.append(url)
            raise RuntimeError("should never be called")
    monkeypatch.setattr("aiohttp.ClientSession", _SpyClientSession)

    out = await check_port80(["internal.example.com"])
    assert head_called == []


@pytest.mark.asyncio
async def test_check_port80_fail_on_client_error(monkeypatch):
    _mock_public_dns(monkeypatch)
    def _ctor(*args, **kwargs):
        return _FakeSession(raise_client_error=True)

    monkeypatch.setattr("aiohttp.ClientSession", _ctor)

    out = await check_port80(["a.example.com"])
    assert out["status"] == "fail"
    assert out["severity"] == "error"


@pytest.mark.asyncio
async def test_check_port80_skipped_when_only_wildcards(monkeypatch):
    """We never probe wildcards (HTTP-01 is not applicable)."""
    out = await check_port80(["*.example.com"])
    assert out["status"] == "skipped"


@pytest.mark.asyncio
async def test_check_port80_fail_on_500(monkeypatch):
    _mock_public_dns(monkeypatch)
    def _ctor(*args, **kwargs):
        return _FakeSession(statuses=[500])

    monkeypatch.setattr("aiohttp.ClientSession", _ctor)
    out = await check_port80(["a.example.com"])
    assert out["status"] == "fail"


# ----------------------------------------------------------------------------
# Routing check
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_routing_warn_when_no_clusters():
    conn = AsyncMock()
    out = await check_routing(conn, ["a.example.com"], [])
    assert out["status"] == "warn"
    conn.fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_check_routing_fail_when_no_port80_frontend():
    conn = AsyncMock()
    conn.fetch.return_value = []
    out = await check_routing(conn, ["a.example.com"], [1])
    assert out["status"] == "fail"
    assert "No HTTP frontend" in out["message"]


@pytest.mark.asyncio
async def test_check_routing_ok_when_port80_frontend_present():
    conn = AsyncMock()
    conn.fetch.return_value = [
        {"id": 1, "name": "fe-http", "bind_address": "0.0.0.0", "bind_port": 80,
         "mode": "http", "default_backend": "be"},
    ]
    out = await check_routing(conn, ["a.example.com"], [1])
    assert out["status"] == "ok"
    assert len(out["details"]["frontends"]) == 1


# ----------------------------------------------------------------------------
# Account check
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_account_fail_when_no_account_id():
    conn = AsyncMock()
    out = await check_account(conn, None)
    assert out["status"] == "fail"
    assert "no ACME account id" in out["message"]


@pytest.mark.asyncio
async def test_check_account_fail_when_not_found():
    conn = AsyncMock()
    conn.fetchrow.return_value = None
    out = await check_account(conn, 99)
    assert out["status"] == "fail"
    assert "Account 99 not found" in out["message"]


@pytest.mark.asyncio
async def test_check_account_fail_when_status_invalid():
    conn = AsyncMock()
    conn.fetchrow.return_value = {
        "id": 1,
        "email": "ops@example.com",
        "status": "deactivated",
        "account_url": "https://acme/acct/1",
    }
    out = await check_account(conn, 1)
    assert out["status"] == "fail"
    assert "deactivated" in out["message"]


@pytest.mark.asyncio
async def test_check_account_warn_when_url_missing():
    conn = AsyncMock()
    conn.fetchrow.return_value = {
        "id": 1, "email": "ops@example.com",
        "status": "valid", "account_url": None,
    }
    out = await check_account(conn, 1)
    assert out["status"] == "warn"


@pytest.mark.asyncio
async def test_check_account_ok():
    conn = AsyncMock()
    conn.fetchrow.return_value = {
        "id": 1, "email": "ops@example.com",
        "status": "valid", "account_url": "https://acme/acct/1",
    }
    out = await check_account(conn, 1)
    assert out["status"] == "ok"
    assert out["severity"] == "info"


# ----------------------------------------------------------------------------
# Agents check
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_agents_warn_when_no_clusters():
    conn = AsyncMock()
    out = await check_agents(conn, [])
    assert out["status"] == "warn"
    conn.fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_check_agents_fail_when_none_registered():
    conn = AsyncMock()
    conn.fetch.return_value = []
    out = await check_agents(conn, [1])
    assert out["status"] == "fail"


@pytest.mark.asyncio
async def test_check_agents_warn_when_none_active():
    conn = AsyncMock()
    conn.fetch.return_value = [
        {"id": 1, "hostname": "h1", "status": "offline", "last_heartbeat": None,
         "cluster_id": 1, "cluster_name": "c1"},
    ]
    out = await check_agents(conn, [1])
    assert out["status"] == "warn"


@pytest.mark.asyncio
async def test_check_agents_ok_with_active():
    conn = AsyncMock()
    conn.fetch.return_value = [
        {"id": 1, "hostname": "h1", "status": "active", "last_heartbeat": None,
         "cluster_id": 1, "cluster_name": "c1"},
        {"id": 2, "hostname": "h2", "status": "offline", "last_heartbeat": None,
         "cluster_id": 1, "cluster_name": "c1"},
    ]
    out = await check_agents(conn, [1])
    assert out["status"] == "ok"
    assert "1 of 2" in out["message"]


# ----------------------------------------------------------------------------
# run_checks orchestration
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_checks_full_suite_returns_all_five(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname_ex",
                        lambda d: (d, [], ["10.0.0.1"]))

    def _ctor(*args, **kwargs):
        return _FakeSession(statuses=[200])

    monkeypatch.setattr("aiohttp.ClientSession", _ctor)

    conn = AsyncMock()
    conn.fetch.return_value = []
    conn.fetchrow.return_value = None

    out = await run_checks(
        conn,
        domains=["a.example.com"],
        cluster_ids=[1],
        account_id=None,
    )
    ids = [c["id"] for c in out]
    assert ids == ["dns", "port80", "routing", "account", "agents"]


@pytest.mark.asyncio
async def test_run_checks_only_filter(monkeypatch):
    """`only` lets the UI re-run a single check."""
    conn = AsyncMock()
    conn.fetchrow.return_value = {
        "id": 1, "email": "x@y", "status": "valid", "account_url": "https://acme/1",
    }
    out = await run_checks(
        conn, domains=["a.example.com"], cluster_ids=[1],
        account_id=1, only=["account"],
    )
    assert len(out) == 1
    assert out[0]["id"] == "account"


@pytest.mark.asyncio
async def test_run_checks_unknown_only_returns_empty():
    conn = AsyncMock()
    out = await run_checks(
        conn, domains=["a.example.com"], cluster_ids=[1],
        account_id=None, only=["bogus"],
    )
    assert out == []
