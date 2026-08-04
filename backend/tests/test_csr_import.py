"""
v1.9.0 CSR creation — unit tests for the signed-certificate import flow and
config-version staging (pattern: test_ssl_service_extraction.py, AsyncMock conn).

Pins the security-relevant invariants:
- key match is a HARD gate: match=False → 400 before any INSERT, and
  match=None (unverifiable) → 500, never a lenient pass (we generated the
  key ourselves — deliberate divergence from create_cert_row's fallback).
- the new cert row is cluster_id=NULL / last_config_status='PENDING' /
  source='csr' (PENDING keeps it invisible to agents until Apply).
- completing the CSR NULLs the private key copy.
- staging reuses the exact `ssl-{id}-create-{ts}` version-name scheme.
"""
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from models.csr import SSLCSRImport
from services.csr_service import (
    assert_csr_name_available,
    import_signed_certificate,
    insert_csr_row,
)
from services.ssl_service import stage_ssl_config_versions


_VALID_PARSE = {
    "primary_domain": "www.example.com",
    "all_domains": ["www.example.com"],
    "expiry_date": datetime(2099, 1, 1, tzinfo=timezone.utc),
    "issuer": "CN=Test CA",
    "fingerprint": "AA:BB:CC",
    "status": "valid",
    "days_until_expiry": 365,
}

_FAKE_CERT = "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----"
_FAKE_KEY = "-----BEGIN PRIVATE KEY-----\nY\n-----END PRIVATE KEY-----"


def _csr_row(**overrides):
    row = {
        "id": 5,
        "name": "csr-www",
        "common_name": "www.example.com",
        "subject": "{}",
        "sans": json.dumps(["www.example.com"]),
        "key_algorithm": "rsa-2048",
        "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nZ\n-----END CERTIFICATE REQUEST-----",
        "private_key_pem": _FAKE_KEY,
        "status": "pending",
        "ssl_certificate_id": None,
    }
    row.update(overrides)
    return row


def _mk_conn():
    conn = AsyncMock()
    # asyncpg's conn.transaction() is a SYNC call returning an async CM.
    conn.transaction = MagicMock()
    return conn


def _import_payload(**overrides):
    base = dict(
        certificate_content=_FAKE_CERT,
        chain_content=None,
        usage_type="frontend",
        is_global=False,
        cluster_ids=[1, 2],
        name=None,
    )
    base.update(overrides)
    return SSLCSRImport(**base)


@contextmanager
def _patched(match=None, parse=None):
    """Patch every parser touchpoint of the import path: the function-local
    imports in csr_service (utils.ssl_parser.*) and the module-level imports
    in ssl_service._prepare_cert_fields (services.ssl_service.*)."""
    match_result = match if match is not None else {"match": True}
    parse_result = dict(parse or _VALID_PARSE)
    with patch("utils.ssl_parser.verify_certificate_key_match", return_value=match_result), \
         patch("utils.ssl_parser.parse_ssl_certificate", return_value=dict(parse_result)), \
         patch("services.ssl_service.parse_ssl_certificate", return_value=dict(parse_result)), \
         patch("services.ssl_service.validate_private_key", return_value=True), \
         patch("services.ssl_service.validate_certificate_chain", return_value=True):
        yield


# ----------------------------------------------------------------------------
# import_signed_certificate
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_happy_path_inserts_pending_csr_sourced_cert():
    conn = _mk_conn()
    conn.fetchrow.side_effect = [_csr_row(), None]  # FOR UPDATE row, no name clash
    conn.fetchval.return_value = 42                 # INSERT ... RETURNING id

    with _patched():
        result = await import_signed_certificate(conn, 5, _import_payload(), user_id=7)

    assert result["certificate_id"] == 42
    assert result["reactivated"] is False

    # Concurrency invariants: everything runs inside a transaction and the
    # CSR row is locked FOR UPDATE (serialises double-import and delete-races).
    assert conn.transaction.call_count == 1
    lock_sql = conn.fetchrow.call_args_list[0].args[0]
    assert "FOR UPDATE" in lock_sql

    insert_sql, *insert_args = conn.fetchval.call_args.args
    assert "INSERT INTO ssl_certificates" in insert_sql
    assert "NULL, 'PENDING'" in insert_sql, "cert must stay invisible to agents until Apply"
    assert "'csr'" in insert_sql, "source column must record the CSR origin"
    # The stored CSR key — not any request-supplied key — must be persisted.
    assert _FAKE_KEY in insert_args

    # One junction row per requested cluster.
    junction_calls = [
        c for c in conn.execute.call_args_list
        if c.args and "ssl_certificate_clusters" in c.args[0] and "INSERT" in c.args[0]
    ]
    assert len(junction_calls) == 2
    assert {c.args[2] for c in junction_calls} == {1, 2}

    # CSR completion must destroy the key copy.
    completion_calls = [
        c for c in conn.execute.call_args_list
        if c.args and "UPDATE ssl_csrs" in c.args[0]
    ]
    assert len(completion_calls) == 1
    assert "private_key_pem = NULL" in completion_calls[0].args[0]
    assert "status = 'completed'" in completion_calls[0].args[0]
    assert completion_calls[0].args[1] == 5   # csr_id
    assert completion_calls[0].args[2] == 42  # cert_id


@pytest.mark.asyncio
async def test_import_global_creates_zero_junction_rows():
    conn = _mk_conn()
    conn.fetchrow.side_effect = [_csr_row(), None]
    conn.fetchval.return_value = 42

    with _patched():
        await import_signed_certificate(
            conn, 5, _import_payload(is_global=True, cluster_ids=None), user_id=7
        )

    junction_calls = [
        c for c in conn.execute.call_args_list
        if c.args and "ssl_certificate_clusters" in c.args[0] and "INSERT" in c.args[0]
    ]
    assert junction_calls == [], "global cert = zero junction rows (existing convention)"


@pytest.mark.asyncio
async def test_import_key_mismatch_rejected_400_before_any_write():
    conn = _mk_conn()
    conn.fetchrow.side_effect = [_csr_row()]

    with _patched(match={"match": False, "reason": "public key mismatch"}):
        with pytest.raises(HTTPException) as exc_info:
            await import_signed_certificate(conn, 5, _import_payload(), user_id=7)

    assert exc_info.value.status_code == 400
    assert "does not match" in exc_info.value.detail
    assert not conn.fetchval.await_count, "nothing must be inserted on mismatch"
    assert not conn.execute.await_count


@pytest.mark.asyncio
async def test_import_unverifiable_key_match_is_hard_error_not_lenient():
    """match=None means OUR stored key is unreadable — integrity failure,
    never the lenient pass create_cert_row historically allows."""
    conn = _mk_conn()
    conn.fetchrow.side_effect = [_csr_row()]

    with _patched(match={"match": None, "reason": "key could not be parsed"}):
        with pytest.raises(HTTPException) as exc_info:
            await import_signed_certificate(conn, 5, _import_payload(), user_id=7)

    assert exc_info.value.status_code == 500
    assert not conn.fetchval.await_count


@pytest.mark.asyncio
async def test_import_expired_certificate_rejected_400():
    conn = _mk_conn()
    conn.fetchrow.side_effect = [_csr_row()]

    expired = dict(_VALID_PARSE)
    expired["status"] = "expired"
    expired["days_until_expiry"] = -10
    with _patched(parse=expired):
        with pytest.raises(HTTPException) as exc_info:
            await import_signed_certificate(conn, 5, _import_payload(), user_id=7)

    assert exc_info.value.status_code == 400
    assert "expired" in exc_info.value.detail.lower()
    assert not conn.fetchval.await_count


@pytest.mark.asyncio
async def test_import_malformed_certificate_rejected_400_not_500():
    """A cert with PEM markers but unparseable content (truncated CA response)
    is OPERATOR INPUT — it must get the manual flow's 400, not the 500 that
    the strict key-match branch reserves for a corrupt STORED key."""
    conn = _mk_conn()
    conn.fetchrow.side_effect = [_csr_row()]

    with _patched(parse={"error": "Could not parse certificate"}):
        with pytest.raises(HTTPException) as exc_info:
            await import_signed_certificate(conn, 5, _import_payload(), user_id=7)

    assert exc_info.value.status_code == 400
    assert "Invalid SSL certificate" in exc_info.value.detail
    assert not conn.fetchval.await_count
    assert not conn.execute.await_count


@pytest.mark.asyncio
async def test_import_completed_csr_conflicts_409():
    conn = _mk_conn()
    conn.fetchrow.side_effect = [_csr_row(status="completed", ssl_certificate_id=42)]

    with pytest.raises(HTTPException) as exc_info:
        await import_signed_certificate(conn, 5, _import_payload(), user_id=7)

    assert exc_info.value.status_code == 409
    assert "already completed" in exc_info.value.detail


@pytest.mark.asyncio
async def test_import_missing_csr_404():
    conn = _mk_conn()
    conn.fetchrow.side_effect = [None]

    with pytest.raises(HTTPException) as exc_info:
        await import_signed_certificate(conn, 999, _import_payload(), user_id=7)

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_import_active_name_collision_rejected_with_hint():
    conn = _mk_conn()
    conn.fetchrow.side_effect = [_csr_row(), {"id": 9, "is_active": True}]

    with _patched():
        with pytest.raises(HTTPException) as exc_info:
            await import_signed_certificate(conn, 5, _import_payload(), user_id=7)

    assert exc_info.value.status_code == 400
    assert "already exists" in exc_info.value.detail
    assert "name" in exc_info.value.detail  # points at the override escape hatch
    assert not conn.fetchval.await_count


@pytest.mark.asyncio
async def test_import_name_override_is_used_for_the_cert_row():
    conn = _mk_conn()
    conn.fetchrow.side_effect = [_csr_row(), None]
    conn.fetchval.return_value = 42

    with _patched():
        result = await import_signed_certificate(
            conn, 5, _import_payload(name="renamed-cert"), user_id=7
        )

    assert result["certificate_name"] == "renamed-cert"
    _, *insert_args = conn.fetchval.call_args.args
    assert "renamed-cert" in insert_args
    # And the collision check must have run against the override, not csr.name.
    name_lookup = conn.fetchrow.call_args_list[1]
    assert name_lookup.args[1] == "renamed-cert"


@pytest.mark.asyncio
async def test_import_reactivates_soft_deleted_name_and_warns():
    conn = _mk_conn()
    conn.fetchrow.side_effect = [_csr_row(), {"id": 77, "is_active": False}]

    with _patched():
        result = await import_signed_certificate(conn, 5, _import_payload(), user_id=7)

    assert result["certificate_id"] == 77
    assert result["reactivated"] is True
    assert any("reactivated" in w for w in result["warnings"])
    assert not conn.fetchval.await_count, "reactivation must UPDATE, not INSERT"
    update_calls = [
        c for c in conn.execute.call_args_list
        if c.args and "UPDATE ssl_certificates" in c.args[0]
    ]
    assert len(update_calls) == 1
    update_sql = update_calls[0].args[0]
    assert "source = 'csr'" in update_sql
    # The reactivated row must come back to life invisible to agents until
    # Apply, with the row itself active again.
    assert "last_config_status = 'PENDING'" in update_sql
    assert "is_active = TRUE" in update_sql
    # Old cluster bindings must be wiped before re-binding to the new scope.
    junction_deletes = [
        c for c in conn.execute.call_args_list
        if c.args and "DELETE FROM ssl_certificate_clusters" in c.args[0]
    ]
    assert len(junction_deletes) == 1
    assert junction_deletes[0].args[1] == 77
    # …and the importer's requested clusters re-bound via the junction.
    junction_inserts = [
        c for c in conn.execute.call_args_list
        if c.args and "INSERT INTO ssl_certificate_clusters" in c.args[0]
    ]
    assert {c.args[2] for c in junction_inserts} == {1, 2}


@pytest.mark.asyncio
async def test_import_san_drift_warns_but_succeeds():
    conn = _mk_conn()
    conn.fetchrow.side_effect = [
        _csr_row(sans=json.dumps(["www.example.com", "api.example.com"])),
        None,
    ]
    conn.fetchval.return_value = 42

    drifted = dict(_VALID_PARSE)
    drifted["all_domains"] = ["www.example.com", "cdn.example.com"]
    with _patched(parse=drifted):
        result = await import_signed_certificate(conn, 5, _import_payload(), user_id=7)

    assert result["certificate_id"] == 42
    assert any("added" in w and "cdn.example.com" in w for w in result["warnings"])
    assert any("dropped" in w and "api.example.com" in w for w in result["warnings"])


# ----------------------------------------------------------------------------
# insert_csr_row / assert_csr_name_available
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_csr_name_taken_by_active_cert_rejected():
    conn = _mk_conn()
    conn.fetchval.side_effect = [11]  # active cert with the name exists

    with pytest.raises(HTTPException) as exc_info:
        await assert_csr_name_available(conn, "taken")
    assert exc_info.value.status_code == 400
    assert "certificate" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_csr_name_taken_by_pending_csr_rejected():
    conn = _mk_conn()
    conn.fetchval.side_effect = [None, 12]  # no cert, but a pending CSR

    with pytest.raises(HTTPException) as exc_info:
        await assert_csr_name_available(conn, "taken")
    assert exc_info.value.status_code == 400
    assert "pending CSR" in exc_info.value.detail


@pytest.mark.asyncio
async def test_insert_csr_row_translates_unique_violation_to_400():
    """The uq_ssl_csrs_name_pending partial index closes the create/create
    race — the loser must get a clean 400, not a 500."""
    import asyncpg as _asyncpg

    conn = _mk_conn()
    # availability checks pass, INSERT hits the unique index
    conn.fetchval.side_effect = [
        None, None, _asyncpg.exceptions.UniqueViolationError("dup"),
    ]
    payload = SimpleNamespace(
        name="raced", common_name="www.example.com", key_algorithm="rsa-2048"
    )
    bundle = {"subject": {}, "sans": ["www.example.com"], "csr_pem": "PEM", "private_key_pem": "KEY"}

    with pytest.raises(HTTPException) as exc_info:
        await insert_csr_row(conn, payload, bundle, user_id=1)
    assert exc_info.value.status_code == 400
    assert "concurrent" in exc_info.value.detail


# ----------------------------------------------------------------------------
# router-level guards
# ----------------------------------------------------------------------------


def test_cluster_id_int32_guard_rejects_out_of_range_with_404():
    """Body-supplied cluster ids must never reach asyncpg out of int4 range
    (DataError → raw 500) — same Bulgu #96 hygiene as the csr_id path param."""
    from routers.csr import _assert_valid_cluster_id

    _assert_valid_cluster_id(1)
    _assert_valid_cluster_id(2_147_483_647)
    for bad in (0, -1, 2_147_483_648, 99_999_999_999):
        with pytest.raises(HTTPException) as exc_info:
            _assert_valid_cluster_id(bad)
        assert exc_info.value.status_code == 404
        assert "Cluster not found" in exc_info.value.detail


# ----------------------------------------------------------------------------
# stage_ssl_config_versions
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stage_creates_one_pending_version_per_cluster_with_ssl_naming():
    import re

    conn = _mk_conn()
    conn.fetchval.return_value = 1001  # config_versions INSERT RETURNING id

    with patch(
        "services.haproxy_config.generate_haproxy_config_for_cluster",
        new=AsyncMock(return_value="# cfg"),
    ):
        results = await stage_ssl_config_versions(conn, 42, [1, 2], created_by=7)

    assert len(results) == 2
    assert all(r["success"] for r in results)
    assert [r["cluster_id"] for r in results] == [1, 2]

    insert_calls = [
        c for c in conn.fetchval.call_args_list
        if c.args and "INSERT INTO config_versions" in c.args[0]
    ]
    assert len(insert_calls) == 2
    for call in insert_calls:
        sql = call.args[0]
        assert "FALSE, 'PENDING'" in sql, "staged versions must be inactive + PENDING"
        version_name = call.args[2]
        # EXACT manual-flow scheme: Apply Management + has_pending_config
        # LIKE-filters key off 'ssl-{id}-...'.
        assert re.match(r"^ssl-42-create-\d+$", version_name), version_name
        assert call.args[5] == 7  # created_by honours the importing user


@pytest.mark.asyncio
async def test_stage_reports_per_cluster_failure_without_raising():
    conn = _mk_conn()
    conn.fetchval.return_value = 1001

    async def _gen(cluster_id):
        if cluster_id == 2:
            raise RuntimeError("config generation exploded")
        return "# cfg"

    with patch(
        "services.haproxy_config.generate_haproxy_config_for_cluster",
        new=AsyncMock(side_effect=_gen),
    ):
        results = await stage_ssl_config_versions(conn, 42, [1, 2], created_by=7)

    assert len(results) == 2
    assert results[0]["success"] is True
    assert results[1]["success"] is False
    assert "exploded" in results[1]["error"]
