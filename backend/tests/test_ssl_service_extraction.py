"""
v1.5.0 service extraction parity — ssl_service.

Asserts:
- create_cert_row inserts with cluster_id=NULL on the cert row itself, then
  binds via the junction (R38 schema).
- ensure_cluster_junction is idempotent via ON CONFLICT DO NOTHING (M11).
- select_existing_cert returns id only when row is_active.

Phase K Phase D follow-up (Bulgu #9) — `create_cert_row` now parses
the PEM via `utils.ssl_parser.parse_ssl_certificate` and validates
the private key + chain before INSERT (parity with the SSL
Management page). Tests patch the parser/validators with valid
return values; an additional negative-path test pins the
HTTPException flow for invalid input.
"""
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from services.ssl_service import (
    create_cert_row,
    ensure_cluster_junction,
    select_existing_cert,
)


# ----------------------------------------------------------------------------
# Test helpers
# ----------------------------------------------------------------------------


_VALID_PARSE = {
    "primary_domain": "www.example.com",
    "all_domains": ["www.example.com"],
    "expiry_date": datetime(2099, 1, 1, tzinfo=timezone.utc),
    "issuer": "CN=Test CA",
    "fingerprint": "AA:BB:CC",
    "status": "valid",
    "days_until_expiry": 365,
}


def _mock_parse_ok(*args, **kwargs):
    return dict(_VALID_PARSE)


# ----------------------------------------------------------------------------
# create_cert_row
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_cert_row_inserts_cluster_id_null():
    """R38: ssl_certificates.cluster_id MUST always be NULL — junction is the truth."""
    conn = AsyncMock()
    conn.fetchval.return_value = 33
    conn.fetchrow.return_value = None  # no existing cert with same name
    payload = SimpleNamespace(
        name="cert-www",
        primary_domain="www.example.com",
        certificate_content="-----BEGIN CERTIFICATE-----\nXX\n-----END CERTIFICATE-----",
        private_key_content="-----BEGIN PRIVATE KEY-----\nYY\n-----END PRIVATE KEY-----",
        chain_content=None,
        all_domains=["www.example.com"],
    )

    with patch("services.ssl_service.parse_ssl_certificate", side_effect=_mock_parse_ok), \
         patch("services.ssl_service.validate_private_key", return_value=True), \
         patch("services.ssl_service.validate_certificate_chain", return_value=True):
        new_id = await create_cert_row(conn, payload, cluster_id=2)
    assert new_id == 33

    sql, *_ = conn.fetchval.call_args.args
    # The literal NULL on cluster_id is part of the templated SQL string.
    assert "cluster_id, last_config_status" in sql
    assert "NULL, 'PENDING'" in sql

    # Junction must be inserted exactly once.
    junction_calls = [
        c for c in conn.execute.call_args_list
        if c.args and "ssl_certificate_clusters" in c.args[0]
    ]
    assert len(junction_calls) == 1
    assert junction_calls[0].args[1] == 33  # ssl_certificate_id
    assert junction_calls[0].args[2] == 2   # cluster_id


@pytest.mark.asyncio
async def test_create_cert_row_serializes_all_domains_jsonb():
    conn = AsyncMock()
    conn.fetchval.return_value = 1
    conn.fetchrow.return_value = None
    payload = SimpleNamespace(
        name="cert", primary_domain="a.example.com",
        certificate_content="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        private_key_content="-----BEGIN PRIVATE KEY-----\nY\n-----END PRIVATE KEY-----",
        chain_content=None,
        all_domains=["a.example.com", "b.example.com"],
    )
    parse_result = dict(_VALID_PARSE)
    parse_result["primary_domain"] = "a.example.com"
    parse_result["all_domains"] = ["a.example.com", "b.example.com"]
    with patch("services.ssl_service.parse_ssl_certificate", return_value=parse_result), \
         patch("services.ssl_service.validate_private_key", return_value=True), \
         patch("services.ssl_service.validate_certificate_chain", return_value=True):
        await create_cert_row(conn, payload, cluster_id=1)
    sql, *args = conn.fetchval.call_args.args
    # all_domains is the 11th positional ($11) — after the new
    # parsed `status` + `days_until_expiry` columns.
    assert json.loads(args[10]) == ["a.example.com", "b.example.com"]


@pytest.mark.asyncio
async def test_create_cert_row_rejects_invalid_pem_with_400():
    """Phase K Phase D (Bulgu #9) — `create_cert_row` must raise
    HTTPException(400) when the PEM cannot be parsed. Pre-fix the
    wizard silently accepted any string and stored a row with NULL
    expiry/issuer/fingerprint, then HAProxy would fail at apply.
    """
    from fastapi import HTTPException

    conn = AsyncMock()
    payload = SimpleNamespace(
        name="bad",
        certificate_content="not a pem",
        private_key_content=None,
        chain_content=None,
    )
    with patch(
        "services.ssl_service.parse_ssl_certificate",
        return_value={"error": "Could not parse certificate"},
    ):
        with pytest.raises(HTTPException) as exc_info:
            await create_cert_row(conn, payload, cluster_id=1)
    assert exc_info.value.status_code == 400
    assert "Invalid SSL certificate" in exc_info.value.detail


@pytest.mark.asyncio
async def test_create_cert_row_rejects_empty_certificate_content():
    """An empty cert content string must short-circuit BEFORE the
    parser runs — clear UX for the operator who left the field blank.
    """
    from fastapi import HTTPException

    conn = AsyncMock()
    payload = SimpleNamespace(
        name="empty",
        certificate_content="",
        private_key_content=None,
        chain_content=None,
    )
    with pytest.raises(HTTPException) as exc_info:
        await create_cert_row(conn, payload, cluster_id=1)
    assert exc_info.value.status_code == 400
    assert "empty" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_create_cert_row_rejects_invalid_private_key_with_400():
    from fastapi import HTTPException

    conn = AsyncMock()
    payload = SimpleNamespace(
        name="bad-key",
        certificate_content="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        private_key_content="this is not a private key",
        chain_content=None,
    )
    with patch("services.ssl_service.parse_ssl_certificate", side_effect=_mock_parse_ok), \
         patch("services.ssl_service.validate_private_key", return_value=False):
        with pytest.raises(HTTPException) as exc_info:
            await create_cert_row(conn, payload, cluster_id=1)
    assert exc_info.value.status_code == 400
    assert "private key" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_create_cert_row_rejects_invalid_chain_with_400():
    from fastapi import HTTPException

    conn = AsyncMock()
    payload = SimpleNamespace(
        name="bad-chain",
        certificate_content="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        private_key_content=None,
        chain_content="not a chain",
    )
    with patch("services.ssl_service.parse_ssl_certificate", side_effect=_mock_parse_ok), \
         patch("services.ssl_service.validate_certificate_chain", return_value=False):
        with pytest.raises(HTTPException) as exc_info:
            await create_cert_row(conn, payload, cluster_id=1)
    assert exc_info.value.status_code == 400
    assert "chain" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_create_cert_row_rejects_duplicate_active_name_with_400():
    """Mirror the SSL Management page's name-conflict response
    (ssl.py:462-468). Pre-fix the wizard would either succeed
    (creating a duplicate row that broke the unique constraint at
    INSERT — 500) or fail with an opaque DB error. Now we return a
    friendly 400 the wizard surfaces as a step-jumpback toast.
    """
    from fastapi import HTTPException

    conn = AsyncMock()
    # Existing active cert with same name in this cluster.
    conn.fetchrow.return_value = {"id": 99, "is_active": True}
    payload = SimpleNamespace(
        name="duplicate",
        certificate_content="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        private_key_content="-----BEGIN PRIVATE KEY-----\nY\n-----END PRIVATE KEY-----",
        chain_content=None,
    )
    with patch("services.ssl_service.parse_ssl_certificate", side_effect=_mock_parse_ok), \
         patch("services.ssl_service.validate_private_key", return_value=True), \
         patch("services.ssl_service.validate_certificate_chain", return_value=True):
        with pytest.raises(HTTPException) as exc_info:
            await create_cert_row(conn, payload, cluster_id=1)
    assert exc_info.value.status_code == 400
    assert "already exists" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_create_cert_row_reactivates_soft_deleted_name():
    """Mirror ssl.py:470-500 — when a soft-deleted cert exists with
    the same name (is_active=False), reuse its row id and UPDATE
    contents instead of inserting a duplicate. Preserves any
    downstream references (auditor history, version names that
    embedded the cert id, etc.).
    """
    conn = AsyncMock()
    conn.fetchrow.return_value = {"id": 77, "is_active": False}
    payload = SimpleNamespace(
        name="recycled",
        certificate_content="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        private_key_content="-----BEGIN PRIVATE KEY-----\nY\n-----END PRIVATE KEY-----",
        chain_content=None,
    )
    with patch("services.ssl_service.parse_ssl_certificate", side_effect=_mock_parse_ok), \
         patch("services.ssl_service.validate_private_key", return_value=True), \
         patch("services.ssl_service.validate_certificate_chain", return_value=True):
        new_id = await create_cert_row(conn, payload, cluster_id=1)
    assert new_id == 77
    # We must NOT have INSERTed (no fetchval call), only UPDATEd + DELETEd-junction + re-INSERTed junction.
    assert not conn.fetchval.await_count
    # And `UPDATE ssl_certificates ... is_active = TRUE` must have run.
    update_calls = [
        c for c in conn.execute.call_args_list
        if c.args and "UPDATE ssl_certificates" in c.args[0]
    ]
    assert len(update_calls) == 1, "soft-deleted cert reactivation must run a single UPDATE"


@pytest.mark.asyncio
async def test_create_cert_row_parses_metadata_from_pem_not_payload():
    """Phase K Phase D (Bulgu #9) — primary_domain / all_domains /
    expiry_date / issuer / fingerprint / status / days_until_expiry
    MUST come from the parsed certificate, NOT from operator-typed
    domain fields on the wizard. Pre-fix the wizard inserted the
    user's frontend domains into the SSL row even when the cert
    SAN was different — confusing UX on the SSL Management page.
    """
    conn = AsyncMock()
    conn.fetchval.return_value = 123
    conn.fetchrow.return_value = None
    payload = SimpleNamespace(
        # Operator typed `app.example.com` for the frontend domain,
        # but the cert SAN is `*.example.com`.
        name="cert-from-pem",
        primary_domain="app.example.com",
        all_domains=["app.example.com"],
        certificate_content="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        private_key_content="-----BEGIN PRIVATE KEY-----\nY\n-----END PRIVATE KEY-----",
        chain_content=None,
    )
    cert_parse = dict(_VALID_PARSE)
    cert_parse["primary_domain"] = "*.example.com"
    cert_parse["all_domains"] = ["*.example.com", "www.example.com"]
    cert_parse["issuer"] = "CN=R3"
    cert_parse["fingerprint"] = "DE:AD:BE:EF"
    with patch("services.ssl_service.parse_ssl_certificate", return_value=cert_parse), \
         patch("services.ssl_service.validate_private_key", return_value=True), \
         patch("services.ssl_service.validate_certificate_chain", return_value=True):
        await create_cert_row(conn, payload, cluster_id=1)
    sql, *args = conn.fetchval.call_args.args
    # primary_domain is $2 → args[1]
    assert args[1] == "*.example.com", (
        "primary_domain must come from the parsed PEM, not the "
        "operator-typed frontend domain"
    )
    # all_domains is now $11 → args[10] (post-Bulgu #9 column order)
    assert json.loads(args[10]) == ["*.example.com", "www.example.com"]
    # issuer $7 → args[6], fingerprint $8 → args[7]
    assert args[6] == "CN=R3"
    assert args[7] == "DE:AD:BE:EF"


# ----------------------------------------------------------------------------
# ensure_cluster_junction (M11 idempotency)
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ensure_cluster_junction_uses_on_conflict_do_nothing():
    conn = AsyncMock()
    await ensure_cluster_junction(conn, ssl_certificate_id=1, cluster_id=2)
    sql, *_ = conn.execute.call_args.args
    assert "INSERT INTO ssl_certificate_clusters" in sql
    assert "ON CONFLICT" in sql
    assert "DO NOTHING" in sql


@pytest.mark.asyncio
async def test_ensure_cluster_junction_can_be_called_twice_safely():
    """Idempotency at the helper level — repeated calls must not raise."""
    conn = AsyncMock()
    await ensure_cluster_junction(conn, 1, 2)
    await ensure_cluster_junction(conn, 1, 2)
    assert conn.execute.await_count == 2


# ----------------------------------------------------------------------------
# select_existing_cert
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_select_existing_cert_returns_id_when_active():
    conn = AsyncMock()
    conn.fetchrow.return_value = {"id": 7}
    out = await select_existing_cert(conn, ssl_certificate_id=7, cluster_id=1)
    assert out == 7
    # Junction must be ensured even on existing-cert reuse (idempotent).
    junction_calls = [c for c in conn.execute.call_args_list
                      if c.args and "ssl_certificate_clusters" in c.args[0]]
    assert len(junction_calls) == 1


@pytest.mark.asyncio
async def test_select_existing_cert_returns_none_when_inactive_or_missing():
    conn = AsyncMock()
    conn.fetchrow.return_value = None
    out = await select_existing_cert(conn, ssl_certificate_id=7, cluster_id=1)
    assert out is None
    # Junction must NOT be inserted for non-existent certs.
    assert all(
        not (c.args and "ssl_certificate_clusters" in c.args[0])
        for c in conn.execute.call_args_list
    )
