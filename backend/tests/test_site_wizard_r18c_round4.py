"""v1.5.0 R18c round 4 (convergence) audit fixes.

Findings discovered during R18c round 4 (regression on R18c 1-3 +
hard-untouched topics):

  R18c-#16 (User-activity API exposes other users' rows — KRITIK
    info leak): pre-fix `GET /api/users/user-activity` only checked
    that the caller had a valid token, never that they were
    authorized to see ANOTHER operator's stream. Any authenticated
    user could omit `user_id` to fetch the entire activity log of
    every operator on the platform — including admin apply rows
    and (after R18b round 6) the wizard's `apply_error` /
    `acme_staging_error` JSON. Admin-only listing now; non-admins
    are limited to their own user_id and rejected on
    cross-account requests.

  R18c-#17 (SSRF dual-stack residual — KRITIK): pre-fix the
    aiohttp ClientSession used the default connector, which did
    its own dual-stack `getaddrinfo` and could connect via AAAA
    even when the SSRF guard's `gethostbyname_ex` only saw IPv4.
    A crafted DNS pair (benign public A + private/loopback AAAA)
    could route the probe through the IPv6 path. Connector now
    forced to family=AF_INET so the family the guard inspects
    matches the family the connector uses.

  R18c-#18 (Migration docstring overstated dedup): pre-fix the
    docstring claimed the partial UNIQUE migration would
    "deduplicate" legacy duplicates. In reality
    `CREATE UNIQUE INDEX IF NOT EXISTS` only skips when the index
    NAME already exists — duplicate ROW data still aborts index
    creation. Operators reading the comment may have wrongly
    expected auto-dedup. Docstring corrected with the manual
    consolidation runbook.
"""
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent


# ----------------- R18c-#16: user-activity admin guard -----------------


def test_user_activity_endpoint_blocks_cross_user_access_for_non_admin():
    src = (_REPO / "routers" / "user.py").read_text()
    # Locate the get_user_activity body.
    fn_idx = src.find("async def get_user_activity")
    assert fn_idx != -1
    body = src[fn_idx:fn_idx + 3500]
    assert "is_admin" in body, (
        "R18c-#16 KRITIK info leak regression: user-activity "
        "endpoint no longer reads is_admin — non-admins can "
        "request another user's activity stream"
    )
    assert "Only administrators" in body or "status_code=403" in body, (
        "R18c-#16 KRITIK info leak regression: cross-user request "
        "no longer raises 403"
    )
    # Default-to-self for non-admins must be present.
    assert "user_id = own_id" in body or "user_id = current_user" in body, (
        "R18c-#16 regression: non-admins no longer default-scoped "
        "to their own user_id when omitted"
    )


# ----------------- R18c-#17: SSRF dual-stack residual -----------------


def test_check_port80_forces_ipv4_connector():
    src = (_REPO / "services" / "acme_diagnostics.py").read_text()
    # The aiohttp connector must force IPv4 family.
    assert "TCPConnector(family=socket.AF_INET" in src, (
        "R18c-#17 KRITIK SSRF regression: aiohttp connector no "
        "longer forced to IPv4 — SSRF guard inspects IPv4-only "
        "DNS but connector can dual-stack to AAAA, bypassing the "
        "guard via crafted DNS pairs"
    )


# ----------------- R18c-#18: migration docstring fix -----------------


def test_migration_docstring_no_longer_claims_auto_dedup():
    src = (_REPO / "database" / "migrations.py").read_text()
    fn_idx = src.find("async def ensure_frontends_bind_unique_constraint")
    assert fn_idx != -1
    block = src[fn_idx:fn_idx + 3500]
    # The misleading "Idempotent: skips on legacy rows..." line must be gone.
    # Allow the word 'idempotent' in any contextual sense, but the
    # specific overstatement about deduplication MUST NOT remain.
    assert (
        "deduplicating with a logical-key keepalive" not in block
        and "skips on legacy rows that already" not in block
    ), (
        "R18c-#18 regression: migration docstring still claims "
        "legacy duplicates are auto-deduplicated — operators may "
        "deploy expecting auto-cleanup that never happens"
    )
    # The corrected runbook hint must be present.
    assert "manually consolidate" in block.lower() or "operationally" in block.lower(), (
        "R18c-#18 regression: corrected docstring no longer "
        "documents the manual consolidation path operators must "
        "take when the index creation aborts"
    )
