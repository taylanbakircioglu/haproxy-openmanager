"""v1.5.0 R18 audit ROUND 2 — concurrency, rollback, multi-tenant fixes.

Findings discovered during the second-round audit:

  R18-#6 (CRITICAL): `entity_snapshot.rollback_entity_from_snapshot`
    treated `old_values={}` as missing because empty dicts are falsy
    in Python. Wizard's bulk_snapshots always emit `"old_values": {}`
    for CREATE entries — so EVERY wizard CREATE rollback silently
    no-op'd. Rejected wizard PENDING versions left orphan entities.

  R18-#7 (HIGH): `GET /api/ssl/certificates` was anonymous-readable.
    Any unauthenticated client could enumerate cert metadata across
    every cluster, breaking the multi-tenant guarantee enforced on
    every other SSL endpoint.

  R18-#8 (HIGH): `cluster.py::reject_all_pending_changes` did not
    track `ssl_certificate` snapshots in `bulk_import_entity_ids`. A
    rejected wizard upload-mode flow left an orphan `ssl_certificates`
    row + on-disk PEM material.

  R18-#9 (Major): `wizard_drafts` cap (50/user) was COUNT-then-INSERT,
    not transactional. Two parallel saves both observing count=49
    could both insert, exceeding the cap. Fix wraps both queries in a
    transaction and takes a per-user `pg_advisory_xact_lock`.

  R18-#10 (UX): `Form.useWatch(['ssl','mode'])` returns `undefined`
    on first render. `acmeBlocksDraft = sslMode === 'acme'` evaluated
    to `false` during hydration so the "Save as PENDING" button
    flashed enabled for resumed ACME drafts; users could click it and
    hit M22's 422 rejection. Fix gates `undefined` as also-blocked.
"""
import re
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent
_FRONT = _REPO.parent / "frontend" / "src"


# ----------------- R18-#6: entity_snapshot CREATE rollback -----------------


def test_entity_snapshot_create_no_longer_gated_by_old_values_truthiness():
    """The pre-R18 guard `if not all([..., old_values]):` rejected
    `old_values={}`. After R18 the CREATE branch must run with empty
    old_values; only UPDATE/UPDATE_RESTORE/DELETE require old_values
    to be present."""
    src = (_REPO / "utils" / "entity_snapshot.py").read_text()
    # Guard must NOT include old_values in the unconditional `not all`
    # check anymore.
    bad_guard = re.search(
        r"if\s+not\s+all\(\s*\[\s*entity_type\s*,\s*entity_id\s*,\s*operation\s*,\s*old_values\s*\]\s*\)",
        src,
    )
    assert not bad_guard, (
        "R18-#6 regression: the rollback guard still includes "
        "old_values in `not all([...])` — wizard CREATE snapshots will "
        "silently no-op again"
    )
    # And the new conditional guard for UPDATE/DELETE must exist.
    assert re.search(
        r'if\s+operation\s+in\s+\(\s*"UPDATE",\s*"UPDATE_RESTORE",\s*"DELETE"\s*\)\s+and\s+not\s+old_values',
        src,
    ), (
        "R18-#6 regression: missing the new conditional old_values "
        "guard for UPDATE/DELETE operations"
    )


# ----------------- R18-#7: SSL list endpoint authentication -----------------


def test_ssl_list_endpoint_requires_authorization_header():
    """The list endpoint must accept an `authorization: str = Header(None)`
    parameter and call `get_current_user_from_token` so it cannot be
    enumerated anonymously."""
    src = (_REPO / "routers" / "ssl.py").read_text()
    # Find the get_ssl_certificates function signature.
    sig_match = re.search(
        r"async\s+def\s+get_ssl_certificates\s*\((.*?)\)\s*:",
        src,
        re.DOTALL,
    )
    assert sig_match, "R18-#7 regression: get_ssl_certificates signature not found"
    sig = sig_match.group(1)
    assert "authorization" in sig and "Header" in sig, (
        "R18-#7 regression: get_ssl_certificates no longer accepts "
        "an Authorization header — endpoint is anonymously readable"
    )
    # Body must call the authenticator. Locate the function body up to
    # the next `@router` or end-of-file.
    body_start = sig_match.end()
    body_end = src.find("@router", body_start)
    body = src[body_start: body_end if body_end != -1 else len(src)]
    assert "get_current_user_from_token(authorization)" in body, (
        "R18-#7 regression: get_ssl_certificates does not call "
        "get_current_user_from_token — token presence is unenforced"
    )


def test_ssl_list_endpoint_validates_cluster_access_when_filtered():
    """When the caller scopes to a specific cluster, the endpoint must
    call `validate_user_cluster_access` so a user without access to
    cluster B cannot enumerate cluster B's certs."""
    src = (_REPO / "routers" / "ssl.py").read_text()
    sig_match = re.search(
        r"async\s+def\s+get_ssl_certificates\s*\(.*?\)\s*:",
        src,
        re.DOTALL,
    )
    body_start = sig_match.end()
    body_end = src.find("@router", body_start)
    body = src[body_start: body_end if body_end != -1 else len(src)]
    assert "validate_user_cluster_access" in body, (
        "R18-#7 regression: get_ssl_certificates no longer "
        "validates cluster access — cross-tenant cert enumeration "
        "is possible again"
    )


# ----------------- R18-#8: SSL cert in reject reconciliation -----------------


def test_reject_tracks_ssl_certificate_snapshots_for_force_delete():
    """`bulk_import_entity_ids` must include `ssl_certificates` and
    the entity_type==='ssl_certificate' branch must append into it.
    Without this the wizard's upload-mode SSL row leaks on reject."""
    src = (_REPO / "routers" / "cluster.py").read_text()
    assert '"ssl_certificates": []' in src, (
        "R18-#8 regression: bulk_import_entity_ids no longer "
        "initialises 'ssl_certificates' bucket"
    )
    assert re.search(
        r'entity_type\s*==\s*"ssl_certificate"\s*:\s*\n\s*#[^\n]*\n(?:\s*#[^\n]*\n)*\s*bulk_import_entity_ids\["ssl_certificates"\]\.append',
        src,
    ), (
        "R18-#8 regression: ssl_certificate entity_type branch no "
        "longer pushes into the ssl_certificates list"
    )


def test_reject_force_deletes_orphan_ssl_certificates():
    """The force-delete fallback must run a DELETE against
    `ssl_certificates` when rollback verification still finds rows."""
    src = (_REPO / "routers" / "cluster.py").read_text()
    assert re.search(
        r'DELETE\s+FROM\s+ssl_certificates\s+WHERE\s+id\s*=\s*ANY\(\$1\)',
        src,
    ), (
        "R18-#8 regression: reject force-delete fallback no longer "
        "DELETEs ssl_certificates rows tracked in bulk_snapshots"
    )


# ----------------- R18-#9: draft cap race -----------------


def test_drafts_cap_uses_advisory_lock_in_transaction():
    """The COUNT and INSERT must be wrapped in a transaction with a
    per-user advisory lock so two parallel saves serialise rather
    than both observing count=49."""
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # We need: async with conn.transaction(): ... pg_advisory_xact_lock(...)
    assert "pg_advisory_xact_lock" in src, (
        "R18-#9 regression: drafts cap no longer takes a per-user "
        "advisory lock — count-then-insert race reintroduced"
    )
    # The advisory lock must be inside an async-with conn.transaction()
    # block, before the COUNT.
    snippet = re.search(
        r"async with conn\.transaction\(\):.*?pg_advisory_xact_lock.*?SELECT COUNT\(\*\).*?FROM wizard_drafts",
        src,
        re.DOTALL,
    )
    assert snippet, (
        "R18-#9 regression: advisory lock is not held in the same "
        "transaction as the COUNT/INSERT pair"
    )


# ----------------- R18-#10: ACME draft hydration UX gate -----------------


def test_acme_blocks_draft_treats_undefined_as_blocked():
    """SUPERSEDED by Phase K Phase D (Bulgu #6).

    R18-#10 originally guarded the "Save as PENDING" button against
    sslMode flash during ACME-draft hydration. Phase K Phase D
    removed the dual-button UI (Create as PENDING + Create & Apply)
    in favour of a single Create button whose semantics are derived
    inside `handleSubmit`:

        effectiveApply = sslMode === 'acme'

    There is no longer a PENDING-only button to flash, so the
    flash-mitigation is no longer needed. The behavioural
    guarantee survives:

      * sslMode='acme' → handleSubmit forces apply_immediately=true,
        independent of any button.
      * sslMode=undefined (mid-hydration) → handleSubmit's
        `effectiveApply = sslMode === 'acme'` evaluates to false,
        but the form-level rules block submit until the operator
        completes the SSL step (covered by Pydantic + the dry-run
        validation card on Step 4).

    This test is kept as documentation of the prior contract and
    re-pins the new contract: `handleSubmit` must read sslMode
    via `values.ssl?.mode` (the post-validate snapshot).
    """
    src = (_FRONT / "components" / "SiteWizard.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    # Phase K Phase D: assert handleSubmit derives effectiveApply
    # from values.ssl?.mode rather than from an external acmeBlocksDraft
    # boolean.
    assert "values.ssl?.mode" in body, (
        "Phase K Phase D regression: handleSubmit no longer reads "
        "the SSL mode from the validated payload (values.ssl?.mode). "
        "Without that read, the ACME → apply_immediately=true forcing "
        "is broken and the operator can submit a payload that the "
        "backend M22 validator will reject with a 422."
    )
    assert "sslModeAtSubmit === 'acme'" in body, (
        "Phase K Phase D regression: handleSubmit no longer special-"
        "cases sslMode='acme' to force apply_immediately=true. The "
        "ACME flow will once again fail the backend M22 validator "
        "with an opaque 422."
    )
