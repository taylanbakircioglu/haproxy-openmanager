"""
v1.5.0 Feature B — reject path safety (CRITICAL — M4/L11).

When a wizard-created config_version is rejected, ALL of the wizard's
entities (frontend + backend + servers + ssl_certificate +
letsencrypt_order) must be cleanly removed so the user can retry without
orphan rows.

These tests target three critical gates:

1. utils/entity_snapshot._rollback_create handles the new
   `letsencrypt_order` entity type (drops the staged ACME order, cascading
   acme_challenges).

2. routers/cluster.py treats `bulk-proxied-host-create-*` as a
   `is_bulk_style_version` so the existing bulk-rejection cleanup applies
   to wizard versions.

3. The same rejection path collects letsencrypt_order entity ids into the
   bulk_import_entity_ids dict so the force-delete sweep removes them.
"""
from unittest.mock import AsyncMock

import pytest

from utils.entity_snapshot import _rollback_create


# ----------------------------------------------------------------------------
# 1. _rollback_create handles letsencrypt_order
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rollback_create_drops_letsencrypt_order():
    conn = AsyncMock()
    ok = await _rollback_create(conn, "letsencrypt_order", entity_id=42)
    assert ok is True
    sql, *args = conn.execute.call_args.args
    assert "DELETE FROM letsencrypt_orders" in sql
    assert args[0] == 42


@pytest.mark.asyncio
async def test_rollback_create_letsencrypt_order_swallows_db_error():
    """If the DELETE fails, return False (not raise)."""
    conn = AsyncMock()
    conn.execute.side_effect = Exception("FK violation")
    ok = await _rollback_create(conn, "letsencrypt_order", entity_id=1)
    assert ok is False


@pytest.mark.asyncio
async def test_rollback_create_unknown_entity_type_returns_false():
    conn = AsyncMock()
    ok = await _rollback_create(conn, "made_up_thing", entity_id=1)
    assert ok is False
    conn.execute.assert_not_awaited()


# ----------------------------------------------------------------------------
# 2. cluster.py is_bulk_style_version recognises wizard prefix
# ----------------------------------------------------------------------------


def _is_bulk_style_version(version_name: str) -> bool:
    """Mirror of the predicate inside routers/cluster.py:apply_pending_changes.

    Pulled into a helper here so we can verify the recognised prefixes
    without standing up the full FastAPI app.
    """
    return (
        version_name.startswith("bulk-import-")
        or version_name.startswith("restore-")
        or version_name.startswith("bulk-site-create-")
        or version_name.startswith("bulk-proxied-host-create-")
    )


def test_is_bulk_style_version_recognises_wizard_prefix():
    assert _is_bulk_style_version("bulk-site-create-1715195200") is True
    # Phase D backward-compat: the legacy `bulk-proxied-host-create-`
    # prefix must keep matching so historical APPLIED versions still
    # reject cleanly after the rename.
    assert _is_bulk_style_version("bulk-proxied-host-create-1715195200") is True


def test_is_bulk_style_version_recognises_existing_prefixes():
    assert _is_bulk_style_version("bulk-import-12345") is True
    assert _is_bulk_style_version("restore-snapshot-99") is True


def test_is_bulk_style_version_rejects_arbitrary_names():
    assert _is_bulk_style_version("manual-edit-1") is False
    assert _is_bulk_style_version("ad-hoc-change") is False
    assert _is_bulk_style_version("user-edit-12345") is False


def test_is_bulk_style_version_actual_predicate_in_cluster_router():
    """Sanity-check that the cluster.py source file truly contains the
    wizard-version prefixes in BOTH locations:
      - the snapshot collection branch
      - the has_bulk_versions detection branch
    Both the current `bulk-site-create-` prefix AND the legacy
    `bulk-proxied-host-create-` prefix must be wired into both
    branches so reject cleanup works for current AND historical
    APPLIED versions.
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "cluster.py"
    text = src.read_text()
    # Current naming.
    site_occurrences = text.count("'bulk-site-create-'")
    assert site_occurrences >= 2, (
        f"Expected >= 2 'bulk-site-create-' occurrences in cluster.py, "
        f"found {site_occurrences}. The reject path only works when BOTH "
        f"branches recognise the wizard prefix (snapshot collect + "
        f"has_bulk_versions)."
    )
    # Legacy naming (Phase D backward-compat).
    legacy_occurrences = text.count("'bulk-proxied-host-create-'")
    assert legacy_occurrences >= 2, (
        f"Expected >= 2 'bulk-proxied-host-create-' (legacy) occurrences "
        f"in cluster.py, found {legacy_occurrences}. After the Phase D "
        f"rename the legacy prefix MUST still be wired into both "
        f"branches so historical APPLIED versions can still be "
        f"rejected/cleaned up."
    )


def test_letsencrypt_order_force_delete_branch_exists_in_cluster_router():
    """Sanity-check that the force-delete cleanup explicitly handles
    letsencrypt_orders (the wizard's staged ACME order).
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "cluster.py"
    text = src.read_text()
    assert "letsencrypt_orders" in text
    # The cluster router must include a DELETE for letsencrypt_orders in the
    # bulk-rejection force-delete sweep — otherwise the wizard's staged
    # ACME order would orphan when the bulk version is rejected.
    assert "DELETE FROM letsencrypt_orders" in text


def test_entity_snapshot_branch_for_letsencrypt_order_exists():
    """Sanity check that entity_snapshot.py truly has the letsencrypt_order
    branch (not just we hand-wrote the helper test above)."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent
           / "utils" / "entity_snapshot.py")
    text = src.read_text()
    assert 'entity_type == "letsencrypt_order"' in text
