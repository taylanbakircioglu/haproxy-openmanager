"""v1.5.0 R18 audit ROUND 3 — broader system fixes.

Findings discovered during the third-round audit:

  R18-#11 (UX/data): Deleting a cluster left every operator's saved
    Site Drafts orphaned: `wizard_drafts.payload->>'cluster_id'`
    pointed at a non-existent cluster, breaking Resume until the 30d
    TTL pruned them. Cluster delete now cascades a JSONB-path-based
    DELETE on `wizard_drafts`.

  R18-#12 (Drift): Manual `BackendConfig` and `BackendConfigUpdate`
    accepted leading-underscore names. The agent's reverse-sync filter
    `_should_sync_backend` silently dropped any such row, producing
    silent control-plane drift between DB and on-disk haproxy.cfg.
    Pydantic `validator('name')` now rejects the prefix at API entry,
    matching the wizard's pre-existing constraint.

  R18-#13 (DX): Swagger `/api/docs` listed wizard endpoints under
    "Proxied Host Wizard". External integrators skimming the docs
    couldn't find them after the Sites rebrand. Tag is now
    "Sites (New Site Wizard)".
"""
import re
from pathlib import Path

import pytest

import importlib


_REPO = Path(__file__).resolve().parent.parent


# ----------------- R18-#11: cluster delete cascades drafts -----------------


def test_cluster_delete_prunes_wizard_drafts_referencing_cluster():
    """The cluster delete handler must DELETE every wizard_drafts row
    whose payload's `cluster_id` JSON path matches the deleted cluster.
    Without this Resume on those drafts surfaces a stale cluster_id
    that no longer exists in `haproxy_clusters`."""
    src = (_REPO / "routers" / "cluster.py").read_text()
    # Look for the JSONB-path DELETE inside the delete_cluster
    # transaction. The numeric-cast regex `~ '^[0-9]+$'` is the
    # safety guard so non-numeric payloads don't blow up the cast.
    # Phase I: the wizard_type filter is now a dual-value IN-list so
    # both pre-rebrand (`proxied_host`) and post-rebrand (`site`)
    # drafts get cleaned up when their target cluster is deleted.
    # Match either the legacy single-value form OR the post-Phase-I
    # IN-list form so this pin survives across the rebrand window.
    assert re.search(
        r"DELETE\s+FROM\s+wizard_drafts\s+WHERE\s+wizard_type\s+IN\s*\(\s*'site'\s*,\s*'proxied_host'\s*\)",
        src,
    ) or re.search(
        r"DELETE\s+FROM\s+wizard_drafts\s+WHERE\s+wizard_type\s*=\s*'proxied_host'",
        src,
    ), (
        "R18-#11 regression: cluster delete no longer prunes "
        "wizard_drafts referencing the deleted cluster (neither the "
        "pre-Phase-I single-value form nor the post-Phase-I dual-"
        "value IN-list form is present)"
    )
    assert "(payload->>'cluster_id')::int" in src, (
        "R18-#11 regression: missing JSONB path cast for cluster_id "
        "in the wizard_drafts cleanup query"
    )
    assert "~ '^[0-9]+$'" in src, (
        "R18-#11 regression: missing numeric-only safety guard before "
        "the int cast — non-numeric payloads will raise"
    )


# ----------------- R18-#12: manual backend rejects `_` prefix -----------------


def test_manual_backend_create_rejects_leading_underscore():
    from models.backend import BackendConfig
    with pytest.raises(Exception) as exc:
        BackendConfig(name="_foo", cluster_id=1)
    assert "underscore" in str(exc.value).lower() or "_" in str(exc.value), (
        "R18-#12 regression: BackendConfig no longer rejects leading "
        "underscore — manual API accepts a name the agent will silently "
        "drop on reverse-sync"
    )


def test_manual_backend_update_rejects_leading_underscore_rename():
    from models.backend import BackendConfigUpdate
    with pytest.raises(Exception) as exc:
        BackendConfigUpdate(name="_renamed_to_system_thing")
    assert "_" in str(exc.value), (
        "R18-#12 regression: BackendConfigUpdate no longer rejects "
        "rename to a leading-underscore name"
    )


def test_manual_backend_create_accepts_normal_name():
    """Belt-and-braces: ensure the new validator does not over-reject."""
    from models.backend import BackendConfig
    # No exception should be raised.
    BackendConfig(name="my_app_backend", cluster_id=1)


# ----------------- R18-#13: OpenAPI tag rebrand -----------------


def test_site_wizard_router_tag_uses_sites_terminology():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # Old tag must be gone, new tag must be present.
    assert '"Proxied Host Wizard"' not in src, (
        "R18-#13 regression: stale 'Proxied Host Wizard' OpenAPI tag "
        "still present"
    )
    assert '"Sites (New Site Wizard)"' in src, (
        "R18-#13 regression: OpenAPI tag no longer rebranded to "
        "'Sites (New Site Wizard)'"
    )


# ----------------- R18-#14: entity_snapshot module doc polish -----------------


def test_entity_snapshot_module_doc_is_english():
    """The historical Turkish/English mix in the module docstring
    looked unpolished for an enterprise codebase. Round 3 polished it.
    Lock that down — nobody should re-introduce a Turkish phrase here."""
    src = (_REPO / "utils" / "entity_snapshot.py").read_text()
    # Cheap sentinel — the previous Turkish prose contained "Bu modül"
    # and "güvenli başlangıç". Both must be gone from the module
    # docstring (the very first triple-quoted block).
    head = src[: src.find("import json")]
    assert "Bu modül" not in head, (
        "R18-#14 regression: Turkish phrase 'Bu modül' reappeared in "
        "the module docstring"
    )
    assert "güvenli başlangıç" not in head, (
        "R18-#14 regression: Turkish phrase 'güvenli başlangıç' "
        "reappeared in the module docstring"
    )
