"""v1.5.0 R18c round 5 audit fixes — final convergence sweep.

Findings discovered during R18c round 5 (after R18c rounds 1-4):

  R18c-#19 (`GET /api/users` info leak — KRITIK): pre-fix any
    authenticated user could fetch the FULL user roster (username,
    email, phone, full_name, is_admin, roles, cluster_ids,
    timestamps). Mutations were already admin-only; the read path
    now matches.

  R18c-#20 (`GET /api/roles` info leak — KRITIK): pre-fix any
    authenticated user could read the full RBAC layout —
    permissions blob and cluster_ids per role. Invaluable
    reconnaissance for privilege escalation. Now admin-only.

  R18c-#21 (Wizard ignores `cluster.acme_enabled` — KRITIK
    functional): pre-fix the wizard staged ACME orders against
    clusters whose `acme_enabled` flag was false. The HAProxy
    config generator only injects the `/.well-known/acme-challenge`
    routing block when that flag is true, so the order's HTTP-01
    validation always failed with no clear cause. The wizard now
    rejects ACME staging on disabled clusters with a clear 400
    pointing the operator at the cluster's ACME toggle.
"""
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent


# ----------------- R18c-#19: get_users admin guard -----------------


def test_get_users_requires_admin():
    src = (_REPO / "routers" / "user.py").read_text()
    fn_idx = src.find("async def get_users")
    assert fn_idx != -1
    body = src[fn_idx:fn_idx + 1500]
    assert "is_admin" in body, (
        "R18c-#19 KRITIK info leak regression: GET /api/users no "
        "longer checks is_admin — full operator roster (incl. "
        "emails, is_admin flags) leaks to any authenticated caller"
    )
    assert "status_code=403" in body, (
        "R18c-#19 regression: non-admin path no longer raises 403"
    )


# ----------------- R18c-#20: get_roles admin guard -----------------


def test_get_roles_requires_admin():
    src = (_REPO / "routers" / "user.py").read_text()
    fn_idx = src.find("async def get_roles")
    assert fn_idx != -1
    body = src[fn_idx:fn_idx + 1500]
    assert "is_admin" in body, (
        "R18c-#20 KRITIK info leak regression: GET /api/roles no "
        "longer checks is_admin — full RBAC permissions blob leaks "
        "to any authenticated caller"
    )
    assert "status_code=403" in body, (
        "R18c-#20 regression: non-admin path no longer raises 403"
    )


# ----------------- R18c-#21: wizard respects cluster.acme_enabled -----------------


def test_wizard_rejects_acme_on_disabled_cluster():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # The wizard CREATE flow must SELECT acme_enabled before
    # staging an ACME order.
    create_idx = src.find("async def create_site")
    assert create_idx != -1
    body = src[create_idx:]
    # The cluster acme_enabled SELECT must be inside the
    # `body.ssl.mode == "acme"` branch.
    acme_block_start = body.find('if body.ssl.mode == "acme":', body.find("ACME mode: resolve account"))
    assert acme_block_start != -1, (
        "R18c-#21 regression: ACME mode block anchor missing in "
        "create_proxied_host — cannot verify cluster guard"
    )
    acme_block = body[acme_block_start:acme_block_start + 2500]
    assert "acme_enabled FROM haproxy_clusters" in acme_block, (
        "R18c-#21 KRITIK functional regression: wizard CREATE no "
        "longer checks the cluster's acme_enabled flag before "
        "staging an order — operators stage doomed orders that "
        "fail HTTP-01 because the cluster does not route "
        "/.well-known/acme-challenge"
    )
    assert "acme_enabled=false" in acme_block.lower() or "has acme_enabled=false" in acme_block, (
        "R18c-#21 regression: error message no longer mentions the "
        "cluster's flag, depriving operators of the actionable hint"
    )
    assert "status_code=400" in acme_block, (
        "R18c-#21 regression: ACME-on-disabled-cluster no longer "
        "raises 400"
    )
