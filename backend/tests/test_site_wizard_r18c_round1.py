"""v1.5.0 R18c round 1 audit fixes — peripheral impact tests.

Findings discovered during R18c round 1 (peripheral impact of
R18 + R18b changes):

  R18c-#1 (KRITIK — uncommitted-data invisibility): the wizard CREATE
    endpoint and the ACME post-completion path generated a fresh
    HAProxy config snapshot via
    `generate_haproxy_config_for_cluster(cluster_id)` — without
    passing the active transaction connection. Under PostgreSQL READ
    COMMITTED, a SECOND pooled connection cannot see the uncommitted
    INSERTs that just created the wizard's backend / servers /
    frontend rows in the same transaction. Result: the
    config_versions snapshot SILENTLY OMITTED the wizard-created
    entities and the operator's apply re-deployed a config without
    the new site even though the API said "created successfully".
    Now both call sites pass `conn` so the snapshot reflects the
    uncommitted state.

  R18c-#2 (Migration safety — UndefinedColumnError): rolling
    deploys can hit the wizard endpoint while migrations are still
    catching up to add new columns (e.g. backend_servers
    `ssl_certificate_id`). Pre-fix that surfaced as 500 with raw
    asyncpg error text. Now mapped to 503 with the same "run
    migrations" hint as the missing-table case.

  R18c-#3 (Bulk rollback iteration order): rejecting a wizard
    PENDING walked `bulk_snapshots` forward (backend → servers →
    ssl_certificate → HTTP frontend → HTTPS frontend). With strict
    FK schemas (frontends.ssl_certificate_id REFERENCES
    ssl_certificates.id) the cert delete fired BEFORE the
    referencing frontend was deleted, hitting an FK violation and
    aborting the rollback half-way. Now iteration is reversed —
    children before parents.

  R18c-#4 (Duplicate audit log): the wizard CREATE endpoint emits
    its own `wizard_create_proxied_host` row from the router. The
    SPECIAL_ACTIONS map ALSO entered `proxied_host_created` for the
    same endpoint, so every successful wizard create produced TWO
    user_activity_logs rows. Removed the SPECIAL_ACTIONS entry AND
    short-circuited the middleware for POST /api/proxied-hosts so
    no fallback path can re-introduce the duplicate.
"""
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent


# ----------------- R18c-#1: uncommitted data visibility -----------------


def test_wizard_create_passes_conn_to_config_generator():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # The wizard's config-gen call must pass the transaction conn.
    assert "generate_haproxy_config_for_cluster(body.cluster_id, conn)" in src, (
        "R18c-#1 KRITIK regression: wizard CREATE no longer passes "
        "the transaction connection into config generation. Without "
        "it, the config_versions snapshot OMITS the wizard's "
        "uncommitted INSERTs and the operator's subsequent apply "
        "deploys a config without the new site."
    )
    # The pre-fix bare-form call must be gone.
    assert "generate_haproxy_config_for_cluster(body.cluster_id)" not in src.replace(
        "generate_haproxy_config_for_cluster(body.cluster_id, conn)", ""
    ), (
        "R18c-#1 KRITIK regression: a bare "
        "`generate_haproxy_config_for_cluster(body.cluster_id)` call "
        "is back in the wizard CREATE flow"
    )


def test_acme_post_completion_passes_conn_to_config_generator():
    src = (_REPO / "routers" / "letsencrypt.py").read_text()
    # The ACME post-completion HTTPS frontend creation must also
    # pass the transaction conn.
    assert "generate_haproxy_config_for_cluster(cluster_id, conn)" in src, (
        "R18c-#1 KRITIK regression: ACME post-completion no longer "
        "passes the transaction connection — the freshly-created "
        "HTTPS frontend is silently omitted from the post-completion "
        "config_versions snapshot, so the cert never goes live until "
        "the next manual config consolidation."
    )


# ----------------- R18c-#2: UndefinedColumnError → 503 -----------------


def test_wizard_create_imports_undefined_column_error():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    assert "UndefinedColumnError" in src, (
        "R18c-#2 regression: wizard router no longer imports "
        "UndefinedColumnError — migration lag (missing column) "
        "surfaces as a generic 500 with raw asyncpg text"
    )
    assert "except UndefinedColumnError" in src, (
        "R18c-#2 regression: create endpoint no longer catches "
        "UndefinedColumnError"
    )
    catch_block = src[src.find("except UndefinedColumnError"):]
    catch_block = catch_block[:catch_block.find("except UndefinedTableError")]
    assert "status_code=503" in catch_block, (
        "R18c-#2 regression: UndefinedColumnError handler no longer "
        "raises 503"
    )
    assert "migrations" in catch_block.lower(), (
        "R18c-#2 regression: 503 detail no longer mentions migrations"
    )


# ----------------- R18c-#3: rollback reverse order -----------------


def test_bulk_rollback_walks_snapshots_in_reverse():
    src = (_REPO / "routers" / "cluster.py").read_text()
    # The reverse-order iteration must be present.
    assert "reversed(bulk_snapshots)" in src, (
        "R18c-#3 regression: bulk_snapshots rollback no longer walks "
        "in reverse — strict FK schemas will FK-violate when the "
        "ssl_certificate snapshot tries to DELETE before the "
        "referencing frontend is deleted, leaving a half-rolled-back "
        "cluster"
    )


# ----------------- R18c-#4: duplicate audit log -----------------


def test_special_actions_no_longer_entries_proxied_host_create():
    src = (_REPO / "middleware" / "activity_logger.py").read_text()
    # The bare `/api/proxied-hosts` SPECIAL_ACTIONS entry must be gone.
    assert "'/api/proxied-hosts': 'proxied_host_created'" not in src, (
        "R18c-#4 regression: SPECIAL_ACTIONS still maps "
        "POST /api/proxied-hosts → 'proxied_host_created' — the "
        "wizard now emits its own richer audit row, so this entry "
        "produces a duplicate user_activity_logs row per create"
    )
    # The non-create wizard endpoints must still be logged.
    for kept in (
        "'/api/proxied-hosts/preview'",
        "'/api/proxied-hosts/preflight-acme'",
        "'/api/proxied-hosts/drafts'",
        "'/api/proxied-hosts/drafts/{draft_id}'",
    ):
        assert kept in src, (
            f"R18c-#4 regression: {kept} dropped from SPECIAL_ACTIONS — "
            "preview / preflight / draft endpoints will no longer be "
            "audited"
        )


def test_middleware_short_circuits_proxied_hosts_post():
    src = (_REPO / "middleware" / "activity_logger.py").read_text()
    # The middleware fast-path must skip POST /api/sites (current
    # canonical) AND POST /api/proxied-hosts (legacy 308 alias) so
    # neither path produces a duplicate audit row.
    assert "'/api/sites'" in src and "'/api/proxied-hosts'" in src, (
        "R18c-#4 regression: middleware short-circuit no longer "
        "covers BOTH the canonical /api/sites slug and the legacy "
        "/api/proxied-hosts alias — Phase B/D rename has dropped "
        "one of them"
    )
    assert "request.method == 'POST'" in src, (
        "R18c-#4 regression: middleware no longer short-circuits the "
        "wizard create POST — the standard CRUD fallback can still "
        "produce a duplicate audit row"
    )
