"""Phase B / D / F static-source pin tests for the post-rebrand
Site Wizard surface.

These tests exercise three orthogonal slices of the rename:

  Phase B : API URL prefix moved from ``/api/proxied-hosts`` to
            ``/api/sites``; ``main.py`` exposes a hidden 308-redirect
            alias so external integrators still pointing at the old
            slug keep working.
  Phase D : audit-log version-name shape moved from
            ``bulk-proxied-host-create-{ts}`` to
            ``bulk-site-create-{ts}``; ``cluster.py`` reject path
            recognises BOTH prefixes (current + legacy) so historical
            APPLIED versions still clean up.
  Phase F : the Site Wizard now embeds the ``ACLRuleBuilder`` React
            component used by the standalone Frontend Management page.
            The wizard fetches cluster-scoped backends, lets the
            operator define ACL / use_backend / redirect rules
            visually, persists them in drafts, and injects the three
            arrays into the create + preview payloads on submit.

All assertions are static source reads — they don't stand up the
FastAPI app or render React. The intent is to pin the *contract* so a
follow-up refactor that accidentally drops one of the rename branches
fails immediately at CI rather than silently shipping a regression.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_BACK = Path(__file__).resolve().parent.parent
_FRONT = _BACK.parent / "frontend"

_SITE_ROUTER = _BACK / "routers" / "site_wizard.py"
_SITE_MODELS = _BACK / "models" / "site_wizard.py"
_MAIN = _BACK / "main.py"
_CLUSTER = _BACK / "routers" / "cluster.py"
_ACTIVITY = _BACK / "middleware" / "activity_logger.py"


# ---------------------------------------------------------------------------
# Phase A pin: module files exist under the new names AND the legacy
# proxied_host.py module path is gone — no backward-compat in source
# tree, only in URL slug + Pydantic alias.
# ---------------------------------------------------------------------------


def test_phase_a_module_files_renamed():
    assert _SITE_ROUTER.is_file(), (
        "Phase A regression: backend/routers/site_wizard.py is missing — "
        "the wizard router file rename is the foundation of the whole "
        "Site rebrand."
    )
    assert _SITE_MODELS.is_file(), (
        "Phase A regression: backend/models/site_wizard.py is missing — "
        "the wizard Pydantic models file rename is part of the Site "
        "rebrand."
    )
    legacy_router = _BACK / "routers" / "proxied_host.py"
    legacy_models = _BACK / "models" / "proxied_host.py"
    assert not legacy_router.exists(), (
        "Phase A regression: the legacy backend/routers/proxied_host.py "
        "is back — the rename must remove the old file. Re-importing "
        "from the legacy module would split the wizard surface into "
        "two parallel routers."
    )
    assert not legacy_models.exists(), (
        "Phase A regression: the legacy backend/models/proxied_host.py "
        "is back — same divergence risk as the router file."
    )


# ---------------------------------------------------------------------------
# Phase B pin: API URL prefix moved + 308 redirect alias preserved.
# ---------------------------------------------------------------------------


def test_phase_b_router_prefix_is_api_sites():
    src = _SITE_ROUTER.read_text()
    assert 'prefix="/api/sites"' in src, (
        "Phase B regression: the wizard APIRouter prefix is no longer "
        "/api/sites — the canonical URL has moved."
    )
    assert 'prefix="/api/proxied-hosts"' not in src, (
        "Phase B regression: the legacy /api/proxied-hosts prefix has "
        "been re-mounted on the primary router. The legacy slug must "
        "live ONLY on the 308-redirect alias in main.py, otherwise "
        "OpenAPI emits two parallel schemas and external integrators "
        "see a confusing duplicate surface."
    )


def test_phase_b_main_py_registers_legacy_redirect_alias():
    src = _MAIN.read_text()
    # Both the bare-root and the wildcard subpath alias must exist
    # (POST /api/proxied-hosts and POST /api/proxied-hosts/preview etc.
    # need separate handlers because FastAPI does not match `/path` and
    # `/path/{rest}` with a single route).
    assert '"/api/proxied-hosts"' in src, (
        "Phase B regression: the legacy /api/proxied-hosts root alias "
        "is missing from main.py — POST /api/proxied-hosts (bare) "
        "would 404 instead of redirecting to /api/sites."
    )
    assert '"/api/proxied-hosts/{rest:path}"' in src, (
        "Phase B regression: the legacy /api/proxied-hosts/* subpath "
        "alias is missing from main.py — every legacy URL except the "
        "bare root would 404."
    )
    assert "status_code=308" in src, (
        "Phase B regression: the legacy alias must use 308 (Permanent "
        "Redirect) so POST/PUT/DELETE preserve method + body. A 301 "
        "or 302 would coerce POST → GET and break the create call."
    )
    assert "include_in_schema=False" in src, (
        "Phase B regression: the legacy alias must be hidden from "
        "OpenAPI so new consumers only see the canonical /api/sites "
        "URLs."
    )


# ---------------------------------------------------------------------------
# Phase B pin: activity_logger middleware short-circuits BOTH the new
# canonical slug AND the legacy slug for POST so the wizard owns its
# own audit row without the middleware producing a duplicate.
# ---------------------------------------------------------------------------


def test_phase_b_activity_logger_short_circuits_both_slugs():
    src = _ACTIVITY.read_text()
    assert "'/api/sites'" in src, (
        "Phase B regression: activity_logger no longer recognises the "
        "canonical /api/sites slug — wizard create POSTs would fall "
        "through to the generic CRUD branch and produce a duplicate "
        "audit row."
    )
    assert "'/api/proxied-hosts'" in src, (
        "Phase B regression: activity_logger no longer recognises the "
        "legacy /api/proxied-hosts slug — although the 308 redirect "
        "intercepts it in practice, the safety-net entry must remain "
        "to defend against any pre-redirect 2xx leak."
    )


# ---------------------------------------------------------------------------
# Phase D pin: version-name shape moved + dual-prefix reject path.
# ---------------------------------------------------------------------------


def test_phase_d_router_emits_bulk_site_create_version_name():
    src = _SITE_ROUTER.read_text()
    assert 'version_name = f"bulk-site-create-{ts}"' in src, (
        "Phase D regression: the wizard router no longer emits the "
        "canonical bulk-site-create-{ts} version name — bulk-version "
        "history would render the old proxied-host shape under the "
        "new product name."
    )
    assert 'f"bulk-proxied-host-create-{ts}"' not in src, (
        "Phase D regression: the wizard router is STILL emitting the "
        "legacy bulk-proxied-host-create-{ts} name — operators see "
        "two competing prefixes in Apply Management."
    )


def test_phase_d_cluster_reject_recognises_both_prefixes():
    src = _CLUSTER.read_text()
    # `is_bulk_version` predicate AND `has_bulk_versions` probe — both
    # branches must accept the current `bulk-site-create-` prefix.
    assert src.count("'bulk-site-create-'") >= 2, (
        "Phase D regression: cluster.py reject path no longer "
        "recognises the canonical bulk-site-create- prefix in BOTH "
        "branches (snapshot collect + has_bulk_versions probe). "
        "Reject of newly-applied wizard versions would fall back to "
        "the generic frontend/backend cleanup, which doesn't know "
        "about the wizard's brand-new entities."
    )
    # Legacy prefix must STILL be wired into both branches so older
    # APPLIED versions remain rejectable.
    assert src.count("'bulk-proxied-host-create-'") >= 2, (
        "Phase D regression: cluster.py reject path dropped the legacy "
        "bulk-proxied-host-create- prefix in one or both branches. "
        "Historical APPLIED versions created before this rename can "
        "no longer be cleaned up cleanly."
    )


def test_phase_d_router_action_name_is_wizard_create_site():
    src = _SITE_ROUTER.read_text()
    assert 'action="wizard_create_site"' in src, (
        "Phase D regression: the wizard's explicit log_user_activity "
        "no longer emits the post-rename `wizard_create_site` action "
        "string — audit reports tracking wizard creates lose their "
        "primary signal."
    )


# ---------------------------------------------------------------------------
# Phase C pin: Pydantic classes renamed + module-level backward-compat
# aliases preserved.
# ---------------------------------------------------------------------------


def test_phase_c_pydantic_classes_renamed_with_aliases():
    src = _SITE_MODELS.read_text()
    # New canonical class names.
    for new_class in (
        "class SiteCreate(BaseModel):",
        "class SitePreflightAcme(BaseModel):",
        "class SiteDraftCreate(BaseModel):",
    ):
        assert new_class in src, (
            f"Phase C regression: canonical Pydantic class declaration "
            f"`{new_class}` is missing — the rename to Site* did not "
            "land."
        )
    # Backward-compat aliases — direct module-level references so
    # OpenAPI does not see a second ghost schema.
    for alias in (
        "ProxiedHostCreate = SiteCreate",
        "ProxiedHostPreflightAcme = SitePreflightAcme",
        "ProxiedHostDraftCreate = SiteDraftCreate",
    ):
        assert alias in src, (
            f"Phase C regression: backward-compat alias `{alias}` is "
            "missing — existing `from models.site_wizard import "
            "ProxiedHostCreate` callers would fail with "
            "ImportError."
        )


# ---------------------------------------------------------------------------
# Phase E pin: frontend axios calls all point at /api/sites/* (not the
# legacy slug). The 308 alias would still work, but every wizard call
# would pay an extra round-trip — pin the canonical URL on the client.
# ---------------------------------------------------------------------------


def _front_or_skip(rel: str) -> str:
    p = _FRONT / "src" / "components" / rel
    if not p.exists():
        pytest.skip(f"frontend tree not mounted ({rel})")
    return p.read_text()


def test_phase_e_sitewizard_uses_api_sites():
    src = _front_or_skip("SiteWizard.js")
    for canonical in (
        "axios.get('/api/sites/suggest'",
        "axios.post('/api/sites/preflight-acme'",
        "axios.post('/api/sites/preview'",
        "axios.post('/api/sites'",
        "axios.post('/api/sites/drafts'",
    ):
        assert canonical in src, (
            f"Phase E regression: SiteWizard.js no longer calls the "
            f"canonical URL `{canonical}` — every wizard request "
            "would hit the legacy /api/proxied-hosts slug and pay "
            "an extra 308 round-trip."
        )
    # No raw legacy /api/proxied-hosts axios calls should remain on
    # the primary code paths (comments are allowed).
    suspicious = [
        line for line in src.splitlines()
        if "/api/proxied-hosts" in line and "//" not in line.split("/api/proxied-hosts")[0][-3:]
    ]
    # Leave a generous tolerance for inline-template strings that
    # embed the legacy slug for documentation.
    assert len(suspicious) <= 1, (
        "Phase E regression: SiteWizard.js still has axios calls to "
        f"/api/proxied-hosts — found {len(suspicious)} non-comment "
        "occurrences. The 308 alias should be the EXTERNAL fallback "
        "only; the wizard itself must use the canonical slug."
    )


def test_phase_e_sitedrafts_uses_api_sites():
    src = _front_or_skip("SiteDrafts.js")
    for canonical in (
        "axios.get('/api/sites/drafts')",
        "axios.post('/api/sites/preview'",
        "/api/sites/drafts/${draft.id}",
    ):
        assert canonical in src, (
            f"Phase E regression: SiteDrafts.js no longer calls the "
            f"canonical URL `{canonical}` — every drafts page request "
            "would hit the legacy /api/proxied-hosts slug."
        )


# ---------------------------------------------------------------------------
# Phase F pin: SiteWizard embeds ACLRuleBuilder, fetches cluster-scoped
# backends, persists ACL state in drafts, and injects the three rule
# arrays into the create + preview payloads on submit.
# ---------------------------------------------------------------------------


def test_phase_f_sitewizard_imports_acl_rule_builder():
    src = _front_or_skip("SiteWizard.js")
    assert "import ACLRuleBuilder from './ACLRuleBuilder'" in src, (
        "Phase F regression: SiteWizard.js no longer imports the "
        "ACLRuleBuilder component — the wizard's Routing & ACLs "
        "section would render nothing."
    )


def test_phase_f_sitewizard_renders_acl_rule_builder():
    src = _front_or_skip("SiteWizard.js")
    assert "<ACLRuleBuilder" in src, (
        "Phase F regression: SiteWizard.js no longer mounts an "
        "<ACLRuleBuilder /> JSX element on the Frontend step — the "
        "operator falls back to the free-text textarea UX, which is "
        "exactly what the rename was meant to fix."
    )
    # The builder must receive all three rule arrays plus the cluster
    # backend list and an onChange callback.
    for prop in (
        "aclRules={aclBuilderData.aclRules}",
        "useBackendRules={aclBuilderData.useBackendRules}",
        "redirectRules={aclBuilderData.redirectRules}",
        "backends={aclBuilderBackends}",
        "onChange={(data) => setAclBuilderData(data)}",
    ):
        assert prop in src, (
            f"Phase F regression: SiteWizard.js <ACLRuleBuilder /> no "
            f"longer wires the `{prop}` prop — the builder cannot "
            "render or persist the operator's edits."
        )


def test_phase_f_sitewizard_fetches_cluster_backends():
    src = _front_or_skip("SiteWizard.js")
    assert "axios.get('/api/backends'" in src, (
        "Phase F regression: SiteWizard.js no longer fetches cluster-"
        "scoped backends for the use_backend_rules dropdown — the "
        "operator can only route ACLs to the wizard's brand-new "
        "backend, which defeats the parity-with-FrontendManagement "
        "intent."
    )
    assert "setClusterBackends" in src, (
        "Phase F regression: SiteWizard.js no longer maintains a "
        "clusterBackends state — the ACL builder dropdown would "
        "always be empty."
    )


def test_phase_f_sitewizard_injects_acl_into_create_payload():
    src = _front_or_skip("SiteWizard.js")
    # Submit handler must inject the three arrays under
    # `frontend.acl_rules / use_backend_rules / redirect_rules` so the
    # backend's FrontendStep validator accepts them.
    create_block_idx = src.find("axios.post('/api/sites'")
    assert create_block_idx != -1, "Phase F regression: create POST not found"
    # Look back ~40 lines from the create call to the submit setup.
    pre = src[max(0, create_block_idx - 4000): create_block_idx]
    for required in (
        "aclBuilderData.aclRules",
        "aclBuilderData.useBackendRules",
        "aclBuilderData.redirectRules",
        "acl_rules:",
        "use_backend_rules:",
        "redirect_rules:",
    ):
        assert required in pre, (
            f"Phase F regression: handleSubmit no longer injects the "
            f"`{required}` field into the wizard create payload — the "
            "ACL rules typed in the builder would never reach the "
            "backend."
        )


def test_phase_f_sitewizard_injects_acl_into_preview_payload():
    src = _front_or_skip("SiteWizard.js")
    preview_idx = src.find("axios.post('/api/sites/preview'")
    assert preview_idx != -1, "Phase F regression: preview POST not found"
    pre = src[max(0, preview_idx - 1500): preview_idx]
    for required in (
        "aclBuilderData.aclRules",
        "aclBuilderData.useBackendRules",
        "aclBuilderData.redirectRules",
    ):
        assert required in pre, (
            f"Phase F regression: previewConfig no longer injects "
            f"`{required}` into the preview payload — the diff "
            "preview would NOT show the ACL/redirect lines the operator "
            "just typed in the builder."
        )


def test_phase_f_sitewizard_persists_acl_in_draft():
    src = _front_or_skip("SiteWizard.js")
    draft_idx = src.find("axios.post('/api/sites/drafts'")
    assert draft_idx != -1, "Phase F regression: draft POST not found"
    pre = src[max(0, draft_idx - 1500): draft_idx]
    assert "aclBuilderData.aclRules" in pre, (
        "Phase F regression: handleSaveDraft no longer persists the "
        "ACL builder state — a resumed draft hydrates with empty "
        "rules, the operator has to redo their routing config."
    )


def test_phase_f_sitewizard_hydrates_acl_on_resume():
    src = _front_or_skip("SiteWizard.js")
    # The mount-only resume effect must hydrate aclBuilderData from
    # the parsed payload's frontend.acl_rules / use_backend_rules /
    # redirect_rules.
    assert "resumedFE.acl_rules" in src or "parsed.frontend.acl_rules" in src or "(parsed && parsed.frontend) || {}" in src, (
        "Phase F regression: SiteWizard.js no longer hydrates the "
        "ACL builder from a resumed draft — the saved rules render "
        "as if the operator never typed them."
    )
    assert "setAclBuilderKey" in src, (
        "Phase F regression: SiteWizard.js no longer bumps the "
        "ACL builder key on hydrate — a controlled-component cache "
        "from the previous render keeps the empty arrays even after "
        "setAclBuilderData."
    )


# ---------------------------------------------------------------------------
# Phase I pin: DB-level Site rebrand — wizard_drafts.wizard_type DEFAULT
# moved from 'proxied_host' to 'site'; application code uses dual-value
# IN-list reads/deletes so pre-rename rows still surface; new INSERTs
# emit the canonical 'site' value.
# ---------------------------------------------------------------------------


def test_phase_i_migration_alters_wizard_drafts_default_to_site():
    src = (_BACK / "database" / "migrations.py").read_text()
    # Idempotent ALTER … SET DEFAULT 'site'. Match either single or
    # double-quoted SQL string literal forms a fmtter might produce.
    import re as _re
    assert _re.search(
        r"ALTER\s+TABLE\s+wizard_drafts\s+ALTER\s+COLUMN\s+wizard_type\s+SET\s+DEFAULT\s+'site'",
        src,
    ), (
        "Phase I regression: migrations.py no longer issues the "
        "ALTER TABLE wizard_drafts ALTER COLUMN wizard_type SET "
        "DEFAULT 'site' statement — fresh installs would still get "
        "the old 'proxied_host' default and emit pre-rebrand rows."
    )
    # The CREATE TABLE branch (taken on truly-fresh installs where
    # the table does not exist yet) must already declare the new
    # default so we don't depend on the ALTER pass for first-deploys.
    assert "DEFAULT 'site'" in src, (
        "Phase I regression: wizard_drafts CREATE TABLE no longer "
        "declares wizard_type DEFAULT 'site'. First-deploy "
        "installations would still create the column with the old "
        "default."
    )
    # And the legacy default must NOT appear inside the live CREATE
    # TABLE statement anymore (matching only the comment-prose
    # mention is fine — the failure mode we're guarding against is a
    # regression that re-introduces the old default in CREATE).
    create_block_idx = src.find("CREATE TABLE wizard_drafts")
    assert create_block_idx != -1, (
        "Phase I regression: CREATE TABLE wizard_drafts not found"
    )
    create_block = src[create_block_idx: create_block_idx + 2000]
    assert "DEFAULT 'proxied_host'" not in create_block, (
        "Phase I regression: CREATE TABLE wizard_drafts still "
        "declares the legacy `wizard_type … DEFAULT 'proxied_host'` "
        "— the DEFAULT migration would do nothing on first-deploy."
    )


def test_phase_i_router_dual_filter_on_drafts_select_and_count():
    src = _SITE_ROUTER.read_text()
    # The 50-draft cap query AND the list_drafts SELECT must use the
    # dual-value IN-list so pre-rebrand drafts are counted/listed.
    assert src.count("wizard_type IN ('site', 'proxied_host')") >= 2, (
        "Phase I regression: the wizard router no longer issues a "
        "dual-value IN-list filter on wizard_type — pre-rebrand "
        "drafts (wizard_type='proxied_host') would be invisible to "
        "their owner after the rename, both in the listing and the "
        "50-draft cap."
    )
    # New INSERT emits the canonical 'site' value (legacy literal
    # must NOT appear in the INSERT statement anymore).
    insert_idx = src.find("INSERT INTO wizard_drafts")
    assert insert_idx != -1, (
        "Phase I regression: INSERT INTO wizard_drafts not found"
    )
    insert_block = src[insert_idx: insert_idx + 800]
    assert "VALUES ($1, 'site'" in insert_block, (
        "Phase I regression: the wizard INSERT no longer emits the "
        "canonical 'site' value — new drafts would still be tagged "
        "with the legacy 'proxied_host' value, defeating the rename."
    )
    assert "'proxied_host'" not in insert_block, (
        "Phase I regression: the wizard INSERT still references the "
        "legacy 'proxied_host' literal — should be 'site' post-Phase-I."
    )


def test_phase_i_cluster_delete_dual_filter_for_drafts_purge():
    src = _CLUSTER.read_text()
    assert "wizard_type IN ('site', 'proxied_host')" in src, (
        "Phase I regression: cluster.py delete handler no longer "
        "purges BOTH legacy `proxied_host` and post-rebrand `site` "
        "drafts whose payload pointed at the deleted cluster — "
        "pre-rename orphans would linger until the 30-day TTL fires."
    )


def test_phase_i_rate_limit_dual_aliases_legacy_action_name():
    """Phase I Audit Loop #1 finding: the wizard's per-user-per-minute
    rate-limit COUNT(*) over user_activity_logs used to filter on the
    legacy `proxied_host_acme_preflight` action_name. Phase D
    activity_logger middleware now emits `site_acme_preflight` for
    the same endpoint, so a single-name filter was effectively
    counting nothing — the limit was bypassed.

    Pin the dual-name behaviour: the helper accepts a canonical
    `site_*` action and auto-aliases the legacy `proxied_host_*`
    companion so a deploy mid-minute cannot reset the quota.
    """
    src = _SITE_ROUTER.read_text()
    # ANY($2::text[]) signals an array-valued IN-list parameter.
    assert "ANY($2::text[])" in src, (
        "Phase I regression: _enforce_rate_limit no longer issues "
        "an ANY(::text[]) lookup — it likely degraded back to the "
        "single-action_name filter that the Phase D activity_logger "
        "rename silently bypassed."
    )
    # The auto-alias derivation must derive the legacy
    # `proxied_host_*` name from the canonical `site_*` input.
    assert "proxied_host_" in src and "site_" in src, (
        "Phase I regression: _enforce_rate_limit auto-alias logic "
        "no longer derives the legacy proxied_host_* companion from "
        "the canonical site_* action — pre-rename log rows are "
        "uncounted."
    )
    # Caller emits the canonical name (post-rebrand).
    assert '"site_acme_preflight"' in src, (
        "Phase I regression: preflight call site no longer passes "
        'the canonical "site_acme_preflight" action — should match '
        "activity_logger's middleware-emitted action."
    )


def test_phase_i_resource_type_emit_is_site():
    src = _SITE_ROUTER.read_text()
    # The wizard's explicit log_user_activity call must emit
    # `resource_type='site'` so newly-created audit rows are
    # consistent with activity_logger's new 'site' resource type
    # for the same path.
    assert 'resource_type="site"' in src, (
        "Phase I regression: the wizard's log_user_activity no "
        "longer emits resource_type='site' — new audit rows would "
        "still carry the legacy 'proxied_host' resource_type and "
        "diverge from activity_logger's middleware-emitted rows."
    )
    assert 'resource_type="proxied_host"' not in src, (
        "Phase I regression: the wizard router still emits "
        "resource_type='proxied_host' somewhere — should be 'site' "
        "post-Phase-I."
    )


def test_phase_f_sitewizard_blocks_https_redirect_with_redirect_rules():
    src = _front_or_skip("SiteWizard.js")
    # The submit handler must short-circuit when https_redirect is on
    # AND redirectRules is non-empty (FrontendStep validator catches
    # this with a 422; surfacing earlier is friendlier UX).
    assert "https_redirect" in src and "redirectRules.length" in src, (
        "Phase F regression: SiteWizard.js no longer pre-validates "
        "the mutually-exclusive https_redirect ⊕ redirect_rules "
        "combination — the operator clicks Submit, waits for a "
        "round-trip, then sees an opaque 422."
    )
    assert "mutually exclusive" in src or "cannot be combined" in src, (
        "Phase F regression: the https_redirect / redirect_rules "
        "guard message is missing or off-vocabulary — the operator "
        "won't know why the wizard refused to submit."
    )
