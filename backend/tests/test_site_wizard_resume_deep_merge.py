"""v1.5.0 R13 — Bulgu #v9: resume must deep-merge draft into initialValues.

Before R13, SiteWizard.js used a flat spread
    form.setFieldsValue({ ...initialValues, ...parsed })
when hydrating from a saved draft. JS spread is shallow: any top-level
key in `parsed` (e.g. `parsed.ssl = {mode: 'acme', auto_renew: true}`)
WHOLLY replaced the initialValues group object — wiping the new R12
advanced defaults (ssl_alpn, ssl_min_ver, hsts_*, backend timeouts,
etc.). The user resumed an older draft and silently lost the modern
defaults.

The fix introduces a per-group _mergeGroup helper and merges
backend/frontend/ssl shallowly so missing nested keys fall back to
initialValues. servers stays as a wholesale array replacement (or
initialValues fallback when the list is empty/missing).

These are static source-level assertions on the React component.
"""
from pathlib import Path

import pytest


_WIZARD_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "src"
    / "components"
    / "SiteWizard.js"
)


if not _WIZARD_PATH.exists():
    pytest.skip(
        f"frontend not present at {_WIZARD_PATH}; running in backend-only "
        "container is expected — skip wizard JS source assertions",
        allow_module_level=True,
    )


WIZARD_JS = _WIZARD_PATH.read_text()


def test_merge_group_helper_present():
    """The fix must expose a _mergeGroup helper and use it in resume."""
    assert "_mergeGroup" in WIZARD_JS, (
        "Bulgu #v9 regression: SiteWizard.js must define a "
        "_mergeGroup helper so resume hydrates each top-level group "
        "(backend/frontend/ssl) as a SHALLOW merge instead of a "
        "wholesale replace."
    )


def test_resume_merges_backend_frontend_ssl_groups():
    """Each of backend / frontend / ssl must go through _mergeGroup."""
    for group in ("backend", "frontend", "ssl"):
        assert f"{group}: _mergeGroup(initialValues.{group}, parsed.{group})" in WIZARD_JS, (
            f"Bulgu #v9 regression: {group!r} group is no longer merged "
            "via _mergeGroup. A flat spread would let an old draft wipe "
            "the modern R12 defaults that the wizard pre-populates."
        )


def test_servers_array_uses_safe_fallback():
    """servers is an array (not a dict) — the fix must keep the parsed
    list when non-empty, fall back to initialValues otherwise."""
    assert "Array.isArray(parsed.servers) && parsed.servers.length" in WIZARD_JS, (
        "Bulgu #v9 regression: servers must fall back to initialValues "
        "when the saved draft has an empty/missing list, otherwise the "
        "wizard renders 0 server rows after resume."
    )


def test_old_flat_spread_pattern_removed():
    """The old `{...initialValues, ...parsed}` pattern must be gone (or
    only appear inside a clearly-different context). Lock down by
    asserting the literal sequence used in the previous implementation
    no longer appears as the entire setFieldsValue argument."""
    bad = "form.setFieldsValue({ ...initialValues, ...parsed });"
    assert bad not in WIZARD_JS, (
        f"Bulgu #v9 regression: {bad!r} reappeared. Use _mergeGroup-based "
        "deep merge instead so old drafts pick up new initialValues defaults."
    )
