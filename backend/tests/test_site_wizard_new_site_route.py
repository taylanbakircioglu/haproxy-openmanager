"""v1.5.0 R18 — "New Site (Wizard)" rebrand regression tests.

History of the rebrand chain (kept in this single test for clarity):
  - v1.5.0 first deploy:   "New Proxied Host" — under Frontends submenu
  - R17:                   "Quick Setup"      — top-level Quick Setup group
  - R18 (this round):      "New Site (Wizard)"— top-level Sites group

Naming rationale (R18, after user feedback):
  "Quick Setup" was ambiguous — it could mean cluster, account or TLS
  setup. "New Site (Wizard)" matches the dominant terminology in the
  ingress / reverse-proxy space (Cloudflare 'Add a site', nginx-proxy-
  manager 'Proxy Hosts', Plesk/cPanel 'Add domain', Caddy 'Sites'). The
  group label is "Sites" — entity-oriented, mirroring the existing
  Frontends / Backend Servers / SSL Certificates pattern.

Backward-compat invariants under test:
  1. Canonical /sites/new + /sites/drafts routes resolve.
  2. R17 /quick-setup{,/drafts} aliases still resolve.
  3. v1.5.0 /proxied-hosts/{new,drafts} aliases still resolve.
  4. Sidebar 'sites-group' precedes 'frontends-group' (primary onboarding).
  5. Frontends submenu does NOT contain wizard links (no duplicates).
  6. Card titles + Drafts page Resume button target the new canonical paths.
"""
import re
from pathlib import Path

import pytest


_REPO_FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend" / "src"
_APP_JS = _REPO_FRONTEND / "App.js"
_WIZARD_JS = _REPO_FRONTEND / "components" / "SiteWizard.js"
_DRAFTS_JS = _REPO_FRONTEND / "components" / "SiteDrafts.js"


def _read(p: Path) -> str:
    if not p.exists():
        pytest.skip(f"frontend tree not mounted at {p} — backend-only env")
    return p.read_text()


# ----------------- Routes -----------------


def test_canonical_sites_route_exists():
    src = _read(_APP_JS)
    assert re.search(
        r'<Route\s+path="/sites/new"\s+element=\{<SiteWizard',
        src,
    ), "R18 regression: canonical /sites/new route not wired to SiteWizard"


def test_canonical_sites_drafts_route_exists():
    src = _read(_APP_JS)
    assert re.search(
        r'<Route\s+path="/sites/drafts"\s+element=\{<SiteDrafts',
        src,
    ), "R18 regression: canonical /sites/drafts route not wired to SiteDrafts"


def test_r17_quick_setup_aliases_preserved():
    """Backward-compat: bookmarks created during the R17 (Quick Setup)
    window must still resolve."""
    src = _read(_APP_JS)
    assert re.search(
        r'<Route\s+path="/quick-setup"\s+element=\{<SiteWizard',
        src,
    ), "R18 regression: R17 /quick-setup alias removed (breaks recent bookmarks)"
    assert re.search(
        r'<Route\s+path="/quick-setup/drafts"\s+element=\{<SiteDrafts',
        src,
    ), "R18 regression: R17 /quick-setup/drafts alias removed"


def test_v15_proxied_hosts_aliases_preserved():
    """Backward-compat: v1.5.0 first-deploy bookmarks/issue links must
    still resolve."""
    src = _read(_APP_JS)
    assert re.search(
        r'<Route\s+path="/proxied-hosts/new"\s+element=\{<SiteWizard',
        src,
    ), "R18 regression: v1.5.0 /proxied-hosts/new alias removed"
    assert re.search(
        r'<Route\s+path="/proxied-hosts/drafts"\s+element=\{<SiteDrafts',
        src,
    ), "R18 regression: v1.5.0 /proxied-hosts/drafts alias removed"


# ----------------- Sidebar order + label -----------------


def test_sites_group_appears_before_frontends_link():
    """The Sites group must come before the Frontends link.

    R18b round 8 update: `frontends-group` was flattened to a single
    top-level `/frontends` link (the group only had one child after
    R18 removed the wizard duplicates). The Sites-before-Frontends
    invariant still holds — primary onboarding (the wizard) sits
    above the lower-level Frontends list page.
    """
    src = _read(_APP_JS)
    sites_idx = src.find("'sites-group'")
    # Match the new top-level Frontends link key.
    fe_idx = src.find("key: '/frontends',")
    assert sites_idx != -1, "R18 regression: 'sites-group' menu key missing"
    assert fe_idx != -1, "R18b round 8 regression: top-level Frontends key missing"
    assert sites_idx < fe_idx, (
        "Sites group must precede the Frontends link in menuItems — "
        "rebrand goal is making the wizard the primary onboarding path"
    )


def test_frontends_group_subpage_was_flattened():
    """R18b round 8: the Frontends entry must be a top-level link,
    NOT a `frontends-group` with a single 'All Frontends' child.

    The pre-R18b shape (single child under a collapsible group) was
    a leftover from when wizard links lived under the same group.
    Now that `sites-group` owns onboarding, a single-child group is
    pure click-cost with no navigational benefit.
    """
    src = _read(_APP_JS)
    # The legacy collapsible-group shape must be gone.
    assert "key: 'frontends-group'" not in src, (
        "R18b round 8 regression: 'frontends-group' menu key still "
        "present — flatten to a top-level /frontends link instead"
    )
    # The legacy single-child label "All Frontends" must be gone too.
    assert ">All Frontends<" not in src, (
        "R18b round 8 regression: 'All Frontends' subpage label still "
        "present in App.js — flatten to top-level 'Frontends'"
    )
    # Top-level Frontends link must use a plain Link to /frontends.
    assert '<Link to="/frontends">Frontends</Link>' in src, (
        "R18b round 8 regression: top-level Frontends Link missing or "
        "label changed unexpectedly"
    )


def test_old_quick_setup_group_removed():
    """The R17 'quick-setup-group' menu key must be GONE — its presence
    after R18 would mean two duplicate top-level groups (Sites +
    Quick Setup) confusing operators."""
    src = _read(_APP_JS)
    # The string can still appear in legacy comments; what we forbid is
    # the actual menuItems entry. A plain `key: 'quick-setup-group'`
    # check is good enough to catch the regression.
    assert "key: 'quick-setup-group'" not in src, (
        "R18 regression: stale 'quick-setup-group' menu key still "
        "present — would render duplicate Sites + Quick Setup groups"
    )


def test_sites_group_uses_action_icon():
    """ThunderboltOutlined is the action-oriented icon used on the
    primary 'New Site' child item — guard against accidentally removing
    the import while keeping the JSX reference (runtime crash)."""
    src = _read(_APP_JS)
    assert "ThunderboltOutlined" in src, (
        "R18 regression: ThunderboltOutlined import dropped while still "
        "referenced in the Sites menu item — runtime crash"
    )


def test_default_open_keys_handles_all_route_generations():
    """defaultOpenKeys must expand the Sites group on canonical AND
    every legacy alias path — otherwise a user landing on a
    bookmarked old URL sees the menu in a confusing collapsed state."""
    src = _read(_APP_JS)
    for prefix in ("/sites", "/quick-setup", "/proxied-hosts"):
        assert re.search(
            rf"selectedKey\.startsWith\('{re.escape(prefix)}'\)",
            src,
        ), f"R18 regression: defaultOpenKeys no longer expands on {prefix}"
    # And the group it opens MUST be the new sites-group, not the
    # stale R17 quick-setup-group.
    assert "'sites-group'" in src
    assert "['quick-setup-group']" not in src, (
        "R18 regression: defaultOpenKeys still references the stale "
        "R17 'quick-setup-group' — the Sites group will not auto-open"
    )


# ----------------- Card title + Drafts navigation -----------------


def test_wizard_card_title_rebranded():
    src = _read(_WIZARD_JS)
    assert re.search(
        r'<Card\s+title="New Site \(Wizard\)"',
        src,
    ), "R18 regression: SiteWizard Card title not 'New Site (Wizard)'"


def test_drafts_card_title_rebranded():
    src = _read(_DRAFTS_JS)
    assert 'title="Site Drafts"' in src, (
        "R18 regression: SiteDrafts Card title not 'Site Drafts'"
    )


def test_drafts_resume_targets_canonical_sites_path():
    """The Resume button on the Drafts page must navigate to the
    canonical /sites/new — legacy aliases still work but new
    navigations target the rebrand for cleaner browser history."""
    src = _read(_DRAFTS_JS)
    assert "navigate('/sites/new')" in src, (
        "R18 regression: Site Drafts Resume button no longer targets "
        "/sites/new"
    )


def test_wizard_cancel_modal_targets_canonical_drafts_path():
    """handleCancel save-and-navigate must target /sites/drafts."""
    src = _read(_WIZARD_JS)
    assert "navigate('/sites/drafts');" in src, (
        "R18 regression: handleCancel no longer targets /sites/drafts"
    )


def test_toast_messages_use_site_terminology():
    """User-facing success toasts on submit must use 'Site' (the new
    terminology) — leaving them as 'Proxied host' creates a mixed
    vocabulary in the same flow."""
    src = _read(_WIZARD_JS)
    assert "Site created and applied successfully" in src
    assert "Site created (PENDING version" in src
