"""
R18c round 9 — Component file rename: ProxiedHost{Wizard,Drafts}.js → Site{Wizard,Drafts}.js
=============================================================================================

UI rebrand under v1.5.0 swung "Proxied Host" → "Site" for every label
(menu entry, page title, button) but the React component file names
were left as ProxiedHostWizard.js / ProxiedHostDrafts.js. R18c-#31
finishes the cleanup by also renaming the source files and the
exported component identifiers.

Goals locked in by this test file:

  Bulgu 1 — old file paths are gone (no stragglers in repo).
  Bulgu 2 — new file paths exist and export Site{Wizard,Drafts}.
  Bulgu 3 — App.js imports + route element references use the new names.
  Bulgu 4 — sessionStorage key migration: writers fire BOTH the new
            (`site_wizard_draft`) and the legacy
            (`proxied_host_wizard_draft`) keys for one release window;
            the wizard reads BOTH on mount and clears BOTH after a
            successful hydrate.
  Bulgu 5 — backend activity log message no longer says "proxied host"
            (UI consistency: history entries created post-rename read
            "Wizard-created site '...'" so the activity log matches the
            rebranded menu / page titles operators see in the UI).

This file is mostly static-source assertions (no FastAPI app boot
needed) so it runs cleanly in the backend-only Docker test image.
Frontend-source assertions are guarded with skipif when frontend/src
is missing (consistent with prior rounds).
"""

from __future__ import annotations

from pathlib import Path

import pytest

# R18c round 9 fix: in the backend-only Docker test image the source
# is mounted at /app (not /repo/backend), so `parents[2]` resolves to
# `/` and the test trips on a non-existent /backend/... path. Mirror
# the round-8 layout instead — _BACK is the directory that contains
# `routers/`, `models/`, `tests/` (regardless of whether that's
# `<repo>/backend/` or `/app/`), and the frontend tree is reached
# from its parent (which only exists in dev / full checkouts).
_BACK = Path(__file__).resolve().parent.parent
_FRONT = _BACK.parent / "frontend" / "src"

_FRONTEND_AVAILABLE = _FRONT.exists()

_WIZARD_NEW = _FRONT / "components" / "SiteWizard.js"
_DRAFTS_NEW = _FRONT / "components" / "SiteDrafts.js"
_WIZARD_OLD = _FRONT / "components" / "ProxiedHostWizard.js"
_DRAFTS_OLD = _FRONT / "components" / "ProxiedHostDrafts.js"
_APP = _FRONT / "App.js"


# ---------------------------------------------------------------------
# Bulgu 1 — old file paths are GONE
# ---------------------------------------------------------------------

@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_old_proxied_host_wizard_path_removed():
    """ProxiedHostWizard.js must no longer exist; the import path
    everywhere now resolves to SiteWizard.js."""
    assert not _WIZARD_OLD.exists(), (
        f"R18c-#31 regression: legacy {_WIZARD_OLD.name} still exists. "
        "Rename to SiteWizard.js (git mv to preserve blame) and update "
        "App.js + every backend test that statically pins the path."
    )


@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_old_proxied_host_drafts_path_removed():
    assert not _DRAFTS_OLD.exists(), (
        f"R18c-#31 regression: legacy {_DRAFTS_OLD.name} still exists. "
        "Rename to SiteDrafts.js and update App.js + backend tests."
    )


# ---------------------------------------------------------------------
# Bulgu 2 — new file paths exist and export Site{Wizard,Drafts}
# ---------------------------------------------------------------------

@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_site_wizard_exists_and_exports_site_wizard():
    assert _WIZARD_NEW.exists(), "SiteWizard.js must exist after the rename"
    src = _WIZARD_NEW.read_text()
    assert "const SiteWizard = (" in src, (
        "SiteWizard.js must declare the component as `const SiteWizard ="
    )
    assert "export default SiteWizard;" in src, (
        "SiteWizard.js must default-export `SiteWizard`. The old "
        "`ProxiedHostWizard` identifier is gone and any legacy "
        "import will surface as a build error."
    )


@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_site_drafts_exists_and_exports_site_drafts():
    assert _DRAFTS_NEW.exists(), "SiteDrafts.js must exist after the rename"
    src = _DRAFTS_NEW.read_text()
    assert "const SiteDrafts = (" in src, (
        "SiteDrafts.js must declare the component as `const SiteDrafts ="
    )
    assert "export default SiteDrafts;" in src, (
        "SiteDrafts.js must default-export `SiteDrafts`."
    )


# ---------------------------------------------------------------------
# Bulgu 3 — App.js wires the new names everywhere
# ---------------------------------------------------------------------

@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_app_imports_use_new_names():
    src = _APP.read_text()
    assert "import SiteWizard from './components/SiteWizard';" in src, (
        "App.js must import SiteWizard from './components/SiteWizard'"
    )
    assert "import SiteDrafts from './components/SiteDrafts';" in src, (
        "App.js must import SiteDrafts from './components/SiteDrafts'"
    )
    # And the old names must be GONE from App.js (no half-rename).
    assert "ProxiedHostWizard" not in src, (
        "App.js must not reference ProxiedHostWizard anymore (rename incomplete)"
    )
    assert "ProxiedHostDrafts" not in src, (
        "App.js must not reference ProxiedHostDrafts anymore (rename incomplete)"
    )


@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_app_routes_wire_new_components():
    """All three route layers (canonical /sites/*, R17 /quick-setup/*,
    v1.5.0 /proxied-hosts/*) must point to <SiteWizard /> / <SiteDrafts />
    so legacy bookmarked URLs keep working without resurrecting the old
    component identifiers."""
    src = _APP.read_text()
    expected_pairs = [
        ('path="/sites/new"', "<SiteWizard />"),
        ('path="/sites/drafts"', "<SiteDrafts />"),
        ('path="/quick-setup"', "<SiteWizard />"),
        ('path="/quick-setup/drafts"', "<SiteDrafts />"),
        ('path="/proxied-hosts/new"', "<SiteWizard />"),
        ('path="/proxied-hosts/drafts"', "<SiteDrafts />"),
    ]
    for path_marker, element_marker in expected_pairs:
        # Find the line containing the path and verify the same line
        # binds the element. Loose substring check is enough — the
        # File is small and the route lines are single-line.
        lines = [ln for ln in src.splitlines() if path_marker in ln]
        assert lines, f"App.js missing route: {path_marker}"
        assert any(element_marker in ln for ln in lines), (
            f"R18c-#31 regression: {path_marker} not wired to {element_marker}"
        )


# ---------------------------------------------------------------------
# Bulgu 4 — sessionStorage key migration (writer + reader)
# ---------------------------------------------------------------------

@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_drafts_writes_both_session_keys_for_resume():
    """SiteDrafts.handleResume must write the payload to BOTH the new
    `site_wizard_draft` key and the legacy `proxied_host_wizard_draft`
    key. This bridges the rename for one release window: a tab still
    running pre-rename SiteWizard JS keeps reading from the legacy key
    while the post-rename SiteWizard prefers the new one."""
    src = _DRAFTS_NEW.read_text()
    assert "const WIZARD_DRAFT_SESSION_KEY = 'site_wizard_draft';" in src, (
        "SiteDrafts must define the new sessionStorage key constant "
        "as `site_wizard_draft`"
    )
    assert (
        "const LEGACY_WIZARD_DRAFT_SESSION_KEY = 'proxied_host_wizard_draft';"
        in src
    ), (
        "SiteDrafts must define the legacy sessionStorage key constant "
        "as `proxied_host_wizard_draft`"
    )
    # Inside handleResume both setItem calls must reference the
    # constants — not bare strings (so the rename is the only place
    # to ever touch the key value).
    assert "sessionStorage.setItem(WIZARD_DRAFT_SESSION_KEY, serialized)" in src, (
        "handleResume must write the new session key"
    )
    assert (
        "sessionStorage.setItem(LEGACY_WIZARD_DRAFT_SESSION_KEY, serialized)"
        in src
    ), "handleResume must also write the legacy session key during the migration window"


@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_wizard_reads_both_session_keys_and_clears_both():
    """SiteWizard's hydrate effect must read from BOTH keys (new
    preferred, legacy fallback) and remove BOTH after consuming so a
    stale draft does not silently rehydrate on a later remount of the
    wizard component."""
    src = _WIZARD_NEW.read_text()
    assert "const WIZARD_DRAFT_SESSION_KEY = 'site_wizard_draft';" in src
    assert (
        "const LEGACY_WIZARD_DRAFT_SESSION_KEY = 'proxied_host_wizard_draft';"
        in src
    )
    # Read fallback chain
    assert (
        "sessionStorage.getItem(WIZARD_DRAFT_SESSION_KEY) ||" in src
        and "sessionStorage.getItem(LEGACY_WIZARD_DRAFT_SESSION_KEY)" in src
    ), (
        "SiteWizard must prefer the new key but fall back to the legacy "
        "one on hydrate"
    )
    # Clear both after consuming.
    assert "sessionStorage.removeItem(WIZARD_DRAFT_SESSION_KEY);" in src
    assert "sessionStorage.removeItem(LEGACY_WIZARD_DRAFT_SESSION_KEY);" in src


# ---------------------------------------------------------------------
# Bulgu 5 — backend activity log message uses "site"
# ---------------------------------------------------------------------

def test_wizard_activity_log_says_site_not_proxied_host():
    """The wizard's create_from_wizard handler writes a config_versions
    description that surfaces in the activity log / version history UI.
    Pre-rename it read 'Wizard-created proxied host ...' which created
    a copy mismatch with every other UI surface ('New Site (Wizard)',
    'Site Drafts', etc). Post-rename: 'Wizard-created site ...'. We
    keep the assertion simple — substring check on the router source —
    so a future refactor that re-introduces 'proxied host' in the log
    flag fails fast.

    NOTE: existing rows in config_versions.description are NOT
    rewritten; this is forward-only consistency for newly created
    versions."""
    router_path = _BACK / "routers" / "site_wizard.py"
    assert router_path.exists(), (
        f"backend/routers/site_wizard.py missing under {_BACK}; the "
        "test path layout assumption is wrong (see _BACK definition)."
    )
    src = router_path.read_text()
    assert "f\"Wizard-created site '" in src, (
        "R18c-#31 regression: wizard activity log message must say "
        "'Wizard-created site' to match the post-rebrand UI"
    )
    assert "Wizard-created proxied host" not in src, (
        "Stale 'Wizard-created proxied host' message must be removed"
    )
