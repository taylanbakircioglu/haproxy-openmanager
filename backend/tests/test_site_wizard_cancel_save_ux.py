"""v1.5.0 R14 #R14-3 — wizard cancel UX must not navigate on save fail.

Before R14, SiteWizard.handleCancel.onCancel awaited
handleSaveDraft() and ALWAYS navigated to /proxied-hosts/drafts —
even when the save itself failed. The user saw an error toast and
landed on an empty drafts list, losing all in-flight wizard state.

R14 fix: handleSaveDraft returns boolean (true on success, false on
failure); onCancel only navigates when the save succeeded.

Static source assertions on the React component.
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


def test_handle_save_draft_returns_boolean():
    """The save-draft handler must return true on success and false on
    failure so callers can branch on the outcome."""
    assert "return true" in WIZARD_JS, (
        "R14-3 regression: handleSaveDraft must `return true` on the "
        "successful axios.post path."
    )
    assert "return false" in WIZARD_JS, (
        "R14-3 regression: handleSaveDraft must `return false` in the "
        "catch block. Otherwise handleCancel can't tell success from "
        "failure and silently navigates the user away from the wizard."
    )


def test_handle_cancel_branches_on_save_result():
    """handleCancel.onCancel must check the boolean from handleSaveDraft
    and only navigate to the drafts list on success."""
    assert "const ok = await handleSaveDraft();" in WIZARD_JS, (
        "R14-3 regression: handleCancel must capture the boolean result "
        "of handleSaveDraft so it can branch on success vs. failure."
    )
    # The navigate call must be guarded by the success branch.
    assert "if (ok) {" in WIZARD_JS
    # R18 rebrand: drafts page moved to /sites/drafts (was R17 /quick-
    # setup/drafts; before that v1.5.0 /proxied-hosts/drafts). The
    # legacy aliases still resolve for old bookmarks but new
    # navigations target the current canonical path.
    assert "navigate('/sites/drafts');" in WIZARD_JS


def test_handle_cancel_does_not_navigate_unconditionally():
    """The OLD pattern was an unconditional `await ...; navigate(...)`.
    Lock that down across all rebrand generations: v1.5.0 /proxied-hosts/
    drafts, R17 /quick-setup/drafts, R18 /sites/drafts. Any of those
    appearing right after `await handleSaveDraft();` (without an `if (ok)`
    guard in between) is a regression."""
    bad_patterns = [
        ("v1.5.0 alias", (
            "        await handleSaveDraft();\n"
            "        navigate('/proxied-hosts/drafts');"
        )),
        ("R17 alias", (
            "        await handleSaveDraft();\n"
            "        navigate('/quick-setup/drafts');"
        )),
        ("R18 canonical", (
            "        await handleSaveDraft();\n"
            "        navigate('/sites/drafts');"
        )),
    ]
    for label, pat in bad_patterns:
        assert pat not in WIZARD_JS, (
            f"R14-3 regression ({label}): the old unconditional "
            "`await; navigate;` pattern reappeared. handleCancel must "
            "guard the navigate behind the boolean returned by "
            "handleSaveDraft."
        )
