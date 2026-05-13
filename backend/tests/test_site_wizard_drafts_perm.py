"""v1.5.0 R12 — Bug A regression: drafts permission relaxed.

After the v1.5.0 first deploy we observed `403 - Insufficient permissions`
for users who had ssl.read but no frontend.create / frontend.read. Drafts
are personal — every authenticated user with ANY of the
host-management permissions should be able to save / list / delete their
own drafts.

These tests are STATIC SOURCE assertions (no DB, no network) — they
verify that the routers/site_wizard.py module exposes a
`_can_use_wizard` helper and that the three draft endpoints are wired
through it instead of the original `check_user_permission(..., "frontend",
"create"/"read")` gate.

The point is to fail fast if a future refactor accidentally tightens the
RBAC again.
"""
from pathlib import Path

import pytest


SOURCE = (
    Path(__file__).resolve().parent.parent
    / "routers"
    / "site_wizard.py"
).read_text()


def test_can_use_wizard_helper_exists():
    assert "async def _can_use_wizard(" in SOURCE, (
        "Bug A regression: routers/site_wizard.py must define "
        "_can_use_wizard so drafts/suggest/preview share a single permission "
        "check."
    )


@pytest.mark.parametrize(
    "endpoint_signature",
    [
        # GET /drafts
        ('@router.get("/drafts")', "_can_use_wizard"),
        # POST /drafts
        ('@router.post("/drafts")', "_can_use_wizard"),
        # DELETE /drafts/{draft_id}
        ('@router.delete("/drafts/{draft_id}")', "_can_use_wizard"),
        # POST /preview
        ('@router.post("/preview"', "_can_use_wizard"),
    ],
)
def test_draft_endpoints_use_can_use_wizard(endpoint_signature):
    decorator, expected_helper = endpoint_signature
    idx = SOURCE.find(decorator)
    assert idx >= 0, f"Decorator {decorator!r} missing from site_wizard.py"
    # Look at the next ~60 lines after the decorator for the helper call.
    snippet = SOURCE[idx : idx + 2200]
    assert expected_helper in snippet, (
        f"Bug A regression: endpoint at {decorator!r} no longer calls "
        f"{expected_helper}. Drafts must remain accessible to read-only "
        "wizard users."
    )


def test_can_use_wizard_grants_read_only_users():
    # The helper should accept frontends.read OR ssl.read — i.e. it must NOT
    # be limited to *.create. We assert by looking for the literal tuple of
    # candidate perms.
    #
    # R18c round 10 (CRITICAL): the resource keys MUST be PLURAL
    # (frontends, backends) to match the seeded role permissions in
    # database/migrations.py. Pre-round-10 this test pinned the
    # singular form, which was technically present in the source
    # but never matched any non-admin role's permissions JSONB at
    # runtime — a textbook example of a static test passing while
    # the runtime contract was broken. Now we assert both: the
    # plural keys are PRESENT, and the singular keys are GONE.
    assert '"frontends", "read"' in SOURCE
    assert '"frontends", "create"' in SOURCE
    assert '"backends", "create"' in SOURCE
    assert '"backends", "read"' in SOURCE
    assert '"ssl", "read"' in SOURCE
    assert '"ssl", "create"' in SOURCE
    # The legacy singular forms must NOT appear inside the
    # _can_use_wizard candidate_perms tuple — but the SOURCE may still
    # contain unrelated occurrences (e.g. `"frontend": {...}` in the
    # preview response, `usage_type = "frontend"` SSL labels). We
    # therefore narrow the check to the candidate_perms block via a
    # balanced-paren walk identical to round 10's helper test.
    start = SOURCE.find("candidate_perms = (")
    assert start >= 0
    open_at = SOURCE.find("(", start)
    depth, end = 0, -1
    for i in range(open_at, len(SOURCE)):
        ch = SOURCE[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    block = SOURCE[start:end + 1]
    assert '"frontend", "read"' not in block
    assert '"frontend", "create"' not in block
    assert '"backend", "create"' not in block
    assert '"backend", "read"' not in block


def test_can_use_wizard_admin_shortcut_present():
    """R12 perf fix (Bulgu #f9): admin users should bypass the roles query
    entirely. The helper accepts an optional current_user dict and
    short-circuits on `is_admin`."""
    assert "current_user.get(\"is_admin\")" in SOURCE, (
        "Bulgu #f9 regression: _can_use_wizard must short-circuit on "
        "current_user['is_admin'] to avoid an unnecessary roles roundtrip "
        "for admin callers."
    )


def test_can_use_wizard_uses_single_get_user_permissions_call():
    """R12 perf fix: the helper must call get_user_permissions ONCE and
    decide locally, not chain 6 sequential check_user_permission calls
    (each opening a fresh DB connection)."""
    # The new implementation imports get_user_permissions from
    # auth_middleware and reads the dict in-memory.
    assert "get_user_permissions" in SOURCE, (
        "Bulgu #f9 regression: _can_use_wizard must use the bulk "
        "get_user_permissions(user_id) helper, not 6 sequential "
        "check_user_permission() round-trips."
    )


def test_callers_pass_current_user_to_can_use_wizard():
    """Each call site must hand the current_user dict to _can_use_wizard
    so the admin shortcut fires when applicable."""
    # We expect every "_can_use_wizard(user_id, current_user=current_user)"
    # call to appear at least once in the source. Less strict: the substring
    # 'current_user=current_user' appears at least 5 times (suggest, preview,
    # save_draft, list_drafts, delete_draft).
    n = SOURCE.count("current_user=current_user")
    assert n >= 5, (
        f"Expected at least 5 _can_use_wizard call sites passing current_user; "
        f"saw {n}. Did a refactor accidentally drop the kwarg from one of the "
        "endpoints?"
    )
