"""
Phase 3 (R11-audit follow-up): wizard-vs-manual flow parity hardening.

The mandate is to bring the wizard up to par with the healthy
patterns the manual single-entity create endpoints have already
battle-tested in production. Where the manual flow has a guard
the wizard didn't have, the wizard now has the same guard.

Two healthy-pattern gaps were identified and closed in this commit:

  1. Reserved-name check on `body.frontend.name` AND `body.backend.name`.
     Manual `create_frontend` (`routers/frontend.py:442`) and
     `create_backend` (`routers/backend.py:545`) refuse names that
     collide with the well-known `listen stats` / `listen monitoring`
     blocks agents preserve from local config. The wizard used to let
     such names through; the apply-time `haproxy -c` would then fail
     with the confusing 'proxy has same name' error far away from the
     create site. Wizard now 400s on these names UP FRONT.

  2. `option httpchk` strip on `body.frontend.options`. Manual
     `create_frontend` runs payload.options through
     `filter_httpchk_from_options` so the backend-only directive
     never lands under a frontend (which produces a clean-but-
     irritating reload warning). Wizard now mirrors that filter
     on BOTH the HTTP and HTTPS frontend `model_copy` payloads.
"""
from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ROUTER = _ROOT / "routers" / "site_wizard.py"


def _src() -> str:
    return _ROUTER.read_text()


# ─────────────────────────────────────────────────────────────────────────────
# Reserved-name check
# ─────────────────────────────────────────────────────────────────────────────


def test_wizard_has_reserved_names_constant():
    """The wizard must declare the reserved-name set explicitly so a
    grep diff against `routers/frontend.py` / `routers/backend.py`
    confirms parity at code-review time."""
    src = _src()
    # Set membership: at least the four most common collisions.
    for name in ("stats", "haproxy-stats", "monitoring", "admin"):
        assert f'"{name}"' in src, (
            f"Phase 3 regression: reserved-name '{name}' is missing "
            "from the wizard's _RESERVED_NAMES set — wizard parity "
            "with manual create endpoints is broken."
        )


def test_wizard_reserved_name_check_blocks_frontend():
    """Reserved frontend names must hit a 400 before the wizard
    enters the atomic transaction (so we never persist a row whose
    name will collide with an agent-preserved listen block)."""
    src = _src()
    # The 400 raise that mentions 'reserved' must appear BEFORE the
    # `async with conn.transaction():` block.
    tx_idx = src.find("async with conn.transaction():")
    assert tx_idx > 0
    reserved_check_idx = src.find('Frontend name', src.find('_RESERVED_NAMES'))
    assert 0 < reserved_check_idx < tx_idx, (
        "Phase 3 regression: reserved-name check must run BEFORE the "
        "atomic transaction so it can raise 400 without leaving any "
        "DB rows behind."
    )


def test_wizard_reserved_name_check_blocks_backend():
    """Reserved backend names must also 400 (manual create_backend
    enforces the same set). Pin the reserved-set membership check
    against `body.backend.name.lower() in _RESERVED_NAMES`."""
    src = _src()
    # Both reserved-name guards must be present and reference the set.
    assert "body.frontend.name.lower() in _RESERVED_NAMES" in src, (
        "Phase 3 regression: frontend reserved-name guard is missing "
        "or no longer references _RESERVED_NAMES."
    )
    assert "body.backend.name.lower() in _RESERVED_NAMES" in src, (
        "Phase 3 regression: backend reserved-name guard is missing "
        "or no longer references _RESERVED_NAMES."
    )


def test_wizard_reserved_name_message_matches_manual():
    """The 400 detail wording must hint at 'listen stats' so the
    operator can act on it. Manual endpoints use the same wording."""
    src = _src()
    assert "listen stats" in src.lower(), (
        "Phase 3 regression: reserved-name 400 detail must mention "
        "'listen stats' so the operator understands why the name is "
        "blocked. Parity with manual endpoints."
    )


# ─────────────────────────────────────────────────────────────────────────────
# `option httpchk` strip on frontend options
# ─────────────────────────────────────────────────────────────────────────────


def test_wizard_filters_httpchk_from_frontend_options():
    """`option httpchk` is BACKEND-only — it must be stripped from
    the wizard's frontend `options` block before the row is
    inserted. The filter helper is defined locally in the wizard
    and applied to BOTH the HTTP and HTTPS frontend payloads."""
    src = _src()
    assert "_filter_httpchk_from_options" in src, (
        "Phase 3 regression: wizard must declare a local "
        "_filter_httpchk_from_options helper to strip backend-only "
        "directives from the frontend options block."
    )
    # The filter must be applied to BOTH model_copy paths.
    occurrences = src.count("_frontend_options_filtered")
    assert occurrences >= 3, (
        "Phase 3 regression: _frontend_options_filtered should be "
        f"used in 3 places (filter site + http payload + https "
        f"payload), but found {occurrences}. The HTTPS branch may "
        f"have been dropped."
    )


def test_filter_httpchk_helper_drops_only_exact_match():
    """The local filter implementation must be EXACT-match (case-
    insensitive `option httpchk` line). It MUST NOT drop
    `option httpchk-strict` or `option httpchk send-state` etc.
    (manual `filter_httpchk_from_options` has the same contract)."""
    src = _src()
    # The filter implementation lambda / function must use a strict
    # equality compare on the stripped+lowered line.
    assert 'line.strip().lower() != "option httpchk"' in src, (
        "Phase 3 regression: _filter_httpchk_from_options must use "
        "STRICT-EQUALITY filtering (`line.strip().lower() != "
        "\"option httpchk\"`). A `startswith` check would also drop "
        "valid variants like `option httpchk send-state`."
    )


def test_filter_httpchk_handles_none_and_empty():
    """The filter must short-circuit on None / empty string (manual
    parity)."""
    src = _src()
    # `if not options: return options` short-circuit must be present.
    assert "if not options:" in src and "return options" in src, (
        "Phase 3 regression: _filter_httpchk_from_options must "
        "short-circuit on None / empty so a missing `options` field "
        "doesn't crash the wizard."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4: preview parity (operator must see the same warning
# the create endpoint hard-blocks on, so they correct names BEFORE
# they invest time filling the rest of the wizard form)
# ─────────────────────────────────────────────────────────────────────────────


def test_preview_surfaces_reserved_name_warning_for_frontend():
    """The wizard preview endpoint must list a reserved-name warning
    when `body.frontend.name` is in the same set the create
    endpoint blocks on. Pre-fix the operator filled the wizard,
    hit Submit, and only THEN saw the 400 — preview now warns
    up front."""
    src = _src()
    # The preview's reserved-name warning must mention "is reserved"
    # AND "Frontend name" alongside the warnings.append call.
    assert "_PREVIEW_RESERVED_NAMES" in src, (
        "Phase 4 regression: preview endpoint must declare its own "
        "reserved-name set (decoupled from the create endpoint's "
        "constant so the two can be moved independently to a shared "
        "module later)."
    )
    assert "will be rejected at create time" in src, (
        "Phase 4 regression: preview reserved-name warning must "
        "explain that the wizard will REJECT this name at create "
        "time so the operator knows the warning is actionable."
    )


def test_preview_reserved_name_check_covers_both_entities():
    """Both frontend and backend names must be checked in preview
    (manual parity — both manual `create_frontend` and
    `create_backend` enforce this set)."""
    src = _src()
    # Slice the preview branch to avoid false positives from the
    # create branch.
    preview_start = src.find("warnings: List[str] = []")
    create_start = src.find("Pre-create checks (must succeed before transaction)")
    assert preview_start > 0 and create_start > preview_start
    preview_slice = src[preview_start:create_start]
    assert (
        "body.frontend.name.lower() in _PREVIEW_RESERVED_NAMES" in preview_slice
    ), "Phase 4 regression: preview missing frontend reserved-name guard"
    assert (
        "body.backend.name.lower() in _PREVIEW_RESERVED_NAMES" in preview_slice
    ), "Phase 4 regression: preview missing backend reserved-name guard"
