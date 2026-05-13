"""v1.5.0 R15 hotfix — TDZ (Temporal Dead Zone) regression guard.

The original v1.5.0 R12-R14 wizard JSX referenced `sslMode` inside the
stepContents array literal (e.g. `{sslMode === 'acme' && (<Alert .../>)}`),
but the actual `const sslMode = Form.useWatch(...)` lived ~40 lines
BELOW the array literal. That's a const referenced before its
declaration in the same render scope.

In dev mode webpack/SWC keep the original variable names so the JS
engine's TDZ check often happens to short-circuit on undefined access
(or the eager re-render cycle re-evaluates with sslMode already bound),
but the production minified build produced the user-facing crash:

    ReferenceError: Cannot access 'N' before initialization
    at Fde (SiteWizard.js:1093:12)

R15 hotfix: hoist `const sslMode = Form.useWatch(...)` and
`const acmeBlocksDraft = ...` to the top of the component, immediately
after the state hooks, so every downstream JSX expression sees them
already initialised.

This test pins the ordering with a static source assertion. Failure
means someone moved the watcher back below stepContents and the bug is
about to ship to prod.
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
        f"frontend not present at {_WIZARD_PATH}; backend-only container "
        "is expected — skip wizard JS source assertions",
        allow_module_level=True,
    )


WIZARD_JS = _WIZARD_PATH.read_text()
LINES = WIZARD_JS.splitlines()


def _line_of(needle: str) -> int:
    """Return the 1-based line number of the first line containing
    `needle`, or raise AssertionError if not found."""
    for i, line in enumerate(LINES, start=1):
        if needle in line:
            return i
    raise AssertionError(f"expected to find {needle!r} in SiteWizard.js")


def test_form_use_watch_for_sslmode_appears_only_once():
    """`Form.useWatch(['ssl', 'mode'], form)` must be declared exactly
    once. Any duplicate (forgotten leftover from R15 hoisting) means
    React would call useWatch twice per render — wasteful, and risks
    re-introducing the TDZ if the second declaration shadows the first."""
    occurrences = WIZARD_JS.count("Form.useWatch(['ssl', 'mode'], form)")
    assert occurrences == 1, (
        f"R15 regression: Form.useWatch(['ssl', 'mode'], form) appears "
        f"{occurrences} times. Expected exactly 1 — duplicate watchers "
        "are wasted and may shadow each other."
    )


def test_sslmode_declared_before_stepcontents():
    """The TDZ fix: `const sslMode = ...` must come BEFORE the
    `stepContents` array literal which references sslMode inline."""
    sslmode_line = _line_of("const sslMode = Form.useWatch")
    stepcontents_line = _line_of("const stepContents = [")
    assert sslmode_line < stepcontents_line, (
        f"R15 regression: const sslMode is declared at line {sslmode_line} "
        f"but stepContents (which references sslMode) starts at line "
        f"{stepcontents_line}. With the production minifier this becomes "
        "a TDZ crash: \"Cannot access 'N' before initialization\"."
    )


def test_acme_blocks_draft_declared_with_sslmode():
    """SUPERSEDED by Phase K Phase D (Bulgu #6).

    The `acmeBlocksDraft` const was the TDZ-safe derivation that
    fed the (now-retired) "Create as PENDING" button's disabled
    state. With the unified single-button UI, the derivation is
    no longer needed — handleSubmit's `effectiveApply = sslModeAtSubmit
    === 'acme'` does the same job at submit time. We re-pin the
    NEW constraint: the unified button label `submitButtonLabel`
    must be derived AFTER sslMode (consistent with the original
    R15 TDZ-safety contract) and BEFORE the JSX that consumes it.
    """
    sslmode_line = _line_of("const sslMode = Form.useWatch")
    submit_label_line = _line_of("const submitButtonLabel =")
    button_consumption_line = _line_of("{submitButtonLabel}")
    assert sslmode_line < submit_label_line < button_consumption_line, (
        f"Phase K Phase D regression: TDZ ordering. sslMode at "
        f"line {sslmode_line}, submitButtonLabel at {submit_label_line}, "
        f"button consumption at {button_consumption_line}. "
        "submitButtonLabel must be declared AFTER sslMode and "
        "BEFORE the button JSX that consumes it."
    )


def test_no_late_redeclaration_of_sslmode_after_stepcontents():
    """Make sure no leftover `const sslMode = Form.useWatch(...)` lingers
    AFTER stepContents (would shadow the hoisted one and re-trigger the
    TDZ in production)."""
    stepcontents_line = _line_of("const stepContents = [")
    # Find every line that declares sslMode via useWatch.
    decls = [
        i + 1 for i, line in enumerate(LINES)
        if "const sslMode = Form.useWatch" in line
    ]
    late = [d for d in decls if d > stepcontents_line]
    assert not late, (
        f"R15 regression: const sslMode = Form.useWatch redeclared at "
        f"line(s) {late}, AFTER stepContents at line {stepcontents_line}. "
        "Either the hoisted top-of-component declaration was reverted, "
        "or a duplicate was added."
    )
