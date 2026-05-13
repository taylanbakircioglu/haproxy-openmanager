"""v1.5.0 R12 — Bug B regression: wizard form must keep ALL step contents
mounted at all times.

In the first 1.5.0 deploy we observed `422 - Validation error` with body
`{apply_immediately: true}` even though the user had filled in the form.
Root cause: the wizard rendered only the active step's content, so Antd
Form.Item registrations for non-visible steps were unmounted and
`form.validateFields()` returned only the visible step's fields. Submit
then sent a body containing nothing but `apply_immediately`.

The fix renders every step's content at all times and toggles visibility
with `display: none`. We pin this fix in source via the assertions below
so a future refactor (e.g. switching back to a single-render Steps
container) cannot silently regress the bug.
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

# Skip the whole module when frontend tree isn't checked out alongside the
# backend (e.g. inside the backend-only Docker container, where only /app
# is mounted). Tests still run on the host and in CI where the full
# repository is present.
if not _WIZARD_PATH.exists():
    pytest.skip(
        f"frontend not present at {_WIZARD_PATH}; running in backend-only "
        "container is expected — skip wizard JS source assertions",
        allow_module_level=True,
    )

WIZARD_JS = _WIZARD_PATH.read_text()


def test_all_step_contents_always_mounted():
    """The wizard must map over all stepContents, NOT index by current step."""
    # Positive marker: stepContents.map(...) renders every step.
    assert "stepContents.map((s, idx)" in WIZARD_JS, (
        "Bug B regression: SiteWizard must render ALL steps so Antd "
        "Form.Item registrations stay alive across step navigation. Use "
        "stepContents.map(...) with display:none gating, not stepContents[step]."
    )
    # Visibility gate: display: 'block' / 'none'.
    assert "step === idx ? 'block' : 'none'" in WIZARD_JS


def test_old_single_step_render_removed():
    """The old single-render pattern must be gone."""
    bad_pattern = "<div>{stepContents[step].content}</div>"
    assert bad_pattern not in WIZARD_JS, (
        f"Bug B regression: {bad_pattern!r} only renders one step at a "
        "time and unmounts the others, causing validateFields()/getFieldsValue "
        "to return an incomplete payload."
    )


def test_submit_uses_get_fields_value_true_fallback():
    """handleSubmit should belt-and-braces merge getFieldsValue(true) so
    that even if a future tweak breaks the always-mounted invariant, we
    still send the full state."""
    # Look at the body of handleSubmit (loose match — survive minor edits).
    idx = WIZARD_JS.find("const handleSubmit")
    assert idx >= 0
    body = WIZARD_JS[idx : idx + 2000]
    assert "form.validateFields()" in body
    assert "form.getFieldsValue(true)" in body, (
        "Bug B regression: handleSubmit should merge getFieldsValue(true) "
        "as a fallback so display:none + form.preserve quirks cannot drop "
        "fields from the POST body."
    )


def test_preview_uses_get_fields_value_true():
    """runPreview must capture the WHOLE form, not just the active step."""
    idx = WIZARD_JS.find("const runPreview")
    assert idx >= 0
    body = WIZARD_JS[idx : idx + 800]
    assert "form.getFieldsValue(true)" in body
