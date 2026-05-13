"""v1.5.0 R16 #v3 — wizard error toast must surface server-side reason.

The backend's GlobalExceptionHandler wraps every error in a custom
envelope:

    {"error": {"message": "...", "details": {"validation_errors": [...]}}}

Pre-R16 the wizard read `err.response.data.detail` (FastAPI default
shape), which is ALWAYS undefined under the envelope handler. Users
saw "Submit failed" / "Preview failed" / "Delete failed" generic
toasts while the real reason — RBAC denial, validation field path,
collision warning — was right there in the response, just at a
different path.

R16 fix: introduce a shared utils/apiError.js helper that unwraps the
modern envelope first AND falls back to the legacy `detail` shape;
swap every wizard-adjacent toast to use it.

These tests pin the helper's existence + integration so a future
refactor can't silently revert.
"""
from pathlib import Path

import pytest


_FRONTEND_SRC = Path(__file__).resolve().parent.parent.parent / "frontend" / "src"


if not _FRONTEND_SRC.exists():
    pytest.skip(
        f"frontend not present at {_FRONTEND_SRC}; backend-only container",
        allow_module_level=True,
    )


HELPER = _FRONTEND_SRC / "utils" / "apiError.js"
WIZARD = _FRONTEND_SRC / "components" / "SiteWizard.js"
DRAFTS = _FRONTEND_SRC / "components" / "SiteDrafts.js"


def test_helper_exists_and_exports_extractApiError():
    assert HELPER.exists(), (
        "R16-3 regression: utils/apiError.js missing. The shared "
        "envelope-aware error extractor must live here so all wizard "
        "components reuse one implementation."
    )
    src = HELPER.read_text()
    assert "export const extractApiError" in src
    assert "validation_errors" in src
    assert "data.error" in src
    assert "data.detail" in src, (
        "R16-3 regression: helper must ALSO support the legacy `detail` "
        "shape so non-envelope endpoints don't break."
    )


def test_helper_handles_envelope_first():
    """Envelope path must be checked BEFORE the legacy detail path —
    otherwise modern envelope errors fall through to the fallback
    string. We match the EXECUTABLE statements (assignments) so that
    any docblock mentioning the legacy shape doesn't false-positive
    the ordering check."""
    src = HELPER.read_text()
    env_pos = src.find("const env = data.error")
    legacy_pos = src.find("const detail = data.detail")
    assert env_pos != -1, "expected `const env = data.error` assignment"
    assert legacy_pos != -1, "expected `const detail = data.detail` assignment"
    assert env_pos < legacy_pos, (
        "R16-3 regression: helper must assign data.error BEFORE "
        "data.detail. Otherwise modern envelope errors would fall "
        "through to the legacy `detail` branch (which is undefined "
        "under the GlobalExceptionHandler) and the fallback string "
        "would always win."
    )


def test_wizard_imports_helper():
    """SiteWizard must import extractApiError from utils/apiError."""
    src = WIZARD.read_text()
    assert "from '../utils/apiError'" in src or 'from "../utils/apiError"' in src
    assert "extractApiError" in src


def test_wizard_no_longer_reads_response_detail_for_user_toasts():
    """Old `err?.response?.data?.detail || '...'` patterns must be gone
    from the wizard — they only ever produced 'Submit failed' style
    toasts because the envelope handler never sets `.detail`."""
    src = WIZARD.read_text()
    # Forbid the exact regression pattern.
    forbidden_patterns = [
        "err?.response?.data?.detail || 'Preview failed'",
        "err?.response?.data?.detail || 'Submit failed'",
        "err?.response?.data?.detail || 'Save draft failed'",
        "err?.response?.data?.detail || 'Preflight failed'",
    ]
    for p in forbidden_patterns:
        assert p not in src, (
            f"R16-3 regression: {p!r} reappeared in the wizard. Use "
            "extractApiError(err, '<fallback>') instead so the user "
            "sees the actual server-side reason."
        )


def test_drafts_uses_helper_too():
    """SiteDrafts uses the same helper for fetch + delete."""
    src = DRAFTS.read_text()
    assert "extractApiError" in src
    assert "err?.response?.data?.detail || 'Failed to load drafts'" not in src
    assert "err?.response?.data?.detail || 'Delete failed'" not in src
