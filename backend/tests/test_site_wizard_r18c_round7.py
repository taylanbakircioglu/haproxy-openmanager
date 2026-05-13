"""v1.5.0 R18c round 7 audit fixes — admin RBAC bypass + draft UX.

Findings discovered during R18c round 7:

  R18c-#26 (KRITIK): admin user receives "Insufficient permissions:
    backend.create required" from the wizard's CREATE endpoint when the
    role attached to that admin doesn't enumerate every granular
    permission. Enterprise super-admin (`users.is_admin = TRUE`) MUST
    bypass granular permission checks system-wide; pre-fix the helper
    only consulted `roles.permissions`. Fix: `check_user_permission`
    now short-circuits on `is_admin` (either via the optional
    current_user kwarg or a single SELECT). Wizard CREATE callsites
    pass `current_user=current_user` to skip the extra DB roundtrip.

  R18c-#27 (UX): resuming a draft from /sites/drafts dropped the user
    on the first wizard step (Cluster & Domains) even though every
    field was already populated. Operator had to click Next four
    times to reach Review & Apply. Fix: the hydrate effect now jumps
    straight to the last step (`WIZARD_LAST_STEP = 4`); the existing
    "Resumed from draft" Alert mentions the Previous button so the
    operator can still go back and edit any earlier field.

  R18c-#28 (UX): drafts list lacked a Preview action. Operators had to
    Resume (and thereby take the wizard out of the drafts page) just
    to see what the draft would create. Fix: new Preview button calls
    /api/proxied-hosts/preview with the draft payload and renders
    the would_create + warnings response in a modal — the same
    contract that the live wizard's Preview step uses.

  R18c-#29 (Drafts SSL display): drafts list showed a single "Expires"
    column counting the draft TTL (created_at + 30 days). When a
    draft selected an existing certificate with 191 days left,
    operators read the 30-day TTL as a cert expiry and reported it
    as a bug. Fix:
      * GET /drafts response now includes ssl_cert_summary (batch
        SELECT, no N+1) for drafts whose ssl.mode == 'existing'.
      * Drafts UI gains a SSL/TLS column (mirroring
        FrontendManagement's SSL/TLS column via getSSLExpiryInfo).
      * The TTL column is renamed to "Draft Expires" so its meaning
        is unambiguous.
"""
import re
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent
_FRONT = _REPO.parent / "frontend" / "src"
_WIZARD_PATH = _FRONT / "components" / "SiteWizard.js"
_DRAFTS_PATH = _FRONT / "components" / "SiteDrafts.js"

# When the test suite is executed inside the backend-only Docker image
# (which is what the CI Dockerfile.test ships) the frontend tree isn't
# present, so the JS source-level assertions cannot run. Skip the
# module rather than fail loudly — backend assertions still run from
# their own per-test file scope.
_FRONTEND_AVAILABLE = _WIZARD_PATH.exists() and _DRAFTS_PATH.exists()


def _read(p: Path) -> str:
    return p.read_text()


_skip_no_frontend = pytest.mark.skipif(
    not _FRONTEND_AVAILABLE,
    reason="frontend/src not present (backend-only test container) — "
           "JS source-level assertions skipped",
)


# =====================================================================
# R18c-#26: admin-aware check_user_permission
# =====================================================================


def test_check_user_permission_has_admin_short_circuit():
    """The helper must accept `current_user` kwarg AND fall back to a
    single SELECT is_admin lookup when the dict isn't supplied."""
    src = _read(_REPO / "auth_middleware.py")

    # Find the function definition so we don't accidentally match other
    # mentions of `is_admin` elsewhere in the module.
    idx = src.find("async def check_user_permission(")
    assert idx != -1, (
        "R18c-#26 regression: check_user_permission helper missing"
    )
    block = src[idx:idx + 3000]

    assert "current_user: Optional[Dict[str, Any]] = None" in block or \
           "current_user: Optional[dict] = None" in block, (
        "R18c-#26 regression: check_user_permission must accept an "
        "optional current_user kwarg so callers with the user dict "
        "already in hand can skip the is_admin DB roundtrip."
    )
    assert "current_user.get(\"is_admin\") is True" in block, (
        "R18c-#26 regression: check_user_permission no longer "
        "short-circuits when current_user is admin."
    )
    assert "SELECT is_admin FROM users WHERE id" in block, (
        "R18c-#26 regression: check_user_permission no longer falls "
        "back to a SELECT is_admin lookup for callers that don't "
        "provide current_user."
    )
    # And — crucially — the role-based path must remain so non-admin
    # users still get filtered correctly.
    assert "get_user_permissions(user_id)" in block, (
        "R18c-#26 regression: check_user_permission stopped consulting "
        "role permissions for non-admin users."
    )


def test_wizard_create_passes_current_user_to_check_user_permission():
    """Every check_user_permission(...) callsite that has a
    current_user dict in scope must forward it via the kwarg so we
    don't pay an extra is_admin SELECT per check.

    Three callsites today: preflight_acme (ssl.read), wizard CREATE
    composite for-loop (backend/frontend/ssl create), and wizard
    CREATE apply.execute. We assert each contains the kwarg.
    """
    src = _read(_REPO / "routers" / "site_wizard.py")
    # Find every `await check_user_permission(` occurrence and assert
    # the call (which may span multiple lines) includes the kwarg.
    import re as _re
    pattern = _re.compile(r"await check_user_permission\(([^)]*)\)", _re.DOTALL)
    callsites = pattern.findall(src)
    assert callsites, (
        "R18c-#26 regression: no check_user_permission(...) callsites "
        "found at all."
    )
    missing = [c for c in callsites if "current_user=current_user" not in c]
    assert not missing, (
        "R18c-#26 regression: some check_user_permission callsites do "
        "NOT forward current_user, so each one pays an extra is_admin "
        f"SELECT for the admin path. Missing on {len(missing)} callsite(s)."
    )


# =====================================================================
# R18c-#27: draft resume jumps to Review & Apply
# =====================================================================


@_skip_no_frontend
def test_wizard_defines_wizard_last_step_constant():
    src = _read(_WIZARD_PATH)
    assert re.search(r"const\s+WIZARD_LAST_STEP\s*=\s*4\b", src), (
        "R18c-#27 regression: WIZARD_LAST_STEP constant missing or "
        "no longer set to 4. The constant gates draft-resume → Review "
        "step navigation; if a future refactor adds/removes a step, "
        "update both the constant and this test."
    )


@_skip_no_frontend
def test_wizard_resume_jumps_to_last_step():
    src = _read(_WIZARD_PATH)
    # The hydrate effect lives below the resumedFromDraft setter call.
    # We check the constant is invoked there.
    assert "setStep(WIZARD_LAST_STEP)" in src, (
        "R18c-#27 regression: hydrate effect no longer calls "
        "setStep(WIZARD_LAST_STEP) after applying the draft. Operators "
        "are dropped on step 0 again."
    )


@_skip_no_frontend
def test_resumed_alert_mentions_previous_navigation():
    src = _read(_WIZARD_PATH)
    # We include "Previous" guidance in the Alert description so users
    # know they can edit earlier steps.
    assert "Previous" in src, (
        "R18c-#27 UX regression: resumed-from-draft Alert no longer "
        "mentions the Previous button. Without that hint operators "
        "may not realize they can edit earlier steps."
    )


# =====================================================================
# R18c-#28: Drafts Preview button
# =====================================================================


@_skip_no_frontend
def test_drafts_imports_eye_icon():
    src = _read(_DRAFTS_PATH)
    assert "EyeOutlined" in src, (
        "R18c-#28 regression: SiteDrafts.js no longer imports "
        "EyeOutlined for the new Preview action."
    )


@_skip_no_frontend
def test_drafts_preview_handler_exists():
    src = _read(_DRAFTS_PATH)
    assert "const handlePreview" in src, (
        "R18c-#28 regression: handlePreview function missing"
    )
    assert "axios.post('/api/sites/preview'" in src, (
        "R18c-#28 regression: handlePreview no longer POSTs to "
        "/api/sites/preview (post-Phase-B URL rename)"
    )


@_skip_no_frontend
def test_drafts_preview_modal_renders_key_sections():
    src = _read(_DRAFTS_PATH)
    # Assert the modal renders the major sections operators expect.
    for label in (
        "Cluster & Domains",
        "Would Create — Backend",
        "Would Create — HTTP Frontend",
        "Would Create — HTTPS Frontend",
        "Warnings",
    ):
        assert label in src, (
            f"R18c-#28 regression: Preview modal no longer renders "
            f"the {label!r} section."
        )


@_skip_no_frontend
def test_drafts_preview_modal_state_cleanup():
    """When the modal closes we must clear preview state to avoid
    showing stale data on the next open."""
    src = _read(_DRAFTS_PATH)
    assert "handleClosePreview" in src, (
        "R18c-#28 regression: handleClosePreview missing"
    )
    # Each setter should be called from handleClosePreview.
    close_idx = src.find("const handleClosePreview")
    assert close_idx != -1
    block = src[close_idx:close_idx + 800]
    for setter in (
        "setPreviewModalOpen(false)",
        "setPreviewData(null)",
        "setPreviewError(null)",
    ):
        assert setter in block, (
            f"R18c-#28 stale-data regression: handleClosePreview no "
            f"longer calls {setter}"
        )


# =====================================================================
# R18c-#29: Drafts SSL/TLS column + ssl_cert_summary
# =====================================================================


def test_list_drafts_response_includes_ssl_cert_summary_field():
    src = _read(_REPO / "routers" / "site_wizard.py")
    # Find the list_drafts function
    idx = src.find("async def list_drafts(")
    assert idx != -1, "list_drafts not found"
    # Read until next async def
    next_idx = src.find("\nasync def ", idx + 1)
    block = src[idx:next_idx if next_idx != -1 else idx + 6000]
    assert '"ssl_cert_summary": ssl_cert_summary' in block, (
        "R18c-#29 regression: list_drafts response no longer carries "
        "ssl_cert_summary; the drafts UI cannot show real cert info."
    )


def test_list_drafts_uses_batch_cert_lookup():
    """ssl_cert_summary lookup must be ONE batch SELECT (ANY array),
    not N+1 SELECT-per-draft."""
    src = _read(_REPO / "routers" / "site_wizard.py")
    idx = src.find("async def list_drafts(")
    assert idx != -1
    next_idx = src.find("\nasync def ", idx + 1)
    block = src[idx:next_idx if next_idx != -1 else idx + 6000]
    assert "ANY($1::int[])" in block, (
        "R18c-#29 perf regression: list_drafts cert lookup is no "
        "longer a single ANY array query — N+1 SELECTs likely."
    )
    assert "ssl_certificates" in block, (
        "R18c-#29 regression: list_drafts no longer joins ssl_certificates"
    )


def test_list_drafts_marks_deleted_certs():
    src = _read(_REPO / "routers" / "site_wizard.py")
    idx = src.find("async def list_drafts(")
    assert idx != -1
    next_idx = src.find("\nasync def ", idx + 1)
    block = src[idx:next_idx if next_idx != -1 else idx + 6000]
    assert '"deleted": True' in block, (
        "R18c-#29 regression: list_drafts no longer surfaces deleted "
        "cert references via ssl_cert_summary['deleted']=True. The UI "
        "would silently fall back to 'no cert' instead of warning."
    )


def test_list_drafts_only_looks_up_existing_mode():
    """We must NOT look up certs for upload/acme/none modes."""
    src = _read(_REPO / "routers" / "site_wizard.py")
    idx = src.find("async def list_drafts(")
    next_idx = src.find("\nasync def ", idx + 1)
    block = src[idx:next_idx if next_idx != -1 else idx + 6000]
    assert 'ssl_obj.get("mode") == "existing"' in block, (
        "R18c-#29 regression: cert lookup no longer gated on "
        "ssl.mode=='existing'; we'd issue useless SELECTs for "
        "upload/acme drafts."
    )


@_skip_no_frontend
def test_drafts_renames_expires_to_draft_expires():
    src = _read(_DRAFTS_PATH)
    assert "title: 'Draft Expires'" in src, (
        "R18c-#29 UX regression: 'Expires' column was not renamed to "
        "'Draft Expires'; operators will keep mistaking the draft TTL "
        "for the SSL cert expiry."
    )


@_skip_no_frontend
def test_drafts_has_ssl_tls_column():
    src = _read(_DRAFTS_PATH)
    assert "title: 'SSL/TLS'" in src, (
        "R18c-#29 regression: SSL/TLS column missing from drafts table"
    )
    assert "renderSslColumn" in src, (
        "R18c-#29 regression: renderSslColumn helper removed"
    )


@_skip_no_frontend
def test_drafts_imports_getSSLExpiryInfo():
    """Reuse the same helper FrontendManagement uses so the visual
    language stays consistent (Tag color, Progress bar, status label)."""
    src = _read(_DRAFTS_PATH)
    assert "getSSLExpiryInfo" in src, (
        "R18c-#29 regression: drafts no longer reuses "
        "getSSLExpiryInfo — visual language drifted from "
        "FrontendManagement's SSL/TLS column."
    )


@_skip_no_frontend
def test_drafts_handles_deleted_cert_state():
    src = _read(_DRAFTS_PATH)
    assert "summary.deleted" in src, (
        "R18c-#29 regression: drafts UI no longer renders the "
        "'Cert deleted' state when ssl_cert_summary.deleted=True."
    )
    assert "Cert deleted" in src, (
        "R18c-#29 regression: 'Cert deleted' label missing"
    )
