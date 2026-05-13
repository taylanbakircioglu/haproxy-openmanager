"""v1.5.0 R17 — Wizard step-validation regression tests.

Pre-R17 the `Next` button on Step 1 (Backend & Servers) called
`form.validateFields(['servers'])` — Antd's behaviour for that path is to
validate the Form.List wrapper itself, NOT the per-row required rules.
Result: a user could leave Server Address blank and `Next` would happily
advance, the error surfacing only at the final submit. R17 walks every
required nested path explicitly via `serverRows.flatMap`.

Same pattern extended to Step 3 (SSL): only when ssl.mode='upload' or
'existing' do we validate the conditional required fields, so users in
'acme' mode aren't blocked by upload-only validators.
"""
import re
from pathlib import Path

import pytest


_WIZARD_JS = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "src"
    / "components"
    / "SiteWizard.js"
)


def _wizard_src():
    if not _WIZARD_JS.exists():
        pytest.skip(
            "frontend tree not mounted — backend-only test environments "
            "skip JS source assertions"
        )
    return _WIZARD_JS.read_text()


# ----------------- Step 1: per-row server validation -----------------


def test_step1_validates_each_server_row_explicitly():
    """The flatMap over serverRows must expand the required server
    paths — without it Antd's validateFields(['servers']) only walks the
    Form.List metadata, leaving Address-blank rows undetected."""
    src = _wizard_src()
    assert "serverRows.flatMap" in src, (
        "R17 regression: per-row server validation pattern missing — "
        "Step 1 Next will not catch blank Address until submit time"
    )
    # The three required paths must all be covered.
    for field in ("server_name", "server_address", "server_port"):
        assert re.search(
            rf"\['servers',\s*i,\s*'{field}'\]",
            src,
        ), f"R17 regression: server.{field} dropped from per-row validation"


def test_step1_validation_still_includes_backend_name():
    """We must still validate the Backend Name on Step 1 — otherwise
    advancing to the Frontend step with a blank backend.name would only
    fail at submit."""
    src = _wizard_src()
    assert re.search(
        r"validateFields\(\s*\[\s*\['backend',\s*'name'\]",
        src,
    ), "R17 regression: backend.name validation dropped from Step 1 Next"


# ----------------- Step 3: SSL conditional validation -----------------


def test_step3_validates_upload_required_fields():
    """When ssl.mode='upload' the Next button must validate name +
    certificate_content + private_key_content. Without this, users get
    bounced back to the SSL step from Review with cryptic Pydantic
    errors."""
    src = _wizard_src()
    # The conditional block must check upload mode and validate all 3 PEM-related fields.
    assert re.search(r"mode\s*===\s*'upload'", src), (
        "R17 regression: Step 3 Next no longer branches on ssl.mode='upload'"
    )
    for field in ("name", "certificate_content", "private_key_content"):
        assert re.search(
            rf"\['ssl',\s*'{field}'\]",
            src,
        ), f"R17 regression: ssl.{field} dropped from Step 3 upload-mode validation"


def test_step3_validates_existing_mode_picks_cert_id():
    """ssl.mode='existing' must validate ssl.ssl_certificate_id. Skipping
    this lets users advance with no cert selected and crash at submit."""
    src = _wizard_src()
    assert re.search(r"mode\s*===\s*'existing'", src), (
        "R17 regression: Step 3 Next no longer branches on ssl.mode='existing'"
    )
    assert re.search(
        r"\['ssl',\s*'ssl_certificate_id'\]",
        src,
    ), "R17 regression: ssl.ssl_certificate_id dropped from Step 3 existing-mode validation"


def test_step3_does_not_block_acme_with_upload_only_validators():
    """Important: ssl.mode='acme' has none of name/certificate_content/
    private_key_content/ssl_certificate_id — those validators must NOT
    run when mode='acme'. We verify by ensuring the upload/existing
    blocks are guarded by mode equality checks (i.e. they don't run
    unconditionally)."""
    src = _wizard_src()
    # Look for a Step 3 (step === 3) block that gates by mode equality.
    block_match = re.search(
        r"if\s*\(\s*step\s*===\s*3\s*\)\s*\{(.*?)\}\s*setStep",
        src,
        re.DOTALL,
    )
    assert block_match, "R17 regression: Step 3 validation block not found"
    block = block_match.group(1)
    # Must NOT validate certificate_content unconditionally.
    assert "if (mode" in block or "mode ===" in block, (
        "R17 regression: Step 3 validation runs unconditionally — would "
        "block ACME users from leaving the SSL step"
    )
