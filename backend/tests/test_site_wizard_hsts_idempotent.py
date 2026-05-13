"""v1.5.0 R12 — HSTS injection must be idempotent.

Bulgu #f6: when the user already wrote a `Strict-Transport-Security`
directive into frontend.response_headers (e.g. resumed from a draft
that they hand-edited, or imported a config from another platform) AND
ssl.hsts_enabled=true, the previous logic blindly appended a SECOND
HSTS directive. HAProxy would emit two `Strict-Transport-Security`
response headers, which:
  - inflates the config diff,
  - triggers spec-strict clients to flag the response,
  - is hard to audit ("which max-age wins?").

The fix detects an existing `strict-transport-security` substring (case
insensitive) and skips the auto-injection.

These are static source-level assertions so a future refactor cannot
regress.
"""
from pathlib import Path


SOURCE = (
    Path(__file__).resolve().parent.parent
    / "routers"
    / "site_wizard.py"
).read_text()


def test_hsts_double_injection_guard_present_for_upload_existing_branch():
    """The wizard's upload/existing branch must guard against double-injection."""
    # Look for the lower()-case substring check.
    assert '"strict-transport-security" in hsts_response_headers.lower()' in SOURCE, (
        "Bulgu #f6 regression: upload/existing branch must skip HSTS "
        "injection when the user already supplied a Strict-Transport-Security "
        "directive in frontend.response_headers."
    )


def test_hsts_double_injection_guard_present_for_acme_branch():
    """The wizard's ACME branch (deferred frontend_config) must also guard."""
    assert '"strict-transport-security" in hsts_acme_headers.lower()' in SOURCE, (
        "Bulgu #f6 regression: ACME branch must skip HSTS injection when "
        "the user already supplied a Strict-Transport-Security directive."
    )


def test_hsts_only_injected_when_enabled_and_not_already_present():
    """Both branches must combine the enable flag AND the absence check."""
    # We expect both branches to contain "if body.ssl.hsts_enabled and not _hsts_already...".
    assert "body.ssl.hsts_enabled and not _hsts_already_present" in SOURCE
    assert "body.ssl.hsts_enabled and not _hsts_already" in SOURCE
