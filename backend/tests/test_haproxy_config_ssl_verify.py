"""R11.A-2 (PR-1 hotfix) — bind-side ssl_verify safeguard parity.

Pre-fix HISTORY:
  R18 audit added literal ``bind_line += f" verify {ssl_verify}"`` on
  both the multi-cert and single-cert HTTPS bind branches so that the
  inbound mTLS column would reach the rendered HAProxy config (it
  was previously a placebo).

Pre-PR-1 BUG (the reason these assertions were inverted):
  Emitting ``verify required|optional`` on a `bind` line WITHOUT a
  ``ca-file <path>`` argument makes HAProxy fail with the fatal
  ALERT::

      Proxy 'X': verify is enabled but no CA file specified for bind '...'

  The `frontends` schema does not have a client-CA bundle column yet
  (planned for PR-7 via ``ssl_client_ca_certificate_id``), so EVERY
  frontend with ``ssl_verify ∈ {required, optional}`` (the column
  DEFAULT was ``'optional'`` until PR-2) broke ``haproxy -c`` reload
  the moment the consolidated config touched it. The user's reported
  bug was exactly this: pre-existing entities they had not modified
  failed validation after a wizard reject + apply cycle.

PR-1 fix in haproxy_config.py:
  Both bind branches now route through `_apply_bind_ssl_verify`, which
  resolves a client-CA bundle path via `_resolve_frontend_client_ca_path`
  and only appends ``ca-file <path> verify <mode>`` when the path is
  resolvable. Until PR-7 lands the resolver always returns ``None``,
  so ``verify`` is silently skipped with an ERROR log — preventing the
  fatal ALERT while preserving the operator's intent in audit
  diagnostics.

These tests are static source assertions; integration coverage lives
in tests/test_site_wizard_round11.py.
"""
import re
from pathlib import Path

import pytest


_GEN = (
    Path(__file__).resolve().parent.parent
    / "services" / "haproxy_config.py"
)


def _src():
    if not _GEN.exists():
        pytest.skip("services/haproxy_config.py not present in this env")
    return _GEN.read_text()


def test_legacy_verbatim_verify_emit_removed():
    """The pre-PR-1 verbatim ``bind_line += f" verify {ssl_verify}"``
    must NOT remain in the generator. This pattern is the one that
    caused the fatal HAProxy ALERT 'verify is enabled but no CA file
    specified' when the frontend lacked a client-CA bundle.
    """
    src = _src()
    matches = re.findall(
        r'bind_line\s*\+=\s*f"\s+verify\s+\{[^}]*ssl_verify[^}]*\}"',
        src,
    )
    assert not matches, (
        "PR-1 R11.A-2 regression: legacy verbatim ssl_verify emit "
        "pattern reappeared — bind line will trigger fatal HAProxy "
        "ALERT when ssl_verify=required|optional and no client-CA is "
        "configured. Use `_apply_bind_ssl_verify` instead."
    )


def test_apply_bind_ssl_verify_helper_called_in_both_branches():
    """Both the multi-cert (NEW mode) and single-cert (OLD mode)
    HTTPS bind branches must route ssl_verify through the safeguard
    helper, ensuring symmetric treatment of the directive."""
    src = _src()
    matches = re.findall(
        r"bind_line\s*=\s*_apply_bind_ssl_verify\(\s*bind_line\s*,",
        src,
    )
    assert len(matches) >= 2, (
        f"PR-1 R11.A-2 regression: expected `_apply_bind_ssl_verify(...)` "
        f"in BOTH bind branches (multi-cert + single-cert); found "
        f"{len(matches)} occurrence(s)"
    )


def test_apply_bind_ssl_verify_skips_when_no_client_ca():
    """The helper must skip the `verify` directive when no client-CA
    bundle is resolvable, logging an ERROR for diagnostics. This is
    the explicit safeguard against the fatal HAProxy ALERT."""
    src = _src()
    assert "BIND SSL_VERIFY DOWNGRADE" in src, (
        "PR-1 R11.A-2 regression: missing diagnostic ERROR log when "
        "ssl_verify is skipped due to absent client-CA bundle"
    )
    assert "_resolve_frontend_client_ca_path" in src, (
        "PR-1 R11.A-2 regression: missing client-CA path resolver "
        "(forward-path placeholder for PR-7 ssl_client_ca_certificate_id)"
    )


def test_strict_sni_still_emitted_unchanged():
    """Sanity check: the existing `strict-sni` directive emission must
    not have been damaged by the PR-1 hotfix changes."""
    src = _src()
    cnt = src.count('bind_line += " strict-sni"')
    assert cnt >= 2, (
        "PR-1 regression: `strict-sni` directive emission count "
        "dropped — the safeguard refactor was destructive"
    )
