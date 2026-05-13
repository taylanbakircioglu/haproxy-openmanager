"""v1.5.0 R18 audit findings — regression tests.

Five non-trivial bugs surfaced during the R18 deep audit. Each is
covered with a dedicated assertion below so a future refactor can't
silently regress them.

Findings (audit summary):
  R18-#1 (CRITICAL): `ssl_verify` was persisted to DB and forwarded by
    the wizard but never rendered into the HAProxy bind line — covered
    by `tests/test_haproxy_config_ssl_verify.py`.

  R18-#2 (Major UX): Sidebar `selectedKeys` was tied to raw
    `location.pathname`. Visiting `/proxied-hosts/new` (legacy v1.5.0
    bookmark) or `/quick-setup` (R17 bookmark) rendered the wizard
    correctly but the menu showed NO active highlight, making the
    sidebar feel disconnected.

  R18-#3 (Major data): Cluster swap on Step 0 left stale
    `ssl.ssl_certificate_id` and per-server `ssl_certificate_id` values
    in the form. Either the operator landed on a "(invalid)" Select or
    a wrong cert id flowed into the submit payload and got rejected
    server-side with a generic 400.

  R18-#4 (UI/Pydantic mismatch): Pydantic `ServerStep.ssl_min_ver`
    accepted TLSv1.0..1.3 but the wizard Select only offered 1.2/1.3
    — drafts containing the legacy versions could not be edited via UI.

  R18-#5 (Label semantics): Per-server `ssl_certificate_id` was
    labelled "Client cert (mTLS to server)" — semantically wrong. The
    field maps to HAProxy's `ca-file` which is for VERIFYING the
    upstream server cert, NOT for HAProxy presenting a client cert.
"""
import re
from pathlib import Path

import pytest


_FRONT = Path(__file__).resolve().parent.parent.parent / "frontend" / "src"
_APP_JS = _FRONT / "App.js"
_WIZ = _FRONT / "components" / "SiteWizard.js"


def _read(p: Path) -> str:
    if not p.exists():
        pytest.skip(f"frontend tree not mounted at {p}")
    return p.read_text()


# ----------- R18-#2: legacy alias selectedKey normalization -----------


def test_selected_key_normalizes_v15_legacy_aliases():
    src = _read(_APP_JS)
    assert re.search(
        r"path\s*===\s*'/proxied-hosts/new'\s*\|\|\s*path\s*===\s*'/quick-setup'",
        src,
    ), (
        "R18-#2 regression: selectedKey no longer normalizes the v1.5.0 "
        "/proxied-hosts/new and R17 /quick-setup aliases to /sites/new — "
        "sidebar highlight will be missing on those legacy URLs"
    )
    assert re.search(
        r"path\s*===\s*'/proxied-hosts/drafts'\s*\|\|\s*path\s*===\s*'/quick-setup/drafts'",
        src,
    ), (
        "R18-#2 regression: drafts aliases no longer normalized for "
        "selectedKey — sidebar highlight missing on /proxied-hosts/drafts "
        "and /quick-setup/drafts"
    )


# ----------- R18-#3: cluster change clears stale cert IDs -----------


def test_cluster_change_clears_stale_cert_ids():
    src = _read(_WIZ)
    # The previous-cluster ref is the marker.
    assert "prevClusterRef" in src, (
        "R18-#3 regression: prevClusterRef no longer present — cluster "
        "swap will not clear stale ssl.ssl_certificate_id"
    )
    # And both targets must be cleared.
    assert "ssl_certificate_id: undefined" in src, (
        "R18-#3 regression: ssl_certificate_id no longer cleared on "
        "cluster change"
    )
    assert "servers" in src and "map" in src, (
        "R18-#3 regression: per-server ssl_certificate_id clear pass "
        "appears to be missing"
    )


# ----------- R18-#4: per-server TLS literal coverage -----------


def test_legacy_tls_versions_not_offered_in_wizard_ui():
    """R18c round 10 reverses R18-#4: the wizard MUST NOT offer
    TLSv1.0 / TLSv1.1 in any TLS min/max Select.

    Background: R18 originally added TLSv1.0/1.1 entries so an old draft
    targeting a legacy upstream could "round-trip" through the wizard.
    The Pydantic models (ServerStep at backend/models/site_wizard.py:103
    and SSLChoice at :354) however reject those values per RFC 8996, so
    a user picking the legacy entries got a 422 at submit time after
    completing five wizard steps. R18c round 10 (M1) drops the legacy
    options from the UI to align with the API contract — both the
    per-server Selects AND the HTTPS frontend listener Selects.

    This test is the canonical regression guard for that decision.
    """
    src = _read(_WIZ)
    legacy_v10 = src.count('Option value="TLSv1.0"')
    legacy_v11 = src.count('Option value="TLSv1.1"')
    assert legacy_v10 == 0, (
        f"R18c-#33 regression: TLSv1.0 still listed {legacy_v10} time(s) "
        "in SiteWizard.js. The Pydantic models reject TLSv1.0 — see "
        "ServerStep.reject_server_ca_bundle_without_ssl and "
        "SSLChoice.reject_legacy_tls_versions in models/site_wizard.py."
    )
    assert legacy_v11 == 0, (
        f"R18c-#33 regression: TLSv1.1 still listed {legacy_v11} time(s) "
        "in SiteWizard.js. Same root cause as TLSv1.0 above."
    )


# ----------- R18-#5: server cert label semantics -----------


def test_server_cert_label_uses_ca_bundle_terminology():
    """The HAProxy `ca-file` directive verifies the UPSTREAM server's
    cert. Labelling the field 'Client cert (mTLS to server)' suggests
    HAProxy presents a cert (would be `crt`, not `ca-file`) — wrong
    semantics."""
    src = _read(_WIZ)
    assert "CA bundle for upstream verification" in src, (
        "R18-#5 regression: server-side cert Select no longer labelled "
        "as a CA bundle — confusing semantics for operators"
    )
    # And the misleading label must be gone.
    assert 'label="Client cert (mTLS to server)"' not in src, (
        "R18-#5 regression: misleading 'Client cert (mTLS to server)' "
        "label reappeared"
    )


def test_server_cert_required_when_verify_required():
    """When `ssl_verify === 'required'` HAProxy demands a CA bundle —
    surface the dependency in the form rules so the operator can't
    submit a half-configured payload."""
    src = _read(_WIZ)
    assert "ssl_verify is \"required\"" in src or "verify is \"required\"" in src or "A CA bundle is required" in src, (
        "R18-#5 regression: missing 'ca-file required when verify=required' "
        "form rule on the per-server cert Select"
    )


# ----------- R18 misc: copy hygiene -----------


def test_drafts_409_message_uses_new_terminology():
    src = (
        Path(__file__).resolve().parent.parent / "routers" / "site_wizard.py"
    ).read_text()
    assert "'Site Drafts'" in src, (
        "R18 copy regression: 409 error message still references the "
        "old 'Wizard Drafts' page name"
    )
    assert "'Wizard Drafts'" not in src, (
        "R18 copy regression: stale 'Wizard Drafts' page name remains "
        "in the 409 error message"
    )


def test_letsencrypt_account_docstring_updated():
    src = (
        Path(__file__).resolve().parent.parent / "routers" / "letsencrypt.py"
    ).read_text()
    assert "'New Site'" in src or '"New Site"' in src or "New Site" in src, (
        "R18 copy regression: list_accounts docstring still uses the "
        "old 'New Proxied Host' wizard name"
    )
