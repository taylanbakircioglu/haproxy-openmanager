"""v1.5.0 R18b round 1 audit fixes — regression tests.

Findings discovered during R18b round 1:

  R18b-#1 (Cross-route consistency): GET /api/frontends returned
    `ssl_verify` masked as "optional" when the DB row was NULL. Edit
    forms then sent the displayed value back, silently flipping
    operator intent ("omit verify directive") to ("verify optional").
    Now the API returns NULL verbatim; the HAProxy generator already
    treats NULL as "omit", so round-trip is correct.

  R18b-#2 (Preview parity): /api/proxied-hosts/preview's `would_create`
    only echoed name/address/port for servers and bind tuple for
    frontends. The actual create persisted ssl_verify, per-server
    ssl_certificate_id, TLS min/max, HSTS shape, etc. — preview did
    not match create. `would_create` now includes the same fields.

  R18b-#2.1 (Preview HSTS bug — discovered round 2): the new HSTS
    block read from `body.frontend.hsts_*` (which doesn't exist on
    FrontendStep). HSTS is on `SSLChoice` (`body.ssl.hsts_*`); fix
    was to flip the source.

  R18b-#3 (Apply-failed UX): the "Created but Apply Failed" Modal
    showed a generic message and dropped `apply_result.error` on the
    floor. Operator had no way to learn why apply failed without
    digging into Apply Changes. Modal now surfaces the error string.

  R18b-#4 (Stale drafts list): wizard saves are append-only
    (each save inserts a new row). A second tab editing the "same"
    draft surface would diverge silently. Drafts page now refetches
    on visibilitychange / window focus.

  R18b-#5 (Default mismatch): FrontendConfig.ssl_verify defaulted to
    "optional". When the FrontendManagement edit form cleared the
    Select, the cleared value was dropped from the JSON payload, and
    Pydantic re-applied "optional" — exactly the behaviour the clear
    was meant to undo. Default is now None.
"""
import re
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent
_FRONT = _REPO.parent / "frontend" / "src"


# ----------------- R18b-#1: ssl_verify NULL preserved -----------------


def test_get_frontends_returns_ssl_verify_verbatim():
    src = (_REPO / "routers" / "frontend.py").read_text()
    # The dangerous masking pattern must be gone…
    assert 'f.get("ssl_verify", "optional")' not in src, (
        "R18b-#1 regression: GET /api/frontends still masks NULL "
        "ssl_verify to 'optional' — edit form will silently switch "
        "verify directive on save"
    )
    # …and the verbatim form must remain.
    assert 'f.get("ssl_verify")' in src, (
        "R18b-#1 regression: GET /api/frontends no longer returns "
        "ssl_verify verbatim from the DB row"
    )


# ----------------- R18b-#5: FrontendConfig default -----------------


def test_frontend_config_default_ssl_verify_is_none():
    """Pydantic default must be None so omitted fields don't silently
    switch a cleared verify directive back to 'optional'."""
    from models.frontend import FrontendConfig
    cfg = FrontendConfig(name="x", bind_port=80)
    assert cfg.ssl_verify is None, (
        "R18b-#5 regression: FrontendConfig.ssl_verify default is no "
        f"longer None — got {cfg.ssl_verify!r}"
    )


def test_frontend_management_initial_value_is_undefined():
    src = (_FRONT / "components" / "FrontendManagement.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    assert "ssl_verify: 'optional'" not in body, (
        "R18b-#5 regression: FrontendManagement initialValues still "
        "hard-codes 'optional' for ssl_verify"
    )
    assert "ssl_verify: undefined" in body, (
        "R18b-#5 regression: FrontendManagement initialValues no longer "
        "marks ssl_verify as undefined (backend default = None)"
    )


def test_bulk_import_no_longer_defaults_ssl_verify_to_optional():
    src = (_REPO / "routers" / "config.py").read_text()
    # The legacy default with a fallback to "optional" must be gone.
    assert 'frontend_data.get("ssl_verify", "optional")' not in src, (
        "R18b-#5 regression: bulk-config-import still defaults missing "
        "ssl_verify to 'optional' — round-trip on import/export skews"
    )


# ----------------- R18b-#2: preview parity -----------------


def test_preview_would_create_includes_ssl_verify_and_server_fields():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # Locate the would_create block.
    assert '"would_create"' in src
    # Server-level fields parity.
    server_fields = [
        '"ssl_enabled": s.ssl_enabled',
        '"ssl_verify": s.ssl_verify',
        '"ssl_certificate_id": s.ssl_certificate_id',
        '"ssl_min_ver": s.ssl_min_ver',
        '"ssl_max_ver": s.ssl_max_ver',
    ]
    for fld in server_fields:
        assert fld in src, (
            f"R18b-#2 regression: preview server entry no longer "
            f"echoes {fld!r}"
        )
    # HTTPS frontend-level fields parity.
    https_fields = [
        '"ssl_alpn": body.ssl.ssl_alpn',
        '"ssl_min_ver": body.ssl.ssl_min_ver',
        '"ssl_strict_sni": body.ssl.ssl_strict_sni',
        '"ssl_verify": body.ssl.ssl_verify',
        '"ssl_certificate_id": body.ssl.ssl_certificate_id',
    ]
    for fld in https_fields:
        assert fld in src, (
            f"R18b-#2 regression: preview frontend_https entry no "
            f"longer echoes {fld!r}"
        )


def test_preview_hsts_block_reads_from_ssl_not_frontend():
    """R18b round 2 fix — HSTS lives on SSLChoice, not FrontendStep.
    The wrong source produced an always-empty HSTS preview."""
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # Find the hsts dict in the would_create context.
    hsts_block_match = re.search(
        r'"hsts":\s*\{[^}]*\}',
        src,
        re.DOTALL,
    )
    assert hsts_block_match, "R18b-#2.1 regression: preview hsts block missing"
    block = hsts_block_match.group(0)
    assert 'body.ssl' in block, (
        "R18b-#2.1 regression: preview hsts block no longer reads "
        "from body.ssl — falls back to a model that has no hsts_* "
        "attrs and produces an always-empty HSTS preview"
    )
    assert 'body.frontend' not in block, (
        "R18b-#2.1 regression: preview hsts block still reads from "
        "body.frontend — FrontendStep has no hsts_* attrs"
    )


# ----------------- R18b-#3: apply_result error surfaced -----------------


def test_wizard_apply_failed_modal_shows_apply_result():
    src = (_FRONT / "components" / "SiteWizard.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    # The handler must extract apply_result from the response.
    assert "apply_result" in body, (
        "R18b-#3 regression: wizard create handler no longer reads "
        "apply_result from the API response"
    )
    # And the Modal content must reference apply_result error.
    assert "apply_result?.error" in body or "apply_result.error" in body, (
        "R18b-#3 regression: 'Created but Apply Failed' Modal no "
        "longer surfaces the actual apply error to the operator"
    )


# ----------------- R18b-#4: drafts visibilitychange refetch -----------------


def test_drafts_refetches_on_visibility_change():
    src = (_FRONT / "components" / "SiteDrafts.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    assert "visibilitychange" in body, (
        "R18b-#4 regression: SiteDrafts no longer refetches on "
        "tab visibility change — stale list when the same operator "
        "edits drafts in another tab"
    )
    # Cleanup must remove the listener too.
    assert "removeEventListener('visibilitychange'" in body, (
        "R18b-#4 regression: SiteDrafts visibilitychange "
        "listener not cleaned up — memory leak risk on remount"
    )
