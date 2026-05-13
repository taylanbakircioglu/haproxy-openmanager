"""v1.5.0 R18c round 2 audit fixes — UI page integrity tests.

Findings discovered during R18c round 2 (UI pages impact):

  R18c-#5 (BackendServers SSL fields stale on toggle off — KRITIK):
    Pre-fix when the operator toggled `ssl_enabled` from true to
    false in the server edit modal, the SSL Form.Items unmounted
    and Ant Design did NOT include their values in the submit
    payload. The backend PUT only updated fields PRESENT in the
    payload, so the existing DB row kept its stale
    ssl_certificate_id / ssl_verify / ssl_sni / ssl_min_ver /
    ssl_max_ver / ssl_ciphers — HAProxy then rendered a server
    line where SSL was "off" but with the leftover certificate
    path, producing inconsistent behaviour. handleServerSubmit now
    explicitly nulls the SSL fields when ssl_enabled is false.

  R18c-#6 (BulkVersionHistory: wizard versions get Restore +
    formatted name): pre-fix `bulk-proxied-host-create-{ts}`
    versions were displayed as raw timestamped strings with no
    "what is this?" hint, AND the Restore button only appeared
    for `apply-consolidated` versions. The operator who applied a
    wizard PENDING and later wanted to roll back had no UI path.
    formatVersionName now returns "New Site (wizard) - {raw}" and
    the Restore predicate accepts the wizard prefix.

  R18c-#7 (UserManagement audit Details summary): pre-fix
    importantKeys lacked the wizard's degraded-outcome fields
    (wizard_status, apply_error, acme_staging_error, version_name,
    ssl_mode), so the truncated table cell defaulted to alphabetical
    keys and the operator only saw the wizard outcome by opening
    the JSON tooltip. Now the wizard fields appear first.

  R18c-#8 (UserManagement Activity rowKey collision): pre-fix
    `rowKey="timestamp"` produced duplicate React keys when burst
    logging happened in the same second (e.g. wizard create + ACME
    staging event). Replaced with a composite (id || timestamp +
    action + resource_id).

  R18c-#9 (SSLManagement delete error message): pre-fix raw string
    concatenation against `error.response?.data?.detail` produced
    "[object Object]" when FastAPI returned validation errors as a
    list. Now uses the shared `extractApiError` helper.
"""
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent
_FRONT = _REPO.parent / "frontend" / "src"


# ----------------- R18c-#5: SSL fields cleared on submit -----------------


def test_backend_servers_clears_ssl_fields_when_disabled():
    src = (_FRONT / "components" / "BackendServers.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    # The cleanup logic must explicitly null all SSL-related fields
    # when ssl_enabled is false.
    assert "if (!requestData.ssl_enabled)" in body, (
        "R18c-#5 KRITIK regression: handleServerSubmit no longer "
        "guards against stale SSL fields when ssl_enabled is "
        "toggled off"
    )
    for f in (
        "ssl_certificate_id",
        "ssl_verify",
        "ssl_sni",
        "ssl_min_ver",
        "ssl_max_ver",
        "ssl_ciphers",
    ):
        # The cleanup loop must list every SSL-related field.
        assert f"'{f}'" in body, (
            f"R18c-#5 KRITIK regression: SSL field '{f}' no longer "
            "explicitly nulled when ssl_enabled=false — DB row "
            "keeps stale value, HAProxy emits inconsistent server "
            "line"
        )


# ----------------- R18c-#6: wizard versions in BulkVersionHistory -----------------


def test_bulk_version_history_formats_wizard_version_name():
    src = (_FRONT / "components" / "BulkVersionHistory.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    assert "bulk-site-create-" in body, (
        "R18c-#6 regression: formatVersionName no longer recognises "
        "the wizard's current `bulk-site-create-` prefix"
    )
    assert "bulk-proxied-host-create-" in body, (
        "R18c-#6 regression: formatVersionName must ALSO keep "
        "recognising the legacy `bulk-proxied-host-create-` prefix "
        "so historical APPLIED versions still render with a human "
        "label after the rename"
    )
    assert "New Site (wizard)" in body, (
        "R18c-#6 regression: formatVersionName no longer surfaces a "
        "human label for wizard versions"
    )


def test_bulk_version_history_allows_restore_of_wizard_versions():
    src = (_FRONT / "components" / "BulkVersionHistory.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    # The Restore predicate must accept the wizard bulk prefix.
    # Locate the predicate by finding the restore Popconfirm scope.
    restore_block = body[body.find("Restore Configuration Version"):]
    restore_block = body[
        max(0, body.find("Restore Configuration Version") - 600):
        body.find("Restore Configuration Version") + 200
    ]
    assert "bulk-site-create-" in restore_block, (
        "R18c-#6 regression: BulkVersionHistory Restore button no "
        "longer surfaces for current-naming wizard bulk versions — "
        "operator cannot roll back to a previous applied state from "
        "this page after a wizard apply"
    )
    assert "bulk-proxied-host-create-" in restore_block, (
        "R18c-#6 regression: BulkVersionHistory Restore predicate "
        "must keep accepting the legacy `bulk-proxied-host-create-` "
        "prefix so historical APPLIED versions remain restorable "
        "after the rename"
    )


# ----------------- R18c-#7 & #8: UserManagement activity table -----------------


def test_user_management_activity_includes_wizard_fields():
    src = (_FRONT / "components" / "UserManagement.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    # Important keys must include the wizard's degraded-outcome
    # fields so the truncated cell highlights actual context.
    for k in (
        "'wizard_status'",
        "'apply_error'",
        "'acme_staging_error'",
        "'version_name'",
        "'ssl_mode'",
    ):
        assert k in body, (
            f"R18c-#7 regression: activity 'Details' summary no "
            f"longer includes {k} — wizard outcome only visible "
            "via JSON tooltip"
        )


def test_user_management_activity_uses_composite_row_key():
    src = (_FRONT / "components" / "UserManagement.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    # Allow the deprecated pattern to appear inside comments (the
    # R18c fix comment intentionally cites the legacy form). Strip
    # line comments before the negative check.
    code_only = "\n".join(
        ln for ln in body.splitlines() if not ln.lstrip().startswith("//")
    )
    assert 'rowKey="timestamp"' not in code_only, (
        "R18c-#8 regression: activity Table still uses "
        "`rowKey=\"timestamp\"` — burst logging produces duplicate "
        "React keys in the same second"
    )
    # Composite key must reference the row id and a fallback.
    assert "rowKey={(r) =>" in body, (
        "R18c-#8 regression: activity Table no longer uses a "
        "composite rowKey function"
    )


# ----------------- R18c-#9: SSLManagement extractApiError -----------------


def test_ssl_management_uses_extract_api_error_on_delete():
    src = (_FRONT / "components" / "SSLManagement.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    assert "extractApiError" in body, (
        "R18c-#9 regression: SSLManagement no longer imports the "
        "shared extractApiError helper — error messages may render "
        "as '[object Object]' on FastAPI validation errors"
    )
    # The pre-fix raw concatenation must be gone from the delete handler.
    bad_pattern = "error.response?.data?.detail"
    delete_block = body[body.find("Failed to delete certificate"):][:300]
    assert bad_pattern not in delete_block, (
        "R18c-#9 regression: delete-cert handler still concatenates "
        "raw response.data.detail into the error toast"
    )
