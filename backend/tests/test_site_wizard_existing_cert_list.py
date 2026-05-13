"""v1.5.0 R18 — Wizard existing-cert list regression tests.

Pre-R18 the wizard called `axios.get('/api/ssl')` which is NOT a real
endpoint (the correct path is `/api/ssl/certificates`). Result:

  - "Reuse existing cert" mode rendered an empty Select with "No data"
    even when the cluster had cluster-specific AND global certs imported.
  - The R17 server-side mTLS Select (per-server Advanced settings) was
    similarly broken — same shared `existingCerts` state.

R18 fix:
  1. Hit the correct endpoint: `/api/ssl/certificates?cluster_id={id}`.
  2. Refetch the list whenever the user changes the cluster on Step 0
     (Form.useWatch('cluster_id')) — global certs are unfiltered, but
     cluster-specific certs MUST be scoped to the targeted cluster.
  3. Empty / pre-cluster state surfaces an Alert telling the user
     exactly what's needed (pick a cluster / no certs imported) instead
     of a blank dropdown.
"""
import re
from pathlib import Path

import pytest


_WIZARD_JS = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend" / "src" / "components" / "SiteWizard.js"
)


def _src():
    if not _WIZARD_JS.exists():
        pytest.skip("frontend tree not mounted")
    return _WIZARD_JS.read_text()


def test_wizard_calls_correct_ssl_certificates_endpoint():
    """Pre-R18 used '/api/ssl' (404). After R18 the wizard MUST call
    /api/ssl/certificates with a cluster_id query param."""
    src = _src()
    assert re.search(
        r"/api/ssl/certificates\?cluster_id=",
        src,
    ), (
        "R18 regression: wizard not calling /api/ssl/certificates "
        "with cluster_id query — existing-cert dropdown will be empty"
    )


def test_wizard_no_longer_calls_bare_api_ssl():
    """The bare /api/ssl endpoint does not exist; ensure no regression
    re-introduces the call. We strip JS line comments first so the
    historical reference in the explanatory comment doesn't trigger a
    false positive."""
    src = _src()
    # Strip `// ... \n` line comments so we only assert against
    # executable code. Block comments aren't relevant here.
    code_only = re.sub(r"//[^\n]*", "", src)
    bad = re.search(
        r"axios\.\w+\(\s*['\"]/api/ssl['\"]",
        code_only,
    )
    assert not bad, (
        "R18 regression: an axios call to the bare '/api/ssl' path "
        "reappeared in executable code — that path is a 404 and "
        "renders the existing-cert dropdown empty"
    )


def test_wizard_watches_cluster_id_for_refetch():
    """The cert list must refetch when the cluster changes — global
    certs aside, cluster-specific certs scoped to cluster A must NOT
    appear for a wizard targeting cluster B."""
    src = _src()
    assert re.search(
        r"Form\.useWatch\(\s*['\"]cluster_id['\"]\s*,\s*form\s*\)",
        src,
    ), (
        "R18 regression: cluster_id no longer watched — switching the "
        "cluster on Step 0 will not refresh the existing-cert list"
    )


def test_wizard_clears_certs_when_no_cluster_selected():
    """Until the user picks a cluster, the existing-cert list must be
    empty (the API requires cluster_id). Otherwise we'd surface stale
    state from a previous render."""
    src = _src()
    # Look for the guard: if (!watchedClusterId) { setExistingCerts([])... }
    assert re.search(
        r"if\s*\(\s*!watchedClusterId\s*\)\s*\{[^}]*setExistingCerts\(\s*\[\s*\]\s*\)",
        src,
        re.DOTALL,
    ), (
        "R18 regression: existing-cert list not cleared when cluster_id "
        "is empty — Select will surface stale certs from a prior cluster"
    )


def test_wizard_existing_mode_disables_select_until_cluster_picked():
    """The 'Reuse existing cert' Select must be disabled (and surfaced
    with a helpful Alert) until a cluster is chosen on Step 0."""
    src = _src()
    # Locate the existing-mode block.
    block = re.search(
        r"if\s*\(\s*sslMode\s*===\s*['\"]existing['\"]\s*\)\s*\{(.*?)\}\s*if\s*\(\s*sslMode\s*===\s*['\"]acme['\"]",
        src,
        re.DOTALL,
    )
    assert block, "R18 regression: ssl.mode==='existing' UI block not found"
    body = block.group(1)
    assert "disabled={!hasCluster}" in body or "disabled={!watchedClusterId}" in body, (
        "R18 regression: Existing-cert Select not disabled until a "
        "cluster is picked"
    )
    assert "Pick a cluster on Step 1" in body or "Select a cluster first" in body, (
        "R18 regression: missing helper text guiding the user to pick "
        "a cluster first"
    )


def test_wizard_omits_usage_type_filter():
    """The wizard must NOT pass usage_type=frontend to the API — the
    same `existingCerts` array drives BOTH the HTTPS frontend Select
    (Step 3) AND the per-server mTLS Select (Step 1 advanced). Filtering
    server-side would hide perfectly valid choices."""
    src = _src()
    # Find the API call line.
    call = re.search(r"/api/ssl/certificates\?cluster_id=[^`'\"]+", src)
    assert call, "R18 regression: cert API call no longer present"
    assert "usage_type" not in call.group(0), (
        "R18 regression: wizard added a usage_type filter — that "
        "would hide server-side mTLS cert candidates"
    )
