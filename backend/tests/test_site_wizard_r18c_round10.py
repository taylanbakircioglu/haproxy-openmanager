"""
R18c round 10 — Wizard / Drafts / ACME deep-dive audit fixes
=============================================================

This round's findings come from three parallel deep-dive audits
(Wizard+Drafts, ACME Diagnostic Panel, Cross-cutting / Architecture)
run against the entire delta from commit 89cbe3d (initial v1.5.0 ship)
through 75cd18e. Per the user's directive ("risksiz ve kompleks
değişiklikler yapma. Enterprise ilerlediğimizi unutma") only the
CRITICAL bug and a curated set of low-risk MEDIUM findings are fixed
here. The HIGH multi-tenant inventory-GET hardening is deferred to
a separate round because it requires a real cluster-scoped filter
contract that may break legacy clients.

Fixes locked in by this test file:

  CRITICAL — RBAC plural mismatch
      Wizard checked ("backend"|"frontend"|"ssl", action) for both
      `_can_use_wizard` and the create endpoint. Seeded role
      permissions in database/migrations.py use PLURAL names
      (frontends.create, backends.create, ssl.create). Result: every
      non-admin role evaluated False on `_can_use_wizard` and 403'd
      on create — the R18c-#7 admin bypass was the only thing keeping
      the feature operable. Aligned the keys.

  M1 — Wizard offered TLSv1.0 / TLSv1.1 in server-side TLS dropdowns
       even though ServerStep.reject_server_ca_bundle_without_ssl
       rejects them per RFC 8996. Removed the legacy options from
       the UI to keep the contract symmetric.

  M2 — Resume hydration jumped to Review & Apply before the cluster-
       scoped existing-cert list finished loading. A fast Submit
       click could race the orphan-cleanup pass and submit a stale
       ssl_certificate_id (FK 400). New `existingCertsLoading`
       state guards the Submit / Save buttons while the fetch is
       in flight AND ssl.mode == 'existing'.

  M3 — `create_proxied_host` 500 catch-all returned `detail=str(e)`
       to the browser, leaking SQL fragments and internal
       identifiers. Replaced with a stable generic message + a
       correlation id surfaced in the operator's toast and logged
       server-side at exception level.

  M4 — handleCancel's Modal.confirm allowed Esc / mask click to
       trigger the Save Draft path silently. Disabled both
       dismissal vectors (`keyboard: false`, `maskClosable: false`)
       so the operator must make an explicit choice.

  M5 — fetchInitial swallowed every error; an outage on
       /api/clusters or /api/letsencrypt/accounts left the wizard
       with empty dropdowns indistinguishable from "no clusters
       provisioned". Replaced silent catch with per-call
       extractApiError + `message.warning` (clusters required) /
       `message.info` (LE accounts optional for non-ACME flows).

  M8 — Review step coerced apply_immediately=true from inside a
       Form.Item shouldUpdate render function via setTimeout(0).
       That is a setState-during-render anti-pattern; React 18
       Strict Mode double-renders it. Moved the coercion to a
       useEffect keyed on the existing sslMode useWatch.

Test layout follows R18c round 9: _BACK is the directory containing
routers/ (works for both dev checkout and the backend-only Docker
test image), and frontend assertions skip when frontend/src is not
mounted into the image.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_BACK = Path(__file__).resolve().parent.parent
_FRONT = _BACK.parent / "frontend" / "src"
_FRONTEND_AVAILABLE = _FRONT.exists()


# =====================================================================
# CRITICAL — RBAC plural keys
# =====================================================================

def test_can_use_wizard_uses_plural_resource_names():
    """`_can_use_wizard` must check the PLURAL resource keys
    (frontends.*, backends.*, ssl.*) that match seeded role
    permissions in database/migrations.py. Pre-round-10 it checked
    SINGULAR (frontend.*, backend.*, ssl.*) and never matched any
    non-admin role's permissions JSONB."""
    src = (_BACK / "routers" / "site_wizard.py").read_text()
    # Walk forward from the tuple opening through balanced parens so
    # nested ("frontends", "read") tuples don't end the block early.
    start = src.find("candidate_perms = (")
    assert start >= 0, "could not locate candidate_perms tuple"
    open_at = src.find("(", start)
    depth = 0
    end = -1
    for i in range(open_at, len(src)):
        ch = src[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    assert end >= 0, "could not find balanced closing paren for candidate_perms"
    block = src[start:end + 1]
    assert '("frontends", "read")' in block
    assert '("frontends", "create")' in block
    assert '("backends", "create")' in block
    assert '("backends", "read")' in block
    assert '("ssl", "read")' in block
    assert '("ssl", "create")' in block
    # And the broken singular forms are GONE inside the tuple itself.
    assert '("frontend", "read")' not in block, (
        "R18c-#32 regression: _can_use_wizard must not check singular "
        "'frontend' (use 'frontends' to match seeded permissions)"
    )
    assert '("frontend", "create")' not in block
    assert '("backend", "create")' not in block
    assert '("backend", "read")' not in block


def test_create_site_uses_plural_resource_names():
    """The composite RBAC loop in `create_proxied_host` must check
    backends.create + frontends.create + ssl.create. Pre-round-10
    it checked the singular form which only ever passed for admins
    via the round-7 bypass."""
    src = (_BACK / "routers" / "site_wizard.py").read_text()
    needle = (
        'for resource, action in (("backends", "create"), '
        '("frontends", "create"), ("ssl", "create"))'
    )
    assert needle in src, (
        "R18c-#32 regression: create_proxied_host must enumerate the "
        "composite RBAC tuple with PLURAL resource names"
    )
    bad = (
        'for resource, action in (("backend", "create"), '
        '("frontend", "create"), ("ssl", "create"))'
    )
    assert bad not in src, (
        "Stale singular RBAC tuple still present — non-admins blocked"
    )


# =====================================================================
# M1 — TLS 1.0/1.1 not offered in server-side TLS dropdowns
# =====================================================================

@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_site_wizard_drops_tls10_tls11_from_server_dropdowns():
    """The wizard's server-side TLS min/max selects must not list
    TLSv1.0 / TLSv1.1 since ServerStep.reject_server_ca_bundle_without_ssl
    rejects those values at the API boundary."""
    src = (_FRONT / "components" / "SiteWizard.js").read_text()
    # Locate the server TLS dropdowns inside the servers Form.List.
    # Inside the "TLS min" / "TLS max" Form.Items there must be only
    # TLSv1.2 and TLSv1.3 Option lines.
    assert 'name={[name, \'ssl_min_ver\']}' in src, (
        "server-side ssl_min_ver Form.Item missing — refactor break"
    )
    # Quick neighborhood scan: between the TLS min Form.Item and the
    # TLS max Form.Item there must be NO TLSv1.0/TLSv1.1 string.
    min_anchor = src.find("name={[name, 'ssl_min_ver']}")
    max_anchor = src.find("name={[name, 'ssl_max_ver']}", min_anchor + 1)
    end_max = src.find("</Select>", max_anchor)
    assert end_max > 0
    snippet = src[min_anchor:end_max]
    assert "TLSv1.0" not in snippet, (
        "R18c-#33 regression: TLSv1.0 still offered in server TLS UI"
    )
    assert "TLSv1.1" not in snippet, (
        "R18c-#33 regression: TLSv1.1 still offered in server TLS UI"
    )
    assert "TLSv1.2" in snippet
    assert "TLSv1.3" in snippet


# =====================================================================
# M2 — Resume hydration race (cert reconciliation guard)
# =====================================================================

@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_site_wizard_tracks_existing_certs_loading_state():
    src = (_FRONT / "components" / "SiteWizard.js").read_text()
    assert "const [existingCertsLoading, setExistingCertsLoading]" in src, (
        "R18c-#34 regression: SiteWizard must track existing-cert "
        "fetch state (existingCertsLoading) to guard Submit during "
        "resume race"
    )


@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_site_wizard_disables_submit_while_cert_reconciliation_pending():
    """The unified submit button must be disabled while sslMode ==
    'existing' and the cluster-scoped cert list is still loading.

    Phase K Phase D (Bulgu #6) — Updated for the post-unification
    UI: the old 'Create as PENDING' button was retired; only the
    'Create Site' / 'Create & Apply (ACME)' button remains. The
    `acmeBlocksDraft` flag was retired too — handleSubmit derives
    apply_immediately from sslMode internally. The cert-race guard
    still applies to the surviving button.
    """
    src = (_FRONT / "components" / "SiteWizard.js").read_text()
    assert "certReconciliationPending" in src, (
        "R18c-#34 regression: SiteWizard must define a guard variable "
        "(certReconciliationPending) to express the resume-race state"
    )
    # Phase K Phase D: only one submit button now — pin the cert-race
    # guard on that button's disabled clause.
    assert "acmeBlocksSubmit || certReconciliationPending" in src, (
        "Create button missing certReconciliationPending guard "
        "(Phase K Phase D unified the two pre-existing submit buttons "
        "into one; the cert-race guard moved onto the survivor)."
    )


@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_site_wizard_existing_cert_fetch_toggles_loading_flag():
    """The cluster-scoped /api/ssl/certificates fetch effect must
    set the loading flag at fetch start AND clear it in finally so
    a network failure does not leave the Submit button disabled."""
    src = (_FRONT / "components" / "SiteWizard.js").read_text()
    assert "setExistingCertsLoading(true);" in src, (
        "fetch effect must set loading=true before issuing the GET"
    )
    assert "setExistingCertsLoading(false);" in src, (
        "fetch effect must always clear loading (use finally branch)"
    )


# =====================================================================
# M3 — 500 detail leakage replaced with correlation id
# =====================================================================

def test_create_site_500_does_not_leak_exception_str():
    src = (_BACK / "routers" / "site_wizard.py").read_text()
    # The new error-handling block uses a uuid4-derived correlation id
    # and a stable user-facing message. The stale `detail=str(e)` form
    # must be gone.
    assert "raise HTTPException(status_code=500, detail=str(e))" not in src, (
        "R18c-#35 regression: 500 catch-all leaks str(e) to client"
    )
    assert "correlation_id = uuid.uuid4().hex" in src, (
        "R18c-#35 regression: 500 path must mint a correlation id"
    )
    assert "Wizard create failed unexpectedly" in src, (
        "R18c-#35 regression: 500 detail must be a stable generic message"
    )
    assert 'correlation_id=' in src, (
        "R18c-#35 regression: server log must include correlation_id label"
    )


# =====================================================================
# M4 — handleCancel Modal must reject mask / keyboard dismissal
# =====================================================================

@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_site_wizard_cancel_modal_disables_keyboard_and_mask():
    src = (_FRONT / "components" / "SiteWizard.js").read_text()
    # Locate the handleCancel function block.
    cancel_start = src.find("const handleCancel = ()")
    assert cancel_start >= 0
    cancel_end = src.find("};", cancel_start)
    block = src[cancel_start:cancel_end]
    assert "keyboard: false" in block, (
        "R18c-#36 regression: handleCancel modal must disable keyboard "
        "(Esc) dismissal so it does not silently invoke Save Draft"
    )
    assert "maskClosable: false" in block, (
        "R18c-#36 regression: handleCancel modal must disable mask click "
        "dismissal for the same reason"
    )


# =====================================================================
# M5 — fetchInitial surfaces failures
# =====================================================================

@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_site_wizard_fetch_initial_no_silent_catch():
    """Phase K Phase D update: the wizard's `fetchInitial` no longer
    duplicates the cluster fetch — `useCluster()` (shared
    ClusterContext) is the single source of truth for the cluster
    list now. The LE accounts fetch remains wizard-local because no
    other page needs it. The pin therefore:

      * still forbids the silent `catch (_e) {}` swallow,
      * still requires LE account failures to surface as info,
      * REMOVES the (now-impossible) cluster-fetch-failure pin
        because there is no cluster fetch left in this function.
    """
    src = (_FRONT / "components" / "SiteWizard.js").read_text()
    # Find the fetchInitial body.
    start = src.find("const fetchInitial = useCallback(async ()")
    assert start >= 0
    # The function ends at the `}, []);` that closes the useCallback.
    end = src.find("}, []);", start)
    block = src[start:end]
    # The legacy silent catch block must be gone.
    assert "catch (_e) {" not in block, (
        "R18c-#37 regression: fetchInitial must not swallow errors via "
        "an empty catch block"
    )
    # LE accounts surfacing remains required.
    assert "message.info(extractApiError(acmeRes.reason" in src, (
        "R18c-#37 regression: LE accounts fetch failure must produce a "
        "user-visible info message"
    )
    # Phase K Phase D: the wizard MUST NOT duplicate the
    # /api/clusters fetch. ClusterContext owns it.
    assert "axios.get('/api/clusters')" not in block, (
        "Phase K Phase D (Bulgu #1) regression: fetchInitial is "
        "back to duplicating the /api/clusters fetch. That doubles "
        "cluster-manager load and races ClusterContext's hydration."
    )


# =====================================================================
# M8 — apply_immediately coercion moved out of render path
# =====================================================================

@pytest.mark.skipif(not _FRONTEND_AVAILABLE, reason="frontend/src not present")
def test_site_wizard_acme_apply_coercion_in_useeffect_not_settimeout():
    src = (_FRONT / "components" / "SiteWizard.js").read_text()
    # The render-time setTimeout that mutated form state must be gone.
    bad = "setTimeout(() => form.setFieldsValue({ apply_immediately: true }), 0)"
    assert bad not in src, (
        "R18c-#38 regression: setTimeout-in-render apply_immediately "
        "coercion must be replaced by a useEffect"
    )
    # And there must be a useEffect dependent on sslMode that performs
    # the coercion.
    needle_effect = "useEffect(() => {\n    if (sslMode === 'acme') {"
    needle_set = "form.setFieldsValue({ apply_immediately: true });"
    assert needle_effect in src, (
        "R18c-#38 regression: missing sslMode-keyed useEffect that "
        "coerces apply_immediately when ssl.mode == 'acme'"
    )
    # Make sure the coercion still runs (idempotently).
    assert needle_set in src, (
        "useEffect must still call setFieldsValue to flip "
        "apply_immediately"
    )
