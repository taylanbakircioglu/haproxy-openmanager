"""Phase K — Site Wizard validation hardening (Phase A pins).

These pins lock the contract / safety / cross-field decisions made in
Phase A of the Site Wizard validation hardening + UX simplification
plan. They are deliberately model-level (not endpoint-level) so the
Pydantic invariant survives any future router refactor without an HTTP
client harness.

Background
----------

Before Phase A:
  * `FrontendStep.acl_rules` was typed `List[dict]` while
    `frontend/src/components/ACLRuleBuilder.js::serializeAclRule`
    emitted `string`.  Every wizard POST containing a single ACL rule
    failed Pydantic validation with
        body -> frontend -> acl_rules -> 0:
            Input should be a valid dictionary
    Same for `use_backend_rules`. The tool was effectively unusable
    for any non-trivial site.
  * `FrontendStep` did not catch `mode='tcp' + https_redirect=true`.
    The renderer would silently emit an HTTP-only directive into a
    TCP frontend and the agent's `haproxy -c` would reject the
    config only at apply time.
  * `SSLChoice` did not catch `ssl_min_ver > ssl_max_ver`. HAProxy
    accepted the syntax but every TLS handshake failed at runtime.

After Phase A:
  * `acl_rules: List[str]`, `use_backend_rules: List[str]` (manual API
    parity at `backend/models/frontend.py::validate_acl_rules`).
  * `redirect_rules: List[Union[str, dict]]` — kept heterogeneous on
    purpose so the structured-redirect path
    (`services/haproxy_config.py::_format_redirect_rule`) keeps
    working for any historical caller.
  * Every rule string is bounded (4 KB), newline-free, danger-pattern
    free, non-empty after `.strip()`. Mirrors the manual frontend
    API's pre-existing security posture.
  * `FrontendStep.reject_tcp_mode_with_https_redirect` and
    `SSLChoice.reject_inverted_tls_versions` close two silent-bug
    gaps surfaced by the audit.
"""

import pytest
from pydantic import ValidationError

from models.site_wizard import FrontendStep, SSLChoice


def _frontend_kwargs(**overrides):
    """Minimal valid FrontendStep kwargs."""
    base = dict(name="fe_http", mode="http", bind_port=80)
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────
# Phase K-A1 — acl_rules contract + safety validators
# ─────────────────────────────────────────────────────────────────────


def test_phase_k_frontend_step_acl_rules_is_list_str_with_safety_validators():
    """Phase A: acl_rules accepts string list + rejects every known
    unsafe shape (dict, newline injection, danger pattern, oversize)."""
    fe = FrontendStep(**_frontend_kwargs(acl_rules=["is_api path_beg /api"]))
    assert fe.acl_rules == ["is_api path_beg /api"]

    with pytest.raises(ValidationError, match="must be HAProxy directive strings"):
        FrontendStep(**_frontend_kwargs(acl_rules=[{"raw": "is_api path_beg /api"}]))

    with pytest.raises(ValidationError, match="line breaks"):
        FrontendStep(
            **_frontend_kwargs(acl_rules=["is_api path_beg /api\nglobal\n  daemon"])
        )

    with pytest.raises(ValidationError, match="dangerous content"):
        FrontendStep(
            **_frontend_kwargs(acl_rules=["is_evil path_beg $(rm -rf /)"])
        )

    with pytest.raises(ValidationError, match="exceeds 4096 characters"):
        FrontendStep(**_frontend_kwargs(acl_rules=["a " * 3000]))


def test_phase_k_frontend_step_use_backend_rules_is_list_str_with_safety_validators():
    """Same matrix as ACL — use_backend_rules has the same contract
    because `routers/backend.py:1281-1298` substring-matches against
    these strings to clean up after a backend deletion."""
    fe = FrontendStep(
        **_frontend_kwargs(use_backend_rules=["api_be if is_api"])
    )
    assert fe.use_backend_rules == ["api_be if is_api"]

    with pytest.raises(ValidationError, match="must be HAProxy directive strings"):
        FrontendStep(
            **_frontend_kwargs(use_backend_rules=[{"backend": "api_be"}])
        )

    with pytest.raises(ValidationError, match="line breaks"):
        FrontendStep(
            **_frontend_kwargs(use_backend_rules=["api_be if is_api\nbackend foo"])
        )

    with pytest.raises(ValidationError, match="dangerous content"):
        FrontendStep(
            **_frontend_kwargs(use_backend_rules=["api_be if `eval x`"])
        )

    with pytest.raises(ValidationError, match="exceeds 4096 characters"):
        FrontendStep(**_frontend_kwargs(use_backend_rules=["x " * 3000]))


# ─────────────────────────────────────────────────────────────────────
# Phase K-A2 — redirect_rules deliberate heterogeneity
# ─────────────────────────────────────────────────────────────────────


def test_phase_k_frontend_step_redirect_rules_accepts_string_or_dict():
    """`redirect_rules` stays `List[Union[str, dict]]` because the
    renderer at `services/haproxy_config.py::_format_redirect_rule`
    deliberately accepts both shapes. Forcing string-only would
    silently break the structured-redirect path."""
    fe_str = FrontendStep(
        **_frontend_kwargs(redirect_rules=["scheme https if !{ ssl_fc }"])
    )
    assert fe_str.redirect_rules == ["scheme https if !{ ssl_fc }"]

    fe_dict = FrontendStep(
        **_frontend_kwargs(redirect_rules=[{"scheme": "https", "code": 301}])
    )
    assert fe_dict.redirect_rules == [{"scheme": "https", "code": 301}]

    fe_mixed = FrontendStep(
        **_frontend_kwargs(
            redirect_rules=[
                "scheme https if !{ ssl_fc }",
                {"scheme": "https", "code": 301},
            ]
        )
    )
    assert len(fe_mixed.redirect_rules) == 2

    with pytest.raises(ValidationError, match="HAProxy directive strings or"):
        FrontendStep(**_frontend_kwargs(redirect_rules=[42]))


# ─────────────────────────────────────────────────────────────────────
# Phase K-A3 — empty / whitespace rule reject (would render as
# `acl ` / `use_backend ` and fail haproxy -c)
# ─────────────────────────────────────────────────────────────────────


def test_phase_k_frontend_step_rejects_empty_string_rule_element():
    """Empty / whitespace-only rule strings are rejected at validation
    time on every rule field — they would otherwise render as bare
    `acl ` / `use_backend ` lines that fail `haproxy -c`."""
    for field in ("acl_rules", "use_backend_rules"):
        with pytest.raises(ValidationError, match="empty / whitespace-only"):
            FrontendStep(**_frontend_kwargs(**{field: [""]}))
        with pytest.raises(ValidationError, match="empty / whitespace-only"):
            FrontendStep(**_frontend_kwargs(**{field: ["   "]}))

    with pytest.raises(ValidationError, match="empty / whitespace-only"):
        FrontendStep(**_frontend_kwargs(redirect_rules=[""]))
    with pytest.raises(ValidationError, match="empty / whitespace-only"):
        FrontendStep(**_frontend_kwargs(redirect_rules=["   "]))


# ─────────────────────────────────────────────────────────────────────
# Phase K-A4 — TCP-mode + https_redirect cross-field validator
# ─────────────────────────────────────────────────────────────────────


def test_phase_k_frontend_step_rejects_tcp_mode_with_https_redirect():
    """`mode='tcp' + https_redirect=true` was a silent bug — the
    renderer emits an HTTP-only directive into a TCP frontend and
    the agent's `haproxy -c` rejects it only at apply time. Phase A
    rejects it at the wizard boundary."""
    with pytest.raises(
        ValidationError,
        match="frontend.mode='tcp' is incompatible with frontend.https_redirect",
    ):
        FrontendStep(**_frontend_kwargs(mode="tcp", https_redirect=True))

    fe_http = FrontendStep(**_frontend_kwargs(mode="http", https_redirect=True))
    assert fe_http.https_redirect is True
    fe_tcp = FrontendStep(**_frontend_kwargs(mode="tcp", https_redirect=False))
    assert fe_tcp.https_redirect is False


# ─────────────────────────────────────────────────────────────────────
# Phase K-A5 — TLS min/max inversion validator on SSLChoice
# ─────────────────────────────────────────────────────────────────────


def test_phase_k_sslchoice_rejects_inverted_tls_versions():
    """`ssl_min_ver > ssl_max_ver` produces a bind that accepts no TLS
    handshakes at runtime — surface the contradiction at the wizard
    boundary instead of in production."""
    with pytest.raises(
        ValidationError,
        match="cannot be greater than ssl.ssl_max_ver",
    ):
        SSLChoice(mode="none", ssl_min_ver="TLSv1.3", ssl_max_ver="TLSv1.2")

    ssl_ok = SSLChoice(mode="none", ssl_min_ver="TLSv1.2", ssl_max_ver="TLSv1.3")
    assert ssl_ok.ssl_min_ver == "TLSv1.2"
    assert ssl_ok.ssl_max_ver == "TLSv1.3"

    ssl_equal = SSLChoice(mode="none", ssl_min_ver="TLSv1.2", ssl_max_ver="TLSv1.2")
    assert ssl_equal.ssl_min_ver == "TLSv1.2"
    assert ssl_equal.ssl_max_ver == "TLSv1.2"

    ssl_one_set = SSLChoice(mode="none", ssl_min_ver="TLSv1.2")
    assert ssl_one_set.ssl_min_ver == "TLSv1.2"
    assert ssl_one_set.ssl_max_ver is None


# ─────────────────────────────────────────────────────────────────────
# Phase K-C — shared synthesis helper + dry-run preview behaviour
# ─────────────────────────────────────────────────────────────────────


def _site_payload(**overrides):
    """Minimal valid SiteCreate payload for synthesis tests."""
    from models.site_wizard import SiteCreate
    base = {
        "cluster_id": 1,
        "domains": ["www.example.com"],
        "backend": {"name": "be"},
        "servers": [{
            "server_name": "s1",
            "server_address": "10.0.0.1",
            "server_port": 80,
        }],
        "frontend": {"name": "fe", "bind_port": 80},
        "ssl": {"mode": "none"},
    }
    base.update(overrides)
    return SiteCreate(**base)


def test_phase_k_create_site_and_preview_use_same_synthesis_helper():
    """Phase K Phase C — both `create_site` and the dry-run preview
    path must route through `_synthesize_candidate_haproxy_config`.
    A static-source pin keeps a future refactor from quietly
    inlining the call on one side and breaking parity between the
    apply gate and the dry-run gate.

    The helper is intentionally two-mode:
      * `entities_already_inserted=True` for `create_site` (the
        wizard's INSERTs are already in the active transaction so
        the renderer sees them).
      * `entities_already_inserted=False` for the preview dry-run
        (no DB writes happen — we render the current cluster + a
        candidate fragment).
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "site_wizard.py"
    body = src.read_text()
    assert "_synthesize_candidate_haproxy_config" in body, (
        "Phase K Phase C regression: routers/site_wizard.py no "
        "longer defines `_synthesize_candidate_haproxy_config`."
    )
    assert body.count("_synthesize_candidate_haproxy_config(") >= 3, (
        "Phase K Phase C regression: the helper is no longer "
        "called from BOTH create_site (entities_already_inserted=True) "
        "and preview_create (entities_already_inserted=False). "
        "Without two callsites the dry-run gate and the apply gate "
        "can desync silently."
    )
    assert "entities_already_inserted=True" in body, (
        "Phase K Phase C regression: create_site no longer passes "
        "entities_already_inserted=True. Without it the helper "
        "would re-render the candidate fragment on top of the "
        "post-insert config, producing duplicate frontend / "
        "backend sections in the persisted version."
    )
    assert "entities_already_inserted=False" in body, (
        "Phase K Phase C regression: the preview dry-run no longer "
        "passes entities_already_inserted=False. Without the "
        "candidate-fragment append, the validator would only see "
        "the cluster's CURRENT config and miss every wizard-input "
        "induced error."
    )


def test_phase_k_synthesis_helper_acme_mode_omits_https_frontend():
    """Phase K Phase C — when `ssl.mode='acme'` the synthesizer
    must NOT emit a `bind … ssl crt …` directive in the candidate
    fragment. ACME's HTTPS frontend is created post-completion
    inside the LE callback (see `routers/letsencrypt.py:1012-1014`)
    — surfacing a synthetic HTTPS bind here would produce false-
    positive errors about a missing crt path.
    """
    from routers.site_wizard import _build_candidate_fragment
    acme_payload = _site_payload(
        ssl={"mode": "acme"},
        apply_immediately=True,
        frontend={"name": "fe", "bind_port": 80, "mode": "http"},
    )
    fragment = _build_candidate_fragment(acme_payload)
    assert "frontend fe" in fragment, "HTTP frontend must still render in ACME mode"
    assert "backend be" in fragment, "backend must still render in ACME mode"
    assert "ssl crt" not in fragment, (
        "Phase K Phase C regression: ACME mode synthesizer is now "
        "emitting `ssl crt …` for an HTTPS frontend that does not "
        "exist yet — this would surface a false positive error in "
        "the dry-run gate when the operator is on Step 4 with a "
        "valid ACME draft."
    )

    upload_payload = _site_payload(
        ssl={
            "mode": "upload",
            "name": "test-cert",
            "certificate_content": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
            "private_key_content": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
        },
    )
    upload_fragment = _build_candidate_fragment(upload_payload)
    assert "ssl crt" in upload_fragment, (
        "Phase K Phase C regression: upload mode no longer renders "
        "a `bind … ssl crt …` directive — the dry-run would miss "
        "every TLS-bind related error class."
    )


def test_phase_k_preview_dry_run_query_param_is_optional():
    """Phase K Phase C — the `validate_haproxy_config` flag must be
    OPTIONAL on `POST /api/sites/preview` (default false). Existing
    callers (e.g. `SiteDrafts.handlePreview`) pass no flag and
    must keep their existing behaviour. Static-source pin.
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "site_wizard.py"
    body = src.read_text()
    assert "validate_haproxy_config: bool = False" in body, (
        "Phase K Phase C regression: the preview endpoint no "
        "longer accepts `validate_haproxy_config` as an OPTIONAL "
        "flag (default False). A non-default would break legacy "
        "callers that never pass it."
    )


def test_phase_k_preview_dry_run_validator_crash_is_non_fatal():
    """Phase K Phase C — when the validator itself raises, the
    preview must return a `validation` block with `is_valid: null`
    + `validator_error`. HTTP status stays 200. Mirrors the
    existing create_site contract at
    `routers/site_wizard.py:1118-1124` (validator-crash-is-non-fatal).
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "site_wizard.py"
    body = src.read_text()
    # The crash branch must (a) emit a logger.warning, (b) wrap the
    # response with is_valid=None, (c) NEVER raise an HTTPException.
    assert '"is_valid": None' in body, (
        "Phase K Phase C regression: the dry-run validator-crash "
        "branch no longer returns `is_valid: None`. The frontend "
        "uses None as a tri-state to render the `unavailable` UX "
        "(orange 'validation could not be performed' Alert)."
    )
    assert "validator_error" in body, (
        "Phase K Phase C regression: the dry-run validator-crash "
        "branch no longer surfaces `validator_error` to the "
        "operator — without it operators cannot tell why the "
        "validation became unavailable."
    )


def test_phase_k_preview_dry_run_rate_limit_only_on_dry_run_path():
    """Phase K Phase C — `_enforce_rate_limit` must run ONLY when
    `validate_haproxy_config=true`. Legacy preview callers
    (`SiteDrafts.handlePreview`) keep their unrestricted budget.
    Static-source pin.
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "site_wizard.py"
    body = src.read_text()
    # Find the preview_create function body — Header(None) has nested
    # parens in the signature so we anchor on the def line and the
    # next `async def `/`def `/`@router.` instead of a parenthesised
    # signature regex.
    start = body.find("async def preview_create(")
    assert start >= 0, "preview_create function not found"
    # End at the next top-level def or router decorator after `start`.
    next_async = body.find("\nasync def ", start + 1)
    next_def = body.find("\ndef ", start + 1)
    next_router = body.find("\n@router.", start + 1)
    candidates = [x for x in (next_async, next_def, next_router) if x >= 0]
    end = min(candidates) if candidates else len(body)
    fn_body = body[start:end]
    assert "if validate_haproxy_config:" in fn_body, (
        "Phase K Phase C regression: the rate-limit path is no "
        "longer gated by the dry-run flag — every legacy preview "
        "caller would be rate-limited too, breaking SiteDrafts."
    )
    assert '_enforce_rate_limit(conn, current_user["id"], "site_previewed")' in fn_body, (
        "Phase K Phase C regression: the dry-run preview path no "
        "longer rate-limits at 5/min. The Step 4 auto-fire could "
        "spam the validator on every keystroke if the wizard's "
        "invalidate-on-change effect ever loops."
    )


def test_phase_k_preview_dry_run_returns_severity_buckets():
    """Phase K Phase C — the dry-run path must bucket validator
    results by severity (errors / warnings / infos). Static-source
    pin on the `validation` envelope shape.
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "site_wizard.py"
    body = src.read_text()
    for key in ('"errors"', '"warnings"', '"infos"', '"is_valid"',
                '"error_count"', '"warning_count"'):
        assert key in body, (
            f"Phase K Phase C regression: the dry-run `validation` "
            f"envelope no longer surfaces {key} — the wizard "
            "frontend's severity-aware UI relies on this exact "
            "shape to render the green / yellow / red Alerts."
        )


def test_phase_k_preview_dry_run_does_not_persist_via_helper():
    """Phase K Phase C — `_synthesize_candidate_haproxy_config`
    only calls the read-only `generate_haproxy_config_for_cluster`
    plus a pure-string `_build_candidate_fragment`. Static-source
    pin guards against a refactor that calls a `create_*_row`
    helper from inside the preview branch.
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "site_wizard.py"
    body = src.read_text()
    start = body.find("async def _synthesize_candidate_haproxy_config(")
    assert start >= 0, "_synthesize_candidate_haproxy_config function body not found"
    next_async = body.find("\nasync def ", start + 1)
    next_def = body.find("\ndef ", start + 1)
    next_router = body.find("\n@router.", start + 1)
    candidates = [x for x in (next_async, next_def, next_router) if x >= 0]
    end = min(candidates) if candidates else len(body)
    fn_body = body[start:end]
    for forbidden in (
        "create_backend_row(",
        "create_server_row(",
        "create_frontend_row(",
        "create_cert_row(",
    ):
        assert forbidden not in fn_body, (
            "Phase K Phase C regression: the synthesizer now "
            f"calls `{forbidden}…` — the dry-run helper must "
            "stay write-free; persistence belongs in `create_site`."
        )


def test_phase_k_preview_dry_run_telemetry_emits_log_lines():
    """Phase K Phase C — each dry-run must emit two structured log
    lines (ENTER + EXIT) so operators can correlate "Create button
    is disabled" with backend telemetry. Static-source pin.
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "site_wizard.py"
    body = src.read_text()
    assert "WIZARD: dry-run /preview ENTER" in body, (
        "Phase K Phase C regression: the dry-run ENTER log line is "
        "no longer emitted. Operators debugging \"why is Create "
        "disabled\" rely on this line to confirm the request "
        "reached the backend."
    )
    assert "WIZARD: dry-run /preview EXIT" in body, (
        "Phase K Phase C regression: the dry-run EXIT log line is "
        "no longer emitted with error_count / warning_count / "
        "duration_ms. Operators rely on this to correlate slow "
        "validations with cluster-side issues."
    )


def test_phase_k_phase_d_sitedrafts_renders_cluster_name_not_raw_id():
    """Phase K Phase D follow-up (operator feedback, round 4) —
    the Site Drafts table previously rendered the raw `cluster_id`
    integer in its "Cluster" column. Operators think in cluster
    names, not surrogate keys: "1" or "2" is meaningless without a
    legend mapping. The page now consumes `useCluster()` and renders
    the cluster's `name`, falling back to a `#id` tag with an
    explanatory tooltip when the cluster is missing from the
    context (deleted / list still loading).

    Static-source pin so a future refactor that switches back to
    `String(cid)` is caught immediately. Pin is skipped in the
    backend-only build container where `frontend/` is not shipped
    (matches the convention used by sibling tests, see e.g.
    `test_site_wizard_form.py`).
    """
    from pathlib import Path
    src = (
        Path(__file__).resolve().parent.parent.parent
        / "frontend"
        / "src"
        / "components"
        / "SiteDrafts.js"
    )
    if not src.exists():
        pytest.skip(
            f"frontend not present at {src}; running in backend-only "
            "container is expected — skip JS source pin"
        )
    body = src.read_text()

    # The drafts page must import `useCluster` so the column renderer
    # has a cluster list to resolve names against.
    assert "useCluster" in body, (
        "SiteDrafts must import `useCluster` to translate cluster_id "
        "values into cluster names."
    )

    # The helper that translates id → display label must exist and
    # be reused by both the table column AND the preview modal so the
    # two stay in sync.
    assert "renderClusterLabel" in body, (
        "SiteDrafts must define a `renderClusterLabel` helper that "
        "maps cluster_id → cluster.name (with id fallback) and is "
        "shared by the table column and the Preview modal."
    )

    # The previous broken rendering branch must be gone.
    assert "String(cid)" not in body, (
        "SiteDrafts regression: the Cluster column is back to "
        "rendering the raw `String(cid)` integer. Use "
        "`renderClusterLabel(cid)` instead."
    )

    # The Preview modal's Descriptions item must use the new helper
    # and the human-friendly label, not "Cluster ID".
    assert 'label="Cluster ID"' not in body, (
        "SiteDrafts Preview modal regression: the cluster row is "
        "back to the operator-hostile `label=\"Cluster ID\"` and "
        "raw integer rendering."
    )
