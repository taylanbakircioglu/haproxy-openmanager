"""R11 (Round 11) — Site Wizard hotfix audit (PR-1 scope).

These tests guard the PR-1 hotfix bundle for the user-reported bug
where wizard-created entities (and pre-existing manually-created
entities after a wizard reject + apply cycle) failed HAProxy
validation with::

    [ALERT] verify is enabled but no CA file specified for bind '...'
    [WARNING] redirect rule parser error '(was '{code:'
    [WARNING] http-request placed after use_backend will still be processed before
    [WARNING] tcp-request placed after http-request ...
    [WARNING] stick-table already declared
    [ALERT] Fatal errors found in configuration

The PR-1 hotfix lives in:

  - ``backend/services/haproxy_config.py``
      * ``_format_redirect_rule`` helper (R11.A-1 redirect dict→string fix)
      * ``_apply_bind_ssl_verify`` helper (R11.A-2 bind-side ssl_verify
        safeguard — no client-CA → no `verify` directive emitted)
      * ``_resolve_frontend_client_ca_path`` placeholder (forward-path
        for PR-7 ssl_client_ca_certificate_id column)
      * ``_categorize_haproxy_directive`` (R2.3 frontend-block emit
        ordering buckets)
      * Per-frontend bucket flush (`_fe_buckets`, `_emit_fe`) replacing
        the prior in-place `config_lines.append(...)` calls so the
        rendered block always emits in canonical HAProxy order:
        prelude → stick → tcp-request → acl → http-request →
        http-response → redirect → use_backend → default_backend.
      * Stick-table emission dedup across frontend.rate_limit + WAF
        rate_limit rules.

  - ``backend/routers/site_wizard.py``
      * ``_build_redirect_rules`` row schema (no URL in 'location' for
        type=scheme; explicit 'scheme' field instead).

These are static-source assertions, NOT integration tests against a
real Postgres fixture — consistent with tests/test_proxied_host_*
peers in the suite. The integration coverage is in the apply path
itself (HAProxy `-c` validation runs in the agent).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


_BACK = Path(__file__).resolve().parent.parent
_GEN = _BACK / "services" / "haproxy_config.py"
_ROUTER = _BACK / "routers" / "site_wizard.py"


def _gen_src() -> str:
    if not _GEN.exists():
        pytest.skip("services/haproxy_config.py not present")
    return _GEN.read_text()


def _router_src() -> str:
    if not _ROUTER.exists():
        pytest.skip("routers/site_wizard.py not present")
    return _ROUTER.read_text()


# ─────────────────────────────────────────────────────────────────────────────
# R11.A-1: redirect_rules dict → string fix + canonical scheme redirect schema
# ─────────────────────────────────────────────────────────────────────────────


def test_format_redirect_rule_helper_exists():
    """The helper that safely renders dict redirect rules into HAProxy
    `redirect <type> ...` lines must exist. Pre-fix the generator
    used `str(redirect)` which stringified dicts and produced
    parser-fatal output."""
    assert "def _format_redirect_rule(" in _gen_src(), (
        "R11.A-1 regression: _format_redirect_rule helper missing"
    )


def test_legacy_str_redirect_pattern_removed():
    """The pre-fix `str(redirect)` stringification must no longer be
    present in the redirect-rules emit branch."""
    src = _gen_src()
    assert "redirect_text = str(redirect).strip()" not in src, (
        "R11.A-1 regression: legacy `str(redirect)` stringification "
        "reappeared — wizard-generated dict redirects will produce "
        "parser-fatal HAProxy output."
    )


def test_format_redirect_rule_renders_scheme_correctly():
    """Behavioural test: scheme-type redirect renders into proper
    HAProxy ``redirect scheme <name> code <N> if <cond>`` syntax."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_haproxy_cfg", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    line = mod._format_redirect_rule({
        "type": "scheme", "scheme": "https",
        "code": 301, "condition": "!{ ssl_fc }",
    })
    assert line is not None
    assert "redirect scheme https" in line
    assert "code 301" in line
    assert "if !{ ssl_fc }" in line
    # No literal URL leaks (the pre-fix bug)
    assert "https://" not in line, (
        "R11.A-1 regression: redirect scheme rendered with URL — "
        "HAProxy `redirect scheme` only accepts a literal scheme name."
    )


def test_format_redirect_rule_renders_location_correctly():
    import importlib.util
    spec = importlib.util.spec_from_file_location("_haproxy_cfg", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    line = mod._format_redirect_rule({
        "type": "location", "location": "/v2/login",
        "code": 302, "condition": "",
    })
    assert "redirect location /v2/login" in line
    assert "code 302" in line


def test_format_redirect_rule_skips_invalid():
    import importlib.util
    spec = importlib.util.spec_from_file_location("_haproxy_cfg", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    assert mod._format_redirect_rule(None) is None
    assert mod._format_redirect_rule({"type": "unknown"}) is None
    assert mod._format_redirect_rule({"type": "scheme", "scheme": "ftp"}) is None
    assert mod._format_redirect_rule({"type": "location", "location": ""}) is None


def test_build_redirect_rules_no_location_key_for_scheme():
    """Wizard `_build_redirect_rules` must not emit a 'location' field
    on a type=scheme rule (HAProxy parser fatal). Pre-fix the row
    contained both 'type:scheme' and 'location:https://...' which
    is the exact cause of the user-reported parser error."""
    src = _router_src()
    # The canonical HTTPS-redirect block in the helper must contain
    # `"scheme": "https"` and must NOT contain a string starting with
    # `https://` (URL leak).
    # Round-13 audit: the original regex used `[^{]*?` which now
    # collides with curly braces inside the Bulgu #29 docstring
    # (e.g. `!{ ssl_fc }`). Locate the function body via slicing
    # from `def _build_redirect_rules(` to the NEXT top-level `def`
    # / EOF, then look for the canonical scheme/code/condition keys.
    idx = src.find("def _build_redirect_rules(")
    assert idx >= 0, "R11.A-1: _build_redirect_rules helper not found"
    # Next top-level def OR end-of-file.
    next_def = src.find("\ndef ", idx + 1)
    body = src[idx:next_def if next_def != -1 else len(src)]

    # Canonical scheme redirect must use the 'scheme' key
    assert '"scheme": "https"' in body or "'scheme': 'https'" in body, (
        "R11.A-1 regression: canonical HTTPS redirect must use the "
        "'scheme: https' field (not a URL in 'location')."
    )
    # The pre-fix URL form must be gone
    assert 'https://%[hdr(host)]' not in body, (
        "R11.A-1 regression: pre-fix URL-as-location pattern remained "
        "in _build_redirect_rules."
    )


# ─────────────────────────────────────────────────────────────────────────────
# R11.A-2: bind-side ssl_verify safeguard
# ─────────────────────────────────────────────────────────────────────────────


def test_apply_bind_ssl_verify_helper_exists():
    src = _gen_src()
    assert "def _apply_bind_ssl_verify(" in src
    assert "def _resolve_frontend_client_ca_path(" in src


def test_apply_bind_ssl_verify_skips_when_no_client_ca():
    """No client-CA path → no `verify` directive on the bind line.
    This is the explicit safeguard for the user-reported fatal
    HAProxy ALERT 'verify is enabled but no CA file specified'.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("_haproxy_cfg", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    bind = "    bind 0.0.0.0:443 ssl crt /etc/ssl/haproxy/foo.pem"
    out = mod._apply_bind_ssl_verify(
        bind, {"name": "fe", "ssl_verify": "required"}, cluster_id=1
    )
    assert "verify required" not in out, (
        "R11.A-2 regression: `verify required` emitted without a "
        "ca-file argument — would trigger HAProxy fatal ALERT."
    )
    assert out == bind


def test_apply_bind_ssl_verify_skips_when_none_or_empty():
    import importlib.util
    spec = importlib.util.spec_from_file_location("_haproxy_cfg", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    bind = "    bind 0.0.0.0:443 ssl crt /etc/ssl/haproxy/foo.pem"
    for val in (None, "", "none", "[]", "{}", "null"):
        out = mod._apply_bind_ssl_verify(bind, {"name": "fe", "ssl_verify": val})
        assert out == bind, (
            f"R11.A-2: ssl_verify={val!r} should be a no-op on the bind line"
        )


def test_apply_bind_ssl_verify_warns_on_unknown_value():
    """Defensive: unknown ssl_verify values must NOT be emitted (the
    DB column had a stale 'true'/'false' default in some legacy
    deployments — surfaced via warning only, not via parser-fatal
    output)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_haproxy_cfg", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    bind = "    bind 0.0.0.0:443 ssl crt /etc/ssl/haproxy/foo.pem"
    out = mod._apply_bind_ssl_verify(bind, {"name": "fe", "ssl_verify": "true"})
    assert out == bind


# ─────────────────────────────────────────────────────────────────────────────
# R2.3: frontend-block emit ordering buckets
# ─────────────────────────────────────────────────────────────────────────────


def test_categorize_helper_exists():
    src = _gen_src()
    assert "def _categorize_haproxy_directive(" in src


def test_categorize_routes_directives_correctly():
    import importlib.util
    spec = importlib.util.spec_from_file_location("_haproxy_cfg", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    cases = [
        ("    acl is_admin path_beg /admin", "acl"),
        ("    stick-table type ip size 100k expire 30s store http_req_rate(10s)", "stick"),
        ("    http-request track-sc0 src", "http_req"),
        ("    http-request deny if X", "http_req"),
        ("    http-response add-header X-Frame-Options DENY", "http_resp"),
        ("    tcp-request inspect-delay 5s", "tcp_req"),
        ("    redirect scheme https code 301 if !{ ssl_fc }", "redirect"),
        ("    use_backend api_be if is_api", "use_be"),
        ("    default_backend web_be", "default_be"),
        ("    option httplog", "prelude"),
        ("    timeout client 30000ms", "prelude"),
        ("    maxconn 1000", "prelude"),
        ("    monitor-uri /healthz", "prelude"),
        ("    compression algo gzip", "prelude"),
        ("    log 127.0.0.1:514 local0 info", "prelude"),
    ]
    for line, expected in cases:
        got = mod._categorize_haproxy_directive(line)
        assert got == expected, (
            f"R2.3 regression: categorize({line!r}) = {got!r}, "
            f"expected {expected!r}"
        )


def test_emit_buckets_flushed_in_canonical_order():
    """The flush block at end of frontend processing must list buckets
    in: prelude → stick → tcp_req → acl → http_req → http_resp →
    redirect → use_be → default_be. Pre-fix `http-request` rules
    interleaved with `use_backend` rules in source order, producing
    HAProxy parser warnings."""
    src = _gen_src()
    flush_match = re.search(
        r'for\s+_bucket_key\s+in\s+\(\s*'
        r'"prelude"\s*,\s*'
        r'"stick"\s*,\s*'
        r'"tcp_req"\s*,\s*'
        r'"acl"\s*,\s*'
        r'"http_req"\s*,\s*'
        r'"http_resp"\s*,\s*'
        r'"redirect"\s*,\s*'
        r'"use_be"\s*,\s*'
        r'"default_be"\s*,?\s*\)',
        src,
    )
    assert flush_match, (
        "R2.3 regression: per-frontend bucket flush is missing or "
        "buckets are listed in the wrong order. Canonical HAProxy "
        "ordering is required to silence "
        "'http-request placed after use_backend' warnings."
    )


def test_no_direct_config_lines_append_inside_use_backend_emit():
    """Sanity: the use_backend / WAF / log_separate emit branches
    must route through `_emit_fe(...)` so they end up in the right
    bucket. A regression here would re-introduce the
    out-of-order emit bug.
    """
    src = _gen_src()
    # Find the use_backend emit branch and inspect its body
    idx = src.find("# Use Backend Rules")
    assert idx >= 0, "use_backend emit branch missing entirely"
    end = src.find("# Add WAF rules for this frontend", idx)
    assert end > idx, "WAF emit branch missing"
    body = src[idx:end]
    # Inside this slice, emit must be via _emit_fe (no direct
    # `config_lines.append` for rule_text).
    assert "_emit_fe(f\"    {rule_text}\")" in body, (
        "R2.3 regression: use_backend rules no longer route through "
        "_emit_fe — they will end up in source order, breaking "
        "canonical bucket ordering."
    )


# ─────────────────────────────────────────────────────────────────────────────
# R3.3: stick-table dedup
# ─────────────────────────────────────────────────────────────────────────────


def test_stick_table_dedup_safeguard_present():
    src = _gen_src()
    assert "_stick_table_emitted" in src, (
        "R3.3 regression: stick-table dedup state variable missing — "
        "multiple WAF rate_limit rules in the same frontend will "
        "redeclare the table (HAProxy fatal 'stick-table already declared')."
    )
    assert "STICK-TABLE DEDUP" in src
