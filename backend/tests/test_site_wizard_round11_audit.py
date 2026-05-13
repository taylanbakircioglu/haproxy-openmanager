"""R11 audit (post-PR-1 + post-PR-2) — bulgu remediation regression tests.

This file pins the behavioural fixes uncovered during the systematic
7-criteria audit of the PR-1 / PR-2 hotfix bundle. Each test maps to
a specific finding (FIX-N below) so a regression can be traced back
to the original audit note in chat history.

FIX-1 (Bug):
  models/frontend.py::FrontendConfig.ssl_verify coerce was case
  sensitive — `'OPTIONAL'`/`'REQUIRED'` survived the pre-validator
  unchanged and were then REJECTED by the Literal, even though the
  lowercase equivalent is a valid value. Inconsistent with the
  sister coercers in `models/site_wizard.py` and the new
  `models/backend.py` validator.

FIX-2 (Bug):
  services/haproxy_config.py::_format_redirect_rule double-prepended
  "if" when the caller passed `condition="if !{ ssl_fc }"`,
  producing the parser-fatal line `redirect scheme https code 301
  if if !{ ssl_fc }`.

FIX-3 (Bug):
  database/migrations.py PR-2 cleanup used `fetchval()` against a
  CTE+RETURNING multi-row UPDATE — only the first row id surfaced
  in the log, masking the true cleanup count. Operators relying on
  the migration log to count touched rows would be misled.

FIX-4 (Test gap):
  No test exercised `_format_redirect_rule` with `type='prefix'`,
  `code` passed as a string (`'301'`), or the leading-`if` edge.

FIX-5 (Test gap):
  No behavioural test for the `_categorize_haproxy_directive` edge
  cases (empty line / WAF comment / `mode http` direct emit).

FIX-8 (Test gap):
  ServerConfig coerce only had lowercase coverage; uppercase
  variants were untested.
"""

from __future__ import annotations

from pathlib import Path
import importlib.util

import pytest
from pydantic import ValidationError


_BACK = Path(__file__).resolve().parent.parent
_GEN = _BACK / "services" / "haproxy_config.py"


def _load_gen():
    spec = importlib.util.spec_from_file_location("_haproxy_cfg", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ─────────────────────────────────────────────────────────────────────────────
# FIX-1: FrontendConfig case-insensitive ssl_verify coerce
# ─────────────────────────────────────────────────────────────────────────────


def test_frontend_config_ssl_verify_uppercase_coerces():
    """`'OPTIONAL'`, `'REQUIRED'`, `'NONE'` (any case) must coerce to
    the canonical lowercase Literal value, not be rejected."""
    from models.frontend import FrontendConfig

    cases = {
        "OPTIONAL": "optional",
        "Optional": "optional",
        "REQUIRED": "required",
        "Required": "required",
        "NONE": "none",
        "None": "none",
        "  Optional  ": "optional",  # surrounding whitespace
    }
    for raw, expected in cases.items():
        m = FrontendConfig(name="fe", bind_port=80, ssl_verify=raw)
        assert m.ssl_verify == expected, (
            f"FIX-1 regression: ssl_verify={raw!r} should coerce to "
            f"{expected!r}, got {m.ssl_verify!r}"
        )


def test_frontend_config_ssl_verify_garbage_still_rejected():
    """Coerce must NOT swallow garbage — only canonical values pass."""
    from models.frontend import FrontendConfig

    for bad in ("yes", "true", "1", "verify", "Optional!"):
        with pytest.raises(ValidationError):
            FrontendConfig(name="fe", bind_port=80, ssl_verify=bad)


# ─────────────────────────────────────────────────────────────────────────────
# FIX-2: _format_redirect_rule duplicate-`if` guard
# ─────────────────────────────────────────────────────────────────────────────


def test_format_redirect_rule_no_duplicate_if():
    """Caller-provided ``condition='if X'`` must NOT result in
    ``... if if X`` in the rendered line."""
    mod = _load_gen()

    line = mod._format_redirect_rule({
        "type": "scheme", "scheme": "https", "code": 301,
        "condition": "if !{ ssl_fc }",
    })
    assert line is not None
    assert " if if " not in line, (
        f"FIX-2 regression: duplicate 'if' guard missing — rendered "
        f"line was {line!r}"
    )
    # The single 'if !{ ssl_fc }' must still be present
    assert "if !{ ssl_fc }" in line


def test_format_redirect_rule_unless_clause():
    """`unless` is the only other valid HAProxy condition prefix —
    treat it the same as a leading 'if '."""
    mod = _load_gen()

    line = mod._format_redirect_rule({
        "type": "scheme", "scheme": "https", "code": 301,
        "condition": "unless { ssl_fc }",
    })
    assert line is not None
    # Must NOT prepend 'if' before 'unless'
    assert "if unless" not in line
    assert "unless { ssl_fc }" in line


def test_format_redirect_rule_naked_condition_gets_if_prefix():
    """A bare condition (no leading 'if'/'unless') must still get the
    'if ' prefix prepended."""
    mod = _load_gen()

    line = mod._format_redirect_rule({
        "type": "scheme", "scheme": "https", "code": 301,
        "condition": "!{ ssl_fc }",
    })
    assert "if !{ ssl_fc }" in line


def test_format_redirect_rule_prefix_type():
    """FIX-4: `type='prefix'` was never exercised by tests."""
    mod = _load_gen()

    line = mod._format_redirect_rule({
        "type": "prefix", "prefix": "/v2",
        "code": 301, "condition": "",
    })
    assert "redirect prefix /v2" in line
    assert "code 301" in line


def test_format_redirect_rule_code_as_string():
    """FIX-4: callers that JSON-decode an old wizard payload may
    deliver `code` as the string `'301'`. The helper must coerce
    it to int and emit `code 301`."""
    mod = _load_gen()

    line = mod._format_redirect_rule({
        "type": "scheme", "scheme": "https", "code": "301",
    })
    assert "code 301" in line


def test_format_redirect_rule_invalid_code_dropped():
    """Invalid `code` values must be dropped (logged), not rendered."""
    mod = _load_gen()

    line = mod._format_redirect_rule({
        "type": "scheme", "scheme": "https", "code": "not-an-int",
    })
    # The line is still rendered — just without the `code <N>` part
    assert "redirect scheme https" in line
    assert "code" not in line, (
        "FIX-4 regression: invalid 'code' value should be dropped "
        "(logged) rather than rendered as `code not-an-int`."
    )


# ─────────────────────────────────────────────────────────────────────────────
# FIX-5: _categorize_haproxy_directive edge cases
# ─────────────────────────────────────────────────────────────────────────────


def test_categorize_empty_line_safe():
    """Empty / whitespace-only lines must not crash the categorizer."""
    mod = _load_gen()
    assert mod._categorize_haproxy_directive("") == "prelude"
    assert mod._categorize_haproxy_directive("   ") == "prelude"
    assert mod._categorize_haproxy_directive("\t\n") == "prelude"


def test_categorize_waf_comment_routes_to_acl():
    """WAF marker comments stick to the same bucket as the ACL/HTTP
    rules they describe so the rendered config is grouped sanely."""
    mod = _load_gen()
    assert mod._categorize_haproxy_directive("    # WAF Rule: foo (Priority: 100)") == "acl"
    assert mod._categorize_haproxy_directive("    # IP Filter Log: blocked") == "acl"
    assert mod._categorize_haproxy_directive("    # Rate Limit Log: x") == "acl"
    assert mod._categorize_haproxy_directive("    # Header Filter Log: x") == "acl"


def test_categorize_unknown_directive_falls_to_prelude():
    """An unrecognised line goes to 'prelude' so it appears early
    in the rendered block — operators see it and the validator
    surfaces it as a warning rather than silently dropping it."""
    mod = _load_gen()
    assert mod._categorize_haproxy_directive("    weird-haproxy-keyword xyz") == "prelude"


# ─────────────────────────────────────────────────────────────────────────────
# FIX-9: WAF custom-comment keywords route to the 'acl' bucket
# ─────────────────────────────────────────────────────────────────────────────


def test_categorize_waf_custom_comment_keywords_route_to_acl():
    """Pre-fix the heuristic only matched 5 keywords (`waf rule:`,
    `ip filter`, `rate limit`, `header filter`, `request filter`).
    `# Log Message: ...`, `# Custom Log: ...`, `# Custom Condition
    for ...` and `# Filter Log: ...` were mis-routed to 'prelude',
    visually disconnecting the comment from the rule it
    documents."""
    mod = _load_gen()
    cases = [
        "    # Log Message: blocked by xyz",
        "    # Custom Log: bot detected",
        "    # Custom Condition for foo",
        "    # IP Filter Log: deny rule for x",
    ]
    for line in cases:
        assert mod._categorize_haproxy_directive(line) == "acl", (
            f"FIX-9 regression: {line!r} should route to 'acl' bucket "
            f"alongside the rule it documents."
        )


# ─────────────────────────────────────────────────────────────────────────────
# FIX-10: BACKEND-MODE-WARNING comments route to the 'default_be' bucket
# ─────────────────────────────────────────────────────────────────────────────


def test_categorize_backend_mode_warning_routes_to_default_be():
    """Mode-mismatch warnings use the BACKEND-MODE-WARNING marker
    so the comment emits NEXT TO the default_backend directive,
    not at the top of the frontend block (operator UX)."""
    mod = _load_gen()
    line = "    # BACKEND-MODE-WARNING: Backend 'be' has mode 'tcp' but frontend has mode 'http'"
    assert mod._categorize_haproxy_directive(line) == "default_be", (
        "FIX-10 regression: BACKEND-MODE-WARNING comments must route "
        "to 'default_be' bucket so they emit next to the directive "
        "they describe."
    )


def test_generator_uses_backend_mode_warning_marker():
    """The generator must use the BACKEND-MODE-WARNING marker (not
    the legacy `# WARNING: ...` text) so the categorize heuristic
    can find them. Pre-fix the comments matched no heuristic
    keyword and landed in the 'prelude' bucket far above the
    actual default_backend directive."""
    src = _GEN.read_text()
    assert "# BACKEND-MODE-WARNING:" in src, (
        "FIX-10 regression: mode-mismatch comments lost the marker "
        "and will route to 'prelude' instead of 'default_be'."
    )


# ─────────────────────────────────────────────────────────────────────────────
# FIX-11: _format_redirect_rule legacy double-prefix guard
# ─────────────────────────────────────────────────────────────────────────────


def test_format_redirect_rule_legacy_string_no_double_prefix():
    """Legacy DB rows from earlier releases sometimes stored the
    FULL `redirect <type> ...` line including the leading
    'redirect ' keyword. Without the guard the helper would
    prepend a second 'redirect '."""
    mod = _load_gen()

    line = mod._format_redirect_rule("redirect scheme https if !{ ssl_fc }")
    assert line is not None
    # The single 'redirect ' prefix must be present exactly once
    assert line.count("redirect ") == 1, (
        f"FIX-11 regression: double 'redirect' prefix in {line!r}"
    )
    assert "redirect scheme https" in line


def test_format_redirect_rule_naked_legacy_string_unchanged():
    """A bare legacy entry (`scheme https if !{ ssl_fc }`) without
    the leading keyword must still get a single 'redirect '
    prefix prepended — the FIX-11 strip must NOT regress this."""
    mod = _load_gen()

    line = mod._format_redirect_rule("scheme https if !{ ssl_fc }")
    assert line is not None
    assert line.count("redirect ") == 1
    assert "redirect scheme https if !{ ssl_fc }" in line


def test_format_redirect_rule_empty_after_keyword_strip():
    """`'redirect '` (just the keyword + whitespace) must skip
    cleanly rather than rendering an empty `'    redirect '`."""
    mod = _load_gen()

    assert mod._format_redirect_rule("redirect ") is None
    assert mod._format_redirect_rule("redirect    ") is None


# ─────────────────────────────────────────────────────────────────────────────
# FIX-12: BIND SSL_VERIFY DOWNGRADE log message hygiene
# ─────────────────────────────────────────────────────────────────────────────


def test_apply_bind_ssl_verify_log_no_dead_link_to_unimplemented_ui():
    """Pre-fix the diagnostic log pointed operators at a UI path
    ('Frontend Management → Advanced TLS') that does not exist
    until PR-7 — operators followed the hint, hit a dead end, and
    reported the safeguard as a bug. The new message offers a
    concrete current-release action AND notes the upcoming
    column."""
    src = _GEN.read_text()
    # The dead-link phrase must be gone
    assert "via Frontend Management → Advanced TLS" not in src, (
        "FIX-12 regression: BIND SSL_VERIFY DOWNGRADE log message "
        "still references 'Frontend Management → Advanced TLS' "
        "which does not exist on the current release."
    )
    # The actionable hint must be present
    assert "set ssl_verify='none'" in src, (
        "FIX-12 regression: BIND SSL_VERIFY DOWNGRADE log message "
        "must offer a concrete current-release action "
        "(set ssl_verify='none') instead of a dead UI link."
    )


# ─────────────────────────────────────────────────────────────────────────────
# FIX-13: uppercase 'NONE' / 'OPTIONAL' / sentinel in bind safeguard
# ─────────────────────────────────────────────────────────────────────────────


def test_apply_bind_ssl_verify_uppercase_none_skips():
    """`'NONE'` (uppercase / mixed case) is one of the legacy
    sentinel values that older clients sent. The helper must
    treat it as 'no verify directive' regardless of case."""
    mod = _load_gen()
    bind = "    bind 0.0.0.0:443 ssl crt /etc/ssl/haproxy/foo.pem"
    for raw in ("NONE", "None", "none", "  None  "):
        out = mod._apply_bind_ssl_verify(bind, {"name": "fe", "ssl_verify": raw})
        assert out == bind, (
            f"FIX-13: ssl_verify={raw!r} should be a no-op on the bind line "
            "(case-insensitive 'none' check)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Asymmetric server-side vs frontend-side ssl_verify behavior pin
# ─────────────────────────────────────────────────────────────────────────────


def test_server_side_emits_explicit_verify_none_downgrade():
    """Sanity pin: server-side mTLS downgrade explicitly emits
    'verify none' (because HAProxy 2.8+ defaults server SSL to
    'verify required' which would FAIL without a CA). Frontend-
    side instead SKIPS the directive entirely (HAProxy default
    is 'verify none' on bind). This asymmetry is intentional;
    the test exists to prevent a future maintainer from
    mistakenly "harmonising" the two paths and breaking server
    SSL reload."""
    src = _GEN.read_text()
    # Server-side path must contain explicit 'verify none' downgrade
    assert 'server_line += " verify none"' in src, (
        "Asymmetry regression: server-side ssl_verify downgrade must "
        "EXPLICITLY emit 'verify none' (HAProxy 2.8+ default is "
        "'verify required' on server SSL — skipping the directive "
        "would break upstream connections)."
    )
    # And the bind-side path must NOT have a 'verify none' fallback
    # (frontend bind defaults to 'verify none' so a skip is safe).
    # Look for the safeguard helper signature instead:
    assert "def _apply_bind_ssl_verify(" in src
    # There must NOT be an explicit 'bind_line += " verify none"'
    # anywhere (would defeat the safeguard's no-op-on-skip
    # contract).
    assert 'bind_line += " verify none"' not in src, (
        "Asymmetry regression: bind-side path should SKIP the "
        "verify directive when no client-CA is resolvable — emitting "
        "'verify none' would be a behaviour change."
    )


# ─────────────────────────────────────────────────────────────────────────────
# FIX-5: _emit_fe / stick-table dedup runtime test (best-effort)
# ─────────────────────────────────────────────────────────────────────────────


def test_stick_table_dedup_logic_via_helper_inspection():
    """The dedup logic lives inside a closure (`_emit_fe`) so a
    direct behavioural call requires building a partial frontend
    fixture. Instead, inspect the source to confirm the dedup
    branch keeps the FIRST `stick-table` line and discards
    subsequent ones.

    Phase K Phase D follow-up (Bulgu #13) updated this test from
    "track-sc0 is NOT dedup'ed" to "track-sc0 IS dedup'ed". The
    rationale: HAProxy only needs one tracking call per frontend;
    every additional `http-request track-sc0 src` is a redundant
    state-table operation per request. The per-rule
    `http-request deny if { sc_http_req_rate(0) gt N }` lines are
    NOT dedup'ed because each WAF rule has its own threshold and
    must still emit.
    """
    src = _GEN.read_text()
    # The dedup must check `startswith("stick-table")` specifically,
    # so other 'stick' keywords (e.g. 'stick on src') are NOT
    # incorrectly suppressed. The exact expression now lives on the
    # `stripped` local but the membership check is preserved.
    assert 'startswith("stick-table")' in src, (
        "FIX-5 regression: dedup branch must scope to `stick-table` "
        "specifically so non-table 'stick' directives still emit."
    )
    # The dedup must short-circuit ONLY when already emitted, not
    # always.
    assert "if _stick_table_emitted" in src and "startswith(\"stick-table\")" in src, (
        "FIX-5 regression: stick-table dedup must be conditional on "
        "the `_stick_table_emitted` flag."
    )
    # Bulgu #13 — track-sc<N> dedup must ALSO be present. Round-2
    # refinement: dedup is now scoped to the full (counter, fetch)
    # signature so `track-sc0 src` and `track-sc0 dst` collapse
    # independently. Accept either the legacy single-flag layout
    # or the new signature-set layout.
    assert (
        "_track_sc_signatures" in src
        or "_track_sc0_emitted" in src
    ), (
        "Bulgu #13 regression: track-sc dedup state is missing — "
        "every WAF rate-limit rule will emit a redundant "
        "`http-request track-sc<N> <fetch>` line into the frontend block."
    )
    assert 'startswith("http-request track-sc")' in src, (
        "Bulgu #13 regression: track-sc dedup must scope to the "
        "track-sc<N> directive family specifically; otherwise unrelated "
        "http-request rules may be incorrectly suppressed."
    )


# ─────────────────────────────────────────────────────────────────────────────
# FIX-8: ServerConfig uppercase ssl_verify coerce
# ─────────────────────────────────────────────────────────────────────────────


def test_server_config_ssl_verify_uppercase_coerces():
    """`'NONE'` / `'REQUIRED'` (any case) must coerce to the
    canonical lowercase Literal value."""
    from models.backend import ServerConfig

    base = dict(server_name="srv", server_address="10.0.0.1", server_port=80)
    for raw, expected in (("NONE", "none"), ("None", "none"),
                         ("REQUIRED", "required"), ("Required", "required")):
        m = ServerConfig(**base, ssl_verify=raw)
        assert m.ssl_verify == expected


def test_server_config_uppercase_optional_coerces_to_none():
    """`'OPTIONAL'` (any case) is invalid server-side — coerce to
    None, do NOT render an invalid `verify optional` directive."""
    from models.backend import ServerConfig

    base = dict(server_name="srv", server_address="10.0.0.1", server_port=80)
    for raw in ("OPTIONAL", "Optional", "optional"):
        m = ServerConfig(**base, ssl_verify=raw)
        assert m.ssl_verify is None


# ─────────────────────────────────────────────────────────────────────────────
# FIX-3: Migration cleanup count parser
# ─────────────────────────────────────────────────────────────────────────────


def test_migration_cleanup_uses_execute_not_fetchval():
    """The pre-fix code path used `fetchval()` with a CTE+RETURNING
    multi-row UPDATE, surfacing only the first row's id and
    masking the true count. Switched to `execute()` + status-tag
    parse for accurate operator-facing reporting."""
    src = (_BACK / "database" / "migrations.py").read_text()

    # The legacy code-line pattern (executable, not in a comment)
    # must be gone.  We strip Python comments before searching so the
    # historical-context comment block in `migrations.py` doesn't
    # trigger a false positive.
    code_only = "\n".join(
        line for line in src.splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "RETURNING f.id" not in code_only, (
        "FIX-3 regression: legacy `RETURNING f.id` from the cleanup "
        "block reappeared — `fetchval` only surfaces the first row id."
    )
    # And `cleanup_count = await conn.fetchval(` (the legacy invocation
    # for this exact block) must not be present either.
    assert "cleanup_count = await conn.fetchval(" not in code_only, (
        "FIX-3 regression: legacy `fetchval()` invocation for the "
        "ssl_verify cleanup block reappeared."
    )
    # The new pattern must be present
    assert "cleanup_status = await conn.execute(" in src, (
        "FIX-3 regression: cleanup must use `execute()` so the "
        "asyncpg status tag (`'UPDATE N'`) can be parsed for the "
        "true row count."
    )
    assert 'int(str(cleanup_status).split()[-1])' in src, (
        "FIX-3 regression: cleanup count parse from asyncpg status "
        "tag is missing — operator log will not surface the true "
        "number of rows touched."
    )
