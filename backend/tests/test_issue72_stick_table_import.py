"""
Issue #72 regression tests: `stick-table` re-definition ignored by Config Import.

Bug: the bulk-config parser had no branch for `stick-table` (frontend and
backend) nor for backend `stick on|match|store-*`, so they were dropped without
a warning. A frontend that kept its `track-sc0` / counter rules then got the
renderer's stick-table auto-inject (`type ip size 100k expire 30s store
http_req_rate(10s)`), i.e. the operator's new table was silently replaced by
the default. Separately, the import preview stripped EVERY `track-sc0 src` /
`sc_http_req_rate(0)` line as "auto-generated", deleting operator trackers.

DB-free: parser behaviour, the import policy helpers and source guards for the
renderer / endpoint wiring.
"""
import dataclasses
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.haproxy_config_parser import parse_haproxy_config
from utils.stick_table_import import (
    drop_platform_stick_tables,
    frontend_uses_counter,
    is_platform_rate_limit_header,
    merge_options,
    stick_advisories,
    strip_auto_headers,
    uses_stick_counter,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NEW_TABLE = "stick-table type ip size 200k expire 3h store http_req_rate(10s),gpc0_rate(10s),gpt0"
DEFAULT_TABLE = "stick-table type ip size 100k expire 30s store http_req_rate(10s)"

ISSUE_72_CONFIG = f"""
frontend fe_web
    bind *:80
    mode http
    option httplog
    {NEW_TABLE}
    http-request track-sc0 src
    http-request deny if {{ sc0_gpc0_rate gt 20 }}
    http-response sc-inc-gpc0(0) if {{ status 404 }}
    default_backend be_web

backend be_web
    mode http
    stick-table type ip size 1m expire 30m
    stick on src
    stick match src table fe_web
    stick store-request src
    server s1 10.0.0.1:80 check
"""


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------- parser


def test_parser_keeps_frontend_stick_table_in_options():
    r = parse_haproxy_config(ISSUE_72_CONFIG)
    fe = r.frontends[0]
    assert fe.options == f"option httplog\n{NEW_TABLE}"
    assert any("stick-table imported as-is" in w and NEW_TABLE in w for w in r.warnings)
    # The rest of the frontend is parsed exactly as before.
    assert fe.request_headers == "http-request track-sc0 src\nhttp-request deny if { sc0_gpc0_rate gt 20 }"
    assert fe.response_headers == "http-response sc-inc-gpc0(0) if { status 404 }"


def test_parser_keeps_backend_stick_directives_in_order():
    be = parse_haproxy_config(ISSUE_72_CONFIG).backends[0]
    assert be.options == (
        "stick-table type ip size 1m expire 30m\n"
        "stick on src\n"
        "stick match src table fe_web\n"
        "stick store-request src"
    )
    assert be.mode == "http"
    assert [s.server_name for s in be.servers] == ["s1"]


def test_parser_ignores_lookalike_directives():
    cfg = """
backend b
    stickiness on
    stick-tablex foo
    server s1 10.0.0.1:80
"""
    be = parse_haproxy_config(cfg).backends[0]
    assert be.options is None


def test_parser_unchanged_without_stick_directives():
    cfg = """
frontend f
    bind *:80
    option httplog
    http-request set-header X-A 1
    default_backend b
backend b
    option forwardfor
    server s1 10.0.0.1:80
"""
    r = parse_haproxy_config(cfg)
    fe = dataclasses.asdict(r.frontends[0])
    be = dataclasses.asdict(r.backends[0])
    assert fe["options"] == "option httplog"
    assert be["options"] == "option forwardfor"
    assert not any("stick" in w for w in r.warnings)


# ------------------------------------------------- generator-owned headers


def test_platform_rate_limit_header_exact_forms():
    assert is_platform_rate_limit_header("http-request track-sc0 src")
    assert is_platform_rate_limit_header("http-request deny if { sc_http_req_rate(0) gt 100 }")
    assert is_platform_rate_limit_header(
        "http-request capture req.hdr(User-Agent) len 64 if { sc_http_req_rate(0) gt 5 }")
    assert not is_platform_rate_limit_header("http-request track-sc0 src table other")
    assert not is_platform_rate_limit_header("http-request track-sc1 src")
    assert not is_platform_rate_limit_header(
        "http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }")


def test_strip_keeps_operator_rate_limit_lines_when_platform_does_not_regenerate():
    rh = "http-request track-sc0 src\nhttp-request deny if { sc_http_req_rate(0) gt 100 }"
    assert strip_auto_headers(rh, platform_regenerates=False) == rh


def test_strip_removes_generator_lines_when_platform_regenerates():
    rh = ("http-request track-sc0 src\n"
          "http-request deny if { sc_http_req_rate(0) gt 100 }\n"
          "http-request set-header X-A 1")
    assert strip_auto_headers(rh, platform_regenerates=True) == "http-request set-header X-A 1"


def test_strip_keeps_non_exact_forms_even_when_platform_regenerates():
    rh = "http-request track-sc0 src table other\nhttp-request track-sc1 src"
    assert strip_auto_headers(rh, platform_regenerates=True) == rh


def test_strip_always_removes_acme_and_waf_lines():
    rh = ("http-request allow if is_acme_challenge\n"
          "http-request deny if waf_block_1\n"
          "http-request set-header X-A 1")
    for regen in (True, False):
        assert strip_auto_headers(rh, regen) == "http-request set-header X-A 1"
    assert strip_auto_headers(None, True) is None
    assert strip_auto_headers("http-request track-sc0 src", True) is None


# ------------------------------------------- generator-shaped stick-tables


def test_drop_platform_table_when_platform_regenerates():
    opts = f"option httplog\nstick-table type ip size 100k expire 60s store http_req_rate(10s)"
    kept, dropped = drop_platform_stick_tables(opts, True, False)
    assert kept == "option httplog"
    assert dropped == ["stick-table type ip size 100k expire 60s store http_req_rate(10s)"]


def test_drop_default_table_when_auto_inject_would_render_it():
    kept, dropped = drop_platform_stick_tables(DEFAULT_TABLE, False, True)
    assert kept is None and dropped == [DEFAULT_TABLE]


def test_keep_generator_shaped_table_the_platform_would_not_render():
    # 60s with only auto-inject in play: auto-inject would render 30s, so keep it.
    t60 = "stick-table type ip size 100k expire 60s store http_req_rate(10s)"
    assert drop_platform_stick_tables(t60, False, True) == (t60, [])
    # Default table with no counter use: nothing would render it (e.g. `table fe` refs).
    assert drop_platform_stick_tables(DEFAULT_TABLE, False, False) == (DEFAULT_TABLE, [])


def test_never_drop_operator_table():
    for regen in (True, False):
        for counter in (True, False):
            assert drop_platform_stick_tables(NEW_TABLE, regen, counter) == (NEW_TABLE, [])


def test_frontend_uses_counter_matches_renderer_rule():
    assert uses_stick_counter("http-request track-sc0 src")
    assert uses_stick_counter("http-request deny if { sc_http_req_rate(0) gt 1 }")
    assert not uses_stick_counter("http-request set-header X-A 1")
    assert frontend_uses_counter([None, "option httplog", ["acl a sc_http_req_rate(0) gt 1"]])
    # stick-table lines themselves never count (they are the thing being decided on)
    assert not frontend_uses_counter([DEFAULT_TABLE])


def test_uses_stick_counter_is_the_renderer_expression():
    s = _src("services/haproxy_config.py")
    assert 'if "track-sc" in stripped or ("sc_" in stripped and "_rate(" in stripped):' in s
    m = _src("utils/stick_table_import.py")
    assert 'return "track-sc" in s or ("sc_" in s and "_rate(" in s)' in m


def test_platform_table_regex_covers_every_generator_form():
    s = _src("services/haproxy_config.py")
    assert s.count("stick-table type ip size 100k expire 30s store http_req_rate(10s)") == 2
    assert "stick-table type ip size 100k expire {waf_rule.get('rate_limit_window', 60)}s store http_req_rate(10s)" in s
    for line in (DEFAULT_TABLE, "stick-table type ip size 100k expire 120s store http_req_rate(10s)"):
        assert drop_platform_stick_tables(line, True, False)[1] == [line]


# ------------------------------------------------------------ options merge


def test_merge_stick_only_import_keeps_existing_option_lines():
    assert merge_options(NEW_TABLE, "option forwardfor") == f"option forwardfor\n{NEW_TABLE}"


def test_merge_option_only_import_keeps_existing_stick_lines():
    assert merge_options("option httplog", f"option forwardfor\n{DEFAULT_TABLE}") == \
        f"option httplog\n{DEFAULT_TABLE}"


def test_merge_replaces_each_group_when_imported():
    assert merge_options(f"option httplog\n{NEW_TABLE}", f"option forwardfor\n{DEFAULT_TABLE}") == \
        f"option httplog\n{NEW_TABLE}"


def test_merge_without_imported_options_keeps_existing_verbatim():
    assert merge_options(None, "option forwardfor") == "option forwardfor"
    assert merge_options(None, None) is None


def test_merge_same_lines_returns_existing_unchanged():
    existing = f"{NEW_TABLE}\noption httplog"
    assert merge_options(f"option httplog\n{NEW_TABLE}", existing) is existing


def test_merge_matches_previous_behaviour_when_no_stick_lines():
    # Pre-#72 bulk import replaced options wholesale when the import had option lines.
    assert merge_options("option httplog", "option forwardfor") == "option httplog"


# ---------------------------------------------------------------- advisories


def test_advisory_table_without_http_req_rate_when_rate_limited():
    t = "stick-table type ip size 200k expire 3h store gpc0_rate(10s),gpt0"
    w = stick_advisories("Frontend", "f", t, t, {}, platform_regenerates=True)
    assert any("does not store http_req_rate" in x for x in w)
    assert not stick_advisories("Frontend", "f", t, t, {}, platform_regenerates=False)
    assert not stick_advisories("Frontend", "f", NEW_TABLE, NEW_TABLE, {}, platform_regenerates=True)


def test_advisory_duplicate_table_in_other_field():
    w = stick_advisories("Backend", "b", NEW_TABLE, NEW_TABLE,
                         {"Request Headers": "stick-table type ip size 1m"}, False)
    assert any("also stored in Request Headers" in x for x in w)
    # Not raised when this import did not bring a table.
    assert not stick_advisories("Backend", "b", NEW_TABLE, None,
                                {"Request Headers": "stick-table type ip size 1m"}, False)


def test_advisory_stick_rule_without_table():
    w = stick_advisories("Backend", "b", "stick on src", "stick on src", {}, False)
    assert any("unable to find stick-table" in x for x in w)
    assert not stick_advisories("Backend", "b", "stick on src table fe", "stick on src table fe", {}, False)
    assert not stick_advisories("Backend", "b", "stick-table type ip size 1m\nstick on src",
                                "stick on src", {}, False)


def test_advisory_peers():
    t = "stick-table type ip size 1m peers mypeers"
    w = stick_advisories("Backend", "b", t, t, {}, False)
    assert any("'mypeers'" in x and "BEFORE the 'defaults'" in x for x in w)


# ------------------------------------------------------------ wiring guards


def test_backend_renderer_dedups_stick_table():
    s = _src("services/haproxy_config.py")
    assert "_be_stick_table_emitted" in s
    assert "BACKEND STICK-TABLE DEDUP" in s
    block = s[s.index("_append_be_free_form(line_stripped: str)"):s.index("# 3. Health check configuration")]
    assert "_append_be_free_form(line_stripped)" in block  # options loop routed through it
    tail = s[s.index("# 8. HTTP Request Headers"):s.index("# Get all servers for this backend")]
    assert tail.count("_append_be_free_form(line_stripped)") == 2  # request + response headers


def test_parse_bulk_uses_conditional_policy():
    s = _src("routers/config.py")
    fn = s[s.index("async def parse_bulk_config("):s.index('@router.post("/bulk-create")')]
    assert '"track-sc0 src" in s' not in fn  # the unconditional strip is gone
    assert "strip_auto_headers(" in fn and "platform_regenerates[" in fn
    assert "drop_platform_stick_tables(" in fn
    assert fn.count("merge_options(") == 2  # frontends + backends
    assert fn.count("stick_advisories(") == 2
    # Bulgu #82 guard window must still see the cluster access check.
    assert "validate_user_cluster_access" in fn[:6000]
