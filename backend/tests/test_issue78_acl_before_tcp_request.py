"""
Issue #78 regression tests: an ACL used by a `tcp-request` rule is rendered
after the rule, and Config Import ignores ACL / routing changes of an existing
frontend.

Bug 1: the frontend buckets are flushed `stick → tcp_req → acl`, so
`tcp-request connection silent-drop if blacklist` came out above
`acl blacklist ...` and `haproxy -c` rejected the config. Only frontends whose
tcp-request rules reference an ACL declared in the same frontend are reordered;
every other frontend renders exactly as before.

Bug 2: the import preview skipped `acl_rules` / `use_backend_rules` ("not
stored in frontends table" — they are) and bulk-create never wrote them, so an
imported ACL change was silently dropped.

DB-free: the real bucket categoriser and hoist helper, the import policy
helpers, and source guards for the endpoint wiring.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.haproxy_config import (
    _categorize_haproxy_directive,
    _hoist_acls_for_tcp_rules,
    _tcp_rules_reference_declared_acls,
)
from utils.frontend_rule_import import (
    ACL,
    USE_BACKEND,
    coerce_rule_list,
    comparable_existing,
    is_platform_rule,
    is_waf_header_line,
    is_waf_named_acl,
    keep_stored_waf_header_lines,
    waf_line_differences,
    waf_named_lines,
    merge_imported_rules,
    normalize_rules,
    removed_rules,
    render_rule,
    rules_changed,
    rules_mangled_by_renderer,
    sanitize_rules,
    strip_platform_rules,
)
from utils.haproxy_config_parser import parse_haproxy_config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _flush_order():
    m = re.search(r"for _bucket_key in \((.*?)\):", _src("services/haproxy_config.py"), re.DOTALL)
    return re.findall(r'"(\w+)"', m.group(1))


def _render(lines):
    """Route lines like `_emit_fe` does, apply the hoist, flush in the real order."""
    order = _flush_order()
    buckets = {k: [] for k in order}
    for line in lines:
        buckets[_categorize_haproxy_directive(line)].append(line)
    refs = _hoist_acls_for_tcp_rules(buckets)
    return [l for k in order for l in buckets[k]], refs


ISSUE_78_FRONTEND = """
frontend main-fe
    bind 10.0.0.1:443 ssl crt /etc/ssl/haproxy/site.pem ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.3
    mode http
    filter spoe engine coraza config /etc/haproxy/coraza.cfg
    stick-table type ip size 200k expire 6h store http_req_rate(10s),gpc0_rate(10s),gpt0,conn_rate(10s)
    acl blacklist src -f /etc/haproxy/acl/blocked-ipv4.acl
    acl main-rut hdr(host) -i mainsite.com
    tcp-request connection silent-drop if blacklist
    tcp-request connection silent-drop if { src_get_gpt0(main-fe) gt 0 }
    tcp-request connection track-sc0 src
    tcp-request connection sc-set-gpt0(0) 1 if { sc0_conn_rate gt 25 }
    http-request silent-drop if { sc_get_gpt0(0) gt 0 }
    use_backend backend-portal if main-rut
    default_backend backend-portal

backend backend-portal
    mode http
    server s1 10.0.0.2:80 check
"""


# ── generator: reference detection ───────────────────────────────────────────

def test_named_acl_reference_detected():
    acls = ["    acl blacklist src -f /x.acl", "    acl main-rut hdr(host) -i a.com"]
    tcp = ["    tcp-request connection silent-drop if blacklist"]
    assert _tcp_rules_reference_declared_acls(tcp, acls) == ["blacklist"]


def test_negation_unless_and_or_forms_detected():
    acls = ["    acl a src 1.1.1.1", "    acl b src 2.2.2.2", "    acl c src 3.3.3.3"]
    assert _tcp_rules_reference_declared_acls(
        ["    tcp-request connection reject if !a"], acls) == ["a"]
    assert _tcp_rules_reference_declared_acls(
        ["    tcp-request content accept unless b"], acls) == ["b"]
    assert _tcp_rules_reference_declared_acls(
        ["    tcp-request connection reject if x || c"], acls) == ["c"]
    assert _tcp_rules_reference_declared_acls(
        ["    tcp-request connection reject if { src 9.9.9.9 } a"], acls) == ["a"]
    assert _tcp_rules_reference_declared_acls(
        ["    tcp-request connection reject if ! b"], acls) == ["b"]


def test_anonymous_and_unrelated_conditions_not_detected():
    acls = ["    acl blacklist src -f /x.acl"]
    tcp = [
        "    tcp-request connection silent-drop if { src_get_gpt0(fe) gt 0 }",
        "    tcp-request connection reject if { src -f blacklist }",
        "    tcp-request connection reject if !{ src -f blacklist }",
        "    tcp-request connection track-sc0 src",
        "    tcp-request inspect-delay 5s",
        "    tcp-request content accept if { req_ssl_hello_type 1 }",
    ]
    assert _tcp_rules_reference_declared_acls(tcp, acls) == []


def test_predefined_acl_never_triggers_even_if_redeclared():
    # Before the declaration HAProxy resolves the predefined ACL; moving the
    # declaration up would switch the rule to the operator's definition.
    acls = ["    acl LOCALHOST src 10.0.0.0/8", "    acl WAIT_END always_false",
            "    acl HTTP_3.0 always_false"]
    tcp = ["    tcp-request content accept if WAIT_END",
           "    tcp-request connection accept if LOCALHOST",
           "    tcp-request content accept if HTTP_3.0"]
    assert _tcp_rules_reference_declared_acls(tcp, acls) == []


def test_comments_and_acme_acl_handled():
    acls = ["    # WAF Rule: x (Priority: 1, Action: deny)",
            "    acl is_acme_challenge path_beg /.well-known/acme-challenge/"]
    assert _tcp_rules_reference_declared_acls(
        ["    tcp-request connection reject if { src 1.2.3.4 }"], acls) == []


def test_no_tcp_rules_or_no_acls():
    assert _tcp_rules_reference_declared_acls([], ["    acl a src 1.1.1.1"]) == []
    assert _tcp_rules_reference_declared_acls(["    tcp-request connection reject if a"], []) == []


# ── generator: hoist + flush ─────────────────────────────────────────────────

def test_default_flush_order_unchanged():
    assert _flush_order() == ["prelude", "filter", "stick", "tcp_req", "acl", "http_req",
                              "http_resp", "redirect", "use_be", "default_be"]


def test_issue_frontend_renders_acls_before_tcp_rules():
    lines = [
        "    filter spoe engine coraza config /etc/haproxy/coraza.cfg",
        "    stick-table type ip size 200k expire 6h store http_req_rate(10s),gpt0",
        "    acl blacklist src -f /etc/haproxy/acl/blocked-ipv4.acl",
        "    acl main-rut hdr(host) -i mainsite.com",
        "    tcp-request connection silent-drop if blacklist",
        "    tcp-request connection track-sc0 src",
        "    http-request silent-drop if { sc_get_gpt0(0) gt 0 }",
        "    use_backend backend-portal if main-rut",
        "    default_backend backend-portal",
    ]
    out, refs = _render(lines)
    assert refs == ["blacklist"]
    first_tcp = next(i for i, l in enumerate(out) if l.strip().startswith("tcp-request"))
    acl_positions = [i for i, l in enumerate(out) if l.strip().startswith("acl ")]
    stick_pos = next(i for i, l in enumerate(out) if l.strip().startswith("stick-table"))
    filter_pos = next(i for i, l in enumerate(out) if l.strip().startswith("filter "))
    assert filter_pos < stick_pos < min(acl_positions)
    assert max(acl_positions) < first_tcp
    # ACL order is preserved
    assert [out[i].split()[1] for i in acl_positions] == ["blacklist", "main-rut"]


def test_frontends_without_reference_render_exactly_as_before():
    cases = [
        ["    acl a hdr(host) -i a.com", "    use_backend b if a", "    default_backend b"],
        ["    tcp-request connection track-sc0 src", "    http-request deny if { sc0_conn_rate gt 9 }"],
        ["    acl a src 1.1.1.1", "    tcp-request connection track-sc0 src",
         "    http-request deny if a", "    default_backend b"],
        ["    tcp-request inspect-delay 5s",
         "    tcp-request content accept if { req_ssl_hello_type 1 }",
         "    acl sni_a req_ssl_sni -i a.com", "    use_backend b if sni_a"],
        ["    acl LOCALHOST src 10.0.0.0/8", "    tcp-request connection accept if LOCALHOST"],
        ["    # WAF Rule: ipf (Priority: 100, Action: deny)", "    acl waf_ipf_ips src 1.2.3.4",
         "    http-request deny if waf_ipf_ips", "    tcp-request connection track-sc0 src",
         "    acl is_acme_challenge path_beg /.well-known/acme-challenge/",
         "    http-request allow if is_acme_challenge"],
    ]
    order = _flush_order()
    for lines in cases:
        before = {k: [] for k in order}
        for line in lines:
            before[_categorize_haproxy_directive(line)].append(line)
        expected = [l for k in order for l in before[k]]
        out, refs = _render(lines)
        assert refs == []
        assert out == expected, lines


def test_hoist_leaves_buckets_untouched_without_reference():
    buckets = {"stick": ["    stick-table type ip size 1k"], "tcp_req": ["    tcp-request connection track-sc0 src"],
               "acl": ["    acl a src 1.1.1.1"]}
    snapshot = json.loads(json.dumps(buckets))
    assert _hoist_acls_for_tcp_rules(buckets) == []
    assert buckets == snapshot


def test_hoist_keeps_stick_table_first():
    buckets = {"stick": ["    stick-table type ip size 1k"],
               "tcp_req": ["    tcp-request connection reject if a"],
               "acl": ["    acl a src 1.1.1.1"]}
    assert _hoist_acls_for_tcp_rules(buckets) == ["a"]
    assert buckets["stick"] == ["    stick-table type ip size 1k", "    acl a src 1.1.1.1"]
    assert buckets["acl"] == []


def test_generator_calls_hoist_after_auto_inject_and_before_flush():
    s = _src("services/haproxy_config.py")
    inject = s.index("STICK-TABLE AUTO-INJECT")
    hoist = s.index("_acl_refs = _hoist_acls_for_tcp_rules(_fe_buckets)")
    flush = s.index("for _bucket_key in (")
    assert inject < hoist < flush


# ── WAF config sync window (routers/cluster.py) ──────────────────────────────

def _waf_window_parse(config_lines):
    """Verbatim twin of the WAF parse loop in routers/cluster.py (apply DB sync,
    restore preview, restore): look at the 9 lines after `# WAF Rule:`."""
    waf_configs = {}
    i = 0
    while i < len(config_lines):
        line = config_lines[i].strip()
        if line.startswith('# WAF Rule:'):
            match = re.search(r'# WAF Rule: ([\w\s\-]+)', line)
            if match:
                name = match.group(1).strip()
                waf_configs[name] = {'config': {}}
                for j in range(i + 1, min(i + 10, len(config_lines))):
                    next_line = config_lines[j].strip()
                    if 'stick-table' in next_line:
                        m = re.search(r'expire\s+(\d+)s', next_line)
                        if m:
                            waf_configs[name]['config']['rate_limit_window'] = int(m.group(1))
                    elif 'http-request deny if' in next_line or 'http-request tarpit if' in next_line:
                        m = re.search(r'gt\s+(\d+)', next_line)
                        if m:
                            waf_configs[name]['config']['rate_limit_requests'] = int(m.group(1))
                    elif next_line.startswith('# WAF Rule:') or next_line.startswith('frontend ') \
                            or next_line.startswith('backend '):
                        break
        i += 1
    return waf_configs


def test_cluster_waf_window_loop_is_the_one_twinned_here():
    s = _src("routers/cluster.py")
    assert s.count("min(i+10, len(config_lines))") == 3
    assert s.count("# Merge parsed config with existing config (preserve fields we didn't parse)") == 2


def test_waf_window_unchanged_for_frontends_that_are_not_hoisted():
    lines = [
        "    # WAF Rule: rl (Priority: 100, Action: deny)",
        "    stick-table type ip size 100k expire 60s store http_req_rate(10s)",
        "    http-request track-sc0 src",
        "    http-request deny if { sc_http_req_rate(0) gt 50 }",
        "    tcp-request connection track-sc0 src",
        "    acl a hdr(host) -i a.com",
        "    use_backend b if a",
    ]
    order = _flush_order()
    before = {k: [] for k in order}
    for line in lines:
        before[_categorize_haproxy_directive(line)].append(line)
    old_out = [l for k in order for l in before[k]]
    new_out, refs = _render(lines)
    assert refs == []
    assert _waf_window_parse(new_out) == _waf_window_parse(old_out)


def test_waf_window_never_reads_tcp_rules_when_hoisted():
    lines = [
        "    # WAF Rule: rl (Priority: 100, Action: deny)",
        "    acl blacklist src -f /x.acl",
        "    tcp-request connection silent-drop if blacklist",
        "    tcp-request connection reject if { sc0_conn_rate gt 99 }",
        "    http-request deny if { sc_http_req_rate(0) gt 50 }",
    ]
    out, refs = _render(lines)
    assert refs == ["blacklist"]
    parsed = _waf_window_parse(out)["rl"]["config"]
    assert parsed.get("rate_limit_requests") in (None, 50)


# ── parser ───────────────────────────────────────────────────────────────────

def test_parser_keeps_acl_and_tcp_rule_order():
    fe = parse_haproxy_config(ISSUE_78_FRONTEND).frontends[0]
    assert fe.acl_rules == ["acl blacklist src -f /etc/haproxy/acl/blocked-ipv4.acl",
                            "acl main-rut hdr(host) -i mainsite.com"]
    assert fe.tcp_request_rules.split("\n")[0] == "tcp-request connection silent-drop if blacklist"
    assert fe.use_backend_rules == ["use_backend backend-portal if main-rut"]


# ── import policy helpers ────────────────────────────────────────────────────

def test_coerce_rule_list_forms():
    assert coerce_rule_list(None) == []
    assert coerce_rule_list('["a b", "c d"]') == ["a b", "c d"]
    assert coerce_rule_list(["x y"]) == ["x y"]
    assert coerce_rule_list("a b\nc d\n") == ["a b", "c d"]
    assert coerce_rule_list('{"a": 1}') == []
    assert coerce_rule_list(42) == []


def test_render_rule_matches_generator_cleanup():
    assert render_rule("host_a hdr(host) -i a.com", ACL) == "acl host_a hdr(host) -i a.com"
    assert render_rule("acl host_a hdr(host) -i a.com", ACL) == "acl host_a hdr(host) -i a.com"
    assert render_rule('["acl x src 1.1.1.1"]', ACL) == "acl x src 1.1.1.1"
    assert render_rule("be1 if host_a", USE_BACKEND) == "use_backend be1 if host_a"
    for skipped in ("", "  ", "[]", "null", "None", "{}"):
        assert render_rule(skipped, ACL) is None
    assert render_rule('""', USE_BACKEND) is None
    assert render_rule({"type": "x"}, ACL) is None


def test_ui_and_import_forms_compare_equal():
    stored_ui = json.dumps(["blacklist src -f /etc/haproxy/acl/blocked-ipv4.acl",
                            "main-rut hdr(host) -i mainsite.com"])
    imported = ["acl blacklist src -f /etc/haproxy/acl/blocked-ipv4.acl",
                "acl main-rut hdr(host) -i mainsite.com"]
    assert not rules_changed(imported, stored_ui, ACL)


def test_round_trip_of_rendered_config_is_not_a_change():
    # A stored row rendered by the generator and imported back must not be
    # flagged as an update.
    stored = json.dumps(["host_a hdr(host) -i a.com", "acl host_b hdr(host) -i b.com",
                         '"acl host_c hdr(host) -i c.com"'])
    rendered = "\n".join("    " + r for r in normalize_rules(stored, ACL))
    fe_text = f"frontend f\n    bind *:80\n    mode http\n{rendered}\n    default_backend b\n"
    parsed = parse_haproxy_config(fe_text).frontends[0]
    assert not rules_changed(parsed.acl_rules, stored, ACL)


def test_order_change_is_a_change():
    stored = json.dumps(["acl main-rut hdr(host) -i mainsite.com", "acl blacklist src -f /x.acl"])
    imported = ["acl blacklist src -f /x.acl", "acl main-rut hdr(host) -i mainsite.com"]
    assert rules_changed(imported, stored, ACL)
    assert removed_rules(imported, stored, ACL) == []


def test_import_without_rules_keeps_stored_list():
    stored = json.dumps(["acl a src 1.1.1.1"])
    assert not rules_changed([], stored, ACL)
    assert not rules_changed(None, stored, ACL)


def test_new_rules_on_empty_row_are_a_change():
    assert rules_changed(["acl a src 1.1.1.1"], None, ACL)
    assert rules_changed(["use_backend b if a"], "[]", USE_BACKEND)


def test_removed_rules_reported():
    stored = json.dumps(["acl a src 1.1.1.1", "acl b src 2.2.2.2"])
    assert removed_rules(["acl a src 1.1.1.1"], stored, ACL) == ["acl b src 2.2.2.2"]


def test_strip_platform_rules_same_result_as_previous_inline_filter():
    acl_rules = ["acl is_acme_challenge path_beg /.well-known/acme-challenge/",
                 "acl waf_x_ips src 1.2.3.4", "acl mine src 5.6.7.8"]
    ub_rules = ["use_backend _acme_challenge_backend if is_acme_challenge", "use_backend b if mine"]
    old_acl = [r for r in acl_rules
               if "is_acme_challenge" not in r and not r.strip().startswith("acl waf_")]
    old_ub = [r for r in ub_rules if "_acme_challenge_backend" not in r]
    assert strip_platform_rules(acl_rules, ACL) == old_acl
    assert strip_platform_rules(ub_rules, USE_BACKEND) == old_ub


def test_platform_rules_recognised_in_unprefixed_db_form():
    assert is_platform_rule("waf_x_ips src 1.2.3.4", ACL)
    assert not is_platform_rule("mine src 1.2.3.4", ACL)
    stored = json.dumps(["waf_x_ips src 1.2.3.4", "mine src 1.2.3.4"])
    assert comparable_existing(stored, ACL) == ["acl mine src 1.2.3.4"]


def test_merge_keeps_generator_owned_lines_already_stored():
    stored = json.dumps(["acl is_acme_challenge path_beg /.well-known/acme-challenge/",
                         "waf_custom src 9.9.9.9", "acl old src 1.1.1.1"])
    merged = merge_imported_rules(["acl new src 2.2.2.2"], stored, ACL)
    assert merged == ["acl is_acme_challenge path_beg /.well-known/acme-challenge/",
                      "waf_custom src 9.9.9.9", "acl new src 2.2.2.2"]
    ub = merge_imported_rules(["use_backend b if new"],
                              json.dumps(["use_backend _acme_challenge_backend if is_acme_challenge"]),
                              USE_BACKEND)
    assert ub == ["use_backend _acme_challenge_backend if is_acme_challenge", "use_backend b if new"]


def test_merge_keeps_stored_platform_lines_in_place():
    stored = json.dumps(["Elasticsearch hdr(host) -i e.example", "Kibana hdr(host) -i k.example",
                         "waf_r1_path path_reg ^/admin", "waf_r1_method method POST",
                         "is_reporting_api path_beg /api/reporting/"])
    imported = ["acl Elasticsearch hdr(host) -i e.example", "acl Kibana hdr(host) -i k2.example",
                "acl is_reporting_api path_beg /api/reporting/"]
    assert merge_imported_rules(imported, stored, ACL) == [
        "acl Elasticsearch hdr(host) -i e.example", "waf_r1_path path_reg ^/admin",
        "waf_r1_method method POST", "acl Kibana hdr(host) -i k2.example",
        "acl is_reporting_api path_beg /api/reporting/"]
    # Nothing generator-owned stored: the import is stored as-is.
    assert merge_imported_rules(imported, json.dumps(["x src 1.1.1.1"]), ACL) == imported


def test_sanitize_drops_only_unsafe_rules():
    keep = ["acl a src -f /etc/haproxy/a.acl", "acl b hdr(host) -i { x }",
            "acl c var(txn.x) -m str %[src]", "acl d req.hdr(x) -m str ${ENV}"]
    bad = ["acl e src 1.1.1.1\n    http-request deny", "acl f src 1.1.1.1\r", "acl g $(id)",
           "acl h `id`", {"x": 1}]
    kept, dropped = sanitize_rules(keep + bad, ACL)
    assert kept == keep
    assert [r for r, _ in dropped] == bad


def test_mangled_rules_detected():
    rules = ['acl api hdr(host) -i "api.example.com"', "acl ok src 1.1.1.1", "acl p path_beg /a]"]
    assert rules_mangled_by_renderer(rules) == ['acl api hdr(host) -i "api.example.com"',
                                                "acl p path_beg /a]"]


# ── waf_* lines the import skips ─────────────────────────────────────────────

def test_waf_named_line_predicates():
    assert is_waf_named_acl("acl waf_demo-rule1_path path_reg ^/admins")
    assert is_waf_named_acl("waf_demo-rule1_path path_reg ^/admins")  # UI-stored form
    assert not is_waf_named_acl("acl blacklist src -f /x.acl")
    assert not is_waf_named_acl("acl is_acme_challenge path_beg /.well-known/acme-challenge/")
    assert is_waf_header_line("    http-request deny if waf_demo-rule1_path waf_demo-rule1_method")
    assert not is_waf_header_line("http-request allow if is_acme_challenge")
    assert not is_waf_header_line("http-response set-header X waf_x")
    assert not is_waf_header_line("http-request set-header X-Waf yes")


def test_stored_waf_header_lines_kept_in_place():
    stored = "http-request del-header Proxy\nhttp-request deny if waf_a_path\nhttp-request set-header Host x"
    new = "http-request del-header Proxy\nhttp-request set-header Host y"
    assert keep_stored_waf_header_lines(new, stored) == (
        "http-request del-header Proxy\nhttp-request deny if waf_a_path\nhttp-request set-header Host y")


def test_unchanged_import_reproduces_the_stored_value_exactly():
    stored = "http-request deny if waf_a_path\nhttp-request del-header Proxy\nhttp-request allow if waf_b_ips"
    new = "http-request del-header Proxy"
    assert keep_stored_waf_header_lines(new, stored) == stored


def test_stored_waf_line_first_and_duplicates():
    stored = "http-request deny if waf_a\nhttp-request deny if waf_a\nhttp-request del-header Proxy"
    assert keep_stored_waf_header_lines("http-request del-header Proxy", stored) == stored


def test_no_waf_lines_returns_new_headers_unchanged():
    new = "http-request set-header A 1\nhttp-request set-header B 2"
    for stored in (None, "", "http-request set-header A 0", "http-request use-service prometheus-exporter"):
        assert keep_stored_waf_header_lines(new, stored) == new


def test_acme_and_rate_limit_lines_are_not_kept():
    stored = ("http-request allow if is_acme_challenge\nhttp-request track-sc0 src\n"
              "http-request deny if { sc_http_req_rate(0) gt 100 }\nhttp-request set-header A 0")
    assert keep_stored_waf_header_lines("http-request set-header A 1", stored) == "http-request set-header A 1"


def test_waf_line_present_in_new_is_not_duplicated():
    stored = "http-request deny if waf_a\nhttp-request set-header A 0"
    new = "http-request deny if waf_a\nhttp-request set-header A 1"
    assert keep_stored_waf_header_lines(new, stored) == new


# ── endpoint wiring (source guards) ──────────────────────────────────────────

def test_parse_bulk_reports_changed_waf_lines():
    s = _src("routers/config.py")
    fn = s[s.index("async def parse_bulk_config("):s.index('@router.post("/bulk-create")')]
    # Compared with what the generator renders now, on its own connection.
    assert "generate_haproxy_config_for_cluster(request.cluster_id)" in fn
    assert "generate_haproxy_config_for_cluster(request.cluster_id, conn)" not in fn
    changed = fn.index("differ from the current configuration and are NOT")
    generic = fn.index("are not imported. {_waf_where}")
    assert changed < fn.index("sanitize_rules(") and generic < fn.index("sanitize_rules(")
    assert changed < fn.index('frontend["request_headers"] = strip_auto_headers(')
    # Bulgu #82 guard window must still see the cluster access check.
    assert "validate_user_cluster_access" in fn[:6000]


def test_waf_named_lines_and_differences():
    acls = ["acl waf_r1_path path_reg ^/admin", "waf_r1_method method POST", "acl host_a hdr(host) -i a"]
    headers = "http-request del-header Proxy\nhttp-request deny if waf_r1_path waf_r1_method"
    lines = waf_named_lines(acls, headers)
    assert lines == ["acl waf_r1_path path_reg ^/admin", "acl waf_r1_method method POST",
                     "http-request deny if waf_r1_path waf_r1_method"]
    edited = ["acl waf_r1_path path_reg ^/admin1"] + lines[1:]
    assert waf_line_differences(edited, lines) == (["acl waf_r1_path path_reg ^/admin1"],
                                                   ["acl waf_r1_path path_reg ^/admin"])
    assert waf_line_differences(lines, lines) == ([], [])
    # Repeated lines (two frontends' worth in one list) are counted, not deduplicated.
    assert waf_line_differences(lines[:1], lines[:1] * 2) == ([], lines[:1])


def test_bulk_create_keeps_stored_waf_header_lines():
    s = _src("routers/config.py")
    fn = s[s.index("async def bulk_create_entities("):]
    block = fn[fn.index('new_headers = frontend_data["request_headers"]'):][:2500]
    assert "merged_headers = keep_stored_waf_header_lines(new_headers, existing_headers)" in block
    assert "merged_headers = merged_headers + '\\n' + '\\n'.join(use_service_lines)" in block
    assert "merged_headers = new_headers" not in block
    # The backend request_headers block is unchanged.
    be = fn[fn.index('new_headers = backend_data["request_headers"]'):][:1500]
    assert "keep_stored_waf_header_lines" not in be

def test_parse_bulk_compares_acl_and_routing_rules():
    s = _src("routers/config.py")
    fn = s[s.index("async def parse_bulk_config("):s.index('@router.post("/bulk-create")')]
    assert "not stored in frontends table" not in fn
    assert "rules_changed(frontend.get(_field), existing.get(_field), _kind)" in fn
    assert '("acl_rules", ACL' in fn and '("use_backend_rules", USE_BACKEND' in fn
    assert "sanitize_rules(" in fn and "rules_mangled_by_renderer(" in fn
    assert "removed_rules(" in fn
    # Bulgu #82 guard window must still see the cluster access check.
    assert "validate_user_cluster_access" in fn[:6000]


def test_bulk_create_updates_rules_without_trusting_the_client():
    s = _src("routers/config.py")
    fn = s[s.index("async def bulk_create_entities("):]
    assert "MVP: DON'T update ACL rules" not in fn
    assert "rules_changed(_imported, existing_full.get(_field), _kind)" in fn
    assert "merge_imported_rules(_imported, existing_full.get(_field), _kind)" in fn
    assert "_changes" not in fn[fn.index("Issue #78: ACL and routing rules"):
                               fn.index("Issue #78: ACL and routing rules") + 1200]
    assert 'json.dumps(_insert_rules["acl_rules"])' in fn
