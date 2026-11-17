"""
Issue #80 regression tests: a frontend with many SSL certificates.

HAProxy parses a config line into at most 64 words; a multi-certificate `bind`
costs two words per certificate, so ~31 certificates (fewer with `alpn`,
`strict-sni`, ...) fail `haproxy -c` with "too many words, truncating after
word 64". Past the limit — and only past it — the certificates move into a
crt-list file whose lines ride in the config header as comments, and the agent
writes the file before it validates the config.

What is pinned here:
  * a bind line that fits renders byte-for-byte as before (no header block,
    no `crt-list`), including exactly 64 words;
  * a bind line of 65+ words becomes `ssl crt-list <file> <options>` with the
    certificates in order inside a header block;
  * the config stays valid for the validator, the parser (Config Restore) and
    the agent's partial-config detection;
  * the agent helpers (Linux and macOS copies, heredoc and daemon) behave:
    write, idempotence, rejection of unsafe blocks, cleanup, reload detection.
"""
import asyncio
import os
import re
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import haproxy_config as hc
from utils.haproxy_config_parser import parse_haproxy_config
from utils.haproxy_validator import HAProxyConfigValidator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "utils", "agent_scripts")


# ── a minimal fake asyncpg connection for the generator ──────────────────────

class _FakeConn:
    def __init__(self, frontends, cert_names=None):
        self.frontends = frontends
        self.cert_names = cert_names or {}

    async def fetchrow(self, sql, *args):
        if "COUNT(*) as count" in sql:
            return {"count": 0}
        if "FROM haproxy_clusters" in sql:
            return {"id": 1, "name": "c1", "stats_socket_path": "/run/haproxy/admin.sock"}
        if "FROM ssl_certificates" in sql:
            cert_id = args[0]
            name = self.cert_names.get(cert_id, f"cert{cert_id}")
            return {"name": name, "domain": f"{name}.example.com", "fingerprint": "ff"}
        return None

    async def fetch(self, sql, *args):
        if "FROM waf_rules" in sql:
            return []
        if sql.strip().startswith("SELECT * FROM frontends"):
            return self.frontends
        return []

    async def fetchval(self, sql, *args):
        return None

    async def execute(self, sql, *args):
        return "OK"


def _frontend(name="web", n_certs=3, **over):
    fe = {
        "id": 1, "name": name, "bind_address": "0.0.0.0", "bind_port": 443,
        "default_backend": None, "mode": "http", "ssl_enabled": True,
        "ssl_certificate_ids": list(range(1, n_certs + 1)), "is_active": True,
        "cluster_id": 1,
    }
    fe.update(over)
    return fe


def _render(frontends, cert_names=None):
    return asyncio.run(
        hc.generate_haproxy_config_for_cluster(1, _FakeConn(frontends, cert_names))
    )


def _bind_lines(cfg):
    return [l for l in cfg.splitlines() if l.startswith("    bind ")]


def _words(line):
    return len(line.split())


# ── generator: byte-for-byte for everything that fits ────────────────────────

def test_fitting_bind_is_unchanged_and_has_no_header_block():
    cfg = _render([_frontend(n_certs=30)])
    (bind,) = _bind_lines(cfg)
    expected = "    bind 0.0.0.0:443 ssl " + " ".join(
        f"crt /etc/ssl/haproxy/cert{i}.pem" for i in range(1, 31)
    )
    assert bind == expected
    assert _words(bind) == 63
    assert "crt-list" not in cfg
    assert "HOM-CRTLIST" not in cfg


def test_exactly_64_words_still_renders_plain():
    # 30 certs + strict-sni = 64 words: HAProxy 2.8 loads it, so it must not change.
    cfg = _render([_frontend(n_certs=30, ssl_strict_sni=True)])
    (bind,) = _bind_lines(cfg)
    assert _words(bind) == 64
    assert "crt-list" not in bind
    assert "HOM-CRTLIST" not in cfg


def test_small_frontends_render_identically_to_the_legacy_format():
    cfg = _render([_frontend(n_certs=2, ssl_alpn="h2,http/1.1", ssl_min_ver="TLSv1.2")])
    (bind,) = _bind_lines(cfg)
    assert bind == (
        "    bind 0.0.0.0:443 ssl crt /etc/ssl/haproxy/cert1.pem "
        "crt /etc/ssl/haproxy/cert2.pem alpn h2,http/1.1 ssl-min-ver TLSv1.2"
    )
    assert "HOM-CRTLIST" not in cfg


# ── generator: over the limit ─────────────────────────────────────────────────

def test_31_certs_use_crt_list():
    cfg = _render([_frontend(n_certs=31)])
    (bind,) = _bind_lines(cfg)
    m = re.fullmatch(
        r"    bind 0\.0\.0\.0:443 ssl crt-list (/etc/ssl/haproxy/crtlists/hom-web-[0-9a-f]{12}\.crtlist)", bind
    )
    assert m, bind
    assert _words(bind) <= 64
    path = m.group(1)
    lines = cfg.splitlines()
    begin = lines.index(f"# HOM-CRTLIST-BEGIN {path}")
    end = lines.index("# HOM-CRTLIST-END")
    assert [l[2:] for l in lines[begin + 1:end]] == [
        f"/etc/ssl/haproxy/cert{i}.pem" for i in range(1, 32)
    ]


def test_options_follow_the_crt_list_and_are_not_lost():
    cfg = _render([_frontend(
        n_certs=30, ssl_alpn="h2,http/1.1", ssl_ciphers="HIGH", ssl_min_ver="TLSv1.2",
        ssl_max_ver="TLSv1.3", ssl_strict_sni=True,
    )])
    (bind,) = _bind_lines(cfg)
    assert re.fullmatch(
        r"    bind 0\.0\.0\.0:443 ssl crt-list \S+\.crtlist alpn h2,http/1\.1 ciphers HIGH "
        r"ssl-min-ver TLSv1\.2 ssl-max-ver TLSv1\.3 strict-sni",
        bind,
    ), bind


def test_alpn_alone_pushes_30_certs_over_the_limit():
    # The reporter's second case: 30 certs fit, 30 certs + alpn do not.
    assert _words(_bind_lines(_render([_frontend(n_certs=30)]))[0]) == 63
    cfg = _render([_frontend(n_certs=30, ssl_alpn="h2,http/1.1")])
    assert "crt-list" in _bind_lines(cfg)[0]


def test_block_sits_between_header_and_first_frontend_and_header_marker_survives():
    cfg = _render([_frontend(n_certs=40)])
    lines = cfg.splitlines()
    first_section = next(i for i, l in enumerate(lines) if l.startswith("frontend "))
    begin = next(i for i, l in enumerate(lines) if l.startswith("# HOM-CRTLIST-BEGIN"))
    assert begin < first_section
    # The agent keys partial-config detection on this marker within the first 20 lines.
    assert any(
        "# Generated by HAProxy Open Manager - Partial Configuration" in l for l in lines[:20]
    )
    # Nothing but comments / blanks precedes the first section.
    assert all(l.startswith("#") or not l.strip() for l in lines[:first_section])


def test_frontend_sections_are_identical_apart_from_the_bind_line():
    over = _render([_frontend(n_certs=31)])
    plain_src = hc.HAPROXY_MAX_LINE_WORDS
    try:
        hc.HAPROXY_MAX_LINE_WORDS = 10 ** 6  # force the legacy rendering
        plain = _render([_frontend(n_certs=31)])
    finally:
        hc.HAPROXY_MAX_LINE_WORDS = plain_src

    def body(cfg):
        return [l for l in cfg.splitlines()[cfg.splitlines().index(next(
            x for x in cfg.splitlines() if x.startswith("frontend "))):]
            if not l.startswith("    bind ")]

    assert body(over) == body(plain)


def test_identical_certificate_lists_share_one_block():
    cfg = _render([_frontend("a", n_certs=31), _frontend("a", n_certs=31, bind_port=444)])
    assert cfg.count("# HOM-CRTLIST-BEGIN") == 1


def test_different_frontends_get_their_own_files():
    cfg = _render([_frontend("a", n_certs=31), _frontend("b", n_certs=32, bind_port=444)])
    assert cfg.count("# HOM-CRTLIST-BEGIN") == 2
    assert cfg.count("ssl crt-list ") == 2


def test_file_name_changes_with_content_and_order():
    p1, _ = hc._plan_crtlist("web", ["/etc/ssl/haproxy/a.pem", "/etc/ssl/haproxy/b.pem"])
    p2, _ = hc._plan_crtlist("web", ["/etc/ssl/haproxy/b.pem", "/etc/ssl/haproxy/a.pem"])
    p3, _ = hc._plan_crtlist("web", ["/etc/ssl/haproxy/a.pem", "/etc/ssl/haproxy/b.pem"])
    assert p1 != p2          # order picks the default certificate
    assert p1 == p3          # deterministic
    assert p1.startswith("/etc/ssl/haproxy/crtlists/hom-web-") and p1.endswith(".crtlist")


def test_frontend_name_is_sanitised_in_the_file_name():
    path, _ = hc._plan_crtlist("we b/../x", ["/etc/ssl/haproxy/a.pem"])
    assert re.fullmatch(r"/etc/ssl/haproxy/crtlists/hom-[A-Za-z0-9_.-]+\.crtlist", path)
    assert "/../" not in path


@pytest.mark.parametrize("bad", [
    "/etc/ssl/haproxy/has space.pem", "/etc/ssl/haproxy/a#b.pem", "relative.pem",
    '/etc/ssl/haproxy/q".pem', "/etc/ssl/haproxy/back\\slash.pem",
])
def test_unsafe_paths_are_not_written_to_a_crt_list(bad):
    assert hc._plan_crtlist("web", ["/etc/ssl/haproxy/ok.pem", bad]) is None


def test_unsafe_certificate_name_keeps_the_legacy_rendering():
    names = {i: f"cert{i}" for i in range(1, 40)}
    names[5] = "has space"
    cfg = _render([_frontend(n_certs=39)], names)
    (bind,) = _bind_lines(cfg)
    assert "crt-list" not in bind and "HOM-CRTLIST" not in cfg


def test_acme_wildcard_certificate_names_are_allowed_in_a_crt_list():
    names = {i: f"cert{i}" for i in range(1, 40)}
    names[3] = "le-*.example.com"
    cfg = _render([_frontend(n_certs=39)], names)
    assert "crt-list" in _bind_lines(cfg)[0]
    assert "# /etc/ssl/haproxy/le-*.example.com.pem" in cfg


def test_old_single_certificate_mode_is_untouched():
    cfg = _render([_frontend(n_certs=0, ssl_certificate_ids=None, ssl_certificate_id=7, ssl_port=8443)])
    assert "    bind 0.0.0.0:8443 ssl crt /etc/ssl/haproxy/cert7.pem" in cfg
    assert "HOM-CRTLIST" not in cfg


def test_non_ssl_frontend_is_untouched():
    cfg = _render([_frontend(ssl_enabled=False, ssl_certificate_ids=None, bind_port=80)])
    assert "    bind 0.0.0.0:80" in cfg and "HOM-CRTLIST" not in cfg


# ── other consumers of the generated text ────────────────────────────────────

def test_validator_accepts_a_crt_list_config():
    cfg = _render([_frontend(n_certs=40, ssl_alpn="h2,http/1.1")])
    report = HAProxyConfigValidator().validate_config(cfg, partial_fragment=True)
    messages = [str(getattr(r, "message", r)) for r in getattr(report, "results", [])]
    assert not any("SSL binding without certificate" in m for m in messages), messages


def test_parser_reads_a_crt_list_config_for_config_restore():
    cfg = _render([_frontend(n_certs=40, ssl_alpn="h2,http/1.1", default_backend="be")])
    cfg += "\nbackend be\n    mode http\n    server s1 10.0.0.1:80\n"
    with_block = parse_haproxy_config(cfg)
    without_block = parse_haproxy_config(
        "\n".join(l for l in cfg.splitlines() if not l.startswith("# HOM-CRTLIST") and not l.startswith("# /etc/ssl"))
    )
    assert not with_block.errors
    fe = next(f for f in with_block.frontends if f.name == "web")
    assert fe.ssl_enabled is True and fe.ssl_port == 443
    # the header block is plain comments to the parser: same entities either way
    assert [(f.name, f.ssl_enabled, f.ssl_port, f.bind_port) for f in with_block.frontends] == [
        (f.name, f.ssl_enabled, f.ssl_port, f.bind_port) for f in without_block.frontends
    ]
    assert [b.name for b in with_block.backends] == [b.name for b in without_block.backends]


# The only parsed fields that differ: the certificate paths themselves (they live in the
# crt-list file, which is not part of the text).
_CERT_FIELDS = {"ssl_cert_path", "ssl_cert_paths"}


def _plain_equivalent(cfg, n_certs):
    """The same config with the certificates back on the bind line as `crt` words
    (what the generator rendered before this change)."""
    import re as _re
    plain_clause = " ".join(f"crt /etc/ssl/haproxy/cert{i}.pem" for i in range(1, n_certs + 1))
    out = _re.sub(r"ssl crt-list \S+", "ssl " + plain_clause, cfg)
    assert out != cfg
    return out


def test_apply_and_restore_read_the_same_frontend_fields_from_a_crt_list_config():
    """Apply (DB SYNC) and Restore (preview + restore) read a stored config back with
    the parser and write bind_address, bind_port, default_backend, mode, ssl_enabled,
    ssl_port, maxconn and timeout_client into the frontend row. A crt-list bind must
    give the parser exactly what the old multi-`crt` bind gave for all of them - and
    for the SSL options on the line (alpn, strict-sni, ...), which Bulk Import compares
    and would otherwise clear on an existing frontend."""
    import dataclasses
    cfg = _render([
        _frontend("web", n_certs=40, ssl_alpn="h2,http/1.1", ssl_ciphers="ECDHE+AESGCM",
                  ssl_min_ver="TLSv1.2", ssl_strict_sni=True, default_backend="be", maxconn=500),
        _frontend("api", n_certs=3, id=2, bind_port=8443, default_backend="be"),
    ])
    cfg += "\nbackend be\n    mode http\n    server s1 10.0.0.1:80\n"
    assert "ssl crt-list " in cfg
    new = parse_haproxy_config(cfg)
    old = parse_haproxy_config(_plain_equivalent(cfg, 40))
    assert not new.errors and not old.errors

    def strip(fe):
        return {k: v for k, v in dataclasses.asdict(fe).items() if k not in _CERT_FIELDS}

    assert [strip(f) for f in new.frontends] == [strip(f) for f in old.frontends]
    web = next(f for f in new.frontends if f.name == "web")
    assert (web.bind_address, web.bind_port, web.ssl_enabled, web.ssl_port) == ("0.0.0.0", 443, True, 443)
    assert (web.ssl_alpn, web.ssl_ciphers, web.ssl_min_ver, web.ssl_strict_sni) == (
        "h2,http/1.1", "ECDHE+AESGCM", "TLSv1.2", True)
    assert [dataclasses.asdict(b) for b in new.backends] == [dataclasses.asdict(b) for b in old.backends]


def test_crt_list_bind_yields_no_certificates_and_warns_on_import():
    """The certificates of a crt-list are not in the pasted text, so none are collected
    (Bulk Import then leaves an existing frontend's certificate assignment alone, as it
    always does) and the import warnings say so instead of staying silent. The SSL
    options on the line are read exactly like on a `crt` bind."""
    cfg = _render([_frontend(n_certs=40, ssl_alpn="h2,http/1.1", default_backend="be")])
    cfg += "\nbackend be\n    mode http\n    server s1 10.0.0.1:80\n"
    new = parse_haproxy_config(cfg)
    fe = next(f for f in new.frontends if f.name == "web")
    assert fe.ssl_cert_paths is None and fe.ssl_cert_path is None
    assert fe.ssl_alpn == "h2,http/1.1"
    assert any("crt-list" in w and "web" in w for w in new.warnings), new.warnings
    assert any("SSL parameters imported" in w and "alpn h2,http/1.1" in w for w in new.warnings)

    old = parse_haproxy_config(_plain_equivalent(cfg, 40))
    assert not any("crt-list" in w for w in old.warnings)


# ── the agent helpers (Linux + macOS; heredoc copy and daemon copy) ──────────

def _helpers(script):
    """Return the shell text of every copy of the three helpers in an agent script."""
    text = open(os.path.join(SCRIPTS, script), encoding="utf-8").read()
    copies = re.findall(
        r"^[ ]*hom_deploy_crtlists\(\) \{.*?^[ ]*hom_cert_in_use\(\) \{.*?^[ ]*\}\n",
        text, re.DOTALL | re.MULTILINE,
    )
    return copies


@pytest.mark.parametrize("script", ["linux_install.sh", "macos_install.sh"])
def test_each_agent_script_carries_two_copies_of_the_helpers(script):
    assert len(_helpers(script)) == 2


@pytest.mark.parametrize("script", ["linux_install.sh", "macos_install.sh"])
def test_agent_calls_are_wired_before_validation_and_after_apply(script):
    text = open(os.path.join(SCRIPTS, script), encoding="utf-8").read()
    # heredoc (function) copy and daemon copy: deploy before validate, cleanup after apply
    assert text.count('hom_deploy_crtlists "$CONFIG_CONTENT"') == 1
    assert text.count('hom_deploy_crtlists "$daemon_config_content"') == 1
    assert text.count('hom_cleanup_crtlists "$HAPROXY_CONFIG_PATH"') == 2
    assert text.count('hom_cleanup_crtlists "$HAPROXY_CONFIG"') == 1
    assert text.count('hom_cert_in_use "') == 2  # the two reload-decision call sites
    # the old plain grep decision is gone from both reload paths
    assert 'grep -qF "$cert_file_path" "$HAPROXY_CONFIG_PATH"' not in text
    assert 'grep -qF "$cert_file_path" "$HAPROXY_CONFIG"' not in text
    assert 'grep -qF "$ssl_file" "$HAPROXY_CONFIG"' not in text
    # deploy precedes the temp-config validation in each flow
    d1 = text.index('hom_deploy_crtlists "$CONFIG_CONTENT"')
    assert d1 < text.index('-c -f "$TEMP_CONFIG"', d1)
    d2 = text.index('hom_deploy_crtlists "$daemon_config_content"')
    assert d2 < text.index("/tmp/haproxy-new-config.cfg -c", d2)


def _run_bash(script_text, body, tmp):
    prelude = 'log() { :; }\n'
    out = subprocess.run(
        ["bash", "-c", prelude + script_text + "\n" + body],
        capture_output=True, text=True, cwd=tmp, timeout=30,
    )
    return out


def _config(tmp, blocks, rest="frontend web\n    bind :443\n"):
    header = "# Generated by HAProxy Open Manager - Partial Configuration\n"
    return header + "".join(blocks) + "\n" + rest


def _block(path, entries):
    return f"# HOM-CRTLIST-BEGIN {path}\n" + "".join(f"# {e}\n" for e in entries) + "# HOM-CRTLIST-END\n"


@pytest.fixture(params=[
    ("linux_install.sh", 0), ("linux_install.sh", 1), ("macos_install.sh", 0), ("macos_install.sh", 1),
])
def helpers(request):
    script, idx = request.param
    return _helpers(script)[idx]


def test_agent_writes_the_file_and_is_idempotent(helpers, tmp_path):
    path = f"{tmp_path}/crtlists/hom-web-abc123def456.crtlist"
    cfg = _config(tmp_path, [_block(path, ["/etc/ssl/haproxy/a.pem", "/etc/ssl/haproxy/le-*.x.com.pem"])])
    body = f'hom_deploy_crtlists "$1"; cat {path}; hom_deploy_crtlists "$1"; cat {path}'
    out = subprocess.run(["bash", "-c", "log() { :; }\n" + helpers + "\n" + body, "_", cfg],
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    one = "/etc/ssl/haproxy/a.pem\n/etc/ssl/haproxy/le-*.x.com.pem\n"
    assert out.stdout == one + one
    assert os.listdir(f"{tmp_path}/crtlists") == ["hom-web-abc123def456.crtlist"]  # no tmp leftovers


def test_agent_ignores_config_without_blocks(helpers, tmp_path):
    out = subprocess.run(["bash", "-c", "log() { :; }\n" + helpers + '\nhom_deploy_crtlists "$1"; ls',
                          "_", "frontend a\n    bind :80\n"], capture_output=True, text=True, cwd=tmp_path)
    assert out.returncode == 0 and out.stdout == ""


@pytest.mark.parametrize("bad_path", [
    "/etc/passwd",
    "/etc/ssl/haproxy/crtlists/hom-x/../../../../tmp/evil.crtlist",
    "/etc/ssl/haproxy/crtlists/other.crtlist",
    "/etc/ssl/haproxy/hom-x.crtlist",
    "/etc/ssl/haproxy/crtlists/hom-x.pem",
    "relative/crtlists/hom-x.crtlist",
])
def test_agent_refuses_blocks_outside_the_crtlist_namespace(helpers, tmp_path, bad_path):
    cfg = _config(tmp_path, [_block(bad_path, ["/etc/ssl/haproxy/a.pem"])])
    out = subprocess.run(["bash", "-c", "log() { :; }\n" + helpers + '\nhom_deploy_crtlists "$1"',
                          "_", cfg], capture_output=True, text=True, cwd=tmp_path)
    assert out.returncode == 0
    # /etc/passwd exists on any host, so judge by content: nothing of ours was written anywhere.
    for p in (bad_path, "/tmp/evil.crtlist", "/etc/ssl/haproxy/crtlists/hom-x/../../../../tmp/evil.crtlist"):
        if os.path.isfile(p):
            assert "/etc/ssl/haproxy/a.pem" not in open(p, errors="ignore").read()


@pytest.mark.parametrize("entries", [
    ["/etc/ssl/haproxy/a.pem", "/etc/ssl/haproxy/b c.pem"],     # whitespace
    ["/etc/ssl/haproxy/../../etc/shadow"],                      # traversal
    [],                                                         # empty
])
def test_agent_refuses_blocks_with_bad_entries(helpers, tmp_path, entries):
    path = f"{tmp_path}/crtlists/hom-web-bad.crtlist"
    cfg = _config(tmp_path, [_block(path, entries)])
    out = subprocess.run(["bash", "-c", "log() { :; }\n" + helpers + '\nhom_deploy_crtlists "$1"',
                          "_", cfg], capture_output=True, text=True, cwd=tmp_path)
    assert out.returncode == 0
    assert not os.path.exists(path)


def test_agent_does_not_read_blocks_placed_after_the_first_section(helpers, tmp_path):
    path = f"{tmp_path}/crtlists/hom-web-late.crtlist"
    cfg = "frontend web\n    bind :443\n" + _block(path, ["/etc/ssl/haproxy/a.pem"])
    out = subprocess.run(["bash", "-c", "log() { :; }\n" + helpers + '\nhom_deploy_crtlists "$1"',
                          "_", cfg], capture_output=True, text=True, cwd=tmp_path)
    assert out.returncode == 0 and not os.path.exists(path)


def test_agent_writes_each_of_several_blocks(helpers, tmp_path):
    p1 = f"{tmp_path}/crtlists/hom-a-1.crtlist"
    p2 = f"{tmp_path}/crtlists/hom-b-2.crtlist"
    cfg = _config(tmp_path, [_block(p1, ["/etc/ssl/haproxy/a.pem"]), _block(p2, ["/etc/ssl/haproxy/b.pem"])])
    subprocess.run(["bash", "-c", "log() { :; }\n" + helpers + '\nhom_deploy_crtlists "$1"', "_", cfg],
                   capture_output=True, text=True, cwd=tmp_path)
    assert open(p1).read() == "/etc/ssl/haproxy/a.pem\n"
    assert open(p2).read() == "/etc/ssl/haproxy/b.pem\n"


def test_cert_in_use_direct_and_through_a_crt_list(helpers, tmp_path):
    cl = tmp_path / "list.crtlist"
    cl.write_text("/etc/ssl/haproxy/in-list.pem\n/etc/ssl/haproxy/le-*.x.pem\n")
    cfg = tmp_path / "haproxy.cfg"
    cfg.write_text(
        "frontend a\n    bind :443 ssl crt /etc/ssl/haproxy/direct.pem\n"
        f"frontend b\n    bind :444 ssl crt-list {cl} alpn h2\n"
    )

    def used(cert):
        out = subprocess.run(
            ["bash", "-c", "log() { :; }\n" + helpers + f'\nhom_cert_in_use "$1" {cfg}', "_", cert],
            capture_output=True, text=True,
        )
        return out.returncode == 0

    assert used("/etc/ssl/haproxy/direct.pem")
    assert used("/etc/ssl/haproxy/in-list.pem")
    assert used("/etc/ssl/haproxy/le-*.x.pem")       # literal, not a glob
    assert not used("/etc/ssl/haproxy/other.pem")
    assert not used("/etc/ssl/haproxy/in-list")      # whole-line match, not a prefix


def test_cleanup_removes_only_unreferenced_hom_crtlists(helpers, tmp_path):
    d = tmp_path / "crtlists"
    d.mkdir()
    keep = d / "hom-keep-1.crtlist"
    drop = d / "hom-drop-2.crtlist"
    foreign = d / "operator.crtlist"
    for f in (keep, drop, foreign):
        f.write_text("/etc/ssl/haproxy/a.pem\n")
    cfg = tmp_path / "haproxy.cfg"
    cfg.write_text(f"frontend a\n    bind :443 ssl crt-list {keep}\n")
    text = helpers.replace("/etc/ssl/haproxy/crtlists", str(d))
    subprocess.run(["bash", "-c", "log() { :; }\n" + text + f'\nhom_cleanup_crtlists {cfg}'],
                   capture_output=True, text=True)
    assert keep.exists() and foreign.exists() and not drop.exists()


def test_cleanup_does_nothing_when_the_config_is_missing(helpers, tmp_path):
    d = tmp_path / "crtlists"
    d.mkdir()
    f = d / "hom-x-1.crtlist"
    f.write_text("x\n")
    text = helpers.replace("/etc/ssl/haproxy/crtlists", str(d))
    subprocess.run(["bash", "-c", "log() { :; }\n" + text + f'\nhom_cleanup_crtlists {tmp_path}/nope.cfg'],
                   capture_output=True, text=True)
    assert f.exists()


def test_end_to_end_backend_block_is_consumed_by_the_agent(helpers, tmp_path):
    """The block the generator emits is exactly what the agent parses."""
    cfg = _render([_frontend(n_certs=33, ssl_alpn="h2,http/1.1")])
    (bind,) = _bind_lines(cfg)
    path = re.search(r"crt-list (\S+)", bind).group(1)
    local = f"{tmp_path}/crtlists/{os.path.basename(path)}"
    cfg_local = cfg.replace(path, local)
    # the agent only accepts paths ending in /crtlists/hom-*.crtlist; the tmp path does
    subprocess.run(["bash", "-c", "log() { :; }\n" + helpers + '\nhom_deploy_crtlists "$1"', "_", cfg_local],
                   capture_output=True, text=True, cwd=tmp_path)
    assert open(local).read().split("\n")[:-1] == [f"/etc/ssl/haproxy/cert{i}.pem" for i in range(1, 34)]
