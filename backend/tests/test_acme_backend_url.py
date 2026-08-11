"""ACME challenge backend URL validation, resolution and change detection.

These pin the behaviour behind a real incident: a split deployment rendered
`server _acme_mgmt <mgmt>:8080` against a port with no listener, HTTP-01 failed for
weeks while DNS-01 kept working, and every existing check reported success. The
three mechanisms below are what make that impossible to repeat silently.
"""
import pytest

from services.haproxy_config import (
    extract_acme_backend_target,
    is_config_generation_error,
)
from utils.acme_backend_url import (
    AcmeBackendUrlError,
    resolve_acme_backend_target,
    validate_acme_backend_url,
)


# ---------------------------------------------------------------------------
# 1. Boundary validation — what an operator may type.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("http://10.90.1.4:80", "http://10.90.1.4:80"),
        ("http://10.90.1.4", "http://10.90.1.4"),
        ("https://mgmt.internal:8443", "https://mgmt.internal:8443"),
        # RFC1918 is the NORMAL answer here, unlike utils/ssrf_guard's policy: the
        # operator is naming their own management host, which on a split deployment
        # is private by definition.
        ("http://192.168.1.5:8080", "http://192.168.1.5:8080"),
        # Empty means "inherit from the next level of the resolution chain".
        (None, None),
        ("", None),
        ("   ", None),
        # Surrounding whitespace is normalised, not rejected — and the NORMALISED
        # value is what callers persist, so it can never reach haproxy.cfg.
        ("  http://10.0.0.5:80  ", "http://10.0.0.5:80"),
    ],
)
def test_accepts_and_normalises_usable_values(value, expected):
    assert validate_acme_backend_url(value) == expected


@pytest.mark.parametrize(
    "value,code",
    [
        # Scheme-less values used to be accepted and then silently became `localhost`
        # in the renderer — the trap that makes a correct diagnosis un-actionable.
        ("10.90.1.4:8080", "no_scheme"),
        ("localhost:8080", "no_scheme"),
        ("ftp://10.0.0.5", "bad_scheme"),
        # A newline would inject directives into a file pushed to every node.
        ("http://10.90.1.4\nbind :9", "whitespace"),
        ("http://10.90.1.4 x", "whitespace"),
        # Loopback by number AND by name: `localhost` is what both shipped defaults
        # contain, so catching only the numeric form would miss the common case.
        ("http://localhost:8080", "loopback"),
        ("http://LOCALHOST", "loopback"),
        ("http://127.0.0.1", "loopback"),
        ("http://[::1]:80", "loopback"),
        ("http://0.0.0.0:80", "unspecified"),
        ("http://169.254.169.254", "link_local"),
        ("http://u:p@10.0.0.5", "userinfo"),
        ("http://10.0.0.5/api", "has_path"),
        ("http://10.0.0.5?x=1", "has_path"),
        # urlparse defers port parsing to attribute access; unguarded this raises
        # inside the config generator and destroys the cluster's whole config.
        ("http://10.0.0.5:99999", "bad_port"),
        ("http://10.0.0.5:abc", "bad_port"),
        ("http://-bad-.com", "invalid_host"),
    ],
)
def test_rejects_unusable_values_with_stable_codes(value, code):
    with pytest.raises(AcmeBackendUrlError) as exc:
        validate_acme_backend_url(value)
    assert exc.value.code == code
    assert str(exc.value), "every rejection must carry operator-facing prose"


def test_rejects_values_longer_than_the_column():
    # VARCHAR(500); without this the write fails as an opaque asyncpg 22001 -> 500.
    with pytest.raises(AcmeBackendUrlError) as exc:
        validate_acme_backend_url("http://" + "a" * 600 + ".com")
    assert exc.value.code == "too_long"


# ---------------------------------------------------------------------------
# 2. Render-time resolution — never rejects, never raises.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,host,port,ssl_flag",
    [
        ("http://10.90.1.4:80", "10.90.1.4", 80, ""),
        # Port-less http stays 8080, NOT the scheme default 80: the bundled compose
        # publishes nginx on 8080, so installs relying on this have a working path
        # today and changing it would break them silently in the renewal loop.
        ("http://10.90.1.4", "10.90.1.4", 8080, ""),
        ("https://m.io", "m.io", 443, " ssl verify none"),
        ("http://localhost:8080", "localhost", 8080, ""),
    ],
)
def test_resolution_preserves_existing_rendering(url, host, port, ssl_flag):
    target = resolve_acme_backend_target(url)
    assert (target.host, target.port, target.ssl_flag) == (host, port, ssl_flag)
    assert target.error_code is None


@pytest.mark.parametrize(
    "url",
    ["", None, "   ", "10.0.0.5:80", "http://h:99999", "http://10.0.0.5\nx", "http://ba d"],
)
def test_resolution_reports_instead_of_raising(url):
    target = resolve_acme_backend_target(url)
    assert target.error_code, "unusable values must be reported, not raised"
    assert target.error_message


def test_resolution_warns_on_loopback_rather_than_refusing():
    # Refusing here would make every existing install unappliable: the shipped
    # defaults ARE loopback, and the failure would block changes unrelated to ACME.
    target = resolve_acme_backend_target("http://localhost:8080")
    assert target.error_code is None
    assert target.warnings and "Loopback" in target.warnings[0]


def test_resolution_warns_when_the_port_is_omitted():
    target = resolve_acme_backend_target("http://10.0.0.5")
    assert target.port == 8080
    assert any("port" in w.lower() for w in target.warnings)


# ---------------------------------------------------------------------------
# 3. Change detection — what makes a panel edit actually reach the nodes.
# ---------------------------------------------------------------------------


_CONFIG = """global
    daemon

frontend fe_http
    bind 10.90.1.100:80
    mode http
    acl is_acme_challenge path_beg /.well-known/acme-challenge/
    use_backend _acme_challenge_backend if is_acme_challenge
    default_backend app

backend app
    server s1 10.0.0.9:8080

# ACME Challenge Backend (auto-managed by HAProxy OpenManager)
backend _acme_challenge_backend
    mode http
    server _acme_mgmt 10.90.1.4:80
"""


def test_extracts_the_challenge_backend_target():
    assert extract_acme_backend_target(_CONFIG) == "10.90.1.4:80"


def test_extracts_target_with_ssl_flag():
    cfg = _CONFIG.replace("10.90.1.4:80", "m.io:443 ssl verify none")
    assert extract_acme_backend_target(cfg) == "m.io:443 ssl verify none"


def test_ignores_server_lines_in_other_backends():
    # Comparing the whole config would flag every unrelated pending edit as a change;
    # this must key on the ACME section alone.
    cfg = _CONFIG.replace("backend _acme_challenge_backend", "backend something_else")
    assert extract_acme_backend_target(cfg) is None


def test_returns_none_when_the_section_has_no_server_line():
    cfg = (
        "backend _acme_challenge_backend\n"
        "    mode http\n"
        "    # ACME challenge backend unavailable (loopback)\n"
    )
    assert extract_acme_backend_target(cfg) is None


@pytest.mark.parametrize("value", ["", None])
def test_extraction_tolerates_empty_input(value):
    assert extract_acme_backend_target(value) is None


def test_url_change_that_renders_the_same_target_is_not_a_change():
    # `http://10.90.1.4` and `http://10.90.1.4:8080` are different strings but the
    # same shipped address; minting a config version for that would put a no-op
    # pending change in front of the operator.
    a = resolve_acme_backend_target("http://10.90.1.4")
    b = resolve_acme_backend_target("http://10.90.1.4:8080")
    assert (a.host, a.port, a.ssl_flag) == (b.host, b.port, b.ssl_flag)


# ---------------------------------------------------------------------------
# 4. The generator's failure sentinel must never be mistaken for a config.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "# Error generating configuration: boom",
        "# Error: Cluster not found",
        "",
        None,
    ],
)
def test_detects_generation_failure_sentinels(content):
    assert is_config_generation_error(content) is True


@pytest.mark.parametrize("content", [_CONFIG, "global\n    daemon\n"])
def test_real_configs_are_not_flagged(content):
    assert is_config_generation_error(content) is False
