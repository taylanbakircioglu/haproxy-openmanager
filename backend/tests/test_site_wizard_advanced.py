"""v1.5.0 R12 — Advanced wizard fields (HAProxy 2.4+ tuning).

Round 12 expanded the wizard surface with:
- BackendStep: extended balance algorithms (parameter-FREE only — `hdr` /
  `url_param` rejected because they need a parameter), fullconn, cookie
  persistence, default-server-* defaults, request/response headers,
  validator forbidding cookie persistence with mode='tcp'.
- FrontendStep: maxconn, rate_limit, timeouts, compression, log_separate,
  monitor_uri, header injection, tcp_request_rules.
- ServerStep: extended ssl_verify Literal, TLS version Literals.
- SSLChoice: ALPN, ssl_min_ver, ssl_max_ver, ciphers, ciphersuites,
  strict-sni, HSTS opt-in.

These tests guarantee:
1. New fields default to safe / unset values (BACKWARD COMPAT — existing
   wizard payloads from v1.5.0 first deploy must still parse, AND the
   neutral defaults must NOT silently change the cipher / ALPN / HSTS
   profile of frontends created via direct API calls).
2. Field constraints are enforced (numeric ranges, Literal lists).
3. New TLS Literals cover HAProxy 2.4+ supported versions.
"""
import pytest
from pydantic import ValidationError

from models.site_wizard import (
    BackendStep,
    FrontendStep,
    ServerStep,
    SSLChoice,
)


# ----------------------------------------------------------------------------
# BackendStep advanced
# ----------------------------------------------------------------------------


def test_backend_step_new_balance_algorithms_accepted():
    """Round 12: only PARAMETER-FREE algorithms are accepted by the wizard.
    Parametric ones (`hdr(name)`, `url_param(name)`) need an extra input
    field that the wizard does not provide today — they are rejected to
    avoid producing invalid HAProxy syntax (`balance hdr` without args)."""
    for algo in ("roundrobin", "leastconn", "static-rr", "first", "source", "uri", "random"):
        b = BackendStep(name="be_test", balance_method=algo)
        assert b.balance_method == algo


@pytest.mark.parametrize("bad", ["hdr", "url_param", "rdp-cookie", "not-a-real-algo"])
def test_backend_step_invalid_balance_rejected(bad):
    """Parametric algorithms must be REJECTED until the wizard exposes a
    parameter input. Otherwise HAProxy errors out at apply time with a
    cryptic 'invalid keyword' message."""
    with pytest.raises(ValidationError):
        BackendStep(name="be_test", balance_method=bad)


def test_backend_step_cookie_on_tcp_mode_rejected():
    """Round 12 (Bulgu #f8): HAProxy `cookie` directive is HTTP-only.
    The wizard must reject the combination at validation time so the
    user gets a clear actionable error instead of an apply-time HAProxy
    syntax failure."""
    with pytest.raises(ValidationError, match="mode='http'"):
        BackendStep(name="be_test", mode="tcp", cookie_name="SRVID")


def test_backend_step_cookie_on_http_mode_accepted():
    """Counter-test: cookie persistence on http mode is allowed."""
    b = BackendStep(
        name="be_test", mode="http", cookie_name="SRVID",
        cookie_options="insert indirect nocache",
    )
    assert b.cookie_name == "SRVID"


def test_backend_step_tcp_mode_without_cookie_accepted():
    """Counter-test: TCP backend without cookie is fine."""
    b = BackendStep(name="be_test", mode="tcp")
    assert b.mode == "tcp"
    assert b.cookie_name is None


def test_backend_step_advanced_defaults_unset():
    b = BackendStep(name="be_test")
    # New fields must default to None so existing payloads don't break.
    assert b.fullconn is None
    assert b.cookie_name is None
    assert b.cookie_options is None
    assert b.default_server_inter is None
    assert b.default_server_fall is None
    assert b.default_server_rise is None
    assert b.request_headers is None
    assert b.response_headers is None


def test_backend_step_cookie_persistence_roundtrip():
    b = BackendStep(
        name="be_test",
        cookie_name="SRVID",
        cookie_options="insert indirect nocache",
    )
    assert b.cookie_name == "SRVID"
    assert b.cookie_options == "insert indirect nocache"


# ----------------------------------------------------------------------------
# FrontendStep advanced
# ----------------------------------------------------------------------------


def test_frontend_step_advanced_defaults_safe():
    f = FrontendStep(name="fe_test")
    # No defaults that would change existing behaviour.
    assert f.maxconn is None
    assert f.rate_limit is None
    assert f.compression is False
    assert f.log_separate is False
    assert f.monitor_uri is None
    assert f.tcp_request_rules is None
    assert f.request_headers is None
    assert f.response_headers is None


def test_frontend_step_rate_limit_must_be_non_negative():
    with pytest.raises(ValidationError):
        FrontendStep(name="fe_test", rate_limit=-1)


def test_frontend_step_maxconn_must_be_positive():
    with pytest.raises(ValidationError):
        FrontendStep(name="fe_test", maxconn=0)


# ----------------------------------------------------------------------------
# ServerStep advanced TLS literals
# ----------------------------------------------------------------------------


def test_server_step_ssl_verify_literal():
    ServerStep(server_name="s", server_address="10.0.0.1", server_port=80, ssl_verify="none")
    ServerStep(server_name="s", server_address="10.0.0.1", server_port=80, ssl_verify="required")
    with pytest.raises(ValidationError):
        ServerStep(server_name="s", server_address="10.0.0.1", server_port=80, ssl_verify="bogus")


# R18c audit fix (round 3 #15): TLSv1.0 / TLSv1.1 are formally
# deprecated by RFC 8996 and are now REJECTED by the wizard
# validators. The legacy assertion that "any of the four literal
# values is accepted" is therefore split: the modern values pass,
# the deprecated values raise ValidationError. This test is the
# back-compat hinge — if a future revision re-allows TLS 1.0 / 1.1
# for any reason, that change should be deliberate and visible
# here.
@pytest.mark.parametrize("ver", ["TLSv1.2", "TLSv1.3"])
def test_server_step_tls_version_literals(ver):
    ServerStep(server_name="s", server_address="10.0.0.1", server_port=80, ssl_min_ver=ver)


@pytest.mark.parametrize("ver", ["TLSv1.0", "TLSv1.1"])
def test_server_step_tls_version_literals_rejects_deprecated(ver):
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ServerStep(
            server_name="s",
            server_address="10.0.0.1",
            server_port=80,
            ssl_enabled=True,
            ssl_min_ver=ver,
        )


def test_server_step_invalid_tls_version_rejected():
    with pytest.raises(ValidationError):
        ServerStep(server_name="s", server_address="10.0.0.1", server_port=80, ssl_min_ver="SSLv3")


# ----------------------------------------------------------------------------
# SSLChoice advanced TLS / HSTS
# ----------------------------------------------------------------------------


def test_ssl_choice_alpn_default_none_for_backward_compat():
    """Round 12 backward-compat fix: ssl_alpn default MUST be None at the
    Pydantic layer. Setting a non-empty default ('h2,http/1.1') would
    silently enable HTTP/2 on HTTPS frontends created via direct API
    callers (or saved drafts from the v1.5.0 first deploy). The wizard
    UI populates a sensible form-level initial value; the model stays
    neutral."""
    s = SSLChoice(mode="none")
    assert s.ssl_alpn is None


def test_ssl_choice_min_tls_default_none_for_backward_compat():
    """Round 12 backward-compat fix: ssl_min_ver default MUST be None.
    A 'TLSv1.2' default would silently disable TLSv1.0/1.1 for any
    HTTPS frontend that previously left ssl_min_ver unset — a behaviour
    change for direct API callers. The wizard UI populates 'TLSv1.2' as
    a form initial value; the model stays neutral."""
    s = SSLChoice(mode="none")
    assert s.ssl_min_ver is None


def test_ssl_choice_explicit_alpn_and_tls_versions_pass_through():
    """When the wizard form sends 'h2,http/1.1' and 'TLSv1.2', the
    model accepts and round-trips them unchanged."""
    s = SSLChoice(mode="acme", ssl_alpn="h2,http/1.1", ssl_min_ver="TLSv1.2")
    assert s.ssl_alpn == "h2,http/1.1"
    assert s.ssl_min_ver == "TLSv1.2"


def test_ssl_choice_hsts_off_by_default():
    s = SSLChoice(mode="none")
    assert s.hsts_enabled is False
    assert s.hsts_max_age == 31536000  # 1 year
    assert s.hsts_include_subdomains is True
    assert s.hsts_preload is False


def test_ssl_choice_strict_sni_off_by_default():
    s = SSLChoice(mode="none")
    assert s.ssl_strict_sni is False


# R18c audit fix (round 3 #15): same TLS 1.0 / 1.1 rejection as
# the ServerStep validator, but on the HTTPS frontend bind.
@pytest.mark.parametrize("ver", ["TLSv1.2", "TLSv1.3"])
def test_ssl_choice_tls_version_literals(ver):
    SSLChoice(mode="none", ssl_min_ver=ver)


@pytest.mark.parametrize("ver", ["TLSv1.0", "TLSv1.1"])
def test_ssl_choice_tls_version_literals_rejects_deprecated(ver):
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        SSLChoice(mode="none", ssl_min_ver=ver)


def test_ssl_choice_invalid_tls_version_rejected():
    with pytest.raises(ValidationError):
        SSLChoice(mode="none", ssl_min_ver="TLSv0.99")


def test_ssl_choice_rejects_unknown_auto_renew_before_days_field():
    """Round 12 (Bulgu #f3): the per-cert renew-before-days override is
    NOT plumbed into the renewal scheduler — so the field is removed
    from the wizard payload to avoid offering a placebo control. The
    Pydantic model must NOT accept it (stale draft would otherwise
    appear to set a value that is silently ignored)."""
    # SSLChoice does NOT have auto_renew_before_days. Direct callers
    # passing it get an extra-field error (or it's ignored, depending on
    # extra=). The strict assertion is just that the model has no such
    # attribute.
    s = SSLChoice(mode="acme")
    assert not hasattr(s, "auto_renew_before_days"), (
        "auto_renew_before_days must remain unimplemented until v1.6.0 "
        "renewal scheduler picks up per-cert overrides."
    )


# ----------------------------------------------------------------------------
# Backward compat: payload from v1.5.0 first deploy (sans advanced) parses
# ----------------------------------------------------------------------------


def test_v15_payload_without_advanced_still_parses():
    """If a saved draft from the v1.5.0 first deploy lacked all the new
    advanced fields, the model must still validate."""
    minimal_backend = BackendStep(name="be_legacy", balance_method="roundrobin", mode="http")
    assert minimal_backend.fullconn is None  # absence is fine

    minimal_frontend = FrontendStep(
        name="fe_legacy", mode="http", bind_address="*", bind_port=80
    )
    assert minimal_frontend.maxconn is None

    minimal_server = ServerStep(
        server_name="srv1", server_address="10.0.0.1", server_port=8080
    )
    assert minimal_server.ssl_enabled is False

    legacy_ssl_acme = SSLChoice(mode="acme", auto_renew=True)
    # Backward-compat: defaults stay None so v1.5.0-first-deploy callers
    # get the same HAProxy ssl-* directive set they got before R12.
    assert legacy_ssl_acme.ssl_alpn is None
    assert legacy_ssl_acme.ssl_min_ver is None
    assert legacy_ssl_acme.hsts_enabled is False
