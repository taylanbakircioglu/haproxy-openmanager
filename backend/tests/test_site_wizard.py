"""
v1.5.0 Feature B — Site Setup Wizard model + helper unit tests.

Coverage matrix (Section 6.4 of the v1.5.0 plan):
- SiteCreate field validation
    * domain regex normalisation (M10)
    * acme mode REQUIRES apply_immediately=true (M22)
    * acme mode REQUIRES frontend.mode='http' AND bind_port=80
      (HTTP-01 challenge; Round 10 micro-finding)
- BackendStep / FrontendStep
    * '_' system-prefix rejection
    * https_redirect & redirect_rules mutual-exclusion (M19)
- _strip_pem_from_payload (draft persistence; M14/M9)

These tests stay 100% in the Pydantic model surface — no DB, no FastAPI
TestClient — so they run hermetically alongside the existing pure-unit
tests in this directory.
"""
import pytest
from pydantic import ValidationError

from models.site_wizard import (
    BackendStep,
    FrontendStep,
    SiteCreate,
    ServerStep,
    SSLChoice,
    _strip_pem_from_payload,
)


# ----------------------------------------------------------------------------
# Helper builders
# ----------------------------------------------------------------------------


def _backend(name="be_test", **overrides):
    return {"name": name, **overrides}


def _server(server_name="srv1", **overrides):
    return {
        "server_name": server_name,
        "server_address": "10.0.0.1",
        "server_port": 8080,
        **overrides,
    }


def _frontend(name="fe_http", mode="http", bind_port=80, **overrides):
    return {"name": name, "mode": mode, "bind_port": bind_port, **overrides}


_DUMMY_CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----"
_DUMMY_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIBdummy\n-----END PRIVATE KEY-----"


def _ssl_for_mode(ssl_mode):
    """Bulgu #31: 'upload' / 'existing' modes need shape-valid payloads."""
    if ssl_mode == "upload":
        return {
            "mode": "upload",
            "name": "cert-test",
            "certificate_content": _DUMMY_CERT_PEM,
            "private_key_content": _DUMMY_KEY_PEM,
        }
    if ssl_mode == "existing":
        return {"mode": "existing", "ssl_certificate_id": 1}
    return {"mode": ssl_mode}


def _payload(ssl_mode="none", apply_immediately=False, **overrides):
    base = {
        "cluster_id": 1,
        "domains": ["www.example.com"],
        "backend": _backend(),
        "servers": [_server()],
        "frontend": _frontend(),
        "ssl": _ssl_for_mode(ssl_mode),
        "apply_immediately": apply_immediately,
    }
    base.update(overrides)
    return base


# ----------------------------------------------------------------------------
# Domain validation
# ----------------------------------------------------------------------------


def test_payload_normalises_domain_to_lowercase():
    p = SiteCreate(**_payload(domains=["WWW.Example.COM"]) | {"domains": ["WWW.Example.COM"]})
    assert p.domains == ["www.example.com"]


def test_payload_rejects_garbage_domain():
    with pytest.raises(ValidationError):
        SiteCreate(**(_payload() | {"domains": ["not a domain"]}))


def test_payload_accepts_wildcard_subdomain():
    p = SiteCreate(**(_payload() | {"domains": ["*.example.com"]}))
    assert p.domains == ["*.example.com"]


def test_payload_rejects_empty_domains_list():
    with pytest.raises(ValidationError):
        SiteCreate(**(_payload() | {"domains": []}))


# ----------------------------------------------------------------------------
# Backend / frontend system-prefix rejection
# ----------------------------------------------------------------------------


def test_backend_rejects_underscore_prefix():
    with pytest.raises(ValidationError):
        BackendStep(**_backend(name="_acme_challenge_backend"))


def test_frontend_rejects_underscore_prefix():
    with pytest.raises(ValidationError):
        FrontendStep(**_frontend(name="_internal_fe"))


def test_backend_accepts_normal_name():
    bs = BackendStep(**_backend(name="be_legitimate"))
    assert bs.name == "be_legitimate"


def test_backend_rejects_invalid_chars():
    with pytest.raises(ValidationError):
        BackendStep(**_backend(name="be with spaces"))


# ----------------------------------------------------------------------------
# https_redirect / redirect_rules mutual exclusion (M19)
# ----------------------------------------------------------------------------


def test_frontend_rejects_https_redirect_with_redirect_rules():
    with pytest.raises(ValidationError, match="mutually exclusive"):
        FrontendStep(**_frontend(
            https_redirect=True,
            redirect_rules=[{"from": "/", "to": "https://x"}],
        ))


def test_frontend_accepts_https_redirect_alone():
    fe = FrontendStep(**_frontend(https_redirect=True))
    assert fe.https_redirect is True
    assert fe.redirect_rules == []


def test_frontend_accepts_redirect_rules_alone():
    fe = FrontendStep(**_frontend(
        https_redirect=False,
        redirect_rules=[{"from": "/", "to": "https://x"}],
    ))
    assert fe.https_redirect is False
    assert len(fe.redirect_rules) == 1


# ----------------------------------------------------------------------------
# ACME mode enforcement (M22 + Round 10 micro-finding)
# ----------------------------------------------------------------------------


def test_acme_mode_requires_apply_immediately():
    with pytest.raises(ValidationError, match="apply_immediately=true"):
        SiteCreate(**_payload(ssl_mode="acme", apply_immediately=False))


def test_acme_mode_requires_frontend_mode_http():
    with pytest.raises(ValidationError, match="frontend.mode='http'"):
        SiteCreate(**(_payload(ssl_mode="acme", apply_immediately=True)
                             | {"frontend": _frontend(mode="tcp")}))


def test_acme_mode_allows_non_80_bind_port():
    """Bulgu #34 (round-15 audit) — pre-fix the model validator hard-
    rejected any ACME payload with `frontend.bind_port != 80`. That
    blanket rule didn't fit the canonical enterprise pattern (one
    shared port-80 frontend host-routing many sites), so operators
    on multi-tenant clusters were stuck — port 80 collided with the
    existing shared frontend, and any other port was rejected here.
    The cluster-aware reachability check has moved to the route
    handler (`_validate_acme_port80_reachable`) where DB lookups are
    available; the model layer no longer blocks based on bind_port.
    """
    p = SiteCreate(**(_payload(ssl_mode="acme", apply_immediately=True)
                         | {"frontend": _frontend(bind_port=8080)}))
    assert p.ssl.mode == "acme"
    assert p.frontend.bind_port == 8080


def test_acme_mode_happy_path():
    p = SiteCreate(**_payload(ssl_mode="acme", apply_immediately=True))
    assert p.ssl.mode == "acme"
    assert p.apply_immediately is True


def test_non_acme_mode_does_not_force_apply_immediately():
    p = SiteCreate(**_payload(ssl_mode="none", apply_immediately=False))
    assert p.apply_immediately is False


def test_upload_mode_does_not_force_http_frontend():
    """Upload mode should accept any frontend port — HTTPS bind is the cert's job.

    R14 #v2: must use distinct ports for HTTP vs HTTPS otherwise the
    bind_port==https_bind_port collision validator fires (correctly —
    HAProxy can't bind the same address:port twice). Pick 8080 / 8443
    so we exercise BOTH the 'non-80 HTTP allowed' path AND the new
    distinct-port invariant simultaneously.
    """
    p_kwargs = _payload(ssl_mode="upload", apply_immediately=False) | {
        "frontend": _frontend(bind_port=8080),
        "ssl": {
            "mode": "upload",
            "name": "x",
            "certificate_content": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
            "private_key_content": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----",
            "https_bind_port": 8443,
        },
    }
    p = SiteCreate(**p_kwargs)
    assert p.frontend.bind_port == 8080
    assert p.ssl.https_bind_port == 8443


# ----------------------------------------------------------------------------
# Bulgu #31: upload mode rejects empty/missing PEMs and missing cert name
# ----------------------------------------------------------------------------


def test_upload_mode_rejects_empty_certificate_content():
    payload = _payload(ssl_mode="upload")
    payload["ssl"] = {**payload["ssl"], "certificate_content": ""}
    with pytest.raises(ValidationError) as ei:
        SiteCreate(**payload)
    assert "certificate_content" in str(ei.value)


def test_upload_mode_rejects_empty_private_key_content():
    payload = _payload(ssl_mode="upload")
    payload["ssl"] = {**payload["ssl"], "private_key_content": ""}
    with pytest.raises(ValidationError) as ei:
        SiteCreate(**payload)
    assert "private_key_content" in str(ei.value)


def test_upload_mode_rejects_non_pem_text():
    payload = _payload(ssl_mode="upload")
    payload["ssl"] = {**payload["ssl"], "certificate_content": "not a pem"}
    with pytest.raises(ValidationError) as ei:
        SiteCreate(**payload)
    assert "PEM" in str(ei.value) or "BEGIN" in str(ei.value)


def test_upload_mode_rejects_missing_cert_name():
    payload = _payload(ssl_mode="upload")
    payload["ssl"] = {**payload["ssl"], "name": ""}
    with pytest.raises(ValidationError) as ei:
        SiteCreate(**payload)
    assert "ssl.name" in str(ei.value) or "name" in str(ei.value)


def test_existing_mode_requires_ssl_certificate_id():
    payload = _payload(ssl_mode="existing")
    payload["ssl"] = {"mode": "existing"}  # missing ssl_certificate_id
    with pytest.raises(ValidationError) as ei:
        SiteCreate(**payload)
    assert "ssl_certificate_id" in str(ei.value)


# ----------------------------------------------------------------------------
# SSLChoice basic shape
# ----------------------------------------------------------------------------


def test_ssl_choice_default_https_bind_port_443():
    # SSLChoice itself does NOT enforce PEM content (the model_validator on
    # SiteCreate does); SSLChoice only enforces mode literal.
    s = SSLChoice(mode="upload", name="x", certificate_content="X", private_key_content="Y")
    assert s.https_bind_port == 443


def test_ssl_choice_acme_default_auto_renew_true():
    s = SSLChoice(mode="acme")
    assert s.auto_renew is True


def test_ssl_choice_invalid_mode_rejected():
    with pytest.raises(ValidationError):
        SSLChoice(mode="self-signed")


# ----------------------------------------------------------------------------
# ServerStep
# ----------------------------------------------------------------------------


def test_server_step_port_range_validated():
    with pytest.raises(ValidationError):
        ServerStep(server_name="s", server_address="10.0.0.1", server_port=70000)


def test_server_step_weight_default_100():
    s = ServerStep(server_name="s", server_address="10.0.0.1", server_port=80)
    assert s.weight == 100


# ----------------------------------------------------------------------------
# _strip_pem_from_payload (M14/M9)
# ----------------------------------------------------------------------------


def test_strip_pem_removes_private_key_content():
    payload = {
        "ssl": {
            "mode": "upload",
            "name": "cert",
            "certificate_content": "-----BEGIN CERT-----",
            "private_key_content": "-----BEGIN PRIVATE KEY-----",
            "chain_content": "-----BEGIN CERT-----",
        },
    }
    out = _strip_pem_from_payload(payload)
    assert out["ssl"]["private_key_content"] == ""
    assert out["ssl"]["certificate_content"] == ""
    assert out["ssl"]["chain_content"] == ""
    # Non-sensitive fields preserved.
    assert out["ssl"]["mode"] == "upload"
    assert out["ssl"]["name"] == "cert"


def test_strip_pem_recurses_into_lists():
    payload = {
        "servers": [
            {"server_name": "s1", "private_key": "K1", "ssl_enabled": True},
            {"server_name": "s2", "private_key": "K2", "ssl_enabled": False},
        ],
    }
    out = _strip_pem_from_payload(payload)
    for s in out["servers"]:
        assert s["private_key"] == ""


def test_strip_pem_preserves_unrelated_fields():
    payload = {
        "domains": ["www.example.com"],
        "cluster_id": 1,
        "ssl": {"mode": "none"},
    }
    out = _strip_pem_from_payload(payload)
    assert out == payload  # No PEM fields present → identical


def test_strip_pem_handles_primitive_values():
    """Top-level primitives should pass through unchanged."""
    assert _strip_pem_from_payload(123) == 123
    assert _strip_pem_from_payload("hello") == "hello"
    assert _strip_pem_from_payload(None) is None
    assert _strip_pem_from_payload([1, 2, 3]) == [1, 2, 3]
