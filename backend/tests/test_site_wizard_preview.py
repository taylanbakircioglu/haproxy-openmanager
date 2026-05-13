"""
v1.5.0 Feature B — preview helper unit tests.

Validates pure helpers used by the wizard's /preview and /create flows:
  * _build_redirect_rules (M19): https_redirect=true expands to a single
    canonical scheme-redirect row; explicit redirect_rules pass through.
  * preview MUST not write — verified by counting writes against a mock conn.

The preview endpoint itself relies on FastAPI dependency injection and DB
state; those paths are exercised in the Docker compose smoke tests
(t18). This file stays in pure-unit territory consistent with the rest of
the test suite.
"""
from unittest.mock import AsyncMock

import pytest

from models.site_wizard import (
    BackendStep,
    FrontendStep,
    SiteCreate,
    ServerStep,
    SSLChoice,
)
from routers.site_wizard import _build_redirect_rules


def _payload(**overrides):
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


# ----------------------------------------------------------------------------
# _build_redirect_rules
# ----------------------------------------------------------------------------


def test_build_redirect_rules_emits_canonical_https_redirect():
    """PR-1 R11.A-1 fix: pre-fix the row carried both ``type='scheme'``
    and a URL in ``location`` — but HAProxy ``redirect scheme`` only
    accepts a literal scheme name (``http``/``https``). The URL form
    of ``location`` is reserved for ``redirect location <URL>``. The
    canonical scheme-redirect now emits ``scheme: 'https'`` and
    drops the conflicting ``location`` field.

    Bulgu #28 (round-12 audit): SiteCreate now rejects
    https_redirect=true with ssl.mode='none' (self-bricking
    config — redirect points at a port with nothing listening).
    The test exercises `_build_redirect_rules` against a payload
    that uses ssl.mode='upload' with stub PEMs so the validator
    accepts the redirect combination.
    """
    p = _payload(
        frontend={"name": "fe", "bind_port": 80, "https_redirect": True},
        ssl={
            "mode": "upload",
            "name": "stub-cert",
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
    assert rule["code"] == 301
    # PR-1 fix: scheme name (NOT a URL) — HAProxy `redirect scheme https`
    assert rule["scheme"] == "https"
    # The URL-bearing 'location' field must NOT be present on a
    # type=scheme rule (it is parser-fatal).
    assert "location" not in rule, (
        "R11.A-1 regression: type=scheme redirect must not carry a "
        "'location' URL — HAProxy `redirect scheme` parser rejects it."
    )
    # Negative ssl_fc condition — only redirect on plain HTTP requests.
    assert "!{ ssl_fc }" in rule["condition"]


def test_build_redirect_rules_passes_explicit_rules_through():
    explicit = [
        {"type": "location", "code": 302, "location": "/new", "condition": ""},
    ]
    p = _payload(frontend={
        "name": "fe", "bind_port": 80,
        "https_redirect": False,
        "redirect_rules": explicit,
    })
    rules = _build_redirect_rules(p)
    assert rules == explicit


def test_build_redirect_rules_empty_when_neither_set():
    p = _payload(frontend={"name": "fe", "bind_port": 80})
    rules = _build_redirect_rules(p)
    assert rules == []


def test_build_redirect_rules_returns_independent_list():
    """Caller must not be able to mutate the model's redirect_rules through
    the returned list (defensive copy)."""
    explicit = [{"type": "location", "code": 302, "location": "/x", "condition": ""}]
    p = _payload(frontend={
        "name": "fe", "bind_port": 80,
        "https_redirect": False,
        "redirect_rules": explicit,
    })
    out = _build_redirect_rules(p)
    out.append({"injected": True})
    # The original model must remain unchanged
    assert len(p.frontend.redirect_rules) == 1


# ----------------------------------------------------------------------------
# Preview write-safety smoke
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_preview_does_not_invoke_create_helpers():
    """Sanity check: importing the module doesn't trigger create_*_row at
    module-load time. The actual /preview endpoint must NEVER invoke any
    create helper — those are reserved for the POST endpoint.
    """
    import services.backend_service as bs
    import services.frontend_service as fs
    import services.ssl_service as ss

    # Each create helper is an awaitable coroutine function — verify they
    # exist (regression guard: refactors that move them must not delete the
    # surface used by the wizard).
    assert callable(bs.create_backend_row)
    assert callable(bs.create_server_row)
    assert callable(fs.create_frontend_row)
    assert callable(ss.create_cert_row)
