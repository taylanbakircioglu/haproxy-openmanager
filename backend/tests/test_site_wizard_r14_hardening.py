"""v1.5.0 R14 — hardening from the deep-dive audit pass after R13.

Bulgular fixed in this round:

#R14-1 (Major): SiteDraftCreate had `payload: dict` with no
  size limit. An authenticated user could POST a 10MB JSON object,
  which gets serialised into a JSONB column in wizard_drafts. Multiplied
  across users and the 30-day retention window this is a slow-burn DOS
  on enterprise storage. Fix: 256KB cap on payload + 50 active drafts
  per user cap at the route layer.

#R14-2 (Major): When SSL is enabled the wizard creates BOTH an HTTP
  frontend (bind_port) AND an HTTPS frontend (https_bind_port) on the
  same agent IPs. If the user mistakenly sets https_bind_port equal to
  bind_port, HAProxy refuses to load the config (same address:port
  bound twice). Fix: model_validator-level rejection with a clear
  error.

These tests are static source assertions plus Pydantic model
exercises so the fix can't silently regress.
"""
import pytest
from pydantic import ValidationError

from models.site_wizard import (
    SiteCreate,
    SiteDraftCreate,
)


# -------------------- #R14-1: payload size cap --------------------


def test_draft_payload_under_cap_accepted():
    """Normal-sized drafts (~5KB) must continue to work — the cap only
    protects against pathological inputs."""
    payload = {
        "cluster_id": 1,
        "domains": ["a.example.com"],
        "backend": {"name": "be", "balance_method": "roundrobin", "mode": "http"},
        "servers": [{"server_name": "s1", "server_address": "10.0.0.1", "server_port": 8080}],
        "frontend": {"name": "fe", "mode": "http", "bind_address": "*", "bind_port": 80},
        "ssl": {"mode": "none"},
    }
    m = SiteDraftCreate(title="t", payload=payload)
    assert m.payload == payload


def test_draft_payload_over_256kb_rejected():
    """A draft with a 300KB blob must be rejected at the model layer
    BEFORE it ever reaches Postgres."""
    big_blob = "x" * (300 * 1024)
    with pytest.raises(ValidationError) as exc:
        SiteDraftCreate(title="t", payload={"big": big_blob})
    msg = str(exc.value)
    assert "256KB" in msg or "size limit" in msg, (
        "R14-1 regression: oversized drafts must be rejected with a "
        "clear, user-actionable message that mentions the cap."
    )


def test_draft_route_caps_per_user_drafts():
    """The route layer must enforce a per-user active-drafts cap of 50.
    Static source assertion (the route does a COUNT(*) check before
    INSERT) — this guards against an accidental refactor that drops
    the gate."""
    from pathlib import Path

    src = (
        Path(__file__).resolve().parent.parent
        / "routers"
        / "site_wizard.py"
    ).read_text()
    assert "50 active wizard drafts" in src
    assert "COUNT(*)" in src
    # Phase I: the cap query was migrated from a single-value
    # `wizard_type = 'proxied_host'` filter to a dual-value
    # `wizard_type IN ('site', 'proxied_host')` filter so the cap
    # still counts pre-rebrand drafts owned by the same user.
    # Accept either form so this pin survives the rebrand window.
    assert (
        "wizard_type IN ('site', 'proxied_host')" in src
        or "wizard_type = 'proxied_host'" in src
    )


# -------------------- #R14-2: bind_port collision ----------------


def _base_payload():
    """Minimal valid payload that we can override per test."""
    return {
        "cluster_id": 1,
        "domains": ["a.example.com"],
        "backend": {"name": "be", "balance_method": "roundrobin", "mode": "http"},
        "servers": [
            {"server_name": "s1", "server_address": "10.0.0.1", "server_port": 8080}
        ],
        "frontend": {
            "name": "fe",
            "mode": "http",
            "bind_address": "*",
            "bind_port": 8080,
        },
        "ssl": {"mode": "none"},
        "apply_immediately": False,
    }


def test_https_bind_port_equal_to_http_bind_port_rejected_for_existing():
    """ssl.mode='existing' — same port on both frontends must be rejected."""
    p = _base_payload()
    p["frontend"]["bind_port"] = 8443
    p["ssl"] = {
        "mode": "existing",
        "ssl_certificate_id": 1,
        "https_bind_port": 8443,  # same as bind_port → collision
    }
    with pytest.raises(ValidationError) as exc:
        SiteCreate(**p)
    msg = str(exc.value)
    assert "https_bind_port" in msg
    assert "cannot equal" in msg or "different ports" in msg


def test_https_bind_port_equal_to_http_bind_port_rejected_for_upload():
    """ssl.mode='upload' — same port on both frontends must be rejected."""
    p = _base_payload()
    p["frontend"]["bind_port"] = 8443
    p["ssl"] = {
        "mode": "upload",
        "name": "x",
        "certificate_content": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
        "private_key_content": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----",
        "https_bind_port": 8443,
    }
    with pytest.raises(ValidationError) as exc:
        SiteCreate(**p)
    assert "https_bind_port" in str(exc.value)


def test_distinct_bind_ports_pass_for_existing():
    """When the two ports differ the model must accept the payload."""
    p = _base_payload()
    p["frontend"]["bind_port"] = 80
    p["ssl"] = {
        "mode": "existing",
        "ssl_certificate_id": 1,
        "https_bind_port": 443,  # different — OK
    }
    # No raise expected.
    SiteCreate(**p)


def test_acme_mode_default_https_port_443_does_not_collide():
    """ssl.mode='acme' forces frontend.bind_port=80 and
    https_bind_port defaults to 443 — must not regress into
    self-collision."""
    p = _base_payload()
    p["frontend"]["bind_port"] = 80
    p["frontend"]["mode"] = "http"
    p["ssl"] = {"mode": "acme"}
    p["apply_immediately"] = True
    SiteCreate(**p)


def test_ssl_mode_none_does_not_check_port_collision():
    """When SSL is disabled there is no HTTPS frontend, so the
    collision check must NOT fire (https_bind_port is irrelevant)."""
    p = _base_payload()
    p["frontend"]["bind_port"] = 8080
    p["ssl"] = {"mode": "none", "https_bind_port": 8080}
    # No raise expected.
    SiteCreate(**p)
