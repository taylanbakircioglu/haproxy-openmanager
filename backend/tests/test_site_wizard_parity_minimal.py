"""v1.5.0 R17 — Wizard ↔ Manual minimum-parity regression tests.

Covers the two new fields the wizard surfaces so users no longer have to
drop down to manual entity creation just for these capabilities:

  1. SSLChoice.ssl_verify (mTLS client cert auth on the HTTPS bind)
     - matches FrontendConfig.ssl_verify Literal["none", "optional", "required"]
     - default None (omitted) so v1.5.0 first-deploy hosts continue
       serving anonymous TLS — opt-in security upgrade
     - forwarded to:
       * routers/site_wizard.py upload+existing branch via
         object.__setattr__(https_payload, "ssl_verify", body.ssl.ssl_verify)
       * deferred_https_action.frontend_config["ssl_verify"] (ACME)
       * routers/letsencrypt.py SimpleNamespace shim (already had key)

  2. ServerStep.ssl_certificate_id (server-side mTLS client cert)
     - matches POST /api/backends/{id}/servers payload
     - default None — backward-compat with v1.5.0 saved drafts
     - rejected when ssl_enabled=False (meaningless combination)
     - forwarded by services/backend_service.create_server_row via
       getattr(server, "ssl_certificate_id", None) — the wizard router
       passes the ServerStep model directly, so no router-side change
       is needed (test pins the contract though)
"""
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from models.site_wizard import (
    SiteCreate,
    SSLChoice,
    ServerStep,
)


_REPO_ROOT = Path(__file__).resolve().parent.parent
_PROXIED_HOST_PY = _REPO_ROOT / "routers" / "site_wizard.py"
_LETSENCRYPT_PY = _REPO_ROOT / "routers" / "letsencrypt.py"
_BACKEND_SERVICE_PY = _REPO_ROOT / "services" / "backend_service.py"


# ----------------- Pydantic: SSLChoice.ssl_verify -----------------


def test_ssl_choice_ssl_verify_accepts_none_only():
    """Bulgu #26 (round-12 audit): SSLChoice.ssl_verify now rejects
    'optional' and 'required' because the renderer's client-CA path
    is a placeholder that silently drops the verify directive, which
    means the operator's mTLS selection would NOT actually be
    enforced. Only 'none' (and unset / form-cleared empties) pass.
    """
    ssl = SSLChoice(
        mode="upload", name="c", certificate_content="x",
        private_key_content="y", ssl_verify="none",
    )
    assert ssl.ssl_verify == "none"
    for forbidden in ("optional", "required"):
        with pytest.raises(ValidationError):
            SSLChoice(
                mode="upload", name="c", certificate_content="x",
                private_key_content="y", ssl_verify=forbidden,
            )


def test_ssl_choice_ssl_verify_default_is_none():
    """Default MUST be None. Setting it to e.g. 'none' here would change
    the bind directive emitted for v1.5.0 hosts that were created before
    the field existed (silent backward-compat regression)."""
    ssl = SSLChoice(
        mode="upload", name="c", certificate_content="x", private_key_content="y"
    )
    assert ssl.ssl_verify is None


def test_ssl_choice_ssl_verify_rejects_invalid_literal():
    with pytest.raises(ValidationError):
        SSLChoice(
            mode="upload",
            name="c",
            certificate_content="x",
            private_key_content="y",
            ssl_verify="optionall",  # typo — must fail
        )


# ----------------- Pydantic: ServerStep.ssl_certificate_id -----------------


def test_server_step_ssl_certificate_id_optional_default_none():
    s = ServerStep(server_name="srv1", server_address="10.0.0.1", server_port=8080)
    assert s.ssl_certificate_id is None


def test_server_step_ssl_certificate_id_requires_ssl_enabled():
    """ssl_certificate_id without ssl_enabled is meaningless — HAProxy
    silently ignores the cert directive on plaintext server lines."""
    with pytest.raises(ValidationError) as exc:
        ServerStep(
            server_name="srv1",
            server_address="10.0.0.1",
            server_port=8080,
            ssl_enabled=False,
            ssl_certificate_id=42,
        )
    assert "ssl_enabled" in str(exc.value).lower()


def test_server_step_ssl_certificate_id_with_ssl_enabled_ok():
    s = ServerStep(
        server_name="srv1",
        server_address="10.0.0.1",
        server_port=8080,
        ssl_enabled=True,
        ssl_certificate_id=42,
    )
    assert s.ssl_certificate_id == 42


def test_server_step_ssl_certificate_id_ge_1():
    """0 / negative IDs must be rejected — defensive guard against
    fat-fingered API calls (FK is enforced by Postgres later)."""
    with pytest.raises(ValidationError):
        ServerStep(
            server_name="srv1",
            server_address="10.0.0.1",
            server_port=8080,
            ssl_enabled=True,
            ssl_certificate_id=0,
        )


# ----------------- Backward-compat: payload without new fields -----------------


def test_legacy_payload_without_new_fields_still_validates():
    """A v1.5.0-shaped payload (no ssl.ssl_verify, no
    server.ssl_certificate_id) MUST still validate cleanly. This is the
    upgrade path: existing saved drafts and direct API callers must not
    break."""
    legacy = {
        "cluster_id": 1,
        "domains": ["example.com"],
        "backend": {"name": "be1", "balance_method": "roundrobin", "mode": "http"},
        "servers": [
            {"server_name": "s1", "server_address": "10.0.0.1", "server_port": 8080}
        ],
        "frontend": {
            "name": "fe1",
            "mode": "http",
            "bind_address": "*",
            "bind_port": 8080,
        },
        "ssl": {
            "mode": "upload",
            "name": "c",
            # Pydantic enforces PEM-shaped strings; minimal but valid
            # PEM blocks satisfy the wizard's regex without needing real
            # crypto material for this unit test.
            "certificate_content": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
            "private_key_content": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----",
            "https_bind_port": 8443,
        },
        "apply_immediately": False,
    }
    p = SiteCreate(**legacy)
    assert p.ssl.ssl_verify is None
    assert p.servers[0].ssl_certificate_id is None


# ----------------- Static source assertions: forwarding contract -----------------


def test_https_payload_setattr_includes_ssl_verify():
    """routers/site_wizard.py upload+existing branch: the
    object.__setattr__ loop on the SSL-cert FrontendConfig shim MUST
    forward `ssl_verify` so that create_frontend_row's bind generation
    sees the wizard's choice. R12 #f1 introduced this forwarding pattern
    for ssl_alpn / hsts / etc.; R17 extends it with ssl_verify."""
    src = _PROXIED_HOST_PY.read_text()
    # The forwarding tuple loop is the canonical place; the new entry
    # MUST be present alongside ssl_strict_sni.
    assert re.search(
        r'\(\s*"ssl_verify"\s*,\s*body\.ssl\.ssl_verify\s*\)',
        src,
    ), 'R17 regression: ssl_verify is no longer forwarded onto https_payload via object.__setattr__'


def test_deferred_https_action_includes_ssl_verify():
    """ACME branch: deferred_https_action.frontend_config MUST carry
    ssl_verify so that letsencrypt.py::_execute_post_completion_actions
    can forward it via the SimpleNamespace shim. Without it, ACME-issued
    HTTPS frontends would silently drop the user's mTLS choice."""
    src = _PROXIED_HOST_PY.read_text()
    assert re.search(
        r'"ssl_verify"\s*:\s*body\.ssl\.ssl_verify',
        src,
    ), "R17 regression: deferred_https_action.frontend_config dropped ssl_verify"


def test_letsencrypt_simple_namespace_forwards_ssl_verify():
    """The SimpleNamespace shim assembled in
    _execute_post_completion_actions must pull ssl_verify out of the
    frontend_config dict. Already present pre-R17, but pinned here so
    a future refactor can't silently drop it."""
    src = _LETSENCRYPT_PY.read_text()
    assert re.search(
        r'ssl_verify\s*=\s*fe_cfg\.get\(\s*"ssl_verify"\s*\)',
        src,
    ), "R17 regression: post-completion SimpleNamespace shim dropped ssl_verify"


def test_create_server_row_forwards_ssl_certificate_id():
    """services/backend_service.py::create_server_row MUST pull
    ssl_certificate_id off the server payload via getattr (so the wizard
    ServerStep model and the manual server create payload share one
    code path). Pin the contract — without it the wizard's new
    server.ssl_certificate_id field would silently drop on its way to
    the INSERT."""
    src = _BACKEND_SERVICE_PY.read_text()
    assert re.search(
        r'getattr\(\s*server,\s*"ssl_certificate_id",\s*None\s*\)',
        src,
    ), 'R17 regression: create_server_row no longer forwards ssl_certificate_id'
    # The column must also still be in the INSERT column list.
    assert "ssl_certificate_id" in src.split("INSERT INTO backend_servers")[1].split(") VALUES")[0]
