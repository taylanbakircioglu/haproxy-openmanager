"""R11 PR-2 — ssl_verify Pydantic Literal unification + DB default flip.

Pre-PR-2 state:
  - `models/frontend.py::FrontendConfig.ssl_verify` was `Optional[str]`
    so any string passed validation, including legacy `'true'` /
    `'false'` / `'1'` and obsolete UI artifacts. The HAProxy generator
    later rendered the value verbatim, producing parser-fatal output.
  - `models/backend.py::ServerConfig.ssl_verify` was also `Optional[str]`.
  - `models/site_wizard.py::ServerStep.ssl_verify` had a strict
    Literal but no empty-string coercion — so the React form's
    cleared select (`''`) raised a ValidationError on every save.
  - `models/site_wizard.py::SSLChoice.ssl_verify` likewise lacked
    coercion.
  - `database/migrations.py` set ``DEFAULT 'optional'`` for the
    frontends.ssl_verify column at table creation AND on
    ADD-COLUMN-on-existing-table paths. Combined with a missing
    client-CA column, this is the root cause of the user-reported
    fatal HAProxy ALERT after a wizard reject + apply cycle.

PR-2 fix:
  - All four models accept the same canonical Literal set. The
    server-side server-line uses `{'none','required'}` (HAProxy
    server SSL has no `optional`); the bind-side uses
    `{'none','optional','required'}`.
  - All four have a `pre`/`mode='before'` validator that coerces
    `''` and sentinel values (`'[]'`, `'{}'`, `'null'`) to None.
  - `migrations.py` drops the `DEFAULT 'optional'` clause on both the
    CREATE TABLE definition and the in-place ALTER ADD COLUMN line,
    AND adds a one-shot cleanup that:
      * drops the column DEFAULT in-place on already-deployed DBs,
      * NULLs out any rows whose ssl_verify is outside the canonical
        Literal set (preserving legitimate operator-set values).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError


_BACK = Path(__file__).resolve().parent.parent


# ─────────────────────────────────────────────────────────────────────────────
# Frontend (manual create endpoint)
# ─────────────────────────────────────────────────────────────────────────────


def test_frontend_config_ssl_verify_is_strict_literal():
    from models.frontend import FrontendConfig

    # Valid values → accepted
    for v in ("none", "optional", "required"):
        m = FrontendConfig(name="fe", bind_port=80, ssl_verify=v)
        assert m.ssl_verify == v

    # Invalid free-form string → rejected.
    # NOTE (R11-audit FIX-1): the case-insensitive coercer accepts
    # `'REQUIRED'`/`'OPTIONAL'`/`'NONE'` and lower-cases them to the
    # canonical Literal value. So we test only values that are
    # genuinely off-vocabulary.
    for bad in ("true", "false", "1", "yes", "Optional!"):
        with pytest.raises(ValidationError):
            FrontendConfig(name="fe", bind_port=80, ssl_verify=bad)


def test_frontend_config_ssl_verify_empty_coerces_to_none():
    from models.frontend import FrontendConfig

    for empty in ("", "[]", "{}", "null"):
        m = FrontendConfig(name="fe", bind_port=80, ssl_verify=empty)
        assert m.ssl_verify is None, (
            f"PR-2 R11.B regression: ssl_verify={empty!r} should coerce "
            "to None (UI form clear) — got {m.ssl_verify!r}"
        )


def test_frontend_config_ssl_verify_none_passthrough():
    from models.frontend import FrontendConfig

    # None and 'none' are distinct: None means "field omitted" while
    # 'none' is the explicit Literal value — both are valid.
    m1 = FrontendConfig(name="fe", bind_port=80)
    assert m1.ssl_verify is None
    m2 = FrontendConfig(name="fe", bind_port=80, ssl_verify=None)
    assert m2.ssl_verify is None


# ─────────────────────────────────────────────────────────────────────────────
# Backend server (manual create endpoint)
# ─────────────────────────────────────────────────────────────────────────────


def test_server_config_ssl_verify_strict_literal_no_optional():
    """HAProxy server-line ssl_verify only supports `none|required`
    (`optional` is a frontend-bind-only mode). The unified Literal
    must reflect that and coerce a stale `'optional'` from old
    payloads to None rather than rendering an invalid directive."""
    from models.backend import ServerConfig

    base = dict(server_name="srv1", server_address="10.0.0.1", server_port=80)

    for v in ("none", "required"):
        m = ServerConfig(**base, ssl_verify=v)
        assert m.ssl_verify == v

    # 'optional' is invalid server-side → coerce to None
    m = ServerConfig(**base, ssl_verify="optional")
    assert m.ssl_verify is None, (
        "PR-2 R11.B regression: server-side `ssl_verify='optional'` "
        "must coerce to None — HAProxy `server ... verify optional` "
        "is invalid syntax."
    )

    # Free-form garbage → rejected
    for bad in ("true", "yes", "1"):
        with pytest.raises(ValidationError):
            ServerConfig(**base, ssl_verify=bad)


def test_server_config_ssl_verify_empty_coerces_to_none():
    from models.backend import ServerConfig

    base = dict(server_name="srv1", server_address="10.0.0.1", server_port=80)
    for empty in ("", "[]", "{}", "null"):
        m = ServerConfig(**base, ssl_verify=empty)
        assert m.ssl_verify is None


# ─────────────────────────────────────────────────────────────────────────────
# Wizard ServerStep + SSLChoice
# ─────────────────────────────────────────────────────────────────────────────


def test_wizard_serverstep_ssl_verify_empty_coerces_to_none():
    from models.site_wizard import ServerStep

    base = dict(server_name="srv1", server_address="10.0.0.1", server_port=80)
    for empty in ("", "[]", "{}", "null"):
        m = ServerStep(**base, ssl_verify=empty)
        assert m.ssl_verify is None, (
            f"PR-2 R11.B regression: ServerStep.ssl_verify={empty!r} "
            "must coerce to None for UI form-clear compat."
        )

    # 'optional' is server-side invalid → coerce
    m = ServerStep(**base, ssl_verify="optional")
    assert m.ssl_verify is None


def test_wizard_sslchoice_ssl_verify_empty_coerces_to_none():
    from models.site_wizard import SSLChoice

    for empty in ("", "[]", "{}", "null"):
        m = SSLChoice(mode="existing", ssl_certificate_id=1, ssl_verify=empty)
        assert m.ssl_verify is None, (
            f"PR-2 R11.B regression: SSLChoice.ssl_verify={empty!r} "
            "must coerce to None for UI form-clear compat."
        )

    # Bulgu #26 (round-12 audit): only 'none' passes; the wizard
    # rejects 'optional' and 'required' until the ca-file column is
    # plumbed through (the renderer's client-CA path is a placeholder
    # that silently drops the verify directive otherwise).
    m = SSLChoice(mode="existing", ssl_certificate_id=1, ssl_verify="none")
    assert m.ssl_verify == "none"
    import pytest as _pytest
    from pydantic import ValidationError as _ValidationError
    for forbidden in ("optional", "required"):
        with _pytest.raises(_ValidationError):
            SSLChoice(mode="existing", ssl_certificate_id=1, ssl_verify=forbidden)


# ─────────────────────────────────────────────────────────────────────────────
# Migration source assertions (CREATE TABLE + ADD COLUMN + cleanup)
# ─────────────────────────────────────────────────────────────────────────────


def test_migration_no_legacy_default_optional():
    """Both the CREATE TABLE and the ADD COLUMN paths in
    `database/migrations.py` must NOT emit ``DEFAULT 'optional'``
    on the frontends.ssl_verify column. Pre-PR-2 every newly INSERTed
    frontend row carried `'optional'`, which combined with the absent
    client-CA column produced the user-reported fatal HAProxy ALERT.
    """
    src = (_BACK / "database" / "migrations.py").read_text()
    # ADD COLUMN path must omit DEFAULT 'optional'
    assert "ADD COLUMN ssl_verify VARCHAR(50) DEFAULT 'optional'" not in src, (
        "PR-2 R11.B regression: ssl_verify ADD COLUMN still emits the "
        "legacy `DEFAULT 'optional'` clause."
    )
    # CREATE TABLE path must not have DEFAULT 'optional'
    assert "ssl_verify VARCHAR(20) DEFAULT 'optional'" not in src, (
        "PR-2 R11.B regression: ssl_verify CREATE TABLE still emits the "
        "legacy `DEFAULT 'optional'` clause."
    )


def test_migration_drops_legacy_default_in_place():
    """Already-deployed databases need an in-place ALTER ... DROP
    DEFAULT to remove the legacy default. The cleanup must be
    idempotent (safe to re-run on databases that already had the
    column flipped)."""
    src = (_BACK / "database" / "migrations.py").read_text()
    assert "ALTER COLUMN ssl_verify DROP DEFAULT" in src, (
        "PR-2 R11.B regression: missing in-place DROP DEFAULT for "
        "frontends.ssl_verify on already-deployed databases."
    )


def test_migration_cleans_up_invalid_values_only():
    """The cleanup migration must NULL only rows OUTSIDE the canonical
    Literal set — operator-set valid values are preserved."""
    src = (_BACK / "database" / "migrations.py").read_text()
    assert "NOT IN ('none', 'optional', 'required')" in src, (
        "PR-2 R11.B regression: ssl_verify cleanup migration is "
        "missing or its WHERE clause is wrong (must filter to "
        "values outside the canonical Literal set only)."
    )
    # Sanity: it must not blanket-reset all rows
    assert "UPDATE frontends SET ssl_verify = NULL" not in src or \
        "WHERE ssl_verify IS NOT NULL" in src, (
        "PR-2 R11.B safety: cleanup must not blanket-NULL operator-set "
        "values — only rows outside the Literal set."
    )
