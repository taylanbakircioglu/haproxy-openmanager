"""v1.5.0 R18b round 5 audit fixes — operator-experience tests.

Findings discovered during R18b round 5 (least-explored angles):

  R18b-#14 (Migration lag → 503): if the API process is brought up
    against a database where `run_all_migrations` has not finished,
    the new SSL eligibility query touches `ssl_certificate_clusters`
    which may not exist yet and the wizard surfaced a generic 500.
    Now mapped to 503 with a clear "run migrations" hint.

  R18b-#15 (HSTS preload sanity): the wizard accepted nonsensical
    HSTS combinations: `hsts_preload=true` with `hsts_enabled=false`
    (no header is emitted, but operator sees "preload on"); preload
    with `max_age < 1 year` (preload list rejects); preload without
    `include_subdomains` (preload list rejects). Now Pydantic
    rejects all three at validation time with a clear message.
"""
import pytest
from pydantic import ValidationError


# ----------------- R18b-#14: UndefinedTableError → 503 -----------------


def test_site_wizard_create_imports_undefined_table_error():
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "routers" / "site_wizard.py").read_text()
    assert "UndefinedTableError" in src, (
        "R18b-#14 regression: proxied_host router no longer imports "
        "UndefinedTableError — migration lag will surface as a "
        "generic 500 with raw asyncpg text"
    )
    assert "except UndefinedTableError" in src, (
        "R18b-#14 regression: create endpoint no longer catches "
        "UndefinedTableError"
    )
    catch_block = src[src.find("except UndefinedTableError"):]
    catch_block = catch_block[:catch_block.find("except ForeignKeyViolationError")]
    assert "status_code=503" in catch_block, (
        "R18b-#14 regression: UndefinedTableError handler no longer "
        "raises HTTP 503 (service unavailable until migrations apply)"
    )
    assert "migrations" in catch_block.lower(), (
        "R18b-#14 regression: 503 detail no longer mentions migrations "
        "— operator has no actionable guidance"
    )


# ----------------- R18b-#15: HSTS preload sanity -----------------


def test_hsts_preload_requires_enabled():
    from models.site_wizard import SSLChoice
    # baseline: enabled is the only constraint that lets preload pass
    SSLChoice(
        mode="none",
        hsts_enabled=True,
        hsts_preload=True,
        hsts_include_subdomains=True,
        hsts_max_age=31536000,
    )
    # preload without enabled — must reject
    with pytest.raises(ValidationError) as exc:
        SSLChoice(
            mode="none",
            hsts_enabled=False,
            hsts_preload=True,
            hsts_include_subdomains=True,
            hsts_max_age=31536000,
        )
    assert "hsts_enabled=true" in str(exc.value)


def test_hsts_preload_requires_one_year_max_age():
    from models.site_wizard import SSLChoice
    # one year - 1s — must reject
    with pytest.raises(ValidationError) as exc:
        SSLChoice(
            mode="none",
            hsts_enabled=True,
            hsts_preload=True,
            hsts_include_subdomains=True,
            hsts_max_age=31535999,
        )
    assert "31536000" in str(exc.value) or "1 year" in str(exc.value)
    # zero with preload — must reject
    with pytest.raises(ValidationError):
        SSLChoice(
            mode="none",
            hsts_enabled=True,
            hsts_preload=True,
            hsts_include_subdomains=True,
            hsts_max_age=0,
        )


def test_hsts_preload_requires_include_subdomains():
    from models.site_wizard import SSLChoice
    with pytest.raises(ValidationError) as exc:
        SSLChoice(
            mode="none",
            hsts_enabled=True,
            hsts_preload=True,
            hsts_include_subdomains=False,
            hsts_max_age=31536000,
        )
    assert "include_subdomains" in str(exc.value).lower()


def test_hsts_disabled_with_preload_off_still_works():
    """Backwards compat: legacy default values must continue to validate."""
    from models.site_wizard import SSLChoice
    SSLChoice(mode="none")  # all defaults
    SSLChoice(mode="none", hsts_enabled=False, hsts_preload=False)
    # operator sets long max_age but keeps preload off — fine
    SSLChoice(mode="none", hsts_enabled=True, hsts_max_age=31536000, hsts_preload=False)
