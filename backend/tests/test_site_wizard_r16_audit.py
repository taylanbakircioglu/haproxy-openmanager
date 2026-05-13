"""v1.5.0 R16 deep-audit fixes.

#R16-1 (Major): wildcard domain + ssl.mode='acme' rejected upfront.
  Pre-R16 the wizard accepted '*.example.com' with ACME mode; LE
  refused the order ("wildcard requires DNS-01") and the user only
  saw an opaque post-staging error. R16 rejects at the Pydantic
  validator with a clear, actionable message.

#R16-2 (Major): ensure_*_table() used to run CREATE INDEX inside the
  `if not exists:` block — meaning existing v1.5.0 first-deploy tables
  never got the prune-supporting expires_at / created_at indexes. The
  daily watermarked retention task fell back to a sequential scan.
  R16 hoists the CREATE INDEX IF NOT EXISTS calls OUT of the
  if-not-exists guard so they run on every startup.
"""
import pytest
from pydantic import ValidationError

from models.site_wizard import SiteCreate


def _base():
    return {
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
            "bind_port": 80,
        },
        "ssl": {"mode": "acme"},
        "apply_immediately": True,
    }


# ---------- #R16-1: wildcard + ACME ---------------


def test_wildcard_domain_rejected_for_acme_mode():
    """*.example.com + ssl.mode='acme' must raise at the Pydantic
    layer with a message that mentions 'wildcard' and 'DNS-01'."""
    p = _base()
    p["domains"] = ["*.example.com"]
    with pytest.raises(ValidationError) as exc:
        SiteCreate(**p)
    msg = str(exc.value)
    assert "wildcard" in msg.lower()
    assert "DNS-01" in msg


def test_mixed_wildcard_and_normal_domains_rejected_for_acme():
    """A wildcard in a SAN list must also fail (not just first domain)."""
    p = _base()
    p["domains"] = ["a.example.com", "*.example.com"]
    with pytest.raises(ValidationError) as exc:
        SiteCreate(**p)
    assert "*.example.com" in str(exc.value)


def test_wildcard_allowed_for_upload_and_existing():
    """Wildcards are fine with 'upload' / 'existing' — the user
    obtained the cert out-of-band so the WebPKI path is irrelevant."""
    # upload
    p = _base()
    p["domains"] = ["*.example.com"]
    p["frontend"]["bind_port"] = 8080
    p["ssl"] = {
        "mode": "upload",
        "name": "wild",
        "certificate_content": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
        "private_key_content": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----",
        "https_bind_port": 8443,
    }
    p["apply_immediately"] = False
    SiteCreate(**p)  # no raise

    # existing
    p2 = _base()
    p2["domains"] = ["*.example.com"]
    p2["frontend"]["bind_port"] = 8080
    p2["ssl"] = {
        "mode": "existing",
        "ssl_certificate_id": 1,
        "https_bind_port": 8443,
    }
    p2["apply_immediately"] = False
    SiteCreate(**p2)


def test_no_wildcard_acme_accepted():
    """Plain a.example.com + acme is the happy path."""
    SiteCreate(**_base())


# ---------- #R16-2: index hoist -------------------


def test_acme_event_indexes_hoisted_out_of_if_not_exists():
    """The CREATE INDEX calls for acme_order_events must NOT live
    inside the `if not exists:` block — older tables otherwise miss
    the indexes and the prune query falls back to a seq scan."""
    from pathlib import Path

    src = (
        Path(__file__).resolve().parent.parent
        / "database"
        / "migrations.py"
    ).read_text()

    # Find the ensure_acme_order_events_table function body.
    start = src.find("async def ensure_acme_order_events_table")
    end = src.find("async def ensure_wizard_drafts_table", start)
    assert start != -1 and end != -1
    func_body = src[start:end]

    # The R16 guarantee: between `if not exists:` and CREATE INDEX
    # there must be a logger.info() call that signals we left the
    # if-not-exists block. (We put `logger.info("Created acme_order_events table")`
    # INSIDE if-not-exists, then the CREATE INDEX runs UNCONDITIONALLY
    # at the same indent as the if-statement.)
    idx_line = func_body.find("CREATE INDEX IF NOT EXISTS idx_acme_order_events_order_id")
    if_line = func_body.find("if not exists:")
    log_line = func_body.find('logger.info("Created acme_order_events table")')
    assert if_line != -1 and idx_line != -1 and log_line != -1
    # Order: if -> logger.info (last line inside if) -> CREATE INDEX (outside if)
    assert if_line < log_line < idx_line, (
        "R16-2 regression: CREATE INDEX for acme_order_events_order_id "
        "appears to live INSIDE the `if not exists:` block. Hoist it "
        "out so existing tables also get the index on next startup."
    )


def test_wizard_drafts_indexes_hoisted_out_of_if_not_exists():
    """Same invariant for wizard_drafts.expires_at / user_type indexes."""
    from pathlib import Path

    src = (
        Path(__file__).resolve().parent.parent
        / "database"
        / "migrations.py"
    ).read_text()

    start = src.find("async def ensure_wizard_drafts_table")
    end = src.find("async def ", start + 10)  # next async def after this one
    assert start != -1
    func_body = src[start:end] if end != -1 else src[start:]

    idx_line = func_body.find("CREATE INDEX IF NOT EXISTS idx_wizard_drafts_expires_at")
    if_line = func_body.find("if not exists:")
    log_line = func_body.find('logger.info("Created wizard_drafts table")')
    assert if_line != -1 and idx_line != -1 and log_line != -1
    assert if_line < log_line < idx_line, (
        "R16-2 regression: CREATE INDEX for wizard_drafts_expires_at "
        "appears to live INSIDE the `if not exists:` block."
    )
