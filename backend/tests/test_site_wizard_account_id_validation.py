"""v1.5.0 R13 — Bulgu #v1: ssl.account_id must be validated.

Before R13, the wizard accepted any truthy `ssl.account_id` and used it
directly:
    acme_account_id = body.ssl.account_id or _resolve_default_acme_account()
This let `account_id=999` (deleted, typo, cross-tenant) bypass validation
and surface much later as an FK violation deep inside
create_order_staged — the user saw a generic 500 long after submit.

R13 fix: explicitly look up letsencrypt_accounts by id and reject
non-existent or non-valid accounts with a clear 400 right at the
pre-flight gate.

These are static source-level assertions to guard against regressions.
"""
from pathlib import Path


SOURCE = (
    Path(__file__).resolve().parent.parent
    / "routers"
    / "site_wizard.py"
).read_text()


def test_account_id_existence_check_present():
    """The ACME branch must SELECT from letsencrypt_accounts by the user-
    supplied id BEFORE proceeding."""
    # Look for the explicit ID lookup query.
    assert "FROM letsencrypt_accounts" in SOURCE
    assert "body.ssl.account_id" in SOURCE


def test_account_id_status_validity_check_present():
    """Beyond existence, the account's status must be 'valid'. The fix
    rejects any other status (e.g. 'revoked', 'deactivated') with 400."""
    assert 'row["status"] != "valid"' in SOURCE, (
        "Bulgu #v1 regression: ssl.account_id must be rejected when the "
        "account exists but has been deactivated/revoked. Otherwise the "
        "wizard happily stages an order against an unusable LE account."
    )


def test_account_id_uses_400_not_500():
    """The validation error must surface as a clear 400 (user fixable)
    rather than letting the FK violation bubble up as a generic 500."""
    # Look for both the 400 status_code and the human-readable message.
    assert 'status_code=400' in SOURCE
    assert 'does not exist' in SOURCE


def test_account_id_none_falls_back_to_default():
    """When account_id is omitted (None), the wizard must still fall back
    to _resolve_default_acme_account so single-account installs don't
    regress."""
    assert "body.ssl.account_id is not None" in SOURCE
    assert "_resolve_default_acme_account" in SOURCE
