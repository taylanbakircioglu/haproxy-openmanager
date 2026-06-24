"""Issue #35 — ACME DNS-01: focused unit tests for the pure logic (no DB/network).

Covers the TXT-value math (RFC 8555 §8.4 — raw SHA-256 digest, base64url, NOT hex),
the _acme-challenge record-name derivation (wildcard stripping), credential encryption
round-trip + tamper handling, and the DNS provider registry/allow-list.
"""
import base64
import hashlib
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-dns01-unit-tests")

from services.acme_service import ACMEService
from services.dns_providers import list_providers, is_supported, get_provider, DnsProviderError
from utils.dns_credentials import (
    encrypt_dns_credentials, decrypt_dns_credentials, reset_fernet_for_tests,
)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def test_dns_txt_value_is_raw_sha256_base64url():
    key_auth = "token123.thumbprintABC"
    expected = _b64url(hashlib.sha256(key_auth.encode("utf-8")).digest())
    assert ACMEService._dns_txt_value(key_auth) == expected
    # Must NOT be the (classic-mistake) base64url of the HEX digest.
    hex_based = _b64url(hashlib.sha256(key_auth.encode("utf-8")).hexdigest().encode("utf-8"))
    assert ACMEService._dns_txt_value(key_auth) != hex_based


def test_challenge_dns_name_derivation():
    assert ACMEService._challenge_dns_name("example.com") == "_acme-challenge.example.com"
    # Wildcard: the '*.' is stripped, so apex + wildcard share the SAME record name.
    assert ACMEService._challenge_dns_name("*.example.com") == "_acme-challenge.example.com"
    assert ACMEService._challenge_dns_name("foo.bar.example.com") == "_acme-challenge.foo.bar.example.com"


def test_credential_encryption_roundtrip():
    reset_fernet_for_tests()
    creds = {"api_token": "super-secret-token-value"}
    token = encrypt_dns_credentials(creds)
    assert token != "super-secret-token-value"
    assert "super-secret-token-value" not in token  # ciphertext, not plaintext
    assert decrypt_dns_credentials(token) == creds


def test_decrypt_invalid_token_returns_none():
    reset_fernet_for_tests()
    assert decrypt_dns_credentials("not-a-valid-fernet-token") is None


def test_provider_registry_and_allow_list():
    names = {p["name"] for p in list_providers()}
    assert {"manual", "cloudflare"} <= names
    assert is_supported("manual") and is_supported("cloudflare")
    assert not is_supported("route53")  # not in MVP allow-list

    assert get_provider("manual").automated is False
    cf = get_provider("cloudflare", {"api_token": "x"})
    assert cf.automated is True
    assert any(f["key"] == "api_token" for f in cf.credential_fields)

    raised = False
    try:
        get_provider("definitely-not-a-provider")
    except ValueError:
        raised = True
    assert raised


def test_cloudflare_token_sanitize():
    # Issue #35 follow-up: a pasted token with quotes/spaces/control/unicode chars produced an
    # invalid Authorization header (CF 6003 "Invalid request headers"). The sanitizer strips them.
    from services.dns_providers.cloudflare import _sanitize_token, CloudflareDNSProvider

    # Surrounding double quotes stripped.
    assert _sanitize_token('"abc123-_def"') == 'abc123-_def'
    # Interior spaces / tabs / newlines removed.
    assert _sanitize_token('abc 123\tdef\n') == 'abc123def'
    # A clean token68 string is unchanged (cannot corrupt a valid Cloudflare token).
    clean = 'A1b2-_C3.d4~e5+f6/g7=='
    assert _sanitize_token(clean) == clean
    # Single quotes and a zero-width char removed.
    assert _sanitize_token("'tok" + chr(0x200b) + "en'") == 'token'

    # The provider constructor sanitizes into _token and keeps the raw input for diagnostics.
    p = CloudflareDNSProvider({"api_token": '"my-token_123"'})
    assert p._token == 'my-token_123'
    assert p._raw_token == '"my-token_123"'
