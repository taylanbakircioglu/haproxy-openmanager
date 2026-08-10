"""v1.11.0: nothing secret reaches request_logs.

The request/response log stores bodies and headers, so redaction is the single
control standing between "operators can debug a failing ACME order" and "the
audit table is a credential store". These tests pin both halves of that: the
things that MUST be redacted, and the innocent field names that must NOT be
(over-matching would silently blank out the fields the feature exists to show).
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.request_log_redaction import (  # noqa: E402
    REDACTED,
    decode_body,
    is_capturable_content_type,
    is_secret_key,
    redact,
    redact_headers,
    safe_error_text,
    scrub_query_string,
    scrub_url,
)


# --------------------------------------------------------------------------
# Key matching
# --------------------------------------------------------------------------

@pytest.mark.parametrize("key", [
    "password", "PASSWORD", "Pass_Word", "passwd", "pwd",
    # api_token is the literal field name of the Cloudflare provider credential
    # (services/dns_providers/cloudflare.py) — it must never survive a round trip.
    "token", "access_token", "refreshToken", "MFA_TOKEN",
    "api_token", "agent_token", "csrf_token", "session_token",
    "api_key", "API-KEY", "apiKey", "x-api-key",
    "secret", "client_secret", "eab_hmac_key",
    "private_key", "cert_private_key", "csr_private_key", "jwk_private_key",
    "authorization", "cookie", "set-cookie",
    "signature", "protected", "payload", "nonce", "replay-nonce",
    "key_authorization", "backup_codes", "totp_secret",
    "stats_password", "credentials", "encryption_key",
])
def test_secret_keys_are_detected(key):
    assert is_secret_key(key), f"{key!r} must be treated as a secret field name"


@pytest.mark.parametrize("key", [
    # Every one of these has a secret-looking substring but is innocent. If any
    # starts redacting, the log stops being useful for the exact debugging it
    # was built for.
    "key_suffix", "monkey", "keyboard", "turkey",
    "payload_size", "nonce_count",
    "public_key_id", "keys_total",
    "name", "status_code", "duration_ms", "domain", "directory_url",
])
def test_innocent_keys_are_not_redacted(key):
    assert not is_secret_key(key), (
        f"{key!r} was redacted by over-matching — the log would blank out a field "
        f"operators need"
    )


# --------------------------------------------------------------------------
# Recursive body redaction
# --------------------------------------------------------------------------

def test_nested_dicts_and_lists_are_redacted_recursively():
    body = {
        "user": {"username": "admin", "password": "hunter2"},
        "accounts": [
            {"email": "a@example.com", "eab_hmac_key": "s3cr3t"},
            {"email": "b@example.com", "api_token": "cf-token"},
        ],
        "cluster_id": 3,
    }
    out = redact(body)

    assert out["user"]["username"] == "admin"
    assert out["user"]["password"] == REDACTED
    assert out["accounts"][0]["email"] == "a@example.com"
    assert out["accounts"][0]["eab_hmac_key"] == REDACTED
    assert out["accounts"][1]["api_token"] == REDACTED
    assert out["cluster_id"] == 3


def test_depth_limit_stops_runaway_nesting():
    deep = current = {}
    for _ in range(20):
        current["child"] = {}
        current = current["child"]
    current["password"] = "leak"

    out = redact(deep)
    flattened = json.dumps(out)
    assert "***DEPTH_LIMIT***" in flattened
    assert "leak" not in flattened


def test_node_budget_bounds_a_very_wide_body():
    wide = {f"field_{i}": i for i in range(5000)}
    out = redact(wide)
    assert out.get("_node_limit") is True
    assert len(out) < 5000, "node budget did not bound a pathologically wide body"


def test_pem_private_key_is_redacted_by_value_shape():
    body = {"blob": "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 200 + "\n-----END RSA PRIVATE KEY-----"}
    out = redact(body)
    assert out["blob"] == REDACTED, (
        "a PEM private key under an innocent key name was stored verbatim"
    )


def test_jwt_shaped_string_is_redacted_by_value_shape():
    jwt_like = "eyJhbGciOiJIUzI1NiJ9." + "a" * 40 + "." + "b" * 40
    out = redact({"data": jwt_like})
    assert out["data"] == REDACTED


def test_long_strings_are_truncated_with_a_marker():
    out = redact({"note": "x" * 9000})
    assert out["note"].endswith("chars]")
    assert len(out["note"]) < 9000


def test_redact_never_raises_on_odd_input():
    class Weird:
        def __repr__(self):
            raise RuntimeError("boom")

    # Non-serializable leaf values must pass straight through, not explode.
    assert redact({"x": Weird()}) is not None


# --------------------------------------------------------------------------
# Headers (allowlist)
# --------------------------------------------------------------------------

def test_headers_use_an_allowlist_with_presence_markers():
    out = redact_headers({
        "Content-Type": "application/json",
        "User-Agent": "curl/8.0",
        "Authorization": "Bearer super-secret-token",
        "Cookie": "session=abc",
        "X-Custom-Internal": "some value",
    })

    assert out["content-type"] == "application/json"
    assert out["user-agent"] == "curl/8.0"
    # Presence is useful when debugging a 401; the value is not.
    assert out["authorization"] == REDACTED
    assert out["cookie"] == REDACTED
    # Not on the allowlist and not a known credential header -> dropped entirely.
    assert "x-custom-internal" not in out


def test_redact_headers_handles_none():
    assert redact_headers(None) is None
    assert redact_headers({}) is None


# --------------------------------------------------------------------------
# URLs and query strings
# --------------------------------------------------------------------------

def test_query_string_secrets_are_scrubbed():
    scrubbed, as_dict = scrub_query_string("token=abc123&page=2&api_key=xyz")
    assert "abc123" not in scrubbed
    assert "xyz" not in scrubbed
    assert "page=2" in scrubbed
    assert as_dict["token"] == REDACTED
    assert as_dict["page"] == "2"


def test_scrub_url_strips_userinfo_and_query_secrets():
    out = scrub_url("https://user:hunter2@api.example.com:8443/v1/zones?api_key=abc&page=1")
    assert "hunter2" not in out
    assert "user" not in out.split("/v1")[0].replace("api.example.com", "")
    assert "abc" not in out
    assert "api.example.com:8443" in out
    assert "page=1" in out


def test_scrub_url_drops_the_fragment():
    # Fragments never reach a server, and they are a classic token carrier.
    assert "#" not in scrub_url("https://example.com/x?a=1#access_token=leak")


# --------------------------------------------------------------------------
# Body decoding, capping, truncation marker
# --------------------------------------------------------------------------

def test_decode_body_parses_and_redacts_json():
    raw = json.dumps({"username": "admin", "password": "hunter2"}).encode()
    value, truncated = decode_body(raw, "application/json", len(raw))
    assert value["username"] == "admin"
    assert value["password"] == REDACTED
    assert truncated is False


def test_decode_body_marks_truncation_with_the_original_size():
    full = b"x" * 20000
    captured = full[:1024]
    value, truncated = decode_body(captured, "text/plain", len(full))
    assert truncated is True
    assert value["_truncated"] is True
    assert value["_original_bytes"] == 20000


def test_decode_body_wraps_non_json_as_raw_object():
    value, _ = decode_body(b"plain text response", "text/plain", 19)
    assert value == {"_raw": "plain text response"}


def test_decode_body_survives_truncated_json():
    # A JSON body cut off at the cap will not parse — keep the prefix rather
    # than losing the field entirely.
    value, truncated = decode_body(b'{"a": "bb', "application/json", 500)
    assert truncated is True
    assert "_raw" in value


def test_decode_body_parses_form_encoded():
    value, _ = decode_body(b"username=admin&password=hunter2",
                           "application/x-www-form-urlencoded", 30)
    assert value["username"] == "admin"
    assert value["password"] == REDACTED


def test_decode_body_returns_none_for_empty():
    assert decode_body(b"", "application/json", 0) == (None, False)
    assert decode_body(None, "application/json", 0) == (None, False)


def test_binary_content_types_are_not_capturable():
    assert is_capturable_content_type("application/json")
    assert is_capturable_content_type("application/json; charset=utf-8")
    assert is_capturable_content_type("text/plain")
    assert not is_capturable_content_type("application/octet-stream")
    assert not is_capturable_content_type("image/png")
    assert not is_capturable_content_type("text/event-stream")


# --------------------------------------------------------------------------
# Error rendering
# --------------------------------------------------------------------------

def test_safe_error_text_type_only_hides_the_message():
    exc = ValueError("https://api.godaddy.com/v1/domains/secret-zone/records failed")
    assert safe_error_text(exc, type_only=True) == "ValueError"
    assert "godaddy" not in safe_error_text(exc, type_only=True)


def test_safe_error_text_includes_the_message_when_allowed():
    text = safe_error_text(RuntimeError("connection refused"))
    assert text.startswith("RuntimeError")
    assert "connection refused" in text
