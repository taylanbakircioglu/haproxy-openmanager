"""Issue #35 — ACME DNS-01: focused unit tests for the pure logic (no DB/network).

Covers the TXT-value math (RFC 8555 §8.4 — raw SHA-256 digest, base64url, NOT hex),
the _acme-challenge record-name derivation (wildcard stripping), credential encryption
round-trip + tamper handling, the DNS provider registry/allow-list, and (v1.10.0) the
GoDaddy provider's zone-relative name derivation and additive RRset merge math.
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
    assert {"manual", "cloudflare", "godaddy"} <= names
    assert is_supported("manual") and is_supported("cloudflare") and is_supported("godaddy")
    assert not is_supported("route53")  # not in the allow-list

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


# --- v1.10.0: GoDaddy provider (pure logic only — no network, no DB) ---


def test_godaddy_credential_fields_schema():
    # Re-assert DnsCredentialsUpsert's validator rules directly against the declared schema, so the
    # UI can never render a field whose submission the API would reject with a 422.
    import re
    from services.dns_providers.godaddy import GoDaddyDNSProvider

    fields = GoDaddyDNSProvider.credential_fields
    assert [f["key"] for f in fields] == ["api_key", "api_secret"]
    for f in fields:
        assert re.match(r"^[a-zA-Z0-9_]{1,50}$", f["key"])         # DnsCredentialsUpsert key regex
        assert f["type"] == "password"                              # renders Input.Password, not Input
        assert isinstance(f["max_length"], int) and 0 < f["max_length"] <= 4000  # validator value cap
        assert f["help"] and isinstance(f["help"], str)             # shown in the Form.Item `extra` slot
    # api_secret is optional on purpose: leaving it blank is how a Personal Access Token is used
    # (Bearer), which is the migration path off the sso-key scheme GoDaddy is retiring.
    assert fields[0]["required"] is True and fields[1]["required"] is False
    # Must not reuse Cloudflare's field name: the register modal's credential Form.Items are named
    # cred_<key> in a SHARED form and are not cleared when the provider dropdown changes.
    assert "api_token" not in {f["key"] for f in fields}


def test_godaddy_provider_is_automated():
    p = get_provider("godaddy", {"api_key": "k", "api_secret": "s"})
    assert p.automated is True      # else the orchestrator takes the manual-confirm branch
    assert p.name == "godaddy" and 1 <= len(p.name) <= 50  # dns_provider Field(min_length=1, max_length=50)
    assert p.label == "GoDaddy"


def test_godaddy_missing_credentials_returns_not_ok():
    # verify_credentials must RETURN {"ok": False}, never raise: the router turns any non-
    # DnsProviderError into the information-free generic 422 and the user never sees the reason.
    import asyncio

    for creds in ({}, {"api_secret": "s"}):  # blank UI fields arrive as MISSING keys, not ""
        r = asyncio.run(get_provider("godaddy", creds).verify_credentials())
        assert r["ok"] is False and r["detail"]
    # Short-circuits before any request, so this touches no network.


def test_godaddy_auth_header_formats_and_secret_never_leaks():
    from services.dns_providers.godaddy import GoDaddyDNSProvider, _scrub

    sentinel = "SENTINEL-SECRET-DO-NOT-LEAK"
    p = GoDaddyDNSProvider({"api_key": "KEY123", "api_secret": sentinel})
    # Literal prefix, one space, a single colon — no base64, no quoting.
    assert p._auth_header() == f"sso-key KEY123:{sentinel}"
    # No secret -> Personal Access Token. This one branch is the whole sso-key-sunset migration.
    assert GoDaddyDNSProvider({"api_key": "PAT"})._auth_header() == "Bearer PAT"
    # _scrub removes credential substrings from anything bound for a log or an order event.
    assert sentinel not in _scrub(f"boom {sentinel} boom", "KEY123", sentinel)
    assert "KEY123" not in _scrub("boom KEY123", "KEY123", sentinel)
    assert _scrub("x" * 500, "KEY123") == "x" * 300  # bounded, so a huge body can't flood an event

    # The channel that actually persists text: _http_error composes the message an order event and
    # letsencrypt_orders.error_detail will carry, so it must scrub its own inputs — a caller that
    # forgets to pre-scrub must not be able to leak. (Regression guard: scrubbing used to live at
    # the single call site in _request instead of here.)
    exc = p._http_error(403, f"DENIED_{sentinel}", f"token {sentinel} rejected", None)
    assert sentinel not in str(exc) and "***" in str(exc)

    # This module must not log at all — logging is the one channel _scrub cannot reach, since the
    # arguments would be formatted by the logging framework rather than passed through it.
    import inspect
    import re as _re
    from services.dns_providers import godaddy as gd_mod

    assert not _re.search(r"\blogger\.\w+\(", inspect.getsource(gd_mod)), \
        "godaddy.py must not log; surface everything through DnsProviderError so it is scrubbed"


def test_godaddy_relative_record_name():
    # GoDaddy names are RELATIVE to the zone with no trailing dot; the apex is the literal "@".
    from services.dns_providers.godaddy import _relative_name

    assert _relative_name("_acme-challenge.example.com", "example.com") == "_acme-challenge"
    assert _relative_name("_acme-challenge.foo.bar.example.com", "example.com") == "_acme-challenge.foo.bar"
    assert _relative_name("example.com", "example.com") == "@"          # never "" — see _rrset_path
    assert _relative_name("_acme-challenge.example.com.", "example.com") == "_acme-challenge"
    assert _relative_name("_ACME-Challenge.Example.COM", "example.com") == "_acme-challenge"
    # Apex and wildcard produce the SAME relative name — which is exactly why the merge below
    # has to be additive.
    apex = ACMEService._challenge_dns_name("example.com")
    wild = ACMEService._challenge_dns_name("*.example.com")
    assert _relative_name(apex, "example.com") == _relative_name(wild, "example.com") == "_acme-challenge"


def test_godaddy_rrset_merge_is_additive():
    # THE critical test: GoDaddy's PUT REPLACES an entire RRset, so the merge math is the only thing
    # keeping a wildcard+apex certificate's two coexisting TXT values alive.
    from services.dns_providers.godaddy import _live_values, _merge_add, _merge_remove

    def vals(body):
        return sorted(r["data"] for r in body)

    assert vals(_merge_add([{"data": "valueA", "ttl": 600}], "valueB")) == ["valueA", "valueB"]
    assert _merge_add([{"data": "valueA"}], "valueA") is None      # idempotent; ACME retries land here
    # Total, not an all()-over-a-computed-list (which passes vacuously on an empty result): the
    # first publish at a fresh name must emit exactly one element, carrying the 600s TTL floor.
    assert _merge_add([], "v") == [{"data": "v", "ttl": 600}]      # below 600 GoDaddy answers 422
    # Tombstone rows ({"data": ""}) must never be echoed back — GoDaddy answers 422 INVALID_BODY.
    assert _live_values([{"data": ""}, {"data": "x"}, {}]) == ["x"]
    assert vals(_merge_add([{"data": ""}, {"data": "valueA"}], "valueB")) == ["valueA", "valueB"]

    assert vals(_merge_remove([{"data": "valueA"}, {"data": "valueB"}], "valueB")) == ["valueA"]
    assert _merge_remove([{"data": "valueA"}], "valueZ") is None    # already gone — tolerate
    assert _merge_remove([], "valueZ") is None
    # [] means "use DELETE": PUT with an empty array is rejected (422, "Records must be specified").
    assert _merge_remove([{"data": "valueA"}], "valueA") == []
    assert _merge_remove([{"data": ""}, {"data": "valueA"}], "valueA") == []


def test_godaddy_never_builds_a_zone_wide_txt_path():
    # A 3-segment path (.../records/TXT) is the endpoint that wipes EVERY TXT in the zone — SPF,
    # DKIM, DMARC, domain verifications. An empty relative name must never be able to produce it.
    from services.dns_providers.godaddy import _rrset_path

    p = _rrset_path("example.com", "_acme-challenge")
    assert p == "/domains/example.com/records/TXT/_acme-challenge"
    assert p.count("/") == 5 and not p.endswith("/TXT")
    assert _rrset_path("example.com", "@").endswith("/%40")  # apex percent-encoded for proxy safety
    # "." and ".." survive quote() and are then normalized away by yarl when the URL is built, so
    # ".../records/TXT/.." would resolve to the whole-zone endpoint. They must be refused too.
    for bad in [("example.com", ""), ("", "_acme-challenge"), ("example.com", "."),
                ("example.com", ".."), ("example.com", "...")]:
        raised = False
        try:
            _rrset_path(*bad)
        except DnsProviderError:
            raised = True
        assert raised, f"_rrset_path{bad} must refuse to build a zone-wide TXT path"
    # And the only way to reach those inputs — a malformed domain — really does produce them.
    from services.dns_providers.godaddy import _relative_name as _rel
    assert _rel("..example.com", "example.com") == "."


def test_godaddy_credential_encryption_roundtrip():
    # The two-field credential dict rides the same Fernet blob as Cloudflare's single token.
    reset_fernet_for_tests()
    creds = {"api_key": "gd-key-plaintext", "api_secret": "gd-secret-plaintext"}
    token = encrypt_dns_credentials(creds)
    assert "gd-key-plaintext" not in token and "gd-secret-plaintext" not in token  # ciphertext
    assert decrypt_dns_credentials(token) == creds
    # This sorted key list is exactly what GET /dns-credentials exposes as credential_fields_present
    # — names only, never values.
    assert sorted(decrypt_dns_credentials(token).keys()) == ["api_key", "api_secret"]


_GD_NS = "/domains/example.com/records/NS"
_GD_TXT = "/domains/example.com/records/TXT/_acme-challenge"


def _gd_provider(responses):
    """A GoDaddy provider whose _request is replaced by a recorder.

    The pure-merge tests above prove the MATH; this proves the WRITE PATH actually uses it. Without
    it, replacing the merge with a single-value PUT — the mutation that silently destroys the
    sibling value of every wildcard+apex certificate — leaves the whole suite green.

    `responses` maps (method, path) -> value to return, or an Exception to raise. Unmapped calls
    return None, which is how the zone suffix-walk's failed probes are modelled.
    """
    import types
    from services.dns_providers.godaddy import GoDaddyDNSProvider

    calls = []

    async def _fake_request(self, session, method, path, **kwargs):
        calls.append((method, path, kwargs.get("json")))
        result = responses.get((method, path))
        if isinstance(result, Exception):
            raise result
        return result

    p = GoDaddyDNSProvider({"api_key": "k", "api_secret": "s"})
    p._request = types.MethodType(_fake_request, p)
    return p, calls


def _assert_never_zone_wide(calls):
    # A write to .../records or .../records/TXT replaces every TXT (or every record) in the zone.
    for method, path, _json in calls:
        if method in ("PUT", "DELETE"):
            assert not path.endswith("/records"), f"zone-wide write: {method} {path}"
            assert not path.endswith("/records/TXT"), f"type-wide write: {method} {path}"


def test_godaddy_add_write_path_merges_siblings():
    import asyncio

    # An existing sibling value at the same name — the apex half of an apex+wildcard certificate.
    p, calls = _gd_provider({
        ("GET", _GD_NS): [{"data": "ns1.domaincontrol.com"}],
        ("GET", _GD_TXT): [{"data": "valueA", "ttl": 600}],
    })
    asyncio.run(p.add_txt_record("_acme-challenge.example.com", "valueB"))

    writes = [c for c in calls if c[0] in ("PUT", "PATCH", "DELETE")]
    assert len(writes) == 1 and writes[0][0] == "PUT" and writes[0][1] == _GD_TXT
    # BOTH values must be in the body: GoDaddy's PUT replaces the whole RRset.
    assert sorted(r["data"] for r in writes[0][2]) == ["valueA", "valueB"]
    _assert_never_zone_wide(calls)


def test_godaddy_add_write_path_is_idempotent_and_fails_closed():
    import asyncio

    # Already published -> no write at all (this is where an ACME retry cycle lands).
    p, calls = _gd_provider({
        ("GET", _GD_NS): [{"data": "ns1.domaincontrol.com"}],
        ("GET", _GD_TXT): [{"data": "valueB", "ttl": 600}],
    })
    asyncio.run(p.add_txt_record("_acme-challenge.example.com", "valueB"))
    assert [c for c in calls if c[0] != "GET"] == []

    # Unreadable RRset read (2xx whose body did not parse as a list) must FAIL, never be treated as
    # an empty RRset — the PUT that follows would replace the sibling values with only ours.
    p, calls = _gd_provider({
        ("GET", _GD_NS): [{"data": "ns1.domaincontrol.com"}],
        ("GET", _GD_TXT): None,
    })
    raised = False
    try:
        asyncio.run(p.add_txt_record("_acme-challenge.example.com", "valueB"))
    except DnsProviderError:
        raised = True
    assert raised, "an unreadable RRset read must not be coerced into an empty RRset"
    assert [c for c in calls if c[0] != "GET"] == []


def test_godaddy_remove_write_path_uses_delete_for_the_last_value():
    import asyncio

    # Two values -> PUT back the survivor only.
    p, calls = _gd_provider({
        ("GET", _GD_NS): [{"data": "ns1.domaincontrol.com"}],
        ("GET", _GD_TXT): [{"data": "valueA"}, {"data": "valueB"}],
    })
    asyncio.run(p.remove_txt_record("_acme-challenge.example.com", "valueB"))
    writes = [c for c in calls if c[0] != "GET"]
    assert len(writes) == 1 and writes[0][0] == "PUT"
    assert [r["data"] for r in writes[0][2]] == ["valueA"]

    # Last value -> DELETE. `PUT []` is rejected by GoDaddy (422 INVALID_BODY), so an empty PUT
    # body would make every cleanup fail forever.
    p, calls = _gd_provider({
        ("GET", _GD_NS): [{"data": "ns1.domaincontrol.com"}],
        ("GET", _GD_TXT): [{"data": "valueA"}],
    })
    asyncio.run(p.remove_txt_record("_acme-challenge.example.com", "valueA"))
    writes = [c for c in calls if c[0] != "GET"]
    assert len(writes) == 1 and writes[0] == ("DELETE", _GD_TXT, None)
    assert not any(c[0] == "PUT" and c[2] == [] for c in calls)

    # Value already gone -> no write, no error.
    p, calls = _gd_provider({
        ("GET", _GD_NS): [{"data": "ns1.domaincontrol.com"}],
        ("GET", _GD_TXT): [{"data": "valueA"}],
    })
    asyncio.run(p.remove_txt_record("_acme-challenge.example.com", "valueZ"))
    assert [c for c in calls if c[0] != "GET"] == []
    _assert_never_zone_wide(calls)


class _FakeGDResponse:
    """Minimal stand-in for aiohttp's ClientResponse: status, headers, and json()."""

    _NO_BODY = object()

    def __init__(self, status, body=_NO_BODY, headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def json(self, content_type=None):
        if self._body is _FakeGDResponse._NO_BODY:
            raise ValueError("no body to decode")  # what an empty 204 does
        return self._body


class _FakeGDSession:
    def __init__(self, response):
        self._response = response
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = self._response

        class _Ctx:
            async def __aenter__(self_inner):
                return response

            async def __aexit__(self_inner, *exc):
                return False

        return _Ctx()


def test_godaddy_request_status_handling():
    import asyncio
    from services.dns_providers.godaddy import GoDaddyDNSProvider

    p = GoDaddyDNSProvider({"api_key": "KEY123", "api_secret": "SEC456"})

    def call(response):
        session = _FakeGDSession(response)
        try:
            return asyncio.run(p._request(session, "PUT", "/domains/example.com/records/TXT/x",
                                          json=[{"data": "v", "ttl": 600}])), None, session
        except DnsProviderError as exc:
            return None, str(exc), session

    # 204 with an EMPTY body is the normal answer to every GoDaddy write — it must not raise.
    body, err, session = call(_FakeGDResponse(204))
    assert body is None and err is None
    # Redirects are deliberately not followed (aiohttp would forward the Authorization header), so
    # a 3xx is a FAILED call. Treating it as success would report a redirected write as a no-op.
    _kw = session.calls[0][2]
    assert _kw["allow_redirects"] is False
    assert _kw["headers"]["Authorization"] == "sso-key KEY123:SEC456"
    assert _kw["headers"]["Accept"] == "application/json"
    for status in (301, 302, 307):
        body, err, _ = call(_FakeGDResponse(status))
        assert body is None and err and str(status) in err, f"HTTP {status} must not read as success"

    # 200 with a list is passed through verbatim.
    body, err, _ = call(_FakeGDResponse(200, [{"data": "v"}]))
    assert err is None and body == [{"data": "v"}]

    # Error mapping: each message must name what the operator has to fix.
    _, err, _ = call(_FakeGDResponse(401, {"code": "UNABLE_TO_AUTHENTICATE", "message": "nope"}))
    assert "PRODUCTION" in err and "UNABLE_TO_AUTHENTICATE" in err
    _, err, _ = call(_FakeGDResponse(403, {"code": "ACCESS_DENIED", "message": "not allowed"}))
    assert "domains.dns:update" in err
    # 429: Retry-After wins; the legacy body field is the fallback; absent both -> 60s default.
    _, err, _ = call(_FakeGDResponse(429, None, {"Retry-After": "17"}))
    assert "~17s" in err
    _, err, _ = call(_FakeGDResponse(429, {"retryAfterSec": 42}))
    assert "~42s" in err
    _, err, _ = call(_FakeGDResponse(429, {"Retry-After": "not-a-number"}))
    assert "~60s" in err
    # A non-dict error body must not crash the error mapper.
    _, err, _ = call(_FakeGDResponse(500, "<html>gateway</html>"))
    assert "500" in err

    # A transport failure MID-READ must not be mistaken for "empty body". Only a decode error may
    # be swallowed: a caller reading an RRset would otherwise see None and could take it for an
    # empty record set, and the full-RRset PUT that follows would destroy the sibling values.
    import aiohttp

    class _TruncatedResponse(_FakeGDResponse):
        async def json(self, content_type=None):
            raise aiohttp.ClientPayloadError("connection closed mid-body")

    body, err, _ = call(_TruncatedResponse(200))
    assert body is None and err and "GoDaddy" in err


def test_godaddy_zone_resolution_walks_suffixes_and_caches():
    import asyncio
    from services.dns_providers.godaddy import _GoDaddyHTTPError

    # The deepest candidate is not a zone (404 = "not this zone"); the walk must continue to the
    # registrable domain and then reuse it, so the second challenge at the same name costs no probe.
    p, calls = _gd_provider({
        ("GET", "/domains/_acme-challenge.example.com/records/NS"):
            _GoDaddyHTTPError("nope", status=404, code="UNKNOWN_DOMAIN"),
        ("GET", _GD_NS): [{"data": "ns1.domaincontrol.com"}],
        ("GET", _GD_TXT): [],
    })
    asyncio.run(p.add_txt_record("_acme-challenge.example.com", "valueA"))
    asyncio.run(p.add_txt_record("_acme-challenge.example.com", "valueB"))
    probes = [c for c in calls if c[1].endswith("/records/NS")]
    assert len(probes) == 2, "the resolved zone must be cached for the life of the provider"
    # Relative name derived from the RESOLVED zone, never from the deepest candidate.
    assert all(c[1] == _GD_TXT for c in calls if "/records/TXT/" in c[1])

    # A credential/eligibility failure during the walk must surface, not be swallowed as
    # "no managed domain" — otherwise the operator chases a DNS problem that is really a bad key.
    p, calls = _gd_provider({
        ("GET", "/domains/_acme-challenge.example.com/records/NS"):
            _GoDaddyHTTPError("denied", status=403, code="ACCESS_DENIED"),
    })
    raised = ""
    try:
        asyncio.run(p.add_txt_record("_acme-challenge.example.com", "v"))
    except DnsProviderError as exc:
        raised = str(exc)
    assert "denied" in raised and "No managed GoDaddy domain" not in raised


def test_b64url_decode_padding_roundtrip():
    # Issue #35 v1.8.2: _b64url_decode must round-trip for EVERY length, including base64url strings
    # whose length is a multiple of 4 (the case the old padding formula '=' * (4 - len%4) over-padded).
    from services.acme_service import _b64url as enc_fn, _b64url_decode as dec_fn
    for n in range(0, 20):
        data = bytes(range(n))
        assert dec_fn(enc_fn(data)) == data, f"round-trip failed at byte length {n}"


def test_nonce_scoped_per_directory():
    # Issue #35 v1.8.2: a nonce cached for one CA (directory_url) must never be returned for another,
    # and must be single-use. Both directories are pre-cached so _get_nonce returns without network.
    import asyncio
    svc = ACMEService()
    svc._nonce_by_dir = {"https://a.example/dir": "NONCE_A", "https://b.example/dir": "NONCE_B"}
    got = asyncio.run(svc._get_nonce("https://a.example/dir"))
    assert got == "NONCE_A"                                            # returns THIS CA's nonce
    assert svc._nonce_by_dir.get("https://a.example/dir") is None      # consumed (single-use)
    assert svc._nonce_by_dir.get("https://b.example/dir") == "NONCE_B" # the other CA is untouched


def _sql_paren_depth(sql: str):
    """Parenthesis depth of a SQL string, counting only OUTSIDE '...' literals (with ''
    escapes), `--` line comments and /* */ block comments. Single-pass state machine so a
    `--` inside a literal or a `'` inside a comment cannot corrupt the count. Dollar-quoted
    strings are out of scope (not used in this codebase). Returns (final_depth, min_depth).
    """
    depth = 0
    min_depth = 0
    state = "normal"
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if state == "normal":
            if ch == "'":
                state = "string"
            elif ch == "-" and nxt == "-":
                state = "line_comment"
                i += 1
            elif ch == "/" and nxt == "*":
                state = "block_comment"
                i += 1
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                min_depth = min(min_depth, depth)
        elif state == "string":
            if ch == "'":
                if nxt == "'":
                    i += 1  # escaped '' stays inside the literal
                else:
                    state = "normal"
        elif state == "line_comment":
            if ch == "\n":
                state = "normal"
        else:  # block_comment
            if ch == "*" and nxt == "/":
                state = "normal"
                i += 1
        i += 1
    return depth, min_depth


def test_acme_sql_parentheses_balanced():
    """Issue #35 v1.8.5: the completion task's order-claim query shipped (v1.8.0-v1.8.4) with an
    extra closing parenthesis, so EVERY 60s cycle died with `syntax error at or near ")"` and no
    background ACME work (claim/finalize/download, DNS-01 publish, wizard-staged promotion,
    retry, TXT cleanup) ever ran. The suite never caught it because the DB layer is mocked and
    raw SQL never reaches a real parser. This guard scans the ACME modules' SQL string literals
    for unbalanced parentheses.

    Guard scope is deliberately conservative to avoid false positives on production changes:
    keyword matching is case-sensitive (SQL is uppercase in this codebase; prose in docstrings
    is not) and f-string fragments are excluded (they split at `{`, so a fragment may be
    legitimately unbalanced).
    """
    import ast
    import re

    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    modules = [
        "main.py",
        os.path.join("services", "dns01_orchestrator.py"),
        os.path.join("services", "acme_service.py"),
        os.path.join("services", "letsencrypt_service.py"),
        os.path.join("routers", "letsencrypt.py"),
        os.path.join("routers", "acme_diagnostics.py"),
    ]
    problems = []
    for rel in modules:
        with open(os.path.join(backend_dir, rel), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fstring_parts = {
            id(const)
            for joined in ast.walk(tree) if isinstance(joined, ast.JoinedStr)
            for const in ast.walk(joined) if isinstance(const, ast.Constant)
        }
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            if id(node) in fstring_parts:
                continue
            sql = node.value
            if not re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", sql):
                continue
            if not re.search(r"\b(FROM|INTO|SET|WHERE)\b", sql):
                continue
            depth, min_depth = _sql_paren_depth(sql)
            if depth != 0 or min_depth < 0:
                problems.append(f"{rel}:{node.lineno} (paren depth {depth:+d}, min {min_depth})")
    assert not problems, f"Unbalanced parentheses in SQL literal(s): {problems}"


def test_sql_paren_depth_scanner():
    # The guard's scanner itself: parens in literals/comments must not count; '' escapes and
    # block comments handled; an extra ')' is reported via min_depth even if a later '(' would
    # re-balance the total.
    assert _sql_paren_depth("SELECT (1)") == (0, 0)
    assert _sql_paren_depth("SELECT (1))") == (-1, -1)                       # the v1.8.0 bug shape
    assert _sql_paren_depth("SELECT ')' , '((' FROM t") == (0, 0)            # literals ignored
    assert _sql_paren_depth("SELECT 'it''s ))' FROM t") == (0, 0)            # '' escape stays inside
    assert _sql_paren_depth("SELECT 1 -- comment ) (\nFROM t") == (0, 0)     # line comment ignored
    assert _sql_paren_depth("SELECT 1 /* ) */ FROM t") == (0, 0)             # block comment ignored
    assert _sql_paren_depth("SELECT 'a--b' AND (x=1\n)") == (0, 0)           # -- inside literal is data
    assert _sql_paren_depth("WHERE x) AND (y") == (0, -1)                    # net 0 but went negative
